//! Generic autonomous task supervisor.
//! See `docs/plans/2026-04-30-autopilot-supervisor-design.md`.

pub mod artifact;
pub mod backend;
pub mod classifier;
pub mod intake;
pub mod job;
pub mod orchestrator;
pub mod planner;
pub mod policy;
pub mod redact;
pub mod reporter;
pub mod state;
pub mod store;
pub mod task;
pub mod verification;
pub mod workflow;
pub mod workspace;

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

use crate::supervisor::artifact::ArtifactManager;
use crate::supervisor::backend::{reasoning::ReasoningBackend, Registry};
use crate::supervisor::classifier::{Classifier, HeuristicClassifier};
use crate::supervisor::intake::IntakeRouter;
use crate::supervisor::orchestrator::Orchestrator;
use crate::supervisor::planner::Planner;
use crate::supervisor::policy::{PolicyDecision, PolicyEngine};
use crate::supervisor::reporter::Reporter;
use crate::supervisor::store::TaskStore;
use crate::supervisor::task::TaskStatus;
use crate::supervisor::verification::{VerificationEngine, VerificationOutcome};

/// A supervisor refusal, as opposed to an internal fault.
///
/// # Why this is a type and not a message
///
/// The dashboard answers a refused lifecycle action with **409** and a genuine
/// failure with **500**. It used to tell them apart by matching substrings of
/// the error text (`"cannot pause a task in state"`, `"illegal state
/// transition"`, …), which is a trap: rewording a `bail!` anywhere in this
/// module silently reclassified every raced refusal as an internal error, with
/// nothing but a string-matching test to notice. Callers now classify with
/// [`anyhow::Error::downcast_ref`], so the compiler holds the two ends
/// together.
///
/// The route still reads the task's state *before* calling the supervisor and
/// answers 409 from that — this type only has to cover the window between that
/// read and the call, where a concurrent request can move the task.
#[derive(Debug)]
pub enum SupervisorError {
    /// No `sup_tasks` row with this id.
    NotFound { task_id: String },
    /// The task's persisted state does not allow the requested transition.
    ///
    /// `from` is the state the store actually holds (for a refusal raised by
    /// [`TaskStore::record_transition`]'s compare-and-swap) or the state the
    /// caller read before the race; `to` is the state it tried to reach.
    StateRefusal { from: TaskStatus, to: TaskStatus },
    /// An `execute_now` for this task is already running in this process.
    AlreadyRunning { task_id: String },
}

impl SupervisorError {
    /// No such task, as an `anyhow::Error` a caller can `downcast_ref`.
    pub fn not_found(task_id: &str) -> anyhow::Error {
        anyhow::Error::new(Self::NotFound {
            task_id: task_id.to_string(),
        })
    }

    /// A transition the task's state does not allow.
    pub fn state_refusal(from: TaskStatus, to: TaskStatus) -> anyhow::Error {
        anyhow::Error::new(Self::StateRefusal { from, to })
    }

    /// A second `execute_now` for a task that is already running.
    pub fn already_running(task_id: &str) -> anyhow::Error {
        anyhow::Error::new(Self::AlreadyRunning {
            task_id: task_id.to_string(),
        })
    }
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { task_id } => write!(f, "task not found: {task_id}"),
            Self::StateRefusal { from, to } => {
                write!(f, "illegal state transition {from:?} -> {to:?}")
            }
            Self::AlreadyRunning { task_id } => write!(
                f,
                "task {task_id} is already running; refusing to start a second run"
            ),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// Task ids with an `execute_now` currently in flight **in this process**.
///
/// A `std::sync::Mutex` rather than a `tokio` one, and the difference is not
/// stylistic: the critical section contains no `await`, and the id has to be
/// released from [`InFlightGuard::drop`], which cannot await — a
/// `tokio::sync::Mutex` guard could not be released there. That `Drop` is what
/// makes a cancelled request (a dropped `execute_now` future) release its task
/// instead of wedging it forever.
#[derive(Default)]
struct InFlight {
    ids: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl InFlight {
    /// Claim `task_id`, or return `None` if a run already holds it.
    fn enter(self: &Arc<Self>, task_id: &str) -> Option<InFlightGuard> {
        let mut ids = self.ids.lock().unwrap_or_else(|e| e.into_inner());
        if !ids.insert(task_id.to_string()) {
            return None;
        }
        Some(InFlightGuard {
            owner: Arc::clone(self),
            task_id: task_id.to_string(),
        })
    }
}

/// Releases the claimed task id when the run ends — normally, on an error, or
/// when the `execute_now` future is dropped mid-flight.
struct InFlightGuard {
    owner: Arc<InFlight>,
    task_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.owner
            .ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.task_id);
    }
}

pub enum SubmitOutcome {
    AutoExecutePlanned { task_id: String },
    NeedsClarification { task_id: String, question: String },
    NeedsApproval { task_id: String, reason: String },
}

impl SubmitOutcome {
    pub fn task_id(&self) -> String {
        match self {
            Self::AutoExecutePlanned { task_id }
            | Self::NeedsClarification { task_id, .. }
            | Self::NeedsApproval { task_id, .. } => task_id.clone(),
        }
    }
}

pub struct Supervisor {
    store: TaskStore,
    artifacts: Arc<ArtifactManager>,
    classifier: Box<dyn Classifier + Send + Sync>,
    policy: PolicyEngine,
    /// One `execute_now` per task id at a time; see [`InFlight`].
    in_flight: Arc<InFlight>,
    pub registry: Registry,
    pub workspace_mgr: Option<Arc<crate::supervisor::workspace::WorkspaceManager>>,
}

impl Supervisor {
    pub fn new_for_test(
        artifacts_root: PathBuf,
        conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        Self {
            store: TaskStore::new(conn.clone()),
            artifacts: Arc::new(ArtifactManager::new(artifacts_root, conn)),
            classifier: Box::new(HeuristicClassifier),
            policy: PolicyEngine::default(),
            in_flight: Arc::new(InFlight::default()),
            registry: Registry::new(),
            workspace_mgr: None,
        }
    }

    pub fn new_for_test_with_repo(
        artifacts_root: PathBuf,
        repo_path: PathBuf,
        conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        let mut sup = Self::new_for_test(artifacts_root, conn);
        sup.workspace_mgr = Some(Arc::new(
            crate::supervisor::workspace::WorkspaceManager::new(repo_path, false),
        ));
        sup
    }

    /// Production constructor. Registry should be pre-populated with backends.
    pub fn new(
        artifacts_root: PathBuf,
        conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
        registry: Registry,
        thresholds: crate::config::RiskThresholdsConfig,
    ) -> Self {
        Self {
            store: TaskStore::new(conn.clone()),
            artifacts: Arc::new(ArtifactManager::new(artifacts_root, conn)),
            classifier: Box::new(HeuristicClassifier),
            policy: PolicyEngine::with_thresholds(thresholds),
            in_flight: Arc::new(InFlight::default()),
            registry,
            workspace_mgr: None,
        }
    }

    pub fn register_test_reasoning_backend<F, Fut>(&mut self, f: F)
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        self.registry
            .register(Arc::new(ReasoningBackend::new_with_executor(f)));
    }

    /// Plan, execute, verify and report a task, synchronously, on this future.
    ///
    /// # Precondition
    ///
    /// The task must be in a state the machine allows to reach `Plan` — this
    /// method's first transition is `task.status -> Plan`. `Intake` and
    /// `Classify` are **not** among them (`Intake -> Plan` is not an edge), and
    /// neither is `PrepareWorkspace`; a task in one of those states is refused
    /// with [`SupervisorError::StateRefusal`] before anything is written. An
    /// earlier version had no such guard, so `execute_now` on an `Intake` task
    /// panicked through `record_transition`'s `debug_assert!` in debug builds
    /// and wrote an illegal `state` in release. The four dashboard routes
    /// cannot reach it (they pre-check), but this is a public method and an
    /// unstated precondition is a bug waiting for its second caller.
    ///
    /// # One run per task at a time
    ///
    /// A second `execute_now` for a task that is already running is refused
    /// with [`SupervisorError::AlreadyRunning`]. The compare-and-swap in
    /// [`TaskStore::record_transition`] is not enough on its own: two calls on
    /// a task that is already in `Execute` both ask for `Execute -> Plan`,
    /// which *is* a legal edge, so both would be accepted and both would run
    /// the plan — duplicate jobs, duplicate artifact writes and a duplicated
    /// audit trail.
    pub async fn execute_now(&self, task_id: &str) -> anyhow::Result<String> {
        // Held for the whole run and released on drop, including when this
        // future is cancelled.
        let _in_flight = self
            .in_flight
            .enter(task_id)
            .ok_or_else(|| SupervisorError::already_running(task_id))?;

        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;

        // PLAN — transition from the task's actual persisted status so that
        // resumed/mid-pipeline tasks produce a correct audit trail.
        if !crate::supervisor::state::transition_allowed(task.status.clone(), TaskStatus::Plan) {
            return Err(SupervisorError::state_refusal(
                task.status,
                TaskStatus::Plan,
            ));
        }
        self.store
            .record_transition(
                task_id,
                task.status.clone(),
                TaskStatus::Plan,
                "supervisor",
                None,
            )
            .await?;
        let plan = Planner::new().plan(&task);
        // Track the IDs of jobs planned for this execution so that, on resume,
        // orphan rows from a previous aborted run are excluded from verification.
        let current_job_ids: std::collections::HashSet<String> =
            plan.jobs.iter().map(|j| j.id.clone()).collect();
        self.artifacts
            .write_text(
                task_id,
                None,
                "plan",
                "plan.json",
                &serde_json::to_string_pretty(&serde_json::json!({
                    "jobs": plan.jobs.iter().map(|j| serde_json::json!({
                        "type": j.job_type, "backend": j.backend, "goal": j.goal,
                    })).collect::<Vec<_>>()
                }))?,
            )
            .await?;

        // PREPARE_WORKSPACE (only for code-modifying tasks when configured)
        let needs_ws = matches!(
            task.task_type,
            crate::supervisor::task::TaskType::CodeChange
                | crate::supervisor::task::TaskType::BugFix
                | crate::supervisor::task::TaskType::Refactor
        );
        let workspace_active = needs_ws && self.workspace_mgr.is_some();
        if workspace_active {
            if let Some(wm) = &self.workspace_mgr {
                self.store
                    .record_transition(
                        task_id,
                        TaskStatus::Plan,
                        TaskStatus::PrepareWorkspace,
                        "supervisor",
                        None,
                    )
                    .await?;
                let ws = wm.prepare(task_id, &task.title).await?;
                self.artifacts
                    .write_text(
                        task_id,
                        None,
                        "workspace",
                        "workspace.json",
                        &serde_json::to_string_pretty(&serde_json::json!({
                            "branch": ws.branch,
                            "path": ws.path.display().to_string(),
                        }))?,
                    )
                    .await?;
            }
        }

        // EXECUTE
        let pre_execute_state = if workspace_active {
            TaskStatus::PrepareWorkspace
        } else {
            TaskStatus::Plan
        };
        self.store
            .record_transition(
                task_id,
                pre_execute_state,
                TaskStatus::Execute,
                "supervisor",
                None,
            )
            .await?;
        let orch = Orchestrator::new(self.registry.clone(), self.store.clone());
        let res = orch.execute_plan(&task, plan).await?;
        // Only verify jobs from the current execution cycle (not orphans from prior runs).
        let all_jobs = self.store.jobs_for_task(task_id).await?;
        let jobs: Vec<_> = all_jobs
            .into_iter()
            .filter(|j| current_job_ids.contains(&j.id))
            .collect();

        // VERIFY
        // M3: regardless of orchestrator outcome we transition Execute->Verify
        // and let VerificationEngine produce the final pass/fail.
        let _ = res;
        if matches!(
            task.execution_mode,
            crate::supervisor::task::ExecutionMode::Rigorous
        ) {
            self.store
                .record_transition(
                    task_id,
                    TaskStatus::Execute,
                    TaskStatus::Review,
                    "supervisor",
                    None,
                )
                .await?;
            self.store
                .record_transition(
                    task_id,
                    TaskStatus::Review,
                    TaskStatus::Verify,
                    "supervisor",
                    None,
                )
                .await?;
        } else {
            self.store
                .record_transition(
                    task_id,
                    TaskStatus::Execute,
                    TaskStatus::Verify,
                    "supervisor",
                    None,
                )
                .await?;
        }
        let v = VerificationEngine.verify(&jobs);

        // REPORT + ARCHIVE
        let report = Reporter::render(&jobs);
        self.artifacts
            .write_text(task_id, None, "result", "report.md", &report)
            .await?;
        match v {
            VerificationOutcome::Passed => {
                self.store
                    .record_transition(
                        task_id,
                        TaskStatus::Verify,
                        TaskStatus::Report,
                        "supervisor",
                        None,
                    )
                    .await?;
                self.store
                    .record_transition(
                        task_id,
                        TaskStatus::Report,
                        TaskStatus::Archive,
                        "supervisor",
                        None,
                    )
                    .await?;
                self.store
                    .record_transition(
                        task_id,
                        TaskStatus::Archive,
                        TaskStatus::Done,
                        "supervisor",
                        None,
                    )
                    .await?;
                Ok(report)
            }
            VerificationOutcome::Failed(reason) => {
                self.store
                    .record_transition(
                        task_id,
                        TaskStatus::Verify,
                        TaskStatus::Failed,
                        "verifier",
                        Some(&reason),
                    )
                    .await?;
                Ok(format!("VERIFICATION FAILED: {reason}\n\n{report}"))
            }
        }
    }

    /// Mark a task as `Paused`. Records the transition unconditionally —
    /// the strict transition-table check is deferred to a later milestone.
    /// Pause a running task.
    ///
    /// Refuses a task the state machine does not allow to be paused. Without
    /// this guard `record_transition` would only catch the mistake through its
    /// `debug_assert!`, which is compiled out of release builds — so a pause of
    /// a finished task would write `Done → Paused` into `sup_tasks` and leave
    /// the supervisor in a state the rest of the code treats as a bug.
    pub async fn pause(&self, task_id: &str) -> anyhow::Result<()> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        if !crate::supervisor::state::transition_allowed(task.status.clone(), TaskStatus::Paused) {
            return Err(SupervisorError::state_refusal(
                task.status,
                TaskStatus::Paused,
            ));
        }
        self.store
            .record_transition(
                task_id,
                task.status,
                TaskStatus::Paused,
                "user",
                Some("paused"),
            )
            .await?;
        Ok(())
    }

    /// Resume a previously-paused task by re-entering `Execute` and running
    /// the rest of the pipeline.
    ///
    /// Only a `Paused` task may be resumed. An earlier version silently skipped
    /// the transition for any other state and called `execute_now` anyway,
    /// which had two consequences: a task parked in `Route` awaiting approval
    /// would run without one, and a finished task would attempt `Done → Plan`,
    /// panicking in debug and writing an illegal state in release.
    pub async fn resume(&self, task_id: &str) -> anyhow::Result<String> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        if task.status != TaskStatus::Paused {
            return Err(SupervisorError::state_refusal(
                task.status,
                TaskStatus::Execute,
            ));
        }
        self.store
            .record_transition(
                task_id,
                TaskStatus::Paused,
                TaskStatus::Execute,
                "user",
                Some("resumed"),
            )
            .await?;
        self.execute_now(task_id).await
    }

    /// IDs of tasks that look resumable on startup (paused or mid-pipeline).
    pub async fn resumable_task_ids(&self) -> anyhow::Result<Vec<String>> {
        self.store.list_resumable_task_ids().await
    }

    pub async fn state(&self, task_id: &str) -> anyhow::Result<TaskStatus> {
        Ok(self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?
            .status)
    }

    pub fn artifacts(&self) -> &ArtifactManager {
        &self.artifacts
    }

    /// Read access to the task store, for callers that need the persisted task
    /// list, a task's jobs, or its audit trail (`TaskStore::list_recent`,
    /// `jobs_for_task`, `transitions`) rather than just the current state.
    pub fn store(&self) -> &TaskStore {
        &self.store
    }

    /// Cancel a task: record `current state -> Cancelled` and nothing else.
    ///
    /// The transition is gated on [`state::transition_allowed`], the single
    /// source of truth for the state machine. From `Cancelled` is refused
    /// (`Cancelled -> Cancelled` is not an edge), as is cancelling a task in a
    /// state the table does not allow to be cancelled — notably `Verify`,
    /// `Report`, `Archive`, `Done`, `Failed` and `Classify`. This method does
    /// **not** invent an edge to make a button work: extending the state machine
    /// is a deliberate change to `state.rs`, not a side effect of a route.
    ///
    /// Scope: this marks the task. It does not abort work already in flight —
    /// `execute_now` runs its plan synchronously through the `Orchestrator`,
    /// which has no cancellation token (`Backend::cancel` is a per-job default
    /// with no supervisor-side caller). Cancelling a task that is mid-`execute_now`
    /// therefore records the state but the running plan still finishes.
    pub async fn cancel(&self, task_id: &str) -> anyhow::Result<()> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        let from = task.status;
        if !crate::supervisor::state::transition_allowed(from.clone(), TaskStatus::Cancelled) {
            return Err(SupervisorError::state_refusal(from, TaskStatus::Cancelled));
        }
        self.store
            .record_transition(
                task_id,
                from,
                TaskStatus::Cancelled,
                "user",
                Some("cancelled"),
            )
            .await?;
        Ok(())
    }

    /// Approve a task awaiting a human decision: drive it into `Execute` and run
    /// the existing pipeline.
    ///
    /// `submit` parks a `PolicyDecision::RequireApproval` task in `Route` (see
    /// the `RequireApproval` arm above, which returns
    /// [`SubmitOutcome::NeedsApproval`] without recording any further
    /// transition), so `Route -> Execute` is the edge this method normally
    /// takes. Approving is otherwise equivalent to resuming execution from
    /// wherever `submit` left the task, so it is implemented in terms of the
    /// existing [`Supervisor::execute_now`] path rather than duplicating the
    /// plan/execute/verify/report orchestration — exactly as
    /// [`Supervisor::resume`] does from `Paused`.
    ///
    /// `Execute` and not `Plan` is the intermediate state: `execute_now` records
    /// `task.status -> Plan` as its first transition, so a `Plan -> Plan` step
    /// would be illegal. `Execute -> Plan` is a legal edge.
    ///
    /// The gate is [`state::transition_allowed`] alone, which means approval is
    /// accepted from the states the table allows to reach `Execute` (`Route`,
    /// `Clarify`, `Plan`, `PrepareWorkspace`, `Paused`, `Review`, `Verify`) and
    /// refused from `Intake`, `Classify`, `Execute`, `Report`, `Archive`,
    /// `Done`, `Failed` and `Cancelled`. Note that approving a mid-pipeline task
    /// re-runs it (new plan, new jobs) — the same semantics `resume` already has,
    /// since both go through `execute_now`.
    pub async fn approve(&self, task_id: &str) -> anyhow::Result<String> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        let from = task.status;
        if !crate::supervisor::state::transition_allowed(from.clone(), TaskStatus::Execute) {
            return Err(SupervisorError::state_refusal(from, TaskStatus::Execute));
        }
        self.store
            .record_transition(task_id, from, TaskStatus::Execute, "user", Some("approved"))
            .await?;
        self.execute_now(task_id).await
    }

    pub async fn submit(
        &self,
        platform: &str,
        user_id: &str,
        chat_id: Option<&str>,
        text: &str,
    ) -> Result<SubmitOutcome> {
        let mut task = IntakeRouter::normalize(text);
        self.store.create(&task, platform, user_id, chat_id).await?;
        self.artifacts
            .write_text(
                &task.id,
                None,
                "intake",
                "intake.json",
                &serde_json::to_string_pretty(&task)?,
            )
            .await?;

        // CLASSIFY
        self.store
            .record_transition(
                &task.id,
                TaskStatus::Intake,
                TaskStatus::Classify,
                "supervisor",
                Some("auto"),
            )
            .await?;
        let outcome = (*self.classifier).classify(text);
        task.task_type = outcome.task_type.clone();
        task.risk_level = outcome.risk_level.clone();
        task.execution_mode = outcome.execution_mode.clone();
        task.required_capabilities = outcome.required_capabilities.clone();
        self.store.update_classification(&task).await?;
        self.artifacts
            .write_text(
                &task.id,
                None,
                "classification",
                "classification.json",
                &serde_json::to_string_pretty(&serde_json::json!({
                    "task_type": task.task_type,
                    "risk_level": task.risk_level,
                    "execution_mode": task.execution_mode,
                    "required_capabilities": task.required_capabilities,
                    "confidence": outcome.confidence,
                }))?,
            )
            .await?;

        // ROUTE → POLICY
        self.store
            .record_transition(
                &task.id,
                TaskStatus::Classify,
                TaskStatus::Route,
                "supervisor",
                None,
            )
            .await?;
        let decision = self.policy.decide(&task);
        self.artifacts
            .write_text(
                &task.id,
                None,
                "policy",
                "policy.json",
                &serde_json::to_string_pretty(&serde_json::json!({
                    "decision": format!("{decision:?}")
                }))?,
            )
            .await?;

        Ok(match decision {
            PolicyDecision::AutoExecute => SubmitOutcome::AutoExecutePlanned { task_id: task.id },
            PolicyDecision::Clarify => {
                self.store
                    .record_transition(
                        &task.id,
                        TaskStatus::Route,
                        TaskStatus::Clarify,
                        "policy",
                        Some("ambiguous"),
                    )
                    .await?;
                SubmitOutcome::NeedsClarification {
                    task_id: task.id,
                    question: "I'm not sure what you want me to do — can you clarify?".into(),
                }
            }
            PolicyDecision::RequireApproval => {
                let reason = match task.risk_level {
                    crate::supervisor::task::RiskLevel::High => {
                        "high-risk task requires approval".to_string()
                    }
                    crate::supervisor::task::RiskLevel::Medium => {
                        if self.policy.thresholds().require_approval_for_medium {
                            "medium-risk task requires approval (threshold config)".to_string()
                        } else if self.policy.thresholds().auto_execute_only_low {
                            "medium-risk task requires approval (auto_execute_only_low)".to_string()
                        } else {
                            "medium-risk task requires approval".to_string()
                        }
                    }
                    crate::supervisor::task::RiskLevel::Low => {
                        "low-risk task requires approval (threshold config)".to_string()
                    }
                };
                SubmitOutcome::NeedsApproval {
                    task_id: task.id,
                    reason,
                }
            }
            other => SubmitOutcome::NeedsApproval {
                task_id: task.id,
                reason: format!("{other:?}"),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::task::{Task, TaskStatus};

    /// Supervisor whose policy escalates a Medium-risk task to `RequireApproval`,
    /// so `submit` really parks the task in `Route` (the only way to get there
    /// through the public API — the heuristic classifier never emits High risk).
    fn supervisor_requiring_approval(
        dir: &std::path::Path,
        memory: &crate::memory::MemoryStore,
    ) -> Supervisor {
        let mut sup = Supervisor::new(
            dir.to_path_buf(),
            memory.connection(),
            Registry::new(),
            crate::config::RiskThresholdsConfig {
                require_approval_for_medium: true,
                ..Default::default()
            },
        );
        sup.register_test_reasoning_backend(|p| async move { Ok(format!("ran:{p}")) });
        sup
    }

    fn plain_supervisor(dir: &std::path::Path, memory: &crate::memory::MemoryStore) -> Supervisor {
        let mut sup = Supervisor::new_for_test(dir.to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|p| async move { Ok(format!("ran:{p}")) });
        sup
    }

    #[tokio::test]
    async fn store_accessor_exposes_the_store_the_supervisor_reads_from() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = Supervisor::new_for_test(dir.path().into(), memory.connection());

        let t = Task::new("listing", "req");
        sup.store().create(&t, "web", "u1", None).await.unwrap();

        // `state()` reads through `self.store`; agreeing with the accessor proves
        // the accessor is not a detached copy.
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Intake);
        assert_eq!(
            sup.store().get(&t.id).await.unwrap().unwrap().title,
            "listing"
        );
        assert_eq!(sup.store().list_recent(20).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn approve_runs_a_task_that_submit_parked_for_approval() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = supervisor_requiring_approval(dir.path(), &memory);

        let outcome = sup
            .submit("web", "u1", None, "refactor the parser")
            .await
            .unwrap();
        assert!(matches!(outcome, SubmitOutcome::NeedsApproval { .. }));
        let id = outcome.task_id();
        // The premise of this test: submit leaves an approval-pending task in Route.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);

        let report = sup.approve(&id).await.unwrap();
        assert!(report.contains("ran:"), "unexpected report: {report}");
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);

        let trail = sup.store().transitions(&id).await.unwrap();
        assert!(
            trail
                .iter()
                .any(|r| r.from == TaskStatus::Route && r.to == TaskStatus::Execute),
            "approve must record Route -> Execute, got {trail:?}"
        );
    }

    #[tokio::test]
    async fn approve_refuses_a_task_the_state_machine_does_not_allow() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let err = sup.approve(&id).await.unwrap_err().to_string();
        assert!(
            err.contains("Done") && err.contains("Execute"),
            "unexpected error: {err}"
        );
        // Refused means nothing was written.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        assert_eq!(sup.store().transitions(&id).await.unwrap().len(), before);
    }

    #[tokio::test]
    async fn cancel_marks_a_pending_task_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);

        sup.cancel(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Cancelled);

        let trail = sup.store().transitions(&id).await.unwrap();
        let last = trail.last().unwrap();
        assert_eq!(last.from, TaskStatus::Route);
        assert_eq!(last.to, TaskStatus::Cancelled);
        assert_eq!(last.actor, "user");
    }

    #[tokio::test]
    async fn cancel_refuses_a_task_that_already_finished() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let err = sup.cancel(&id).await.unwrap_err().to_string();
        assert!(
            err.contains("Done") && err.contains("Cancelled"),
            "unexpected error: {err}"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        assert_eq!(sup.store().transitions(&id).await.unwrap().len(), before);
    }

    /// `Verify -> Cancelled` is not an edge in `state.rs`, so a task under
    /// verification must be refused too — the guard is the state machine, not a
    /// "terminal states only" check.
    #[tokio::test]
    async fn cancel_is_refused_while_a_task_is_being_verified() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let t = Task::new("verify me", "req");
        sup.store().create(&t, "web", "u1", None).await.unwrap();
        for (from, to) in [
            (TaskStatus::Intake, TaskStatus::Classify),
            (TaskStatus::Classify, TaskStatus::Route),
            (TaskStatus::Route, TaskStatus::Plan),
            (TaskStatus::Plan, TaskStatus::Execute),
            (TaskStatus::Execute, TaskStatus::Verify),
        ] {
            sup.store()
                .record_transition(&t.id, from, to, "test", None)
                .await
                .unwrap();
        }
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Verify);

        assert!(sup.cancel(&t.id).await.is_err());
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Verify);
    }

    /// An unknown id must be a *typed* not-found, so the dashboard can answer
    /// 404 rather than 500 for a task that vanished under a request.
    #[tokio::test]
    async fn the_lifecycle_methods_report_a_missing_task_as_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let cancel_err = sup.cancel("does-not-exist").await.unwrap_err();
        assert!(
            matches!(
                cancel_err.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::NotFound { .. })
            ),
            "unexpected error: {cancel_err:?}"
        );
        let approve_err = sup.approve("does-not-exist").await.unwrap_err();
        assert!(
            matches!(
                approve_err.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::NotFound { .. })
            ),
            "unexpected error: {approve_err:?}"
        );
        for error in [
            sup.pause("does-not-exist").await.unwrap_err(),
            sup.resume("does-not-exist").await.unwrap_err(),
            sup.state("does-not-exist").await.unwrap_err(),
            sup.execute_now("does-not-exist").await.unwrap_err(),
        ] {
            assert!(
                matches!(
                    error.downcast_ref::<SupervisorError>(),
                    Some(SupervisorError::NotFound { .. })
                ),
                "unexpected error: {error:?}"
            );
            assert!(
                error.to_string().contains("task not found"),
                "unexpected message: {error}"
            );
        }
    }

    /// A task parked in `Route` by `submit` is awaiting approval. Resuming it
    /// must be refused: an earlier version skipped the `Paused` check and ran
    /// `execute_now` anyway, so a task awaiting a human decision would execute
    /// without one.
    #[tokio::test]
    async fn resume_refuses_a_task_that_is_awaiting_approval() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = supervisor_requiring_approval(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "refactor the parser")
            .await
            .unwrap()
            .task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let err = sup.resume(&id).await.unwrap_err();
        // Asserted on the typed refusal rather than on the message text: the
        // route classifies with `downcast_ref`, so what has to hold is the
        // *type* of the error, and `from` has to be the state it actually read.
        assert!(
            matches!(
                err.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::StateRefusal {
                    from: TaskStatus::Route,
                    to: TaskStatus::Execute,
                })
            ),
            "unexpected error: {err:?}"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
        assert_eq!(
            sup.store().transitions(&id).await.unwrap().len(),
            before,
            "a refused resume must not record a transition"
        );
    }

    /// `Done -> Plan` is not an edge, so resuming a finished task used to panic
    /// through `record_transition`'s `debug_assert!` in debug builds and write
    /// an illegal state in release builds.
    #[tokio::test]
    async fn resume_refuses_a_finished_task_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);

        let err = sup.resume(&id).await.unwrap_err().to_string();
        assert!(err.contains("Done"), "unexpected error: {err}");
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    #[tokio::test]
    async fn resume_accepts_a_paused_task() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.pause(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Paused);

        assert!(sup.resume(&id).await.is_ok());
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    /// `pause` had the same missing guard as `resume`: without it a finished
    /// task would take the illegal `Done -> Paused` edge.
    #[tokio::test]
    async fn pause_refuses_a_finished_task() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        let before = sup.store().transitions(&id).await.unwrap().len();

        assert!(sup.pause(&id).await.is_err());
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        assert_eq!(sup.store().transitions(&id).await.unwrap().len(), before);
    }

    // ── Concurrency ─────────────────────────────────────────────────────────
    //
    // Everything above runs on the default current-thread runtime, which is
    // exactly why the lost-update bug these tests guard survived the suite:
    // with one thread the two requests only interleave at `await` points, and
    // the registered test backend never yields, so the whole read-check-write
    // of a lifecycle method ran to completion before the second request was
    // even polled. Production is `#[tokio::main]` — multi-thread — and
    // reproduced it every time.

    /// A second `execute_now` for a task that is already running must be
    /// refused.
    ///
    /// The compare-and-swap in `record_transition` cannot catch this pair on
    /// its own: the task is in `Execute`, and `Execute -> Plan` **is** a legal
    /// edge, so both runs are accepted by the state machine and both run the
    /// plan. One reviewer reproduced exactly that, and in a debug build it
    /// surfaced as a `Plan -> Plan` panic out of `record_transition`.
    ///
    /// The backend parks the first run inside the orchestrator and reports on a
    /// channel when it got there, so the second call is issued against a task
    /// that is provably mid-plan: the interleaving is a fact of the test, not a
    /// matter of timing. The park has a short timeout because a *duplicate* run
    /// (the bug) waits for a release that only arrives after the second call
    /// has returned — without it this test would deadlock instead of failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn execute_now_refuses_a_second_run_of_a_task_already_running() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();

        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);

        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(move |prompt: String| {
            let entered_tx = entered_tx.clone();
            let mut release_rx = release_rx.clone();
            async move {
                let _ = entered_tx.send(());
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while !*release_rx.borrow_and_update() {
                        if release_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
                Ok(format!("ran:{prompt}"))
            }
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        // The premise of the test: `submit` leaves an auto-executed task in
        // Route, and `Route -> Plan` is a legal edge, so the state machine
        // accepts both runs.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);

        let first = {
            let sup = Arc::clone(&sup);
            let id = id.clone();
            tokio::spawn(async move { sup.execute_now(&id).await })
        };
        // The first run only reaches the backend after its `Route -> Plan` and
        // `Plan -> Execute` transitions, so by the time this returns the task
        // is demonstrably mid-plan.
        entered_rx
            .recv()
            .await
            .expect("the first run must reach the backend");

        let second = sup.execute_now(&id).await;
        assert!(
            matches!(
                second
                    .as_ref()
                    .err()
                    .and_then(|e| e.downcast_ref::<SupervisorError>()),
                Some(SupervisorError::AlreadyRunning { .. })
            ),
            "the second run must be refused as already running, got {second:?}"
        );

        release_tx.send(true).unwrap();
        let first = first.await.expect("the first run must not panic");
        assert!(first.is_ok(), "the first run must complete: {first:?}");

        let task = sup.store().get(&id).await.unwrap().unwrap();
        let planned = Planner::new().plan(&task).jobs.len();
        assert_eq!(
            sup.store().jobs_for_task(&id).await.unwrap().len(),
            planned,
            "a refused second run must not create a second set of jobs"
        );
        let trail = sup.store().transitions(&id).await.unwrap();
        let plan_edges = trail.iter().filter(|r| r.to == TaskStatus::Plan).count();
        assert_eq!(
            plan_edges, 1,
            "the plan must be entered exactly once: {trail:?}"
        );
    }

    /// The reviewer's reproduction, as a regression test: eight concurrent
    /// `resume`s of the same paused task.
    ///
    /// Before the fix, every one of them that read the task while it was still
    /// `Paused` recorded its own `Paused -> Execute` edge and ran the plan:
    /// several successes, several sets of job rows, several artifact rows for
    /// the same paths with different `sha256`, and — in debug builds — a
    /// `Plan -> Plan` panic out of `record_transition`. With the
    /// compare-and-swap exactly one can win, because after the first the row is
    /// no longer `Paused`.
    ///
    /// This test is deliberately on a **multi-thread** runtime. On the default
    /// current-thread runtime the futures only interleave at `await` points, so
    /// it would prove nothing — which is precisely how the old suite stayed
    /// green at 0/20 while production failed 20/20.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_resumes_start_the_plan_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|prompt| async move {
            tokio::task::yield_now().await;
            Ok(format!("ran:{prompt}"))
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.pause(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Paused);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let sup = Arc::clone(&sup);
            let id = id.clone();
            handles.push(tokio::spawn(async move { sup.resume(&id).await }));
        }

        let mut accepted = 0usize;
        let mut refused = 0usize;
        let mut panicked: Vec<String> = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(_report)) => accepted += 1,
                Ok(Err(e)) => {
                    assert!(
                        matches!(
                            e.downcast_ref::<SupervisorError>(),
                            Some(SupervisorError::StateRefusal { .. })
                                | Some(SupervisorError::AlreadyRunning { .. })
                        ),
                        "a refused resume must be a typed refusal, got {e:?}"
                    );
                    refused += 1;
                }
                // A panic is not a refusal. It is counted separately so the
                // failure message says which of the two happened.
                Err(join) => panicked.push(join.to_string()),
            }
        }
        assert!(panicked.is_empty(), "no run may panic: {panicked:?}");
        assert_eq!(
            accepted,
            1,
            "exactly one resume may start the plan (refused {refused}, panicked {})",
            panicked.len()
        );
        assert_eq!(refused, 7, "every other resume must be refused");

        let trail = sup.store().transitions(&id).await.unwrap();
        let resumed_edges = trail
            .iter()
            .filter(|r| r.from == TaskStatus::Paused && r.to == TaskStatus::Execute)
            .count();
        assert_eq!(
            resumed_edges, 1,
            "the audit trail must not carry duplicate edges: {trail:?}"
        );

        let task = sup.store().get(&id).await.unwrap().unwrap();
        let planned = Planner::new().plan(&task).jobs.len();
        assert_eq!(
            sup.store().jobs_for_task(&id).await.unwrap().len(),
            planned,
            "the task must have exactly one set of jobs"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    /// `Intake -> Plan` is not an edge, so `execute_now` on a task that has not
    /// been classified has no legal first transition. It used to reach
    /// `record_transition`'s `debug_assert!` and panic — a public method with an
    /// unstated precondition. It must be refused, and refuse *before* writing
    /// anything.
    #[tokio::test]
    async fn execute_now_refuses_a_task_that_has_not_been_classified() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let t = Task::new("raw", "req");
        sup.store().create(&t, "web", "u1", None).await.unwrap();
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Intake);

        let error = sup.execute_now(&t.id).await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::StateRefusal {
                    from: TaskStatus::Intake,
                    to: TaskStatus::Plan,
                })
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Intake);
        assert!(sup.store().transitions(&t.id).await.unwrap().is_empty());
        assert!(sup.store().jobs_for_task(&t.id).await.unwrap().is_empty());
    }

    /// The in-flight guard is released even when the run fails, or a task that
    /// hit a bad backend could never be run again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_in_flight_guard_is_released_after_a_failed_run() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|_prompt| async move {
            anyhow::bail!("the backend refused to run")
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        // The orchestrator records the failure as a failed job rather than
        // propagating it, so the run itself returns Ok; what matters is that
        // the guard is not still held afterwards.
        sup.execute_now(&id).await.unwrap();
        let error = sup.execute_now(&id).await.unwrap_err();
        assert!(
            !matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::AlreadyRunning { .. })
            ),
            "the guard must have been released: {error:?}"
        );
    }
}
