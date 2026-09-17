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

    pub async fn execute_now(&self, task_id: &str) -> anyhow::Result<String> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("task not found"))?;

        // PLAN — transition from the task's actual persisted status so that
        // resumed/mid-pipeline tasks produce a correct audit trail.
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
            .ok_or_else(|| anyhow::anyhow!("task not found"))?;
        if !crate::supervisor::state::transition_allowed(task.status.clone(), TaskStatus::Paused) {
            anyhow::bail!("cannot pause a task in state {:?}", task.status);
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
            .ok_or_else(|| anyhow::anyhow!("task not found"))?;
        if task.status != TaskStatus::Paused {
            anyhow::bail!(
                "cannot resume a task in state {:?}; only a paused task can be resumed",
                task.status
            );
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
            .ok_or_else(|| anyhow::anyhow!("task missing"))?
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
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        let from = task.status;
        if !crate::supervisor::state::transition_allowed(from.clone(), TaskStatus::Cancelled) {
            anyhow::bail!("illegal state transition {from:?} -> Cancelled");
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
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        let from = task.status;
        if !crate::supervisor::state::transition_allowed(from.clone(), TaskStatus::Execute) {
            anyhow::bail!("illegal state transition {from:?} -> Execute");
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

    #[tokio::test]
    async fn cancel_and_approve_error_on_an_unknown_task_id() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let cancel_err = sup.cancel("does-not-exist").await.unwrap_err().to_string();
        assert!(cancel_err.contains("task not found"), "{cancel_err}");
        let approve_err = sup.approve("does-not-exist").await.unwrap_err().to_string();
        assert!(approve_err.contains("task not found"), "{approve_err}");
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

        let err = sup.resume(&id).await.unwrap_err().to_string();
        assert!(err.contains("resume"), "unexpected error: {err}");
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
}
