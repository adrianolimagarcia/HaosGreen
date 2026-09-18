//! Supervisor task routes (design spec §5.2).
//!
//! ```text
//! GET  /api/supervisor/tasks            -> { tasks: [TaskSummary] }
//! GET  /api/supervisor/tasks/{id}       -> { task, jobs, transitions, artifacts }
//! POST /api/supervisor/tasks            -> { task_id, outcome, state, question?, reason? }
//! POST /api/supervisor/tasks/{id}/pause -> { id, state }
//! POST /api/supervisor/tasks/{id}/resume
//! POST /api/supervisor/tasks/{id}/cancel
//! POST /api/supervisor/tasks/{id}/approve
//! ```
//!
//! Every route is on the guarded router, so a caller has already passed the
//! source-IP gate, the CSRF check and the session/bearer check. The dashboard
//! has exactly one operator account; there is no per-user view of the tasks.
//!
//! # Status codes
//!
//! * **404** — no such task. Never an empty object: a dashboard that renders
//!   `{}` as a task is worse than one that says the id is unknown.
//! * **409** — the task is in a state that does not allow the action. This is
//!   decided by reading the task's state *before* the supervisor is called, so
//!   the four lifecycle routes do not depend on parsing an error to tell a
//!   refusal from a fault. See [`lifecycle`].
//! * **500** — a genuine internal failure. The body is a fixed sentence; the
//!   `anyhow` chain is logged, never returned, because a `rusqlite` error
//!   carries the failing statement and an artifact error carries an absolute
//!   path.
//! * **503** — the dashboard was started without a supervisor
//!   (`WebState::supervisor_or_unavailable`). The six routes that take no body
//!   check this first, so a missing supervisor is uniformly a 503 rather than
//!   sometimes a 404. `POST /api/supervisor/tasks` validates its body first,
//!   because an empty request is malformed on a wired dashboard too.
//!
//! # `cancel` marks the task; it does not stop it
//!
//! `POST /api/supervisor/tasks/{id}/cancel` records `current state -> Cancelled`
//! and nothing else. It does **not** abort work in flight: `execute_now` runs
//! its plan synchronously through the `Orchestrator`, which holds no
//! cancellation token, so a task cancelled mid-execution still finishes the plan
//! it started. The route reports the state the store now holds, not the state of
//! the process.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::supervisor::artifact::ArtifactRow;
use crate::supervisor::job::{Job, JobStatus, JobType};
use crate::supervisor::state::transition_allowed;
use crate::supervisor::store::{TransitionRow, MAX_RECENT_TASKS};
use crate::supervisor::task::{ExecutionMode, RiskLevel, Task, TaskStatus, TaskType};
use crate::supervisor::{SubmitOutcome, Supervisor, SupervisorError};
use crate::web::state::WebState;

pub fn router() -> Router<WebState> {
    Router::new()
        .route("/api/supervisor/tasks", get(list_tasks).post(submit_task))
        .route("/api/supervisor/tasks/{id}", get(read_task))
        .route("/api/supervisor/tasks/{id}/pause", post(pause_task))
        .route("/api/supervisor/tasks/{id}/resume", post(resume_task))
        .route("/api/supervisor/tasks/{id}/cancel", post(cancel_task))
        .route("/api/supervisor/tasks/{id}/approve", post(approve_task))
}

/// The body of every "no such task" answer.
///
/// The id is not echoed, for the same reason `routes::chat` does not echo a
/// session id: the caller already has it, and a reflected id is one more thing
/// a response can carry.
const UNKNOWN_TASK: &str = "unknown supervisor task";

/// The body of every internal failure.
const INTERNAL_ERROR: &str = "the supervisor could not complete that request";

fn unknown_task() -> Response {
    (StatusCode::NOT_FOUND, UNKNOWN_TASK).into_response()
}

fn conflict(message: &str) -> Response {
    (StatusCode::CONFLICT, message.to_string()).into_response()
}

/// Log a 500 and answer with the fixed sentence.
///
/// The log carries the **whole** `anyhow` chain (`{error:#}`), not
/// `error = %error`. `Display` on an `anyhow::Error` prints only the outermost
/// context, so a failure whose real cause is `no such table: sup_transitions`
/// used to be logged as nothing but `insert sup_tasks` — every 500 in this
/// module was undiagnosable, and Phase 4's log view renders exactly this line.
/// The body stays the fixed sentence: a `rusqlite` error carries the failing
/// statement and an artifact error carries an absolute path.
fn internal_error(what: &str, error: &anyhow::Error) -> Response {
    tracing::error!(
        error = %format!("{error:#}"),
        what = %what,
        "web: supervisor request failed"
    );
    (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR).into_response()
}

/// The status code a failed supervisor lifecycle call answers with.
///
/// Pure and total over `anyhow::Error`, so the mapping can be tested without a
/// running server, a store or a request: every arm is a statement about the
/// error's **type**, read with [`anyhow::Error::downcast_ref`], never about its
/// text. It searches the whole chain, so a `SupervisorError` wrapped in
/// `.context(...)` by `execute_now` still classifies correctly — which is not a
/// detail, because `execute_now` wraps the release failure in context and the
/// dashboard must not answer 500 for it.
///
/// `StateRefusal`, `AlreadyRunning` and `LeaseLost` all answer **409**: in every
/// case the caller's request conflicts with the task's real state, and the
/// difference between them is only which sentence is sent back (see
/// [`lifecycle_conflict_message`], and the re-read in [`lifecycle`] that
/// `StateRefusal` needs).
fn lifecycle_failure_status(error: &anyhow::Error) -> StatusCode {
    match error.downcast_ref::<SupervisorError>() {
        // The task was deleted between the pre-check and the call. A vanished
        // task is not a server fault.
        Some(SupervisorError::NotFound { .. }) => StatusCode::NOT_FOUND,
        // Another owner holds the task, this process already runs it, or the
        // state moved under us. All three are conflicts, not faults.
        Some(SupervisorError::StateRefusal { .. })
        | Some(SupervisorError::AlreadyRunning { .. })
        | Some(SupervisorError::LeaseLost { .. }) => StatusCode::CONFLICT,
        // A plain `anyhow` error, or a `SupervisorError` this route does not
        // know about: a genuine fault.
        None => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The 409 body for a typed conflict.
///
/// `StateRefusal` is deliberately absent: [`lifecycle`] rebuilds its message
/// from a fresh read of the task, so it never asks for this one. The fallback
/// is the message for a conflict whose type was not recognised as one, which
/// cannot happen through [`lifecycle_failure_status`] but keeps this function
/// total rather than panicking on a future variant.
fn lifecycle_conflict_message(error: &anyhow::Error) -> &'static str {
    match error.downcast_ref::<SupervisorError>() {
        Some(SupervisorError::AlreadyRunning { .. }) => "that task is already running",
        // The run was aborted because its execution lease was gone. Like
        // `AlreadyRunning`, that is a conflict with another owner, not a fault
        // in this request.
        //
        // The wording is deliberately **cause-neutral**: `LeaseLost` is raised
        // both when another owner really took the task over and when the lease
        // store could not be reached after every retry, and this route cannot
        // tell the two apart — the type does not carry the distinction. Saying
        // "another owner took it over" would assert a takeover that never
        // happened during a store outage. The task id is not echoed here, for
        // the same reason [`UNKNOWN_TASK`] does not echo one; `Display` on the
        // error carries it for logs.
        Some(SupervisorError::LeaseLost { .. }) => {
            "the execution lease for that task is no longer held by this run"
        }
        _ => "the task is no longer in a state that allows that action",
    }
}

// ── Wire types ──────────────────────────────────────────────────────────────

/// The per-task projection the list view renders.
///
/// A projection rather than `Task` itself for two reasons: `Task::inputs`,
/// `constraints` and `expected_outputs` are reconstructed as `Value::Null` by
/// the store (`store::row_to_task`), so they would be dead weight in every
/// response, and `user_request` belongs to the detail drawer rather than to
/// twenty rows of a list.
///
/// `state` is `Task::status` under the name the `sup_tasks` column and the
/// `sup_transitions` audit rows use.
#[derive(Serialize)]
struct TaskSummary {
    id: String,
    title: String,
    state: TaskStatus,
    task_type: TaskType,
    risk_level: RiskLevel,
    priority: u8,
}

impl TaskSummary {
    fn of(task: &Task) -> Self {
        Self {
            id: task.id.clone(),
            title: task.title.clone(),
            state: task.status.clone(),
            task_type: task.task_type.clone(),
            risk_level: task.risk_level.clone(),
            priority: task.priority,
        }
    }
}

/// The detail view's task: everything [`TaskSummary`] carries, plus the fields
/// the drawer needs. Flattened so the two shapes cannot drift apart.
#[derive(Serialize)]
struct TaskDetail {
    #[serde(flatten)]
    summary: TaskSummary,
    execution_mode: ExecutionMode,
    user_request: String,
    required_capabilities: Vec<String>,
}

impl TaskDetail {
    fn of(task: &Task) -> Self {
        Self {
            summary: TaskSummary::of(task),
            execution_mode: task.execution_mode.clone(),
            user_request: task.user_request.clone(),
            required_capabilities: task.required_capabilities.clone(),
        }
    }
}

#[derive(Serialize)]
struct TaskList {
    tasks: Vec<TaskSummary>,
}

/// `TransitionRow` is a store row, not a wire type, so it is projected rather
/// than derived into the API surface.
#[derive(Serialize)]
struct TransitionView {
    from: TaskStatus,
    to: TaskStatus,
    actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    occurred_at: String,
}

impl TransitionView {
    fn of(row: TransitionRow) -> Self {
        Self {
            from: row.from,
            to: row.to,
            actor: row.actor,
            reason: row.reason,
            occurred_at: row.occurred_at,
        }
    }
}

/// `ArtifactRow` is a store row too. `path` is relative to the configured
/// artifacts root — `ArtifactManager::write_text` strips the root before
/// indexing — so the absolute location is not part of the response.
#[derive(Serialize)]
struct ArtifactView {
    id: String,
    kind: String,
    path: String,
}

impl ArtifactView {
    fn of(row: ArtifactRow) -> Self {
        Self {
            id: row.id,
            kind: row.kind,
            path: row.path,
        }
    }
}

/// The per-job projection the detail view renders.
///
/// `Job` is a store row, exactly like `Task`, `TransitionRow` and
/// `ArtifactRow`, so it is projected rather than serialized as-is. What is
/// **not** here, and why — deliberately, rather than by omission:
///
/// * `workspace` — never assigned anywhere in the supervisor; every job the
///   pipeline creates leaves it `None`, so it would be a permanent `null`.
/// * `input_context` — written only by the MCP backend
///   (`supervisor/backend/mcp.rs`), which `main.rs` does not register. It is
///   `null` for every job this dashboard can produce. `Task::inputs` and
///   `constraints` are left out of `TaskSummary` for the same reason.
/// * `prompt` — duplicates `goal` for the jobs the planner emits (it is the
///   task's `user_request` verbatim) and is the largest free-text field on the
///   row; the artifact and report surfaces are where full text belongs.
/// * `timeout_secs`, `retry_max`, `retry_count`, `allow_tools` — scheduling
///   internals of the orchestrator, not something the operator acts on.
///
/// `error` **is** included, and the trade is stated rather than hidden: it is
/// the one field that explains a failed job, and a failed job with no reason is
/// a worse dashboard than one that names a path. It can carry an absolute path
/// today, because a backend failure is persisted as its `anyhow` chain. The
/// text is already scrubbed of secrets at the persistence boundary
/// (`TaskStore::update_job_status` runs `redact::redact`); the path is not, and
/// is the same class of value the 500 body withholds.
#[derive(Serialize)]
struct JobView {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_job_id: Option<String>,
    job_type: JobType,
    backend: String,
    goal: String,
    status: JobStatus,
    /// The stored summary, present once the job has finished. The store
    /// reconstructs `Job::result` from `result_summary` (`store::jobs_for_task`),
    /// so the summary is read back from there.
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl JobView {
    fn of(job: Job) -> Self {
        Self {
            id: job.id,
            parent_job_id: job.parent_job_id,
            job_type: job.job_type,
            backend: job.backend,
            goal: job.goal,
            status: job.status,
            summary: job.result.map(|r| r.summary),
            error: job.error,
        }
    }
}

#[derive(Serialize)]
struct TaskDetailResponse {
    task: TaskDetail,
    jobs: Vec<JobView>,
    transitions: Vec<TransitionView>,
    artifacts: Vec<ArtifactView>,
}

#[derive(Deserialize)]
struct SubmitRequest {
    text: String,
}

/// The kind of a [`SubmitOutcome`], as a wire value.
///
/// `SubmitOutcome` is not `Serialize`, and the two parked variants are the
/// point of this field: an operator has to be able to tell a submit that
/// planned work from one that is waiting on them. Reporting a bare success for
/// a task that is parked would hide the reason nothing is running.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum SubmitOutcomeKind {
    AutoExecutePlanned,
    NeedsClarification,
    NeedsApproval,
}

#[derive(Serialize)]
struct SubmitResponse {
    task_id: String,
    outcome: SubmitOutcomeKind,
    /// The state the task holds after the submit. `ROUTE` for both a planned
    /// task and one awaiting approval; `CLARIFY` when a question is attached.
    /// `submit` classifies, routes and returns — nothing is executed.
    state: TaskStatus,
    /// Present only for `needs_clarification`.
    #[serde(skip_serializing_if = "Option::is_none")]
    question: Option<String>,
    /// Present only for `needs_approval`.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// The body of a successful lifecycle action.
///
/// Uniform across the four actions so the UI has one shape to handle. The
/// report that `resume` and `approve` return is **not** echoed: it is persisted
/// as the task's `result` artifact and rendered by the detail route, and a task
/// whose verification failed is reported by its `FAILED` state.
#[derive(Serialize)]
struct TaskActionResponse {
    id: String,
    state: TaskStatus,
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn list_tasks(State(state): State<WebState>) -> Response {
    let supervisor = match state.supervisor_or_unavailable() {
        Ok(supervisor) => supervisor,
        Err((status, message)) => return (status, message).into_response(),
    };

    // The named constant rather than a literal: `list_recent` clamps to
    // `MAX_RECENT_TASKS` regardless, and naming it here is what keeps the route
    // and the clamp from drifting apart.
    match supervisor.store().list_recent(MAX_RECENT_TASKS).await {
        Ok(tasks) => Json(TaskList {
            tasks: tasks.iter().map(TaskSummary::of).collect(),
        })
        .into_response(),
        Err(e) => internal_error("list supervisor tasks", &e),
    }
}

async fn read_task(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    let supervisor = match state.supervisor_or_unavailable() {
        Ok(supervisor) => supervisor,
        Err((status, message)) => return (status, message).into_response(),
    };

    let task = match supervisor.store().get(&id).await {
        Ok(Some(task)) => task,
        Ok(None) => return unknown_task(),
        Err(e) => return internal_error("read a supervisor task", &e),
    };

    let jobs = match supervisor.store().jobs_for_task(&id).await {
        Ok(jobs) => jobs,
        Err(e) => return internal_error("read a supervisor task's jobs", &e),
    };

    let transitions = match supervisor.store().transitions(&id).await {
        Ok(rows) => rows.into_iter().map(TransitionView::of).collect(),
        Err(e) => return internal_error("read a supervisor task's transitions", &e),
    };

    let artifacts = match supervisor.artifacts().list(&id).await {
        Ok(rows) => rows.into_iter().map(ArtifactView::of).collect(),
        Err(e) => return internal_error("read a supervisor task's artifacts", &e),
    };

    Json(TaskDetailResponse {
        task: TaskDetail::of(&task),
        jobs: jobs.into_iter().map(JobView::of).collect(),
        transitions,
        artifacts,
    })
    .into_response()
}

async fn submit_task(State(state): State<WebState>, Json(body): Json<SubmitRequest>) -> Response {
    // Validated before the wiring check: an empty request is malformed on a
    // dashboard with a supervisor too, and 400 is the answer that says so.
    // The six routes with no body check the wiring first, so that
    // `supervisor: None` is uniformly a 503 — see the module documentation.
    //
    // The trimmed text is what is passed on, so the value that was validated is
    // the value that is classified and stored. (`IntakeRouter::normalize` also
    // trims, so the persisted `user_request` was already trimmed; the route
    // should not depend on a callee to repair its own input.)
    let text = body.text.trim();
    if text.is_empty() {
        return (StatusCode::BAD_REQUEST, "the task text must not be empty").into_response();
    }

    let supervisor = match state.supervisor_or_unavailable() {
        Ok(supervisor) => supervisor,
        Err((status, message)) => return (status, message).into_response(),
    };

    // `platform` / `user_id` record where the task came from. The dashboard is
    // a single operator account, so there is no per-user identity to record;
    // the platform string keeps dashboard tasks distinguishable from Telegram
    // ones in `sup_tasks`.
    let outcome = match supervisor.submit("web", "dashboard", None, text).await {
        Ok(outcome) => outcome,
        Err(e) => return internal_error("submit a supervisor task", &e),
    };

    let task_id = outcome.task_id();

    let task_state = match supervisor.state(&task_id).await {
        Ok(state) => state,
        Err(e) => return internal_error("read a supervisor task's state", &e),
    };

    let (kind, question, reason) = match outcome {
        SubmitOutcome::AutoExecutePlanned { .. } => {
            (SubmitOutcomeKind::AutoExecutePlanned, None, None)
        }
        SubmitOutcome::NeedsClarification { question, .. } => {
            (SubmitOutcomeKind::NeedsClarification, Some(question), None)
        }
        SubmitOutcome::NeedsApproval { reason, .. } => {
            (SubmitOutcomeKind::NeedsApproval, None, Some(reason))
        }
    };

    Json(SubmitResponse {
        task_id,
        outcome: kind,
        state: task_state,
        question,
        reason,
    })
    .into_response()
}

async fn pause_task(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    lifecycle(state, id, Action::Pause).await
}

async fn resume_task(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    lifecycle(state, id, Action::Resume).await
}

/// Mark a task `Cancelled`.
///
/// This records `current state -> Cancelled` and nothing else. It does **not**
/// abort work in flight: `execute_now` runs its plan synchronously through the
/// `Orchestrator`, which holds no cancellation token, so a task cancelled
/// mid-execution still finishes the plan it started. The response reports the
/// state the store now holds, not the state of the process — do not read a 200
/// here as "the work has stopped".
///
/// A task in a state the machine does not allow to be cancelled — `Verify`,
/// `Report`, `Archive`, `Done`, `Failed`, `Classify` — is a 409, not a 200.
async fn cancel_task(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    lifecycle(state, id, Action::Cancel).await
}

async fn approve_task(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    lifecycle(state, id, Action::Approve).await
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

/// A lifecycle action, expressed as the precondition the state machine puts on
/// the task's current state.
#[derive(Debug, Clone, Copy)]
enum Action {
    Pause,
    Resume,
    Cancel,
    Approve,
}

impl Action {
    /// Whether a task in `current` may take this action.
    ///
    /// Three of the four are exactly the [`transition_allowed`] edge the
    /// supervisor method takes. `resume` is deliberately stricter than the
    /// table: `Paused -> Execute` is a legal edge, but `Supervisor::resume`
    /// refuses any task that is not `Paused`. Without that, a task parked in
    /// `Route` awaiting approval would be run without one.
    fn permitted_from(self, current: &TaskStatus) -> bool {
        match self {
            Self::Resume => *current == TaskStatus::Paused,
            Self::Pause => transition_allowed(current.clone(), TaskStatus::Paused),
            Self::Cancel => transition_allowed(current.clone(), TaskStatus::Cancelled),
            Self::Approve => transition_allowed(current.clone(), TaskStatus::Execute),
        }
    }

    /// The 409 message. It names the task's current state and nothing else —
    /// no path, no error chain.
    fn refusal(self, current: &TaskStatus) -> String {
        match self {
            Self::Pause => format!("a task in state {current:?} cannot be paused"),
            Self::Resume => format!(
                "a task in state {current:?} cannot be resumed; only a paused task can be resumed"
            ),
            Self::Cancel => format!("a task in state {current:?} cannot be cancelled"),
            Self::Approve => format!("a task in state {current:?} cannot be approved"),
        }
    }

    async fn apply(self, supervisor: &Supervisor, id: &str) -> anyhow::Result<()> {
        match self {
            Self::Pause => supervisor.pause(id).await,
            Self::Cancel => supervisor.cancel(id).await,
            // `resume` and `approve` run the plan and return its report, which
            // is persisted as the `result` artifact.
            Self::Resume => supervisor.resume(id).await.map(|_report| ()),
            Self::Approve => supervisor.approve(id).await.map(|_report| ()),
        }
    }
}

/// The shared body of the four lifecycle routes.
///
/// # 409 is decided before the supervisor is called
///
/// `pause`, `resume`, `cancel` and `approve` all refuse an illegal transition
/// through `state::transition_allowed` (or, for `resume`, an exact `Paused`
/// check). A refusal is a fact about the task's current state, so this route
/// reads that state itself and answers **409** without attempting the
/// operation. Only an error that survives the pre-check is a genuine fault, and
/// those answer **500**.
///
/// The pre-check cannot cover a task that moves between it and the call — two
/// operators, two browsers. There the error **type** is the signal left, and it
/// is read with `anyhow::Error::downcast_ref` on [`SupervisorError`] rather
/// than by matching error text; a re-read then supplies the current state for
/// the message. Matching text is the trap this replaced: rewording a `bail!`
/// anywhere in `supervisor/mod.rs` silently turned every raced refusal into a
/// 500, with nothing but a string-matching test to notice. The type-to-status
/// part of that decision lives in [`lifecycle_failure_status`], a pure function
/// with its own tests, so it can be checked without a server.
///
/// The classification is deliberately *not* "the state no longer permits the
/// action": `resume` and `approve` also fail **after** a legal transition,
/// because they run the plan, and a failure there is an internal fault rather
/// than a conflict.
async fn lifecycle(state: WebState, id: String, action: Action) -> Response {
    let supervisor = match state.supervisor_or_unavailable() {
        Ok(supervisor) => supervisor,
        Err((status, message)) => return (status, message).into_response(),
    };

    let task = match supervisor.store().get(&id).await {
        Ok(Some(task)) => task,
        Ok(None) => return unknown_task(),
        Err(e) => return internal_error("read a supervisor task", &e),
    };

    if !action.permitted_from(&task.status) {
        return conflict(&action.refusal(&task.status));
    }

    if let Err(e) = action.apply(&supervisor, &id).await {
        let status = lifecycle_failure_status(&e);
        if status == StatusCode::NOT_FOUND {
            return unknown_task();
        }
        if status != StatusCode::CONFLICT {
            return internal_error("apply a supervisor lifecycle action", &e);
        }
        // A conflict. Which one decides only the message.
        if matches!(
            e.downcast_ref::<SupervisorError>(),
            Some(SupervisorError::StateRefusal { .. })
        ) {
            // Lost a race with another request. The state is re-read rather
            // than echoed from the error, so the message carries this task's
            // current state and nothing from the error chain.
            return match supervisor.store().get(&id).await {
                Ok(Some(task)) => conflict(&action.refusal(&task.status)),
                Ok(None) => unknown_task(),
                Err(_) => conflict("the task is no longer in a state that allows that action"),
            };
        }
        return conflict(lifecycle_conflict_message(&e));
    }

    match supervisor.state(&id).await {
        Ok(state) => Json(TaskActionResponse { id, state }).into_response(),
        Err(e) => internal_error("read a supervisor task's state", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_supervisor(dir: &std::path::Path) -> Supervisor {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut supervisor = Supervisor::new_for_test(dir.to_path_buf(), memory.connection());
        supervisor.register_test_reasoning_backend(|p| async move { Ok(format!("ran:{p}")) });
        supervisor
    }

    /// Drive a task to `Done` by writing the audit trail directly, so the test
    /// does not depend on the orchestrator or on a classifier decision.
    async fn finish(supervisor: &Supervisor, task: &Task) {
        for (from, to) in [
            (TaskStatus::Intake, TaskStatus::Classify),
            (TaskStatus::Classify, TaskStatus::Route),
            (TaskStatus::Route, TaskStatus::Plan),
            (TaskStatus::Plan, TaskStatus::Execute),
            (TaskStatus::Execute, TaskStatus::Verify),
            (TaskStatus::Verify, TaskStatus::Report),
            (TaskStatus::Report, TaskStatus::Archive),
            (TaskStatus::Archive, TaskStatus::Done),
        ] {
            supervisor
                .store()
                .record_transition(&task.id, from, to, "test", None)
                .await
                .unwrap();
        }
    }

    #[test]
    fn the_list_summary_carries_exactly_the_agreed_fields() {
        let mut task = Task::new("t", "req");
        task.status = TaskStatus::Paused;
        task.priority = 7;

        let value = serde_json::to_value(TaskSummary::of(&task)).unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        // The exact shape, so a field invented on the wire (or one dropped by
        // accident) fails here rather than in the UI.
        assert_eq!(
            keys,
            [
                "id",
                "priority",
                "risk_level",
                "state",
                "task_type",
                "title"
            ]
        );
        // `state` is `Task::status`; the name is the only difference.
        assert_eq!(value["state"], serde_json::json!("PAUSED"));
        assert_eq!(value["priority"], serde_json::json!(7));
    }

    #[test]
    fn the_detail_view_keeps_the_summary_fields_at_the_top_level() {
        let mut task = Task::new("t", "the original request");
        task.required_capabilities = vec!["reasoning".into()];

        let value = serde_json::to_value(TaskDetail::of(&task)).unwrap();

        assert_eq!(value["state"], serde_json::json!("INTAKE"));
        assert_eq!(value["title"], serde_json::json!("t"));
        assert_eq!(
            value["user_request"],
            serde_json::json!("the original request")
        );
        assert_eq!(value["execution_mode"], serde_json::json!("standard"));
        assert_eq!(
            value["required_capabilities"],
            serde_json::json!(["reasoning"])
        );
    }

    /// `Route -> Execute` is a legal edge and `approve` takes it; `resume` must
    /// not, or a task parked awaiting approval would run without one.
    #[test]
    fn resume_is_stricter_than_the_transition_table() {
        assert!(transition_allowed(TaskStatus::Route, TaskStatus::Execute));
        assert!(Action::Approve.permitted_from(&TaskStatus::Route));
        assert!(!Action::Resume.permitted_from(&TaskStatus::Route));
        assert!(Action::Resume.permitted_from(&TaskStatus::Paused));
    }

    #[test]
    fn a_route_task_may_be_paused_cancelled_and_approved() {
        assert!(Action::Pause.permitted_from(&TaskStatus::Route));
        assert!(Action::Cancel.permitted_from(&TaskStatus::Route));
        assert!(Action::Approve.permitted_from(&TaskStatus::Route));
    }

    #[test]
    fn a_finished_task_permits_no_lifecycle_action() {
        for action in [
            Action::Pause,
            Action::Resume,
            Action::Cancel,
            Action::Approve,
        ] {
            assert!(
                !action.permitted_from(&TaskStatus::Done),
                "{action:?} must be refused on a Done task"
            );
        }
    }

    #[test]
    fn every_refusal_names_the_current_state() {
        for action in [
            Action::Pause,
            Action::Resume,
            Action::Cancel,
            Action::Approve,
        ] {
            let message = action.refusal(&TaskStatus::Verify);
            assert!(
                message.contains("Verify"),
                "{action:?} must name the state: {message}"
            );
        }
    }

    /// The classifier in [`lifecycle`] is only useful if the supervisor really
    /// raises the typed refusal it looks for. This is the test that would catch
    /// a lifecycle method reverting to a bare `anyhow::bail!`: the error would
    /// stop being a `StateRefusal` and every raced refusal would answer 500.
    #[tokio::test]
    async fn the_supervisor_refusals_are_typed_state_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let supervisor = test_supervisor(dir.path());

        let task = Task::new("finished", "req");
        supervisor
            .store()
            .create(&task, "web", "dashboard", None)
            .await
            .unwrap();
        finish(&supervisor, &task).await;

        for action in [
            Action::Pause,
            Action::Resume,
            Action::Cancel,
            Action::Approve,
        ] {
            let error = action.apply(&supervisor, &task.id).await.unwrap_err();
            assert!(
                matches!(
                    error.downcast_ref::<SupervisorError>(),
                    Some(SupervisorError::StateRefusal { .. })
                ),
                "{action:?} must raise SupervisorError::StateRefusal, got {error:?}"
            );
        }
    }

    /// The other half of the distinction: a real fault must not be read as a
    /// refusal, or every database error would become a 409. A plain `anyhow`
    /// error carries no `SupervisorError` in its chain, so it stays a 500. The
    /// per-variant statuses (404 for a vanished task, 409 for an
    /// already-running one and for a lost lease) are pinned separately by
    /// [`every_supervisor_error_variant_maps_to_its_status`].
    ///
    /// This goes through [`lifecycle_failure_status`], the function
    /// [`lifecycle`] itself calls. An earlier version of this test defined its
    /// own local `is_state_refusal` and asserted on that, so it would have kept
    /// passing while the production mapping changed underneath it — a test that
    /// guarded nothing. The context-wrapped refusal below is the case
    /// [`every_supervisor_error_variant_maps_to_its_status`] does not cover:
    /// the type is searched down the whole `anyhow` chain, not only at the top.
    #[test]
    fn a_genuine_fault_is_not_mistaken_for_a_refusal() {
        for fault in [
            anyhow::anyhow!("no such table: sup_tasks"),
            anyhow::anyhow!(
                "write artifact /home/op/.haos-green/supervisor/x/plan.json: Permission denied"
            ),
        ] {
            assert_eq!(
                lifecycle_failure_status(&fault),
                StatusCode::INTERNAL_SERVER_ERROR,
                "a genuine fault must not be answered as a conflict: {fault:#}"
            );
        }

        let wrapped = SupervisorError::state_refusal(TaskStatus::Done, TaskStatus::Plan)
            .context("resume a finished task");
        assert_eq!(
            lifecycle_failure_status(&wrapped),
            StatusCode::CONFLICT,
            "a refusal wrapped in context is still a conflict: {wrapped:#}"
        );
    }

    /// A lost execution lease must be answered as a **409 conflict**, not as a
    /// 404, not as "this process is already running it", and not as a 500.
    ///
    /// The status comes from [`lifecycle_failure_status`], the pure function
    /// [`lifecycle`] itself calls, so this is the route's real decision and not
    /// a restatement of it. [`a_lost_lease_is_its_own_refusal`] covers the
    /// error's own shape.
    #[test]
    fn a_lost_lease_is_answered_as_a_conflict() {
        let error = SupervisorError::lease_lost("6f1c");
        assert_eq!(lifecycle_failure_status(&error), StatusCode::CONFLICT);
        assert_eq!(
            lifecycle_conflict_message(&error),
            "the execution lease for that task is no longer held by this run"
        );
    }

    /// The same decision through the shape the route actually receives: a
    /// `LeaseLost` wrapped in context by `execute_now`'s release-failure arm.
    /// A `downcast_ref` that only looked at the outermost error would answer
    /// 500 here — which is exactly the bug that made `release` return an
    /// untyped `anyhow::bail!`.
    #[test]
    fn a_context_wrapped_lost_lease_is_still_a_conflict() {
        let error = SupervisorError::lease_lost("6f1c")
            .context("failed to release execution lease: execution lease lost before release");
        assert_eq!(lifecycle_failure_status(&error), StatusCode::CONFLICT);
        assert_eq!(
            lifecycle_conflict_message(&error),
            "the execution lease for that task is no longer held by this run"
        );
    }

    /// Every `SupervisorError` variant, mapped. The four arms are the route's
    /// whole decision table, and the compiler will not tell us if one of them
    /// silently changes status.
    #[test]
    fn every_supervisor_error_variant_maps_to_its_status() {
        assert_eq!(
            lifecycle_failure_status(&SupervisorError::not_found("6f1c")),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            lifecycle_failure_status(&SupervisorError::state_refusal(
                TaskStatus::Done,
                TaskStatus::Plan
            )),
            StatusCode::CONFLICT
        );
        assert_eq!(
            lifecycle_failure_status(&SupervisorError::already_running("6f1c")),
            StatusCode::CONFLICT
        );
        assert_eq!(
            lifecycle_failure_status(&SupervisorError::lease_lost("6f1c")),
            StatusCode::CONFLICT
        );
        // An error with no `SupervisorError` anywhere in its chain is a fault.
        assert_eq!(
            lifecycle_failure_status(&anyhow::anyhow!("no such table: sup_tasks")),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // And the two 409 messages are distinct, so a lease loss is not
        // reported as "already running" and vice versa.
        assert_eq!(
            lifecycle_conflict_message(&SupervisorError::already_running("6f1c")),
            "that task is already running"
        );
        assert_ne!(
            lifecycle_conflict_message(&SupervisorError::already_running("6f1c")),
            lifecycle_conflict_message(&SupervisorError::lease_lost("6f1c"))
        );
    }

    /// A lost execution lease is its own typed refusal: it carries
    /// `SupervisorError::LeaseLost`, so [`lifecycle_failure_status`] — not a
    /// substring of the message — can classify it. This pins the error's own
    /// shape; the status it maps to is pinned above.
    #[test]
    fn a_lost_lease_is_its_own_refusal() {
        let error = SupervisorError::lease_lost("6f1c");
        let typed = error
            .downcast_ref::<SupervisorError>()
            .expect("lease_lost must carry the typed error");

        assert!(
            matches!(typed, SupervisorError::LeaseLost { task_id } if task_id == "6f1c"),
            "unexpected error: {error:?}"
        );
        assert!(!matches!(typed, SupervisorError::NotFound { .. }));
        assert!(!matches!(typed, SupervisorError::AlreadyRunning { .. }));
        assert!(!matches!(typed, SupervisorError::StateRefusal { .. }));
        // The message has to stand on its own: unlike `StateRefusal`, the route
        // answers this arm without re-reading the task.
        let message = error.to_string();
        assert!(message.contains("6f1c"), "must name the task: {message}");
        assert!(message.contains("lease"), "must name the loss: {message}");
    }

    /// `Job` is a store row; the detail view gets a projection. `workspace` and
    /// `input_context` are dropped because nothing in the registered pipeline
    /// ever sets them, and the raw row must not reach the wire.
    #[test]
    fn the_job_view_carries_exactly_the_agreed_fields() {
        let mut job = Job::new("task-1", JobType::ExecutorJob, "shell", "echo hello");
        job.workspace = Some("/home/op/.haos-green/supervisor/ws".into());
        job.input_context = serde_json::json!({"api_key": "leak"});
        job.status = JobStatus::Succeeded;
        job.result = Some(crate::supervisor::job::JobOutput {
            status: JobStatus::Succeeded,
            summary: "ran".into(),
            evidence: vec![],
            errors: vec![],
            changed_files: vec!["/home/op/secret.txt".into()],
            next_step: None,
        });
        job.error = Some("boom".into());

        let value = serde_json::to_value(JobView::of(job)).unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            ["backend", "error", "goal", "id", "job_type", "status", "summary"]
        );
        assert_eq!(value["summary"], serde_json::json!("ran"));
        assert!(
            !value.to_string().contains("input_context")
                && !value.to_string().contains("workspace")
                && !value.to_string().contains("secret.txt"),
            "the raw store row must not reach the wire: {value}"
        );
    }

    /// `parent_job_id` is present only for a spawned subjob, and the summary
    /// only once the job has finished — the two `skip_serializing_if` fields
    /// must actually be skipped rather than serialized as `null`.
    #[test]
    fn the_job_view_omits_the_optional_fields_when_they_are_absent() {
        let job = Job::new("task-1", JobType::ExecutorJob, "reasoning", "do it");
        let value = serde_json::to_value(JobView::of(job)).unwrap();
        assert!(value.get("parent_job_id").is_none(), "got {value}");
        assert!(value.get("summary").is_none(), "got {value}");
        assert!(value.get("error").is_none(), "got {value}");
    }

    /// Collects what a `tracing` subscriber formats, so a test can read the log
    /// line a handler emitted.
    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLog;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The 500 log must carry the **root cause**, not only the outermost
    /// context.
    ///
    /// `anyhow`'s `Display` prints the outer layer alone, so a failure whose
    /// real cause is `no such table: sup_transitions` was logged as nothing but
    /// `insert sup_tasks` — every 500 in this module undiagnosable, and Phase
    /// 4's log view renders exactly this line. `error = %error` fails this test;
    /// `error = %format!("{error:#}")` passes it.
    ///
    /// The subscriber is installed with `with_default`, which is scoped to this
    /// thread, so the test neither installs nor depends on a global subscriber.
    #[test]
    fn the_internal_error_log_carries_the_whole_error_chain() {
        let error = anyhow::anyhow!("no such table: sup_transitions").context("insert sup_tasks");

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let response = tracing::subscriber::with_default(subscriber, || {
            internal_error("submit a supervisor task", &error)
        });

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("insert sup_tasks"),
            "the log must keep the outer context: {logged:?}"
        );
        assert!(
            logged.contains("no such table: sup_transitions"),
            "the log must carry the root cause, not just the outermost context: {logged:?}"
        );
        // The body stays the fixed sentence — the chain is logged, never
        // returned.
        assert!(
            !INTERNAL_ERROR.contains("sup_transitions"),
            "the response body must not carry the chain"
        );
    }
}
