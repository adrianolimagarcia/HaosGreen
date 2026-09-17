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
use crate::supervisor::job::Job;
use crate::supervisor::state::transition_allowed;
use crate::supervisor::store::{TransitionRow, MAX_RECENT_TASKS};
use crate::supervisor::task::{ExecutionMode, RiskLevel, Task, TaskStatus, TaskType};
use crate::supervisor::{SubmitOutcome, Supervisor};
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

fn internal_error(what: &str, error: &anyhow::Error) -> Response {
    tracing::error!(error = %error, what = %what, "web: supervisor request failed");
    (StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_ERROR).into_response()
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

#[derive(Serialize)]
struct TaskDetailResponse {
    task: TaskDetail,
    jobs: Vec<Job>,
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
        jobs,
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
    if body.text.trim().is_empty() {
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
    let outcome = match supervisor
        .submit("web", "dashboard", None, &body.text)
        .await
    {
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

/// Whether an error from a lifecycle method is a refusal by the state machine
/// rather than a fault.
///
/// The pre-check in [`lifecycle`] answers 409 in every ordinary case, so this
/// is only a fallback for the window between that check and the call, where a
/// concurrent request can move the task. It is a fallback rather than the
/// primary mechanism on purpose: matching error text is brittle, and the route
/// should not have to depend on it where it does not have to.
///
/// The strings are the ones `Supervisor::{pause,resume,cancel,approve}` produce.
/// `the_refusal_signatures_match_the_supervisor_messages` pins them, so a
/// reworded `bail!` in `supervisor/mod.rs` fails that test instead of silently
/// turning every refusal into a 500.
fn is_state_refusal(message: &str) -> bool {
    message.contains("cannot pause a task in state")
        || message.contains("cannot resume a task in state")
        || message.contains("illegal state transition")
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
/// operators, two browsers. There the error text is the only signal left, and
/// [`is_state_refusal`] reads it; a re-read then supplies the current state for
/// the message. The classification is deliberately *not* "the state no longer
/// permits the action": `resume` and `approve` also fail **after** a legal
/// transition, because they run the plan, and a failure there is an internal
/// fault rather than a conflict.
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
        if is_state_refusal(&e.to_string()) {
            // Lost a race with another request. The state is re-read rather
            // than echoed from the error, so the message carries this task's
            // current state and nothing from the error chain.
            return match supervisor.store().get(&id).await {
                Ok(Some(task)) => conflict(&action.refusal(&task.status)),
                _ => conflict("the task is no longer in a state that allows that action"),
            };
        }
        return internal_error("apply a supervisor lifecycle action", &e);
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

    /// The fallback classifier is only useful if it matches the messages the
    /// supervisor really produces.
    #[tokio::test]
    async fn the_refusal_signatures_match_the_supervisor_messages() {
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
                is_state_refusal(&error.to_string()),
                "{action:?} must be recognised as a refusal, got {error}"
            );
        }
    }

    /// The other half of the distinction: a real fault must not be read as a
    /// refusal, or every database error would become a 409.
    #[test]
    fn a_genuine_fault_is_not_mistaken_for_a_refusal() {
        assert!(!is_state_refusal("no such table: sup_tasks"));
        assert!(!is_state_refusal(
            "write artifact /home/op/.haos-green/supervisor/x/plan.json: Permission denied"
        ));
        assert!(!is_state_refusal("task not found: 6f1c"));
    }
}
