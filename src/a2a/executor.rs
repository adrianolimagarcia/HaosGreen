//! Bridges an A2A task to a HaosGreen agent turn, under the peer's tool policy.
//!
//! This is the security-critical module of Phase 2. Two things must hold:
//!
//! 1. The agent turn runs through [`Agent::run_with_policy`], never
//!    `process_message` — the latter hardcodes `allowed_tools: None`, which in
//!    `LoopConfig` means *no restriction at all*.
//! 2. The tool policy is re-resolved against the **live** registry. `authenticate`
//!    resolves against an empty slice (`src/a2a/auth.rs`), so a `["*"]` peer —
//!    the most privileged configuration that exists — would otherwise get
//!    **zero** tools.
//!
//! [`Agent::run_with_policy`]: crate::agent::Agent::run_with_policy

use crate::a2a::policy::resolve_allowed_tools;
use crate::llm::{ChatMessage, MessageContent};
use a2a::errors::A2AError;
use a2a::event::{StreamResponse, TaskStatusUpdateEvent};
use a2a::types::{Message, Part, PartContent, Role, Task, TaskState, TaskStatus};
use a2a_server::{AgentExecutor, ExecutorContext, ServiceParams};
use futures::stream::BoxStream;
use std::sync::Arc;

struct AgentTaskCleanup {
    handle: Option<tokio::task::JoinHandle<anyhow::Result<crate::loop_runner::LoopOutcome>>>,
    agent: Arc<crate::agent::Agent>,
    key: String,
    cancel: tokio_util::sync::CancellationToken,
}

impl Drop for AgentTaskCleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        self.cancel.cancel();
        // Drop may run after the runtime has shut down. Never spawn here:
        // synchronous best-effort cleanup is safe in both runtime and teardown
        // contexts; normal execution performs awaited cleanup below.
        self.agent.try_clear_cancel_token(&self.key);
    }
}

/// Header the auth middleware uses to hand the resolved peer name to the SDK
/// handler.
///
/// The SDK forwards request headers into [`ExecutorContext`] via
/// `service_params` (`middleware.rs:17-28`), and that is the **only** identity
/// channel available: the SDK sets `ctx.user` to `None` unconditionally
/// (`handler.rs:558`, `handler.rs:668`).
pub const PEER_HEADER: &str = "x-haos-green-a2a-peer";

/// Cancel-registry key for an A2A task.
///
/// `Agent::cancel_token_registry` is a bare map keyed by Telegram `user_id`, and
/// `/stop` cancels by that key. Without namespacing, `/stop` and `CancelTask`
/// would cancel each other's runs.
pub fn cancel_key(task_id: &str) -> String {
    format!("a2a:{task_id}")
}

/// Recover the peer name the auth middleware resolved.
///
/// Deliberately does **not** re-authenticate: the executor has no source IP, so
/// it cannot. It trusts the header because `auth_gate` runs first and rejects
/// unauthenticated callers. A missing header means the middleware was bypassed —
/// a routing bug — so this returns an empty name, which matches no peer and
/// therefore resolves to an empty policy. Fail closed.
pub fn peer_from_service_params(params: &ServiceParams) -> String {
    params
        .get(PEER_HEADER)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

/// The prompt text from the text parts of the incoming message.
fn prompt_from(ctx: &ExecutorContext) -> String {
    ctx.message
        .as_ref()
        .map(|m| {
            m.parts
                .iter()
                .filter_map(|p| match &p.content {
                    PartContent::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Bound on concurrently running A2A agent turns.
///
/// A semaphore with `max_concurrent_tasks` permits. `execute` takes a permit
/// with `try_acquire_owned` and, when the limit is held, fails the task
/// immediately instead of queueing it: with a synchronous `SendMessage` a
/// queued task would occupy the peer's HTTP connection for the entire queue
/// wait with no feedback.
#[derive(Debug, Clone)]
pub struct TaskGate {
    permits: Arc<tokio::sync::Semaphore>,
    limit: usize,
}

/// The semaphore is exhausted.
#[derive(Debug)]
pub struct GateFull {
    pub message: String,
}

impl TaskGate {
    pub fn new(limit: usize) -> Self {
        // Clamp: `max_concurrent_tasks = 0` must mean "one at a time", never
        // "refuse everything forever". Config validation rejects 0 anyway;
        // this is defence in depth for callers that skip it.
        let limit = limit.max(1);
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(limit)),
            limit,
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn try_acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, GateFull> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| GateFull {
                message: format!(
                    "concurrency limit reached (max_concurrent_tasks = {})",
                    self.limit
                ),
            })
    }
}

/// Drives an A2A task through the HaosGreen agent loop.
pub struct A2aExecutor {
    agent: Arc<crate::agent::Agent>,
    gate: TaskGate,
}

impl A2aExecutor {
    pub fn new(agent: Arc<crate::agent::Agent>) -> Self {
        let limit = agent.config.a2a.max_concurrent_tasks;
        Self {
            agent,
            gate: TaskGate::new(limit),
        }
    }

    /// Resolve a peer's tool policy against the **live** tool registry.
    ///
    /// Never forward [`PeerIdentity::allowed_tools`] directly: `authenticate`
    /// computes it against an empty registry, which yields an empty list for a
    /// `["*"]` peer.
    ///
    /// [`PeerIdentity::allowed_tools`]: crate::a2a::PeerIdentity
    fn policy_for(&self, peer: &str) -> Vec<String> {
        let available: Vec<String> = self
            .agent
            .all_tool_definitions()
            .into_iter()
            .map(|d| d.function.name)
            .collect();
        match self.agent.config.a2a.peers.get(peer) {
            Some(cfg) => resolve_allowed_tools(peer, cfg, &available),
            // Unknown peer: `authenticate` should already have rejected this,
            // so treat it as a bug rather than an allow.
            None => Vec::new(),
        }
    }
}

#[async_trait::async_trait]
impl AgentExecutor for A2aExecutor {
    fn execute(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let agent = self.agent.clone();
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        let prompt = prompt_from(&ctx);
        let peer = peer_from_service_params(&ctx.service_params);
        // Hazard: emitting `StreamResponse::Task` REPLACES the stored task
        // (handler.rs:218), so history must be carried forward or it is lost.
        let prior_history = ctx.stored_task.as_ref().and_then(|t| t.history.clone());
        let prior_artifacts = ctx.stored_task.as_ref().and_then(|t| t.artifacts.clone());

        // Resolved BEFORE the async block: the returned stream must be
        // `'static`, and `policy_for` borrows `&self`. Resolving here also
        // keeps the policy a snapshot of the registry at request time.
        let allowed = self.policy_for(&peer);
        let gate = self.gate.clone();

        Box::pin(async_stream::stream! {
            let _permit = match gate.try_acquire() {
                Ok(p) => p,
                Err(full) => {
                    tracing::warn!(task_id = %task_id, peer = %peer, limit = gate.limit(),
                        "A2A task refused: concurrency limit reached");
                    yield Ok(StreamResponse::Task(failed_task(&task_id, &context_id, &full.message)));
                    return;
                }
            };

            let key = cancel_key(&task_id);
            let cancel = agent.register_cancel_token(&key).await;

            yield Ok(StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
                task_id: task_id.clone(),
                context_id: context_id.clone(),
                status: TaskStatus { state: TaskState::Working, message: None, timestamp: None },
                metadata: None,
            }));

            let (token_tx, mut token_rx) = tokio::sync::mpsc::channel::<String>(128);
            let prior_history_for_agent = prior_history.clone();
            let agent_task = {
                let agent = agent.clone();
                let prompt = prompt.clone();
                let allowed = allowed.clone();
                let cancel_for_task = cancel.clone();
                tokio::spawn(async move {
                    agent.run_with_policy_streaming_history(
                        prior_history_for_agent.unwrap_or_default().into_iter().filter_map(|message| {
                            let role = match message.role {
                                Role::User => "user",
                                Role::Agent => "assistant",
                                _ => return None,
                            };
                            let text = message.parts.iter().filter_map(|part| match &part.content {
                                PartContent::Text(text) => Some(text.as_str()),
                                _ => None,
                            }).collect::<Vec<_>>().join("\n");
                            (!text.is_empty()).then(|| ChatMessage {
                                role: role.to_string(),
                                content: Some(MessageContent::from_text(text)),
                                tool_calls: None,
                                tool_call_id: None,
                            })
                        }),
                        &prompt,
                        allowed,
                        Some(cancel_for_task),
                        Some(token_tx),
                    ).await
                })
            };
            let mut cleanup = AgentTaskCleanup {
                handle: Some(agent_task),
                agent: agent.clone(),
                key: key.clone(),
                cancel: cancel.clone(),
            };
            let outcome = loop {
                tokio::select! {
                    Some(_token) = token_rx.recv() => {}
                    result = cleanup.handle.as_mut().expect("agent handle available") => break result,
                }
            };
            cleanup.handle.take();
            agent.clear_cancel_token(&key).await;
            let outcome = match outcome {
                Ok(result) => result,
                Err(join_error) => Err(anyhow::anyhow!("agent task failed: {join_error}")),
            };
            let (state, text) = match outcome {
                Ok(crate::loop_runner::LoopOutcome::FinalResponse(t)) => (TaskState::Completed, t),
                Ok(crate::loop_runner::LoopOutcome::MaxIterations) => (TaskState::Failed, "The agent reached its maximum number of iterations.".to_string()),
                Ok(crate::loop_runner::LoopOutcome::Cancelled) => (TaskState::Canceled, "Cancelled.".to_string()),
                Err(e) => (TaskState::Failed, format!("Agent error: {e}")),
            };
            let mut history = prior_history.unwrap_or_default();
            history.push(Message { message_id: uuid::Uuid::new_v4().to_string(), context_id: Some(context_id.clone()), task_id: Some(task_id.clone()), role: Role::Agent, parts: vec![Part::text(text)], metadata: None, extensions: None, reference_task_ids: None });
            yield Ok(StreamResponse::Task(Task { id: task_id, context_id, status: TaskStatus { state, message: None, timestamp: None }, artifacts: prior_artifacts, history: Some(history), metadata: None }));
        })
    }

    fn cancel(&self, ctx: ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let agent = self.agent.clone();
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        let history = ctx
            .stored_task
            .as_ref()
            .and_then(|task| task.history.clone());
        let artifacts = ctx
            .stored_task
            .as_ref()
            .and_then(|task| task.artifacts.clone());

        Box::pin(futures::stream::once(async move {
            let cancelled = agent.cancel_processing(&cancel_key(&task_id)).await;
            let state = if cancelled {
                TaskState::Canceled
            } else {
                // Nothing was running: report the task as failed rather than
                // claiming a cancellation that did not happen.
                TaskState::Failed
            };
            Ok(StreamResponse::Task(Task {
                id: task_id,
                context_id,
                status: TaskStatus {
                    state,
                    message: None,
                    timestamp: None,
                },
                artifacts,
                history,
                metadata: None,
            }))
        }))
    }
}

/// A terminal `Failed` task carrying `message`, used for errors that happen
/// before the agent turn starts (e.g. the concurrency gate refusing a task).
fn failed_task(task_id: &str, context_id: &str, message: &str) -> Task {
    Task {
        id: task_id.to_string(),
        context_id: context_id.to_string(),
        status: TaskStatus {
            state: TaskState::Failed,
            message: Some(Message {
                message_id: uuid::Uuid::new_v4().to_string(),
                context_id: Some(context_id.to_string()),
                task_id: Some(task_id.to_string()),
                role: Role::Agent,
                parts: vec![Part::text(message)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            }),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}

/// An executor that never runs an agent turn.
///
/// Exists for two reasons: it is the honest representation of "no executor is
/// wired" for tests that only exercise the transport (auth, routing, the Agent
/// Card), and it lets those tests build a router without constructing an
/// `Agent`, which needs 17 arguments including a self-referential `Weak`.
///
/// It emits an empty stream, so a `SendMessage` routed to it produces no
/// terminal event. Do not wire it into `spawn`.
pub struct NoopExecutor;

#[async_trait::async_trait]
impl AgentExecutor for NoopExecutor {
    fn execute(
        &self,
        _ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        Box::pin(futures::stream::empty())
    }
    fn cancel(
        &self,
        _ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        Box::pin(futures::stream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::A2aPeerConfig;

    #[test]
    fn cancel_keys_are_namespaced_away_from_telegram_user_ids() {
        // Hazard: the registry is keyed by Telegram user_id and `/stop`
        // cancels by that key. An A2A key must be distinguishable so the two
        // cannot cancel each other's runs.
        assert_eq!(cancel_key("task-abc"), "a2a:task-abc");
        assert_ne!(cancel_key("12345"), "12345");
    }

    #[test]
    fn the_peer_header_is_read_from_service_params() {
        let mut params = ServiceParams::new();
        params.insert(PEER_HEADER.to_string(), vec!["laptop".to_string()]);
        assert_eq!(peer_from_service_params(&params), "laptop");
    }

    #[test]
    fn a_missing_peer_header_resolves_to_no_peer() {
        // Fail closed: an empty name matches no peer, so `policy_for` yields an
        // empty policy. If this ever returned a real name, the auth middleware
        // was bypassed.
        let params = ServiceParams::new();
        assert_eq!(peer_from_service_params(&params), "");
    }

    #[test]
    fn a_wildcard_peer_must_be_resolved_against_the_registry_not_an_empty_list() {
        // Documents the trap this module exists to avoid: `authenticate`
        // resolves against `&[]`, so a wildcard peer gets NOTHING from it.
        let peer = A2aPeerConfig {
            token: "t".to_string(),
            ip: vec!["127.0.0.1".to_string()],
            tools: Some(vec!["*".to_string()]),
        };
        let registry = vec!["read_file".to_string(), "execute_command".to_string()];

        let provisional = resolve_allowed_tools("p", &peer, &[]);
        assert!(
            provisional.is_empty(),
            "the provisional list from authenticate() is empty for a wildcard peer"
        );

        let real = resolve_allowed_tools("p", &peer, &registry);
        assert_eq!(
            real.len(),
            2,
            "re-resolving against the registry restores it"
        );
    }

    #[test]
    fn a_default_peer_never_gains_execute_command() {
        let peer = A2aPeerConfig {
            token: "t".to_string(),
            ip: vec!["127.0.0.1".to_string()],
            tools: None,
        };
        let registry = vec![
            "read_file".to_string(),
            "execute_command".to_string(),
            "write_file".to_string(),
        ];
        let resolved = resolve_allowed_tools("p", &peer, &registry);
        assert!(!resolved.iter().any(|t| t == "execute_command"));
        assert!(!resolved.iter().any(|t| t == "write_file"));
        for t in crate::a2a::DEFAULT_PEER_TOOLS {
            assert!(resolved.iter().any(|r| r == t), "{t} must be granted");
        }
    }

    #[test]
    fn gate_acquires_when_under_the_limit() {
        let gate = TaskGate::new(2);
        let p1 = gate.try_acquire().expect("first permit");
        let _p2 = gate.try_acquire().expect("second permit");
        drop(p1);
    }

    #[test]
    fn gate_refuses_when_the_limit_is_held() {
        let gate = TaskGate::new(1);
        let _held = gate.try_acquire().expect("first permit must succeed");
        assert!(
            gate.try_acquire().is_err(),
            "a second task must be refused while the only permit is held"
        );
    }

    #[test]
    fn gate_never_creates_a_zero_permit_deadlock() {
        // `max_concurrent_tasks = 0` must clamp to 1, not create a gate that
        // refuses every task forever.
        let gate = TaskGate::new(0);
        assert_eq!(gate.limit(), 1);
        let _ = gate
            .try_acquire()
            .expect("a zero-configured gate must still admit one task");
    }

    #[test]
    fn gate_reports_the_limit_in_the_error() {
        let gate = TaskGate::new(3);
        let _a = gate.try_acquire().unwrap();
        let _b = gate.try_acquire().unwrap();
        let _c = gate.try_acquire().unwrap();
        let err = gate.try_acquire().unwrap_err();
        assert!(
            err.message.contains("3"),
            "error must name the limit: {}",
            err.message
        );
    }
}
