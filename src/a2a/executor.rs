//! Bridges an A2A task to a RustFox agent turn, under the peer's tool policy.
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
use a2a::errors::A2AError;
use a2a::event::StreamResponse;
use a2a::types::{Message, Part, PartContent, Role, Task, TaskState, TaskStatus};
use a2a_server::{AgentExecutor, ExecutorContext, ServiceParams};
use futures::stream::BoxStream;
use std::sync::Arc;

/// Header the auth middleware uses to hand the resolved peer name to the SDK
/// handler.
///
/// The SDK forwards request headers into [`ExecutorContext`] via
/// `service_params` (`middleware.rs:17-28`), and that is the **only** identity
/// channel available: the SDK sets `ctx.user` to `None` unconditionally
/// (`handler.rs:558`, `handler.rs:668`).
pub const PEER_HEADER: &str = "x-rustfox-a2a-peer";

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

/// Drives an A2A task through the RustFox agent loop.
pub struct A2aExecutor {
    agent: Arc<crate::agent::Agent>,
}

impl A2aExecutor {
    pub fn new(agent: Arc<crate::agent::Agent>) -> Self {
        Self { agent }
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

        // Resolved BEFORE the async block: the returned stream must be
        // `'static`, and `policy_for` borrows `&self`. Resolving here also
        // keeps the policy a snapshot of the registry at request time.
        let allowed = self.policy_for(&peer);

        // The executor emits exactly one terminal event, so `once` is enough
        // and needs no extra dependency.
        Box::pin(futures::stream::once(async move {
            let key = cancel_key(&task_id);
            let cancel = agent.register_cancel_token(&key).await;

            tracing::info!(
                task_id = %task_id,
                peer = %peer,
                tools = allowed.len(),
                "A2A task starting"
            );

            let outcome = agent.run_with_policy(&prompt, allowed, Some(cancel)).await;
            agent.clear_cancel_token(&key).await;

            let (state, text) = match outcome {
                Ok(crate::loop_runner::LoopOutcome::FinalResponse(t)) => (TaskState::Completed, t),
                Ok(crate::loop_runner::LoopOutcome::MaxIterations) => (
                    TaskState::Failed,
                    "The agent reached its maximum number of iterations.".to_string(),
                ),
                Ok(crate::loop_runner::LoopOutcome::Cancelled) => {
                    (TaskState::Canceled, "Cancelled.".to_string())
                }
                Err(e) => (TaskState::Failed, format!("Agent error: {e}")),
            };

            let mut history = prior_history.unwrap_or_default();
            history.push(Message {
                message_id: uuid::Uuid::new_v4().to_string(),
                context_id: Some(context_id.clone()),
                task_id: Some(task_id.clone()),
                role: Role::Agent,
                parts: vec![Part::text(text)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            });

            Ok(StreamResponse::Task(Task {
                id: task_id,
                context_id,
                status: TaskStatus {
                    state,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: Some(history),
                metadata: None,
            }))
        }))
    }

    fn cancel(&self, ctx: ExecutorContext) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let agent = self.agent.clone();
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();

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
                artifacts: None,
                history: None,
                metadata: None,
            }))
        }))
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
}
