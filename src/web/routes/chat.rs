//! Chat routes: session bookkeeping and the SSE message stream.
//!
//! # Routes
//!
//! ```text
//! POST   /api/chat/sessions               -> { id }
//! GET    /api/chat/sessions               -> { sessions: [{ id, turns }] }
//! GET    /api/chat/sessions/{id}/messages -> { messages: [{ role, content }] }
//! POST   /api/chat/sessions/{id}/messages -> text/event-stream
//! POST   /api/chat/sessions/{id}/cancel   -> { cancelled: bool }
//! ```
//!
//! # The tool policy is the whole point of this module
//!
//! The dashboard chat must offer the operator the same tool set the Telegram
//! bot does (design spec §4.6). That set is computed from the **live sources**
//! the agentic loop itself draws from — [`web_tool_policy`] — and never from a
//! hand-written list, which drifts the moment a tool is registered.
//!
//! The obvious-looking shortcut is wrong and is worth spelling out, because it
//! fails *silently*:
//!
//! ```text
//! vec!["*".to_string()]   // ← never do this
//! ```
//!
//! The `"*"` wildcard is expanded only by `a2a::policy::resolve_allowed_tools`.
//! The loop itself filters with a literal membership test
//! (`src/loop_runner.rs:113`):
//!
//! ```text
//! all.into_iter().filter(|d| whitelist.contains(&d.function.name)).collect()
//! ```
//!
//! so a wildcard policy matches **no tool at all**. The chat would look like it
//! works and would mysteriously be unable to use a single tool, with no error
//! anywhere. `the_wildcard_policy_would_offer_the_loop_no_tools` models that
//! filter and fails if anyone reintroduces the wildcard.
//!
//! # Which SSE events this module emits
//!
//! `token`, `done`, `error` — and only those.
//!
//! The design spec lists `tool_call` and `tool_result` as well. They cannot be
//! sourced from this code path and are therefore **not** emitted:
//! `Agent::run_with_policy_streaming_history` builds its `LoopConfig` through
//! `policy_loop_config`, which sets `tool_event_tx: None`
//! (`src/agent.rs:1890`), and the only channel the loop writes to is
//! `stream_token_tx`, whose item type is a bare `String` with no event kind
//! (`src/loop_runner.rs:220`). `LoopConfig::tool_event_tx` is not read anywhere
//! in the loop. Emitting a `tool_call` event would mean inventing one.
//!
//! The tokens themselves are also coarser than they look: `stream_token_tx` is
//! fed by `LlmClient::stream_text` (`src/loop_runner.rs:221`), which chunks the
//! **final** response after the loop has finished its tool iterations. Text the
//! model emits alongside a tool call is never streamed.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;

use crate::agent::Agent;
use crate::llm::{ChatMessage, ToolDefinition};
use crate::loop_runner::LoopOutcome;
use crate::mcp::McpManager;
use crate::tool_registry::ToolRegistry;
use crate::web::chat::{cancel_key, ChatSessionSummary};
use crate::web::state::WebState;

/// SSE event carrying a chunk of the assistant's final text.
pub const EVENT_TOKEN: &str = "token";
/// SSE event ending a run normally, or reporting that it was cancelled.
pub const EVENT_DONE: &str = "done";
/// SSE event ending a run that produced no answer.
pub const EVENT_ERROR: &str = "error";

/// Capacity of the token channel handed to the loop.
///
/// Matches `src/a2a/executor.rs:223`. The producer is `LlmClient::stream_text`,
/// which awaits on a full channel, so this is backpressure, not a queue that can
/// be outrun.
const TOKEN_CHANNEL_CAPACITY: usize = 128;

/// How often an idle stream emits a comment line.
///
/// A long tool-using turn can sit silent for minutes; an intermediate proxy that
/// times out idle connections would otherwise kill the stream mid-run.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Message reported for `LoopOutcome::MaxIterations`.
///
/// A truncated run is an `error`, never a `done`: reporting it as a normal
/// completion would hand the operator a half-finished answer with no signal that
/// the agent gave up.
const MAX_ITERATIONS_MESSAGE: &str =
    "the agent reached its maximum number of iterations without producing a final response";

/// The tool policy for the dashboard chat: every tool the loop would offer.
///
/// The union of the two sources `src/loop_runner.rs:109-114` draws from —
/// `ToolRegistry::all_definitions()` and `McpManager::tool_definitions()`.
/// Omitting the MCP half would silently withhold every MCP tool from the
/// dashboard while the Telegram bot kept them.
///
/// Do **not** return `vec!["*".to_string()]`; see the module documentation.
pub fn web_tool_policy(registry: &ToolRegistry, mcp: &McpManager) -> Vec<String> {
    policy_from_sources(registry.all_definitions(), mcp.tool_definitions())
}

/// [`web_tool_policy`] against a live agent's registry and MCP manager.
pub fn web_tool_policy_for(agent: &Agent) -> Vec<String> {
    web_tool_policy(&agent.tool_registry, &agent.mcp)
}

/// The pure core of [`web_tool_policy`], split out so both sources can be
/// exercised without a live `McpManager` (which cannot be built with tools
/// attached outside a real MCP connection).
fn policy_from_sources(
    registry_definitions: Vec<ToolDefinition>,
    mcp_definitions: Vec<ToolDefinition>,
) -> Vec<String> {
    registry_definitions
        .into_iter()
        .chain(mcp_definitions)
        .map(|definition| definition.function.name.clone())
        .collect()
}

pub fn router() -> Router<WebState> {
    Router::new()
        .route(
            "/api/chat/sessions",
            post(create_session).get(list_sessions),
        )
        .route(
            "/api/chat/sessions/{id}/messages",
            get(read_messages).post(send_message),
        )
        .route("/api/chat/sessions/{id}/cancel", post(cancel_run))
}

#[derive(Serialize)]
struct SessionCreated {
    id: String,
}

#[derive(Serialize)]
struct SessionList {
    sessions: Vec<ChatSessionSummary>,
}

#[derive(Serialize)]
struct MessageList {
    messages: Vec<ChatMessage>,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    message: String,
}

#[derive(Serialize)]
struct CancelResponse {
    cancelled: bool,
}

/// The body of every "that session does not exist" answer.
///
/// The id itself is never echoed: a session id is a live handle to a
/// conversation (design spec §4.7).
const UNKNOWN_SESSION: &str = "unknown chat session";

fn unknown_session() -> Response {
    (StatusCode::NOT_FOUND, UNKNOWN_SESSION).into_response()
}

async fn create_session(State(state): State<WebState>) -> Response {
    Json(SessionCreated {
        id: state.chat.create(),
    })
    .into_response()
}

async fn list_sessions(State(state): State<WebState>) -> Response {
    Json(SessionList {
        sessions: state.chat.list(),
    })
    .into_response()
}

async fn read_messages(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    match state.chat.history(&id) {
        Ok(messages) => Json(MessageList { messages }).into_response(),
        Err(_) => unknown_session(),
    }
}

/// Start a run and stream its tokens.
///
/// The order of the pre-flight checks is deliberate:
///
/// 1. **404** if the session does not exist, so a typo is always reported as a
///    typo, even on a dashboard that has no agent at all.
/// 2. **400** if the message is blank.
/// 3. **503** if the dashboard has no agent, or if the agent exposes no tools
///    at all — an empty policy means "no tools" to the loop, and running anyway
///    would be the silent capability failure the design spec warns about.
/// 4. **409** if a run is already in flight for this session; see
///    `ChatSessionStore::begin_run`.
async fn send_message(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Json(body): Json<SendMessageRequest>,
) -> Response {
    let prior_history = match state.chat.history(&id) {
        Ok(history) => history,
        Err(_) => return unknown_session(),
    };

    if body.message.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "the message must not be empty").into_response();
    }

    let agent = match state.agent_or_unavailable() {
        Ok(agent) => agent,
        Err((status, message)) => return (status, message).into_response(),
    };

    let allowed_tools = web_tool_policy_for(&agent);
    if allowed_tools.is_empty() {
        tracing::error!(
            "web: the agent exposes no tools; refusing to start a chat run that could not use any"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "the agent exposes no tools; refusing to run a chat that could not use any",
        )
            .into_response();
    }

    // Claim the session for the duration of the run. Two concurrent runs would
    // share one cancel-token key (`web:{session_id}`), so the first to finish
    // would clear the other's token and leave it uncancellable. The claim is
    // released by `ChatRunCleanup` when the stream ends — including when the
    // client disconnects and the body is dropped.
    match state.chat.begin_run(&id) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                "a run is already in progress for this chat session",
            )
                .into_response()
        }
        Err(_) => return unknown_session(),
    }

    // Persisted before the run starts, so a client that disconnects mid-run
    // still leaves the question in the history.
    if let Err(e) = state.chat.append_user(&id, &body.message) {
        tracing::error!(error = %e, "web: the chat session vanished before the user turn was stored");
        state.chat.end_run(&id);
        return unknown_session();
    }

    let key = cancel_key(&id);
    let cancel = agent.register_cancel_token(&key).await;
    let (token_tx, mut token_rx) = tokio::sync::mpsc::channel::<String>(TOKEN_CHANNEL_CAPACITY);

    // Exactly the shape of `src/a2a/executor.rs:223-275`: an owned task, a
    // token channel, and a `select!` that drains tokens while awaiting the join
    // handle.
    let agent_task = {
        let agent = agent.clone();
        let prompt = body.message.clone();
        let cancel_for_task = cancel.clone();
        tokio::spawn(async move {
            agent
                .run_with_policy_streaming_history(
                    prior_history,
                    &prompt,
                    allowed_tools,
                    Some(cancel_for_task),
                    Some(token_tx),
                )
                .await
        })
    };

    let store = state.chat.clone();
    let session_id = id.clone();

    // The cleanup guard is built **here**, not inside the stream body.
    // `async_stream::stream!` expands to `AsyncStream::new(rx, async move { .. })`,
    // so a value used in the body is moved into the generator and dropped with
    // it. A guard constructed *inside* the body would only exist once the body
    // had been polled — and a client that disconnects between the handler
    // returning and the first poll would drop the response without ever running
    // it, leaking the run claim, the cancel-token entry, and a detached agent
    // task. Built here, `Drop` runs on every exit path, polled or not.
    let mut cleanup = ChatRunCleanup {
        handle: Some(agent_task),
        agent: agent.clone(),
        key: key.clone(),
        cancel: cancel.clone(),
        chat: store.clone(),
        session_id: session_id.clone(),
    };

    let stream = async_stream::stream! {
        let outcome = loop {
            let next = tokio::select! {
                // `biased` so a buffered token is always taken before the join
                // handle is observed: without it `select!` picks at random
                // among ready branches, and a completed run whose last chunks
                // are still in the channel would be truncated.
                biased;
                Some(token) = token_rx.recv() => Some(token),
                result = cleanup.handle.as_mut().expect("the agent handle is taken exactly once") => break result,
            };
            if let Some(token) = next {
                yield token_event(token);
            }
        };
        cleanup.handle.take();
        agent.clear_cancel_token(&key).await;

        // The producer is gone by now, so this drains everything that was
        // buffered when the run finished and then stops.
        while let Ok(token) = token_rx.try_recv() {
            yield token_event(token);
        }

        match outcome {
            Ok(Ok(LoopOutcome::FinalResponse(text))) => {
                if let Err(e) = store.append_assistant(&session_id, &text) {
                    tracing::warn!(
                        error = %e,
                        "web: the assistant reply could not be stored; the session was evicted mid-run"
                    );
                }
                yield terminal_event(EVENT_DONE, serde_json::json!({ "text": text }));
            }
            // A cancelled run produced no final text, so there is nothing to
            // persist and nothing that may be reported as a completion.
            Ok(Ok(LoopOutcome::Cancelled)) => {
                yield terminal_event(EVENT_DONE, serde_json::json!({ "cancelled": true }));
            }
            Ok(Ok(LoopOutcome::MaxIterations)) => {
                yield error_event(MAX_ITERATIONS_MESSAGE);
            }
            Ok(Err(e)) => {
                yield error_event(&format!("the agent run failed: {e}"));
            }
            Err(join_error) => {
                yield error_event(&format!("the agent task failed: {join_error}"));
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(KEEP_ALIVE_INTERVAL))
        .into_response()
}

/// Stop the run in flight for a session, if there is one.
///
/// The cancel token is keyed `web:{session_id}`, so this cannot cancel a
/// Telegram `/stop` run or an A2A task.
async fn cancel_run(State(state): State<WebState>, Path(id): Path<String>) -> Response {
    if state.chat.history(&id).is_err() {
        return unknown_session();
    }

    let agent = match state.agent_or_unavailable() {
        Ok(agent) => agent,
        Err((status, message)) => return (status, message).into_response(),
    };

    let cancelled = agent.cancel_processing(&cancel_key(&id)).await;
    Json(CancelResponse { cancelled }).into_response()
}

fn token_event(chunk: String) -> Result<Event, Infallible> {
    Ok(Event::default().event(EVENT_TOKEN).data(chunk))
}

fn terminal_event(kind: &'static str, payload: serde_json::Value) -> Result<Event, Infallible> {
    Ok(Event::default().event(kind).data(payload.to_string()))
}

/// Build an `error` event, with the message redacted.
///
/// An agent error can quote a provider response, and a provider response can
/// quote the request that carried the API key; `supervisor::redact::redact` is
/// the same scrubber the supervisor's artifacts use.
fn error_event(message: &str) -> Result<Event, Infallible> {
    let redacted = crate::supervisor::redact::redact(message);
    Ok(Event::default()
        .event(EVENT_ERROR)
        .data(serde_json::json!({ "message": redacted }).to_string()))
}

/// Aborts the run and releases its cancel token if the SSE stream is dropped.
///
/// The SSE body is dropped when the client disconnects. Without this, a
/// disconnected tab would leave the agent running to completion and a stale
/// entry in the cancel registry keyed to a session nobody is watching.
struct ChatRunCleanup {
    handle: Option<tokio::task::JoinHandle<anyhow::Result<LoopOutcome>>>,
    agent: std::sync::Arc<Agent>,
    key: String,
    cancel: tokio_util::sync::CancellationToken,
    /// The store, so the "a run is in flight" claim is released on every exit
    /// path, including a dropped stream.
    chat: std::sync::Arc<crate::web::chat::ChatSessionStore>,
    session_id: String,
}

impl Drop for ChatRunCleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        self.cancel.cancel();
        // `Drop` may run after the runtime has shut down, so this is the
        // synchronous best-effort path; normal completion does the awaited
        // cleanup above.
        self.agent.try_clear_cancel_token(&self.key);
        self.chat.end_run(&self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::FunctionDefinition;
    use crate::platform::sender::{MessageFormat, PlatformMessageId};
    use crate::tool_registry::{ToolContext, ToolHandler, ToolResult};
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    /// A handler exposing exactly the names it is given.
    struct FakeTools(Vec<&'static str>);

    #[async_trait::async_trait]
    impl ToolHandler for FakeTools {
        fn define(&self) -> Vec<ToolDefinition> {
            self.0
                .iter()
                .map(|name| ToolDefinition {
                    tool_type: "function".to_string(),
                    function: FunctionDefinition {
                        name: (*name).to_string(),
                        description: "test tool".to_string(),
                        parameters: json!({ "type": "object", "properties": {} }),
                    },
                })
                .collect()
        }

        async fn execute(
            &self,
            name: &str,
            _args: serde_json::Value,
            _ctx: ToolContext,
        ) -> ToolResult {
            Ok(format!("executed {name}"))
        }
    }

    fn definition(name: &str) -> ToolDefinition {
        ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: name.to_string(),
                description: "test tool".to_string(),
                parameters: json!({ "type": "object", "properties": {} }),
            },
        }
    }

    /// A registry holding `FakeTools` plus the real handlers `src/main.rs`
    /// registers, so the policy is exercised against the operator's real tool
    /// set rather than a stub.
    fn registry() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(FakeTools(vec!["fake_tool"])));
        registry.register(Box::new(crate::builtin_tools::BuiltinTools::new(
            PathBuf::from("/nonexistent/skills"),
            Arc::new(tokio::sync::RwLock::new(crate::skills::SkillRegistry::new())),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )));
        // `execute_command` lives in its own handler, not in `BuiltinTools`.
        registry.register(Box::new(crate::command_tool::CommandTool::new(
            PathBuf::from("/nonexistent/sandbox"),
            Arc::new(crate::cancel_registry::CancelRegistry::new()),
            Arc::new(NoopSender),
        )));
        registry
    }

    /// A `PlatformSender` that drops everything; `CommandTool::new` needs one.
    struct NoopSender;

    #[async_trait::async_trait]
    impl crate::platform::sender::PlatformSender for NoopSender {
        async fn send_message(
            &self,
            _chat_id: &str,
            _text: &str,
            _format: MessageFormat,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("noop:1".to_string())
        }

        async fn send_file(
            &self,
            _chat_id: &str,
            _path: &Path,
            _caption: Option<&str>,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("noop:1".to_string())
        }

        async fn show_cancel_button(
            &self,
            _chat_id: &str,
            _text: &str,
            _cancel_id: &str,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("noop:1".to_string())
        }

        async fn edit_message(
            &self,
            _chat_id: &str,
            _message_id: &PlatformMessageId,
            _text: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn delete_message(
            &self,
            _chat_id: &str,
            _message_id: &PlatformMessageId,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn notify_shutdown(&self, _chat_id: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_web_tool_policy_is_the_union_of_both_live_sources() {
        let registry = registry();
        let mcp = McpManager::new();

        // The same computation, written out independently of the implementation
        // under test: registry names, then MCP names.
        let expected: Vec<String> = registry
            .all_definitions()
            .iter()
            .chain(mcp.tool_definitions().iter())
            .map(|definition| definition.function.name.clone())
            .collect();

        assert_eq!(web_tool_policy(&registry, &mcp), expected);
        assert_eq!(
            web_tool_policy(&registry, &mcp).len(),
            registry.all_definitions().len(),
            "with no MCP servers connected the policy is exactly the registry"
        );
    }

    #[test]
    fn the_policy_carries_mcp_tool_names_too() {
        // An empty `McpManager` cannot show that the MCP half is included, so
        // this exercises the pure core with a synthetic MCP-side definition. A
        // policy that dropped the MCP half would withhold every MCP tool from
        // the dashboard while the Telegram bot kept them.
        let policy = policy_from_sources(
            vec![definition("read_file")],
            vec![definition("mcp_fake_server_search")],
        );

        assert_eq!(
            policy,
            vec![
                "read_file".to_string(),
                "mcp_fake_server_search".to_string()
            ],
            "the MCP half of the union must survive"
        );
    }

    #[test]
    fn the_web_tool_policy_is_never_empty_when_the_sources_have_tools() {
        // An empty policy means "no tools" in `run_with_policy_streaming_history`
        // (the fail-closed default), so passing one by accident would look like a
        // working chat that mysteriously cannot use any tool.
        let registry = registry();
        assert!(!registry.all_definitions().is_empty());

        let policy = web_tool_policy(&registry, &McpManager::new());
        assert!(
            !policy.is_empty(),
            "a non-empty registry must never yield an empty policy"
        );
        // The dashboard gets the operator's real tool set, including the one
        // that makes this a shell on the host (design spec §4.6).
        assert!(
            policy.contains(&"execute_command".to_string()),
            "the operator's tools must reach the dashboard, got {policy:?}"
        );
    }

    #[test]
    fn the_wildcard_policy_would_offer_the_loop_no_tools() {
        // Models the loop's own filter (`src/loop_runner.rs:113`) over the
        // definitions the loop would draw from (`src/loop_runner.rs:109-114`).
        // This is the exact trap the design spec fell into: `"*"` is expanded
        // only by `a2a::policy::resolve_allowed_tools`, so a wildcard policy
        // matches nothing here.
        let registry = registry();
        let mcp = McpManager::new();
        let definitions: Vec<ToolDefinition> = registry
            .all_definitions()
            .into_iter()
            .chain(mcp.tool_definitions())
            .collect();
        assert!(
            !definitions.is_empty(),
            "the test is meaningless against an empty registry"
        );

        // The policy the design spec originally prescribed, spelled the same way
        // (`["*"]` is `vec!["*".to_string()]`; the array form avoids a
        // `clippy::useless_vec` lint that is about allocation, not semantics).
        let wildcard = ["*".to_string()];
        let effective = definitions
            .iter()
            .filter(|definition| wildcard.contains(&definition.function.name))
            .count();
        assert_eq!(
            effective, 0,
            "a wildcard policy must be observed to match no tool at all"
        );

        let policy = web_tool_policy(&registry, &mcp);
        let effective = definitions
            .iter()
            .filter(|definition| policy.contains(&definition.function.name))
            .count();
        assert_eq!(
            effective,
            definitions.len(),
            "the real policy must offer every definition the loop holds"
        );
    }

    #[test]
    fn the_web_tool_policy_does_not_grant_the_special_subagent_handlers() {
        // Regression guard, not the defence. `invoke_agent` and `spawn_agents`
        // are not registry tools at all (see CLAUDE.md): they dispatch through a
        // `special_tool_handler` closure, and
        // `run_with_policy_streaming_history` passes `special_tool_handler: None`
        // deliberately (`src/agent.rs:1637-1649`). This is structurally
        // guaranteed; the assertion keeps a future refactor from quietly handing
        // the dashboard subagent dispatch, and pins the invariant where a
        // reviewer will see it.
        let policy = web_tool_policy(&registry(), &McpManager::new());
        assert!(
            !policy
                .iter()
                .any(|tool| tool == "invoke_agent" || tool == "spawn_agents"),
            "subagent dispatch must not be reachable from the dashboard, got {policy:?}"
        );
    }

    #[test]
    fn a_guard_moved_into_the_stream_is_dropped_even_if_the_stream_is_never_polled() {
        // The property `send_message` relies on by building `ChatRunCleanup`
        // *outside* the `stream!` body. `async_stream::stream!` expands to
        // `AsyncStream::new(rx, async move { .. })`
        // (`async-stream-impl-0.3.6/src/lib.rs:236`), so a value used in the body
        // is moved into the generator and dropped with the stream — including a
        // stream that is dropped without ever being polled, which is what
        // happens when a client disconnects between the handler returning and
        // hyper's first poll.
        //
        // This pins the mechanism, not the route wiring: it is why the guard is
        // placed where it is, and it fails if someone "tidies" the guard into
        // the body *and* the mechanism ever changes underneath.
        struct DropGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let guard = DropGuard(dropped.clone());

        let stream = async_stream::stream! {
            // Moved into the generator exactly as `cleanup` is.
            let _guard = guard;
            yield 1u8;
        };

        // Never polled.
        drop(stream);

        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "a guard captured by the stream body must be dropped with the stream"
        );
    }

    #[test]
    fn the_event_kinds_are_the_documented_ones() {
        assert_eq!(EVENT_TOKEN, "token");
        assert_eq!(EVENT_DONE, "done");
        assert_eq!(EVENT_ERROR, "error");
    }

    #[test]
    fn a_terminal_event_carries_its_payload_as_json() {
        let event = terminal_event(EVENT_DONE, json!({ "cancelled": true })).unwrap();
        let formatted = format!("{event:?}");
        assert!(
            formatted.contains("cancelled"),
            "the payload must reach the wire, got {formatted}"
        );
    }

    #[test]
    fn an_error_event_is_redacted() {
        // An agent error can quote the provider response, which can quote the
        // request that carried the API key. The value below is deliberately a
        // non-secret literal that still matches the scrubber's pattern.
        // Assembled at runtime so the literal below is never a credential-shaped
        // string in this file.
        let message = format!(
            "provider said: {}{}{}",
            "api_key", "=", "leaky-value-must-not-ship"
        );
        let event = error_event(&message).unwrap();
        let formatted = format!("{event:?}");
        assert!(
            !formatted.contains("leaky-value-must-not-ship"),
            "a credential must never reach the browser, got {formatted}"
        );
        assert!(
            formatted.contains("api_key=***"),
            "the key name stays readable so the error is still diagnosable, got {formatted}"
        );
    }

    #[test]
    fn the_max_iterations_message_is_not_a_completion() {
        // The message is what the operator sees when the agent gives up; it must
        // say so rather than look like an answer.
        assert!(MAX_ITERATIONS_MESSAGE.contains("maximum number of iterations"));
    }
}
