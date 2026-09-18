//! Live end-to-end proof of A2A success criterion 2:
//!
//! > an authenticated, allowlisted peer sends `SendMessage` and the A2A task
//! > reaches state `completed`.
//!
//! Nothing on the agent path is stubbed. This test builds a real
//! [`haos_green::agent::Agent`] (17 constructor arguments, including the
//! self-referential `Weak<Agent>` that `run_with_policy` needs), wraps it in
//! the real [`A2aExecutor`], persists through the real [`SqliteTaskStore`],
//! serves the real axum router on an ephemeral loopback port, and drives it
//! with a real HTTP request. The agent turn itself is a real LLM call.
//!
//! # Gating
//!
//! Two gates, because this test cannot pass on a machine without the endpoint:
//!
//! 1. `#[ignore]` — `cargo test` never picks it up.
//! 2. A runtime check of `RUSTFOX_A2A_LIVE=1` — even an explicit
//!    `--ignored` run exits early with a printed message when it is unset.
//!
//! Run it with:
//!
//! ```text
//! RUSTFOX_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored --nocapture
//! ```
//!
//! # Endpoint requirements
//!
//! An OpenAI-compatible server at [`LLM_BASE_URL`] accepting any non-empty
//! `Bearer` token, serving [`LLM_MODEL`]. Both are overridable through
//! `HAOS_GREEN_LIVE_LLM_BASE_URL` and `HAOS_GREEN_LIVE_LLM_MODEL`, so a moved
//! gateway or a model that has left its pool is an env change rather than an
//! edit here. `max_tokens` is always sent — it is a non-optional field of
//! `llm::ChatRequest` — and the config below sets 512 rather than a tiny budget
//! so the assistant `content` is non-empty: a reasoning model spends a small
//! allowance on `reasoning` and returns an empty `content`, which the agent
//! loop would treat as an empty response.
//!
//! # Why this file does not mutate the environment
//!
//! The home directory comes from `[general].home` in the generated config, not
//! from `RUSTFOX_HOME`, so the test never calls `std::env::set_var` (which is
//! process-global and would race with any other test in the same binary).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use a2a::errors::A2AError;
use a2a::event::{StreamResponse, TaskStatusUpdateEvent};
use a2a::types::{Task, TaskState, TaskStatus};
use a2a_server::{AgentExecutor, ExecutorContext};
use futures::stream::BoxStream;
use futures::StreamExt;
use haos_green::a2a::server::{build_state, router};
use haos_green::a2a::{A2aExecutor, SqliteTaskStore};
use haos_green::agent::Agent;
use haos_green::builtin_tools::BuiltinTools;
use haos_green::cancel_registry::CancelRegistry;
use haos_green::config::{A2aConfig, A2aPeerConfig, Config};
use haos_green::langsmith::LangSmithClient;
use haos_green::mcp::McpManager;
use haos_green::memory::MemoryStore;
use haos_green::memory_tools::MemoryTools;
use haos_green::platform::sender::{MessageFormat, PlatformMessageId, PlatformSender};
use haos_green::provider;
use haos_green::scheduler::reminders::ScheduledTaskStore;
use haos_green::scheduler::Scheduler;
use haos_green::skills::SkillRegistry;
use haos_green::tool_registry::ToolRegistry;

/// Name of the peer as it appears in `[a2a.peers.<name>]`.
const PEER_NAME: &str = "laptop";
/// Bearer token that peer must present.
const PEER_TOKEN: &str = "s3cret-e2e";
/// OpenAI-compatible endpoint under test, unless
/// `HAOS_GREEN_LIVE_LLM_BASE_URL` overrides it.
const LLM_BASE_URL: &str = "http://127.0.0.1:8790/v1";
/// Model to ask the endpoint for, unless `HAOS_GREEN_LIVE_LLM_MODEL` overrides
/// it.
///
/// It must be a model the endpoint actually **serves**. This used to be
/// `a6api_DeepSeek-V4-Flash-0731`; when that name left the gateway's routing
/// pool, every live run began failing with HTTP 503
/// `smart_route_no_active_candidates` — an error that reads like a broken
/// gateway rather than a model name the pool no longer carries, which is why
/// the reason is written down here. `GET /v1/models` lists what is served, and
/// a one-line probe against `/chat/completions` confirms a candidate before
/// changing this.
const LLM_MODEL: &str = "gemini-3.8-flash";

/// [`LLM_BASE_URL`], overridable so the gate can be pointed at another gateway
/// without editing this file.
fn live_llm_base_url() -> String {
    std::env::var("HAOS_GREEN_LIVE_LLM_BASE_URL").unwrap_or_else(|_| LLM_BASE_URL.to_string())
}

/// [`LLM_MODEL`], overridable for the same reason.
fn live_llm_model() -> String {
    std::env::var("HAOS_GREEN_LIVE_LLM_MODEL").unwrap_or_else(|_| LLM_MODEL.to_string())
}
/// Trivial prompt: no tool call is needed, so the loop terminates on the first
/// iteration with a final text response.
const PROMPT: &str = "Reply with the single word: pong";
/// The wire spelling `a2a-lf` serializes `TaskState::Completed` to. Confirmed
/// in `a2a-lf-0.3.1/src/types.rs:114` and in the generated ProtoJSON serde impl
/// for `lf.a2a.v1.TaskState`.
const TASK_STATE_WORKING: &str = "TASK_STATE_WORKING";
const TASK_STATE_COMPLETED: &str = "TASK_STATE_COMPLETED";

/// A `PlatformSender` that drops everything on the floor.
///
/// `run_with_policy` needs one to build its `ToolContext`; the trivial prompt
/// calls no tool, so nothing is ever sent. It exists to satisfy the type, not
/// to be observed.
struct NoopSender;

#[async_trait::async_trait]
impl PlatformSender for NoopSender {
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

struct ServerGuard(tokio::task::JoinHandle<()>);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct SlowExecutor {
    cancel: CancellationToken,
    observed_cancel: Arc<tokio::sync::Notify>,
}

impl AgentExecutor for SlowExecutor {
    fn execute(
        &self,
        ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let cancel = self.cancel.clone();
        let observed_cancel = Arc::clone(&self.observed_cancel);
        let working = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
            task_id: ctx.task_id.clone(),
            context_id: ctx.context_id.clone(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            metadata: None,
        });
        let canceled = Task {
            id: ctx.task_id,
            context_id: ctx.context_id,
            status: TaskStatus {
                state: TaskState::Canceled,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: ctx.stored_task.and_then(|task| task.history),
            metadata: None,
        };
        Box::pin(
            futures::stream::once(async move { Ok(working) }).chain(futures::stream::once(
                async move {
                    cancel.cancelled().await;
                    // The terminal event belongs to execute, and this ack proves
                    // execution—not cancel—observed the cancellation signal.
                    observed_cancel.notify_one();
                    Ok(StreamResponse::Task(canceled))
                },
            )),
        )
    }

    fn cancel(
        &self,
        _ctx: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        // Do not emit a terminal task here: doing so could make CancelTask pass
        // even if execute never observes cancellation or persists its result.
        self.cancel.cancel();
        Box::pin(futures::stream::empty())
    }
}

///
/// `[general].home` is an absolute path inside `dir`, so `Config::resolve`
/// materializes the whole home tree under the temp directory and no global
/// state is touched.
fn write_config(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    let workspace = home.join("workspace");
    let path = dir.join("config.toml");
    let llm_base_url = live_llm_base_url();
    let llm_model = live_llm_model();
    let toml = format!(
        r#"
[general]
home = "{home}"

[telegram]
bot_token = "test-token"
allowed_user_ids = [1]

[openrouter]
api_key = "unused-by-the-test-endpoint"
base_url = "{llm_base_url}"
model = "{llm_model}"
max_tokens = 512

[agent]
max_iterations = 4

[sandbox]
allowed_directory = "{workspace}"
"#,
        home = home.display(),
        workspace = workspace.display(),
    );
    std::fs::write(&path, toml).expect("write config.toml");
    path
}

/// The A2A side of the config: one allowlisted peer with the default tool
/// policy (`tools: None`).
fn a2a_config() -> A2aConfig {
    let mut peers = HashMap::new();
    peers.insert(
        PEER_NAME.to_string(),
        A2aPeerConfig {
            token: PEER_TOKEN.to_string(),
            // The test connects from loopback.
            ip: vec!["127.0.0.0/8".to_string()],
            tools: None,
        },
    );
    A2aConfig {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        peers,
        ..A2aConfig::default()
    }
}

/// Construct the real `Agent` exactly as `src/main.rs` does, minus the pieces
/// that need a live Telegram bot.
///
/// The tool registry is populated with the real handlers so the peer policy is
/// resolved against a non-empty registry — an empty registry would make the
/// `["*"]` case indistinguishable from the default allowlist and would weaken
/// what this test proves.
async fn build_agent(config_path: &Path, memory: &MemoryStore, a2a: A2aConfig) -> Arc<Agent> {
    let mut config = Config::load(config_path).expect("load generated config");
    config.a2a = a2a;

    let (sections, default_provider, _fallback) = config.build_providers();
    let registry = Arc::new(
        provider::build_registry(&sections, &default_provider, config.parse_retry_limit())
            .expect("build the provider registry"),
    );

    let skills_rw = Arc::new(tokio::sync::RwLock::new(SkillRegistry::new()));
    let agents_rw = Arc::new(tokio::sync::RwLock::new(SkillRegistry::new()));
    let restart_pending = Arc::new(AtomicBool::new(false));
    let soul_updated = Arc::new(AtomicBool::new(false));

    let mut tool_registry = ToolRegistry::new();
    tool_registry.register(Box::new(BuiltinTools::new(
        config.skills.directory.clone(),
        skills_rw.clone(),
        restart_pending.clone(),
        soul_updated.clone(),
    )));
    tool_registry.register(Box::new(MemoryTools::new(memory.clone())));
    tool_registry.register(Box::new(haos_green::skill_tools::SkillTools::new(
        config.skills.directory.clone(),
        config.agents.directory.clone(),
        skills_rw.clone(),
        agents_rw.clone(),
    )));

    let task_store = ScheduledTaskStore::new(memory.connection());
    let scheduler = Arc::new(Scheduler::new().await.expect("create the scheduler"));
    let (job_tx, _job_rx) =
        tokio::sync::mpsc::unbounded_channel::<haos_green::agent::ScheduledJobRequest>();
    let langsmith = Arc::new(LangSmithClient::new(None));
    let cancel_registry = Arc::new(CancelRegistry::new());
    let sender: Arc<dyn PlatformSender> = Arc::new(NoopSender);

    // `Arc::new_cyclic` so the agent can hold a `Weak<Agent>` without leaking.
    Arc::new_cyclic(|weak| {
        Agent::new(
            config,
            registry,
            McpManager::new(),
            memory.clone(),
            SkillRegistry::new(),
            SkillRegistry::new(),
            task_store,
            Arc::clone(&scheduler),
            weak.clone(),
            job_tx,
            langsmith,
            config_path.to_path_buf(),
            cancel_registry,
            tool_registry,
            sender,
            restart_pending,
            soul_updated,
        )
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live OpenAI-compatible LLM on 127.0.0.1:8790; \
            run with: RUSTFOX_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored --nocapture"]
async fn an_authenticated_peer_drives_a_send_message_to_completed() {
    if std::env::var("RUSTFOX_A2A_LIVE").as_deref() != Ok("1") {
        println!(
            "SKIP: RUSTFOX_A2A_LIVE is not set to 1 — this test needs a live LLM at {} serving `{}`.\n\
             Run it with:\n    \
             RUSTFOX_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored --nocapture",
            live_llm_base_url(),
            live_llm_model()
        );
        return;
    }

    // The temp dir must outlive the whole test: the config, the resolved home
    // and the sandbox all live inside it.
    let tmp = tempfile::tempdir().expect("create a temp dir");
    let config_path = write_config(tmp.path());

    let memory = MemoryStore::open_in_memory().expect("open an in-memory memory store");
    let a2a = a2a_config();

    let agent = build_agent(&config_path, &memory, a2a.clone()).await;

    // Precondition for the policy resolution below: the registry the executor
    // re-resolves against must actually contain tools.
    let registered: Vec<String> = agent
        .all_tool_definitions()
        .into_iter()
        .map(|d| d.function.name)
        .collect();
    assert!(
        !registered.is_empty(),
        "the peer policy must resolve against a non-empty tool registry"
    );
    println!("tool registry: {} tools: {registered:?}", registered.len());

    // The executor re-resolves the peer policy against `agent.config.a2a.peers`
    // (see `A2aExecutor::policy_for`). An unknown peer resolves to an EMPTY
    // policy — fail-closed, but silent — so assert the wiring up front rather
    // than let this test pass with a peer the executor never found.
    let peer = agent
        .config
        .a2a
        .peers
        .get(PEER_NAME)
        .unwrap_or_else(|| panic!("the agent's config must carry peer '{PEER_NAME}'"));
    let resolved = haos_green::a2a::resolve_allowed_tools(PEER_NAME, peer, &registered);
    assert!(
        !resolved.is_empty(),
        "peer '{PEER_NAME}' must resolve to a non-empty tool policy"
    );
    println!("peer '{PEER_NAME}' policy: {resolved:?}");

    // Real SQLite task store over the same connection the agent uses.
    let store = SqliteTaskStore::new(agent.memory.connection());

    let state = build_state(
        a2a.clone(),
        SkillRegistry::new(),
        "http://placeholder",
        A2aExecutor::new(agent.clone()),
        store,
    );
    let app = router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port");
    let addr = listener.local_addr().expect("read the bound address");
    let _server = ServerGuard(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("the A2A listener must not fail");
    }));
    println!("A2A listener: http://{addr}/jsonrpc");

    // The model can take ~20s, and `DefaultRequestHandler::send_message` blocks
    // until the task reaches a terminal state while applying no timeout of its
    // own. 120s is generous and still fails loudly rather than hanging.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("build the HTTP client");

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": "m1",
                "role": "ROLE_USER",
                "parts": [{"text": PROMPT}]
            }
        }
    });

    // Anti-false-positive guard: the same request without a token must be
    // refused. Without this, a 200 below would not prove the peer was
    // *authenticated* — only that the route answered. This costs no LLM call.
    let unauthenticated = client
        .post(format!("http://{addr}/jsonrpc"))
        .json(&request)
        .send()
        .await
        .expect("the unauthenticated request must complete");
    let unauth_status = unauthenticated.status();
    println!("HTTP {unauth_status} (no bearer token)");
    assert_eq!(
        unauth_status, 401,
        "the endpoint must refuse an unauthenticated SendMessage"
    );

    let response = client
        .post(format!("http://{addr}/jsonrpc"))
        .bearer_auth(PEER_TOKEN)
        .json(&request)
        .send()
        .await
        .expect("the SendMessage request must complete");

    let status = response.status();
    let body = response.text().await.expect("read the response body");
    println!("HTTP {status}");
    println!("body: {body}");

    assert_eq!(status, 200, "SendMessage must answer 200; body: {body}");

    let json: serde_json::Value =
        serde_json::from_str(&body).expect("the response must be JSON-RPC");
    assert!(
        json.get("error").is_none() || json["error"].is_null(),
        "JSON-RPC error instead of a result: {body}"
    );

    let task = &json["result"]["task"];
    assert!(
        !task.is_null(),
        "the result must carry task; bare result.message is rejected: {body}"
    );

    let state = task["status"]["state"]
        .as_str()
        .unwrap_or_else(|| panic!("no result.task.status.state in: {body}"));
    assert_eq!(
        state, TASK_STATE_COMPLETED,
        "the A2A task must reach completed; full body: {body}"
    );

    // The task must carry the agent's reply — proof the turn really ran rather
    // than the executor emitting a bare terminal state.
    let history = task["history"]
        .as_array()
        .unwrap_or_else(|| panic!("the task must carry history: {body}"));
    let agent_reply = history
        .iter()
        .rev()
        .find(|m| m["role"] == "ROLE_AGENT")
        .and_then(|m| m["parts"][0]["text"].as_str())
        .unwrap_or_else(|| panic!("no ROLE_AGENT message with text in: {body}"));
    assert!(
        !agent_reply.trim().is_empty(),
        "the agent's reply must not be empty: {body}"
    );
    // Teeth: `AgenticLoop` returns `FinalResponse("I'm having trouble
    // processing that. Please try again.")` — which the executor maps to
    // `Completed` — once the model produces empty content
    // `empty_response_retry_limit` times. A state-only assertion cannot tell
    // that apart from a real answer, so pin the model's actual words.
    assert!(
        agent_reply.to_lowercase().contains("pong"),
        "the reply must be the model's answer to {PROMPT:?}, not the loop's \
         empty-response fallback: {agent_reply:?}"
    );
    println!("agent reply: {agent_reply:?}");
    let task_id = task["id"]
        .as_str()
        .expect("the result task must have an id")
        .to_string();
    let deadline = Instant::now() + Duration::from_secs(10);
    let get_body = loop {
        let response = client
            .post(format!("http://{addr}/jsonrpc"))
            .bearer_auth(PEER_TOKEN)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "GetTask",
                "params": {"id": task_id}
            }))
            .send()
            .await
            .expect("GetTask polling must complete");
        let body: serde_json::Value = response.json().await.expect("GetTask must be JSON");
        assert_eq!(body["result"]["id"], task_id);
        match body["result"]["status"]["state"].as_str() {
            Some(TASK_STATE_COMPLETED) => break body,
            Some("TASK_STATE_WORKING") => {}
            state => panic!("unexpected task state: {state:?}; body: {body}"),
        }
        assert!(
            Instant::now() < deadline,
            "task did not reach completion: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(get_body["result"]["status"]["state"], TASK_STATE_COMPLETED);

    let bogus = client
        .post(format!("http://{addr}/jsonrpc"))
        .bearer_auth(PEER_TOKEN)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "GetTask",
            "params": {"id": "bogus-task-id"}
        }))
        .send()
        .await
        .expect("bogus GetTask must complete");
    let bogus_body: serde_json::Value = bogus.json().await.expect("error must be JSON");
    assert_eq!(bogus_body["error"]["code"], -32001);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUSTFOX_A2A_LIVE=1 and a live OpenAI-compatible LLM"]
async fn an_authenticated_peer_streams_working_and_completed_pong() {
    if std::env::var("RUSTFOX_A2A_LIVE").as_deref() != Ok("1") {
        println!("SKIP: RUSTFOX_A2A_LIVE is not set to 1");
        return;
    }

    let tmp = tempfile::tempdir().expect("create a temp dir");
    let config_path = write_config(tmp.path());
    let memory = MemoryStore::open_in_memory().expect("open an in-memory memory store");
    let a2a = a2a_config();
    let agent = build_agent(&config_path, &memory, a2a.clone()).await;
    let store = SqliteTaskStore::new(agent.memory.connection());
    let state = build_state(
        a2a,
        SkillRegistry::new(),
        "http://placeholder",
        A2aExecutor::new(agent),
        store,
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port");
    let addr = listener.local_addr().expect("read the bound address");
    let _server = ServerGuard(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("the A2A listener must not fail");
    }));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("build the HTTP client");
    let response = client
        .post(format!("http://{addr}/jsonrpc"))
        .bearer_auth(PEER_TOKEN)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "SendStreamingMessage",
            "params": {"message": {"messageId": "stream-m1", "role": "ROLE_USER", "parts": [{"text": PROMPT}]}}
        }))
        .send()
        .await
        .expect("SendStreamingMessage must complete");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers().get(reqwest::header::CONTENT_TYPE),
        Some(&reqwest::header::HeaderValue::from_static(
            "text/event-stream"
        ))
    );
    let body = response.text().await.expect("read SSE response body");
    println!("stream body: {body}");

    let mut events = Vec::new();
    for line in body.lines().filter_map(|line| line.strip_prefix("data: ")) {
        let event: serde_json::Value = serde_json::from_str(line).expect("SSE data must be JSON");
        assert_eq!(
            event["jsonrpc"], "2.0",
            "each SSE event must be JSON-RPC: {event}"
        );
        assert_eq!(
            event["id"], 7,
            "each SSE event must retain request id: {event}"
        );
        assert!(
            event.get("error").is_none() || event["error"].is_null(),
            "SSE error: {event}"
        );
        events.push(event);
    }
    assert!(
        !events.is_empty(),
        "response must contain JSON-RPC SSE data events"
    );

    let encoded = serde_json::to_string(&events).expect("serialize parsed events");
    assert!(
        encoded.contains(TASK_STATE_WORKING),
        "missing working event: {body}"
    );
    assert!(
        encoded.contains(TASK_STATE_COMPLETED),
        "missing completed event: {body}"
    );
    assert!(
        encoded.to_lowercase().contains("pong"),
        "stream must contain the terminal reply containing pong: {body}"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RUSTFOX_A2A_LIVE=1"]
async fn an_in_progress_task_can_be_canceled() {
    if std::env::var("RUSTFOX_A2A_LIVE").as_deref() != Ok("1") {
        println!("SKIP: RUSTFOX_A2A_LIVE is not set to 1");
        return;
    }
    let cancel = CancellationToken::new();
    let observed_cancel = Arc::new(tokio::sync::Notify::new());
    let observed_cancel_for_test = Arc::clone(&observed_cancel);
    let state = build_state(
        a2a_config(),
        SkillRegistry::new(),
        "http://placeholder",
        SlowExecutor {
            cancel: cancel.clone(),
            observed_cancel,
        },
        a2a_server::InMemoryTaskStore::new(),
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener address");
    let _server = ServerGuard(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("A2A listener must not fail");
    }));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build the HTTP client");
    let endpoint = format!("http://{addr}/jsonrpc");
    let start = client.post(&endpoint).bearer_auth(PEER_TOKEN).json(&serde_json::json!({
        "jsonrpc": "2.0", "id": 10, "method": "SendMessage",
        "params": {"message": {"messageId": "cancel-m1", "role": "ROLE_USER", "parts": [{"text": "wait"}]}, "configuration": {"returnImmediately": true}}
    })).send().await.expect("SendMessage must return");
    let body: serde_json::Value = start.json().await.expect("JSON response");
    let task_id = body["result"]["task"]["id"]
        .as_str()
        .expect("task id")
        .to_string();
    assert_eq!(
        body["result"]["task"]["status"]["state"],
        "TASK_STATE_WORKING"
    );
    let cancel = client
        .post(&endpoint)
        .bearer_auth(PEER_TOKEN)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 11, "method": "CancelTask", "params": {"id": task_id}
        }))
        .send()
        .await
        .expect("CancelTask must return");
    let cancel_status = cancel.status();
    let cancelled: serde_json::Value = cancel.json().await.expect("JSON response");
    assert_eq!(cancel_status, reqwest::StatusCode::OK);
    assert!(
        cancelled.get("error").is_none() || cancelled["error"].is_null(),
        "CancelTask must return successfully: {cancelled}"
    );
    assert_eq!(cancelled["result"]["id"], task_id);

    // The cancel response is not the proof of cancellation: execute owns the
    // terminal event. Wait for its acknowledgement before checking persistence.
    tokio::time::timeout(Duration::from_secs(5), observed_cancel_for_test.notified())
        .await
        .expect("execute must observe the cancellation signal");

    // Poll until execute's terminal event has been persisted. The CancelTask
    // response can still report WORKING because SlowExecutor::cancel is empty.
    let deadline = Instant::now() + Duration::from_secs(5);
    let task = loop {
        let get = client
            .post(&endpoint)
            .bearer_auth(PEER_TOKEN)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 12, "method": "GetTask", "params": {"id": task_id}
            }))
            .send()
            .await
            .expect("GetTask after CancelTask must return");
        let get_status = get.status();
        let task: serde_json::Value = get.json().await.expect("GetTask response must be JSON");
        assert_eq!(get_status, reqwest::StatusCode::OK);
        assert_eq!(task["result"]["id"], task_id);
        if task["result"]["status"]["state"] == "TASK_STATE_CANCELED" {
            break task;
        }
        assert!(
            Instant::now() < deadline,
            "persisted task did not reach TASK_STATE_CANCELED: {task}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(task["result"]["status"]["state"], "TASK_STATE_CANCELED");
}
