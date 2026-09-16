//! Live end-to-end proof of A2A success criterion 2:
//!
//! > an authenticated, allowlisted peer sends `SendMessage` and the A2A task
//! > reaches state `completed`.
//!
//! Nothing on the agent path is stubbed. This test builds a real
//! [`rustfox::agent::Agent`] (17 constructor arguments, including the
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
//! `Bearer` token. `max_tokens` is always sent — it is a non-optional field of
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
use std::time::Duration;

use rustfox::a2a::server::{build_state, router};
use rustfox::a2a::{A2aExecutor, SqliteTaskStore};
use rustfox::agent::Agent;
use rustfox::builtin_tools::BuiltinTools;
use rustfox::cancel_registry::CancelRegistry;
use rustfox::config::{A2aConfig, A2aPeerConfig, Config};
use rustfox::langsmith::LangSmithClient;
use rustfox::mcp::McpManager;
use rustfox::memory::MemoryStore;
use rustfox::memory_tools::MemoryTools;
use rustfox::platform::sender::{MessageFormat, PlatformMessageId, PlatformSender};
use rustfox::provider;
use rustfox::scheduler::reminders::ScheduledTaskStore;
use rustfox::scheduler::Scheduler;
use rustfox::skills::SkillRegistry;
use rustfox::tool_registry::ToolRegistry;

/// Name of the peer as it appears in `[a2a.peers.<name>]`.
const PEER_NAME: &str = "laptop";
/// Bearer token that peer must present.
const PEER_TOKEN: &str = "s3cret-e2e";
/// OpenAI-compatible endpoint under test.
const LLM_BASE_URL: &str = "http://127.0.0.1:8790/v1";
/// Verified-working model on that endpoint.
const LLM_MODEL: &str = "a6api_DeepSeek-V4-Flash-0731";
/// Trivial prompt: no tool call is needed, so the loop terminates on the first
/// iteration with a final text response.
const PROMPT: &str = "Reply with the single word: pong";
/// The wire spelling `a2a-lf` serializes `TaskState::Completed` to. Confirmed
/// in `a2a-lf-0.3.1/src/types.rs:114` and in the generated ProtoJSON serde impl
/// for `lf.a2a.v1.TaskState`.
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

/// Write a self-contained config into `dir` and return its path.
///
/// `[general].home` is an absolute path inside `dir`, so `Config::resolve`
/// materializes the whole home tree under the temp directory and no global
/// state is touched.
fn write_config(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    let workspace = home.join("workspace");
    let path = dir.join("config.toml");
    let toml = format!(
        r#"
[general]
home = "{home}"

[telegram]
bot_token = "test-token"
allowed_user_ids = [1]

[openrouter]
api_key = "unused-by-the-test-endpoint"
base_url = "{LLM_BASE_URL}"
model = "{LLM_MODEL}"
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
    tool_registry.register(Box::new(rustfox::skill_tools::SkillTools::new(
        config.skills.directory.clone(),
        config.agents.directory.clone(),
        skills_rw.clone(),
        agents_rw.clone(),
    )));

    let task_store = ScheduledTaskStore::new(memory.connection());
    let scheduler = Arc::new(Scheduler::new().await.expect("create the scheduler"));
    let (job_tx, _job_rx) =
        tokio::sync::mpsc::unbounded_channel::<rustfox::agent::ScheduledJobRequest>();
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
            "SKIP: RUSTFOX_A2A_LIVE is not set to 1 — this test needs a live LLM at {LLM_BASE_URL}.\n\
             Run it with:\n    \
             RUSTFOX_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored --nocapture"
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
    let resolved = rustfox::a2a::resolve_allowed_tools(PEER_NAME, peer, &registered);
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
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("the A2A listener must not fail");
    });
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
        "the result must carry a task (not a bare message): {body}"
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
    println!("task id: {}", task["id"]);

    server.abort();
}
