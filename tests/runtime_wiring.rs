//! Public runtime wiring regressions. Plan: construct isolated real Agent, record
//! provider requests, exercise model switching and verifier dispatch, then run scoped tests.
use anyhow::Result;
use async_trait::async_trait;
use haos_green::{
    agent::Agent,
    cancel_registry::CancelRegistry,
    config::{Config, ProviderSection},
    langsmith::LangSmithClient,
    llm::{ChatCompletion, ChatMessage, ToolDefinition},
    mcp::McpManager,
    memory::MemoryStore,
    platform::{sender::MessageFormat, IncomingMessage, PlatformMessageId, PlatformSender},
    provider::{Provider, ProviderConfig, ProviderRegistry},
    scheduler::{reminders::ScheduledTaskStore, Scheduler},
    skills::SkillRegistry,
    tool_registry::{ToolRegistry, ToolUiMode},
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

#[derive(Clone)]
struct Request {
    provider: String,
    model: String,
    messages: Vec<ChatMessage>,
    tools: Vec<String>,
}
struct FakeProvider {
    config: ProviderConfig,
    requests: Arc<Mutex<Vec<Request>>>,
    entered: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
}
#[async_trait]
impl Provider for FakeProvider {
    fn name(&self) -> &str {
        &self.config.name
    }
    fn default_model(&self) -> &str {
        &self.config.default_model
    }
    fn supports_vision(&self) -> bool {
        self.config.supports_vision
    }
    fn config(&self) -> &ProviderConfig {
        &self.config
    }
    async fn list_models(&self, _: &reqwest::Client) -> Result<Vec<String>> {
        Ok(vec![self.config.default_model.clone()])
    }
    async fn chat_completion(
        &self,
        _: &reqwest::Client,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        model: &str,
        _: u32,
    ) -> Result<ChatCompletion> {
        self.requests.lock().await.push(Request {
            provider: self.name().into(),
            model: model.into(),
            messages: messages.to_vec(),
            tools: tools.iter().map(|t| t.function.name.clone()).collect(),
        });
        if let Some(entered) = &self.entered {
            entered.notify_one();
        }
        if let Some(release) = &self.release {
            tokio::time::timeout(Duration::from_secs(5), release.notified()).await?;
        }
        let has_result = messages.iter().any(|m| m.role == "tool");
        let message = if model == "modelA"
            && messages.iter().any(|m| {
                m.content
                    .as_ref()
                    .is_some_and(|c| c.as_text().contains("verify-runtime"))
            })
            && !has_result
        {
            serde_json::json!({"role":"assistant","tool_calls":[{"id":"verify-call","type":"function","function":{"name":"invoke_agent","arguments":"{\"agent\":\"verifier\",\"prompt\":\"check runtime\"}"}}]})
        } else if model == "childModel" {
            serde_json::json!({"role":"assistant","content":"PASS"})
        } else {
            serde_json::json!({"role":"assistant","content":"DONE"})
        };
        Ok(ChatCompletion {
            message: serde_json::from_value(message)?,
            finish_reason: Some("stop".into()),
            model: model.into(),
        })
    }
}
struct NoopSender;
#[async_trait]
impl PlatformSender for NoopSender {
    async fn send_message(&self, _: &str, _: &str, _: MessageFormat) -> Result<PlatformMessageId> {
        Ok("1".into())
    }
    async fn send_file(&self, _: &str, _: &Path, _: Option<&str>) -> Result<PlatformMessageId> {
        Ok("1".into())
    }
    async fn show_cancel_button(&self, _: &str, _: &str, _: &str) -> Result<PlatformMessageId> {
        Ok("1".into())
    }
    async fn edit_message(&self, _: &str, _: &PlatformMessageId, _: &str) -> Result<()> {
        Ok(())
    }
    async fn delete_message(&self, _: &str, _: &PlatformMessageId) -> Result<()> {
        Ok(())
    }
    async fn notify_shutdown(&self, _: &str) -> Result<()> {
        Ok(())
    }
}
async fn fixture(
    barrier: bool,
) -> (
    tempfile::TempDir,
    Arc<Agent>,
    Arc<Mutex<Vec<Request>>>,
    Arc<Notify>,
    Arc<Notify>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(&path, format!("[telegram]\nbot_token='fake'\nallowed_user_ids=[1]\n[openrouter]\napi_key='fake'\nmodel='providerA/modelA'\n[sandbox]\nallowed_directory='{}'\n", tmp.path().display())).unwrap();
    let mut config = Config::load(&path).unwrap();
    config.memory.query_rewriter_enabled = false;
    config.skills.directory = tmp.path().join("skills");
    config.agents.directory = tmp.path().join("agents");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    for (name, model) in [("providerA", "modelA"), ("providerB", "modelB")] {
        let section: ProviderSection = toml::from_str(&format!("name='{name}'\ntype='openai_compatible'\nbase_url='http://127.0.0.1:1'\nmodel='{model}'")).unwrap();
        providers.insert(
            name.into(),
            Arc::new(FakeProvider {
                config: {
                    let mut config = ProviderConfig::from(&section);
                    config.supports_vision = name == "providerA";
                    config
                },
                requests: requests.clone(),
                entered: (barrier && name == "providerA").then(|| entered.clone()),
                release: (barrier && name == "providerA").then(|| release.clone()),
            }),
        );
    }
    let registry = Arc::new(ProviderRegistry::new(providers, "providerA".into()));
    let memory = MemoryStore::open_in_memory().unwrap();
    let task_store = ScheduledTaskStore::new(memory.connection());
    let scheduler = Arc::new(Scheduler::new().await.unwrap());
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let mut agents = SkillRegistry::new();
    // Real on-disk predefined agent: bootstrap skipped to isolate dispatch wiring.
    let verifier_dir = tmp.path().join("agents/verifier");
    std::fs::create_dir_all(&verifier_dir).unwrap();
    std::fs::write(verifier_dir.join("SKILL.md"), "---\nname: verifier\ndescription: Verify runtime\nmodel: providerB/childModel\ntools: []\nskip_bootstrap: true\n---\nReturn PASS.\n").unwrap();
    agents.register(
        haos_green::skills::Skill {
            name: "verifier".into(),
            description: "Verify runtime".into(),
            content: "Return PASS.".into(),
            tags: vec![],
            model: Some("providerB/childModel".into()),
            tools: vec![],
            max_iterations: Some(2),
            skip_bootstrap: true,
            supervisor_workflow: None,
            supervisor_required_caps: vec![],
        },
        verifier_dir,
    );
    let agent = Arc::new_cyclic(|weak| {
        Agent::new(
            config,
            registry,
            McpManager::new(),
            memory,
            SkillRegistry::new(),
            agents,
            task_store,
            scheduler,
            weak.clone(),
            tx,
            Arc::new(LangSmithClient::new(None)),
            path,
            Arc::new(CancelRegistry::new()),
            ToolRegistry::new(),
            Arc::new(NoopSender),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    });
    (tmp, agent, requests, entered, release)
}
fn incoming(user: &str) -> IncomingMessage {
    IncomingMessage {
        platform: "test".into(),
        user_id: user.into(),
        chat_id: "1".into(),
        user_name: "Test".into(),
        text: "hello".into(),
        attachments: vec![],
    }
}
async fn turn(agent: &Agent, user: &str) -> String {
    tokio::time::timeout(
        Duration::from_secs(10),
        agent.process_message(&incoming(user), None, None, ToolUiMode::from_memory(None)),
    )
    .await
    .unwrap()
    .unwrap()
}
#[tokio::test]
async fn main_invoke_agent_reaches_predefined_verifier() {
    let (_tmp, agent, requests, _, _) = fixture(false).await;
    let mut message = incoming("verifier-user");
    message.text = "verify-runtime".into();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        agent.process_message(&message, None, None, ToolUiMode::from_memory(None)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, "DONE");
    let requests = requests.lock().await;
    assert_eq!(requests.len(), 3);
    assert!(requests[0].tools.iter().any(|t| t == "invoke_agent"));
    assert_eq!(
        (requests[1].provider.as_str(), requests[1].model.as_str()),
        ("providerB", "childModel")
    );
    assert!(!requests[1]
        .tools
        .iter()
        .any(|t| t == "invoke_agent" || t == "spawn_agents"));
    assert!(requests[2].messages.iter().any(|m| m.role == "tool"
        && m.tool_call_id.as_deref() == Some("verify-call")
        && m.content
            .as_ref()
            .is_some_and(|c| c.as_text().contains("PASS"))));
}

#[tokio::test]
async fn explicit_remote_policy_does_not_grant_invoke_agent() {
    let (_tmp, agent, requests, _, _) = fixture(false).await;
    // An adversarial provider emits a tool omitted from the explicit policy.
    let _outcome = tokio::time::timeout(
        Duration::from_secs(10),
        agent.run_with_policy("verify-runtime", vec!["read_skill_file".into()], None),
    )
    .await
    .unwrap()
    .unwrap();
    let requests = requests.lock().await;
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|r| r.model == "modelA"));
    assert!(requests.iter().all(|r| !r
        .tools
        .iter()
        .any(|t| t == "invoke_agent" || t == "spawn_agents")));
    assert!(requests.iter().flat_map(|r| &r.messages).any(|m| {
        m.role == "tool"
            && m.tool_call_id.as_deref() == Some("verify-call")
            && m.content.as_ref().is_some_and(|c| {
                c.as_text() == "Tool 'invoke_agent' is not available to this agent."
            })
    }));
}

#[tokio::test]
async fn explicit_remote_invoke_permission_does_not_install_dispatch_handler() {
    let (_tmp, agent, requests, _, _) = fixture(false).await;
    // Passing the allowlist gate must still not grant local subagent dispatch.
    tokio::time::timeout(
        Duration::from_secs(10),
        agent.run_with_policy("verify-runtime", vec!["invoke_agent".into()], None),
    )
    .await
    .unwrap()
    .unwrap();
    let requests = requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.model == "modelA"));
    assert!(requests[1].messages.iter().any(|m| m.role == "tool"
        && m.tool_call_id.as_deref() == Some("verify-call")
        && m.content
            .as_ref()
            .is_some_and(|c| c.as_text() == "Error: Unknown tool: invoke_agent")));
}

#[tokio::test]
async fn runtime_model_switch_e2e() {
    let (_tmp, agent, requests, _, _) = fixture(false).await;
    assert_eq!(turn(&agent, "1").await, "DONE");
    agent.set_model("providerB/modelB").await.unwrap();
    assert_eq!(turn(&agent, "2").await, "DONE");
    let requests = requests.lock().await;
    assert_eq!(
        requests
            .iter()
            .map(|r| (r.provider.as_str(), r.model.as_str()))
            .collect::<Vec<_>>(),
        [("providerA", "modelA"), ("providerB", "modelB")]
    );
}
#[tokio::test]
async fn runtime_inflight_turn_keeps_model_snapshot() {
    let (tmp, agent, requests, _, _) = fixture(false).await;
    let image = tmp.path().join("image.png");
    std::fs::write(&image, b"fake image bytes: processing only base64-encodes").unwrap();
    let mut message = incoming("1");
    message.attachments.push(haos_green::platform::Attachment {
        kind: haos_green::platform::AttachmentKind::Image,
        path: image,
        mime_type: "image/png".into(),
        file_name: Some("image.png".into()),
    });
    // Poll exactly once while SQLite is locked: the entry routing snapshot has
    // executed, but no conversation/attachment/request work can finish yet.
    let connection = agent.memory.connection();
    let guard = connection.lock().await;
    let first = agent.process_message(&message, None, None, ToolUiMode::from_memory(None));
    tokio::pin!(first);
    assert!(futures::poll!(first.as_mut()).is_pending());
    agent.set_model("providerB/modelB").await.unwrap();
    drop(guard);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), first)
            .await
            .unwrap()
            .unwrap(),
        "DONE"
    );
    assert_eq!(turn(&agent, "2").await, "DONE");
    let requests = requests.lock().await;
    assert_eq!(requests[0].model, "modelA");
    assert_eq!(requests[0].provider, "providerA");
    assert_eq!(requests[1].model, "modelB");
    assert!(requests[0].messages.iter().any(|m| matches!(&m.content, Some(haos_green::llm::MessageContent::Parts(parts)) if parts.iter().any(|p| matches!(p, haos_green::llm::ContentPart::ImageUrl { .. })))));
}
