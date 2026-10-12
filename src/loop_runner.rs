use anyhow::Result;
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::conversation::ConversationManager;
use crate::langsmith::LangSmithClient;
use crate::llm::{ChatMessage, LlmClient, MessageContent};
use crate::mcp::McpManager;
use crate::platform::sender::PlatformSender;
use crate::platform::tool_notifier::ToolEvent;
use crate::tool_registry::{ToolContext, ToolRegistry};

pub type ToolHandlerFn = Box<
    dyn Fn(
            &str,
            &Value,
            &str,
            &str,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'static>>
        + Send
        + Sync,
>;

pub type LoopHandlerFn<'a> = Box<
    dyn Fn(
            &str,
            &str,
            &crate::loop_detector::LoopInfo,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>
        + Send
        + Sync
        + 'a,
>;

pub struct LoopConfig {
    pub max_iterations: u32,
    pub empty_response_retry_limit: u32,
    pub context_window: usize,
    pub loop_detection_enabled: bool,
    pub loop_detection_threshold: usize,
    pub interactive_loop_callback: bool,
    pub allowed_tools: Option<Vec<String>>,
    pub langsmith_project: Option<String>,
    pub model: Option<String>,
    pub tool_event_tx: Option<mpsc::Sender<ToolEvent>>,
    pub stream_token_tx: Option<mpsc::Sender<String>>,
    pub recovery_nudge: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum LoopOutcome {
    FinalResponse(String),
    Cancelled,
    MaxIterations,
    LoopDetected { tool_name: String, count: usize },
}

#[allow(dead_code)]
#[allow(clippy::type_complexity)]
pub struct AgenticLoop<'a> {
    llm: &'a LlmClient,
    tools: &'a ToolRegistry,
    mcp: &'a McpManager,
    config: &'a LoopConfig,
    cancel: Option<CancellationToken>,
    chain_run_id: Option<String>,
    langsmith: Option<&'a LangSmithClient>,
    platform_sender: &'a dyn PlatformSender,
    make_tool_ctx: Box<dyn Fn(&str, &str) -> ToolContext + Send + Sync + 'a>,
    special_tool_handler: Option<ToolHandlerFn>,
    loop_handler: Option<LoopHandlerFn<'a>>,
}

#[allow(clippy::type_complexity)]
impl<'a> AgenticLoop<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        llm: &'a LlmClient,
        tools: &'a ToolRegistry,
        mcp: &'a McpManager,
        config: &'a LoopConfig,
        cancel: Option<CancellationToken>,
        chain_run_id: Option<String>,
        langsmith: Option<&'a LangSmithClient>,
        platform_sender: &'a dyn PlatformSender,
        make_tool_ctx: Box<dyn Fn(&str, &str) -> ToolContext + Send + Sync + 'a>,
        special_tool_handler: Option<ToolHandlerFn>,
    ) -> Self {
        Self {
            llm,
            tools,
            mcp,
            config,
            cancel,
            chain_run_id,
            langsmith,
            platform_sender,
            make_tool_ctx,
            special_tool_handler,
            loop_handler: None,
        }
    }

    pub fn with_loop_handler(mut self, handler: LoopHandlerFn<'a>) -> Self {
        self.loop_handler = Some(handler);
        self
    }

    pub async fn run(
        &self,
        messages: &mut MessageContainer,
        user_id: &str,
        chat_id: &str,
    ) -> Result<LoopOutcome> {
        let context_window = self.config.context_window;
        let mut empty_count = 0u32;
        let mut loop_detector = crate::loop_detector::LoopDetector::new(
            self.config.loop_detection_threshold.max(1),
            self.config.loop_detection_enabled,
        );

        for iteration in 0..self.config.max_iterations {
            if let Some(ref cancel) = self.cancel {
                if cancel.is_cancelled() {
                    return Ok(LoopOutcome::Cancelled);
                }
            }

            let prepared = messages.prepare(context_window);

            let tool_defs = {
                let mut all = self.tools.all_definitions();
                all.extend(self.mcp.tool_definitions());
                if self.special_tool_handler.is_some() {
                    all.extend(crate::agent::special_agent_tool_definitions());
                }
                if let Some(ref whitelist) = self.config.allowed_tools {
                    all.into_iter()
                        .filter(|d| whitelist.contains(&d.function.name))
                        .collect()
                } else {
                    all
                }
            };

            let chat_fut = async {
                if let Some(ref model) = self.config.model {
                    let completion = self
                        .llm
                        .chat_completion_with_fallback(&prepared.messages, &tool_defs, model)
                        .await?;
                    let text = completion
                        .message
                        .content
                        .as_ref()
                        .map(|c| c.as_text())
                        .unwrap_or_default();
                    let tool_calls = completion.message.tool_calls.clone().unwrap_or_default();
                    Ok::<_, anyhow::Error>((text, tool_calls))
                } else {
                    let default_model = self.llm.registry().default_qualified_model();
                    let completion = self
                        .llm
                        .chat_completion_with_fallback(
                            &prepared.messages,
                            &tool_defs,
                            &default_model,
                        )
                        .await?;
                    let text = completion
                        .message
                        .content
                        .as_ref()
                        .map(|c| c.as_text())
                        .unwrap_or_default();
                    let tool_calls = completion.message.tool_calls.clone().unwrap_or_default();
                    Ok::<_, anyhow::Error>((text, tool_calls))
                }
            };

            let (text, tool_calls) = if let Some(ref cancel) = self.cancel {
                tokio::select! {
                    res = chat_fut => res?,
                    _ = cancel.cancelled() => {
                        return Ok(LoopOutcome::Cancelled);
                    }
                }
            } else {
                chat_fut.await?
            };

            if text.is_empty() && tool_calls.is_empty() {
                empty_count += 1;
                if let Some(ref nudge) = self.config.recovery_nudge {
                    let nudge_msg = ChatMessage {
                        role: "user".to_string(),
                        content: Some(MessageContent::from_text(nudge.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                    };
                    match messages {
                        MessageContainer::Conversation(cm) => cm.add_user_turn(nudge_msg),
                        MessageContainer::Plain(msgs) => msgs.push(nudge_msg),
                    }
                }
                if empty_count >= self.config.empty_response_retry_limit {
                    return Ok(LoopOutcome::FinalResponse(
                        "I'm having trouble processing that. Please try again.".to_string(),
                    ));
                }
                continue;
            }

            if !tool_calls.is_empty() {
                loop_detector.record(&tool_calls, iteration as usize);
                if let Some(info) = loop_detector.detect_loop() {
                    tracing::warn!(
                        tool = %info.tool_name,
                        count = info.call_count,
                        "Loop detected in tool calls"
                    );
                    if self.config.interactive_loop_callback {
                        if let Some(handler) = &self.loop_handler {
                            // The callback owns timeout/cancel cleanup; do not abandon it here.
                            if handler(user_id, chat_id, &info).await {
                                loop_detector.clear();
                                continue;
                            }
                            if self.cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                                return Ok(LoopOutcome::Cancelled);
                            }
                        }
                    }
                    return Ok(LoopOutcome::LoopDetected {
                        tool_name: info.tool_name,
                        count: info.call_count,
                    });
                }

                messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: Some(MessageContent::Text(text.clone())),
                    tool_calls: Some(tool_calls.clone()),
                    tool_call_id: None,
                });

                for tc in &tool_calls {
                    if let Some(ref cancel) = self.cancel {
                        if cancel.is_cancelled() {
                            return Ok(LoopOutcome::Cancelled);
                        }
                    }

                    if let Some(ref whitelist) = self.config.allowed_tools {
                        if !whitelist.contains(&tc.function.name) {
                            messages.push_tool_result(
                                &tc.id,
                                format!(
                                    "Tool '{}' is not available to this agent.",
                                    tc.function.name
                                ),
                            );
                            continue;
                        }
                    }

                    let args: Value = match serde_json::from_str(&tc.function.arguments) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                "Invalid JSON arguments for tool {}: {}",
                                tc.function.name,
                                e
                            );
                            messages.push_tool_result(
                                &tc.id,
                                "Error: invalid JSON arguments; regenerate the tool call."
                                    .to_string(),
                            );
                            continue;
                        }
                    };

                    // Check special tool handler first (for invoke_agent/spawn_agents)
                    if let Some(ref handler) = self.special_tool_handler {
                        let fut = (handler)(&tc.function.name, &args, user_id, chat_id);
                        let special_res = if let Some(ref cancel) = self.cancel {
                            tokio::select! {
                                res = fut => res,
                                _ = cancel.cancelled() => {
                                    return Ok(LoopOutcome::Cancelled);
                                }
                            }
                        } else {
                            fut.await
                        };
                        if let Some(result) = special_res {
                            messages.push_tool_result(&tc.id, result);
                            continue;
                        }
                    }

                    let exec_fut = async {
                        if tc.function.name.starts_with("mcp_") {
                            self.mcp
                                .call_tool(&tc.function.name, &args)
                                .await
                                .unwrap_or_else(|e| format!("Error: {e}"))
                        } else {
                            let ctx = (self.make_tool_ctx)(user_id, chat_id);
                            self.tools
                                .execute(&tc.function.name, args, ctx)
                                .await
                                .unwrap_or_else(|e| format!("Error: {e}"))
                        }
                    };

                    let result = if let Some(ref cancel) = self.cancel {
                        tokio::select! {
                            res = exec_fut => res,
                            _ = cancel.cancelled() => {
                                return Ok(LoopOutcome::Cancelled);
                            }
                        }
                    } else {
                        exec_fut.await
                    };

                    messages.push_tool_result(&tc.id, result);
                }
                continue;
            }

            if !text.is_empty() {
                if let Some(ref cancel) = self.cancel {
                    if cancel.is_cancelled() {
                        return Ok(LoopOutcome::Cancelled);
                    }
                }
                if let Some(ref tx) = self.config.stream_token_tx {
                    let _ = LlmClient::stream_text(text.clone(), tx.clone()).await;
                }
                return Ok(LoopOutcome::FinalResponse(text));
            }

            empty_count += 1;
        }

        Ok(LoopOutcome::MaxIterations)
    }
}

pub enum MessageContainer {
    Conversation(Box<ConversationManager>),
    Plain(Vec<ChatMessage>),
}

impl MessageContainer {
    pub fn prepare(&self, context_window: usize) -> crate::agent_prompt::PreparedPrompt {
        match self {
            MessageContainer::Conversation(cm) => cm.prepare(context_window),
            MessageContainer::Plain(msgs) => {
                crate::agent_prompt::prepare_messages_for_llm(msgs, context_window)
            }
        }
    }

    pub fn push(&mut self, msg: ChatMessage) {
        match self {
            MessageContainer::Conversation(cm) => cm.add_assistant_turn(msg),
            MessageContainer::Plain(msgs) => msgs.push(msg),
        }
    }

    pub fn push_tool_result(&mut self, tool_call_id: &str, result: String) {
        let msg = ChatMessage {
            role: "tool".to_string(),
            content: Some(MessageContent::Text(result)),
            tool_calls: None,
            tool_call_id: Some(tool_call_id.to_string()),
        };
        match self {
            MessageContainer::Conversation(cm) => cm.add_tool_result(msg),
            MessageContainer::Plain(msgs) => msgs.push(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel_registry::CancelRegistry;
    use crate::config::ProviderType;
    use crate::llm::{
        ChatCompletion, ChatMessage, FunctionCall, FunctionDefinition, MessageContent, ToolCall,
        ToolDefinition,
    };
    use crate::platform::sender::{MessageFormat, PlatformMessageId, PlatformSender};
    use crate::provider::{Provider, ProviderConfig, ProviderRegistry};
    use crate::tool_registry::{ToolContext, ToolHandler, ToolRegistry, ToolResult, ToolUiMode};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Mutex, RwLock};

    struct DummySender;
    #[async_trait]
    impl PlatformSender for DummySender {
        async fn send_message(
            &self,
            _: &str,
            _: &str,
            _: MessageFormat,
        ) -> Result<PlatformMessageId> {
            Ok("m1".into())
        }
        async fn send_file(&self, _: &str, _: &Path, _: Option<&str>) -> Result<PlatformMessageId> {
            Ok("f1".into())
        }
        async fn show_cancel_button(&self, _: &str, _: &str, _: &str) -> Result<PlatformMessageId> {
            Ok("c1".into())
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

    fn test_provider_config() -> ProviderConfig {
        ProviderConfig {
            name: "mock".to_string(),
            provider_type: ProviderType::OpenAICompatible,
            base_url: "http://localhost:8080/v1".to_string(),
            api_key: None,
            default_model: "mock-model".to_string(),
            supports_vision: false,
            max_tokens: 1024,
            discover_models: false,
            context_window: 4096,
            context_window_cache: Arc::new(RwLock::new(HashMap::new())),
            parse_retry_limit: 0,
        }
    }

    struct MockSlowProvider {
        config: ProviderConfig,
        delay: Duration,
    }

    #[async_trait]
    impl Provider for MockSlowProvider {
        fn name(&self) -> &str {
            "mock"
        }
        fn default_model(&self) -> &str {
            "mock-model"
        }
        fn supports_vision(&self) -> bool {
            false
        }
        fn config(&self) -> &ProviderConfig {
            &self.config
        }
        async fn chat_completion(
            &self,
            _client: &reqwest::Client,
            _messages: &[ChatMessage],
            _tools: &[ToolDefinition],
            _model: &str,
            _max_tokens: u32,
        ) -> Result<ChatCompletion> {
            tokio::time::sleep(self.delay).await;
            Ok(ChatCompletion {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: Some(MessageContent::Text("done".into())),
                    tool_calls: None,
                    tool_call_id: None,
                },
                finish_reason: Some("stop".into()),
                model: "mock-model".into(),
            })
        }
        async fn list_models(&self, _client: &reqwest::Client) -> Result<Vec<String>> {
            Ok(vec!["mock-model".into()])
        }
    }

    struct MockToolCallingProvider {
        config: ProviderConfig,
    }

    #[async_trait]
    impl Provider for MockToolCallingProvider {
        fn name(&self) -> &str {
            "mock"
        }
        fn default_model(&self) -> &str {
            "mock-model"
        }
        fn supports_vision(&self) -> bool {
            false
        }
        fn config(&self) -> &ProviderConfig {
            &self.config
        }
        async fn chat_completion(
            &self,
            _client: &reqwest::Client,
            _messages: &[ChatMessage],
            _tools: &[ToolDefinition],
            _model: &str,
            _max_tokens: u32,
        ) -> Result<ChatCompletion> {
            Ok(ChatCompletion {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: None,
                    tool_calls: Some(vec![ToolCall {
                        id: "call-1".into(),
                        call_type: "function".into(),
                        function: FunctionCall {
                            name: "slow_tool".into(),
                            arguments: "{}".into(),
                        },
                    }]),
                    tool_call_id: None,
                },
                finish_reason: Some("tool_calls".into()),
                model: "mock-model".into(),
            })
        }
        async fn list_models(&self, _client: &reqwest::Client) -> Result<Vec<String>> {
            Ok(vec!["mock-model".into()])
        }
    }

    struct SlowToolHandler;
    #[async_trait]
    impl ToolHandler for SlowToolHandler {
        fn define(&self) -> Vec<ToolDefinition> {
            vec![ToolDefinition {
                tool_type: "function".into(),
                function: FunctionDefinition {
                    name: "slow_tool".into(),
                    description: "A slow test tool".into(),
                    parameters: serde_json::json!({
                        "type": "object",
                        "properties": {}
                    }),
                },
            }]
        }
        async fn execute(&self, _name: &str, _args: Value, _ctx: ToolContext) -> ToolResult {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok("slow done".into())
        }
    }

    struct TestToolHandler {
        name: String,
        called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ToolHandler for TestToolHandler {
        fn define(&self) -> Vec<ToolDefinition> {
            vec![ToolDefinition {
                tool_type: "function".into(),
                function: FunctionDefinition {
                    name: self.name.clone(),
                    description: "A test tool".into(),
                    parameters: serde_json::json!({
                        "type": "object",
                        "properties": {}
                    }),
                },
            }]
        }
        async fn execute(&self, _name: &str, _args: Value, _ctx: ToolContext) -> ToolResult {
            self.called.store(true, Ordering::SeqCst);
            Ok("ok".into())
        }
    }

    struct SequenceMockProvider {
        config: ProviderConfig,
        responses: Arc<Mutex<Vec<ChatCompletion>>>,
        captured_tools: Arc<Mutex<Vec<ToolDefinition>>>,
    }

    #[async_trait]
    impl Provider for SequenceMockProvider {
        fn name(&self) -> &str {
            "mock"
        }
        fn default_model(&self) -> &str {
            "mock-model"
        }
        fn supports_vision(&self) -> bool {
            false
        }
        fn config(&self) -> &ProviderConfig {
            &self.config
        }
        async fn chat_completion(
            &self,
            _client: &reqwest::Client,
            _messages: &[ChatMessage],
            tools: &[ToolDefinition],
            _model: &str,
            _max_tokens: u32,
        ) -> Result<ChatCompletion> {
            *self.captured_tools.lock().await = tools.to_vec();
            let mut list = self.responses.lock().await;
            if !list.is_empty() {
                Ok(list.remove(0))
            } else {
                Ok(ChatCompletion {
                    message: ChatMessage {
                        role: "assistant".into(),
                        content: Some(MessageContent::Text("done".into())),
                        tool_calls: None,
                        tool_call_id: None,
                    },
                    finish_reason: Some("stop".into()),
                    model: "mock-model".into(),
                })
            }
        }
        async fn list_models(&self, _client: &reqwest::Client) -> Result<Vec<String>> {
            Ok(vec!["mock-model".into()])
        }
    }

    fn test_loop_config() -> LoopConfig {
        LoopConfig {
            max_iterations: 5,
            empty_response_retry_limit: 1,
            context_window: 4096,
            loop_detection_enabled: false,
            loop_detection_threshold: 3,
            interactive_loop_callback: false,
            allowed_tools: None,
            langsmith_project: None,
            model: None,
            tool_event_tx: None,
            stream_token_tx: None,
            recovery_nudge: None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn test_tool_ctx_factory<'a>() -> Box<dyn Fn(&str, &str) -> ToolContext + Send + Sync + 'a> {
        let cancel_reg = Arc::new(CancelRegistry::new());
        let sender: Arc<dyn PlatformSender> = Arc::new(DummySender);
        Box::new(move |user_id: &str, chat_id: &str| ToolContext {
            sandbox_dir: PathBuf::from("/tmp"),
            home_dir: None,
            sender: sender.clone(),
            cancel_registry: cancel_reg.clone(),
            user_id: user_id.to_string(),
            chat_id: chat_id.to_string(),
            tool_ui_mode: ToolUiMode::Silent,
        })
    }

    #[tokio::test]
    async fn test_cancellation_before_run() {
        let provider = MockSlowProvider {
            config: test_provider_config(),
            delay: Duration::from_millis(10),
        };
        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let tools = ToolRegistry::new();
        let mcp = McpManager::new();
        let config = test_loop_config();
        let cancel = CancellationToken::new();
        cancel.cancel(); // cancel before running

        let sender = DummySender;
        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            Some(cancel),
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            None,
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("hello".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let outcome = loop_runner
            .run(&mut messages, "user-1", "chat-1")
            .await
            .expect("loop should run without error");

        assert_eq!(outcome, LoopOutcome::Cancelled);
    }

    #[tokio::test]
    async fn test_cancellation_during_llm_call() {
        let provider = MockSlowProvider {
            config: test_provider_config(),
            delay: Duration::from_millis(500),
        };
        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let tools = ToolRegistry::new();
        let mcp = McpManager::new();
        let config = test_loop_config();
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });

        let sender = DummySender;
        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            Some(cancel),
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            None,
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("hello".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let outcome = loop_runner
            .run(&mut messages, "user-1", "chat-1")
            .await
            .expect("loop should return cancelled");

        assert_eq!(outcome, LoopOutcome::Cancelled);
    }

    #[tokio::test]
    async fn test_cancellation_during_tool_execution() {
        let provider = MockToolCallingProvider {
            config: test_provider_config(),
        };
        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let mut tools = ToolRegistry::new();
        tools.register(Box::new(SlowToolHandler));
        let mcp = McpManager::new();
        let config = test_loop_config();
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });

        let sender = DummySender;
        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            Some(cancel),
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            None,
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("hello".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let outcome = loop_runner
            .run(&mut messages, "user-1", "chat-1")
            .await
            .expect("loop should return cancelled");

        assert_eq!(outcome, LoopOutcome::Cancelled);
    }

    #[tokio::test]
    async fn test_cancellation_during_special_tool_handler() {
        let provider = MockToolCallingProvider {
            config: test_provider_config(),
        };
        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let tools = ToolRegistry::new();
        let mcp = McpManager::new();
        let config = test_loop_config();
        let cancel = CancellationToken::new();

        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });

        let special_handler: ToolHandlerFn = Box::new(|_name, _args, _user_id, _chat_id| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                Some("special done".to_string())
            })
        });

        let sender = DummySender;
        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            Some(cancel),
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            Some(special_handler),
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("hello".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let outcome = loop_runner
            .run(&mut messages, "user-1", "chat-1")
            .await
            .expect("loop should return cancelled");

        assert_eq!(outcome, LoopOutcome::Cancelled);
    }

    #[tokio::test]
    async fn test_invalid_json_arguments_does_not_execute_tool() {
        let called = Arc::new(AtomicBool::new(false));
        let mut tools = ToolRegistry::new();
        tools.register(Box::new(TestToolHandler {
            name: "test_tool".into(),
            called: called.clone(),
        }));

        let responses = Arc::new(Mutex::new(vec![
            ChatCompletion {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: None,
                    tool_calls: Some(vec![ToolCall {
                        id: "call-bad-json".into(),
                        call_type: "function".into(),
                        function: FunctionCall {
                            name: "test_tool".into(),
                            arguments: "{invalid_json:".into(),
                        },
                    }]),
                    tool_call_id: None,
                },
                finish_reason: Some("tool_calls".into()),
                model: "mock-model".into(),
            },
            ChatCompletion {
                message: ChatMessage {
                    role: "assistant".into(),
                    content: Some(MessageContent::Text("recovered".into())),
                    tool_calls: None,
                    tool_call_id: None,
                },
                finish_reason: Some("stop".into()),
                model: "mock-model".into(),
            },
        ]));

        let provider = SequenceMockProvider {
            config: test_provider_config(),
            responses,
            captured_tools: Arc::new(Mutex::new(Vec::new())),
        };

        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let mcp = McpManager::new();
        let config = test_loop_config();
        let sender = DummySender;

        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            None,
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            None,
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("run bad tool".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let outcome = loop_runner
            .run(&mut messages, "user-1", "chat-1")
            .await
            .expect("loop should succeed");

        assert_eq!(outcome, LoopOutcome::FinalResponse("recovered".to_string()));
        assert!(
            !called.load(Ordering::SeqCst),
            "Tool must NOT be executed with invalid JSON arguments"
        );

        let has_err_msg = match &messages {
            MessageContainer::Plain(msgs) => msgs.iter().any(|m| {
                m.role == "tool"
                    && m.content
                        .as_ref()
                        .map(|c| c.as_text().contains("invalid JSON arguments"))
                        .unwrap_or(false)
            }),
            _ => false,
        };
        assert!(
            has_err_msg,
            "Should contain error tool result for invalid JSON arguments"
        );
    }

    #[tokio::test]
    async fn test_loop_detector_triggers_loop_detected_outcome() {
        let called = Arc::new(AtomicBool::new(false));
        let mut tools = ToolRegistry::new();
        tools.register(Box::new(TestToolHandler {
            name: "test_tool".into(),
            called: called.clone(),
        }));

        let make_tc = || ChatCompletion {
            message: ChatMessage {
                role: "assistant".into(),
                content: None,
                tool_calls: Some(vec![ToolCall {
                    id: "call-repeat".into(),
                    call_type: "function".into(),
                    function: FunctionCall {
                        name: "test_tool".into(),
                        arguments: "{\"key\": \"val\"}".into(),
                    },
                }]),
                tool_call_id: None,
            },
            finish_reason: Some("tool_calls".into()),
            model: "mock-model".into(),
        };

        let responses = Arc::new(Mutex::new(vec![make_tc(), make_tc(), make_tc()]));
        let provider = SequenceMockProvider {
            config: test_provider_config(),
            responses,
            captured_tools: Arc::new(Mutex::new(Vec::new())),
        };

        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let mcp = McpManager::new();
        let mut config = test_loop_config();
        config.loop_detection_enabled = true;
        config.loop_detection_threshold = 2;
        let sender = DummySender;

        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            None,
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            None,
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("loop".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let outcome = loop_runner
            .run(&mut messages, "user-1", "chat-1")
            .await
            .expect("loop should detect repetition");

        assert_eq!(
            outcome,
            LoopOutcome::LoopDetected {
                tool_name: "test_tool".to_string(),
                count: 2,
            }
        );
    }

    #[tokio::test]
    async fn loop_callback_can_continue_without_executing_repeated_batch() {
        let repeat = || ChatCompletion {
            message: ChatMessage {
                role: "assistant".into(),
                content: None,
                tool_calls: Some(vec![ToolCall {
                    id: "repeat".into(),
                    call_type: "function".into(),
                    function: FunctionCall {
                        name: "test_tool".into(),
                        arguments: "{}".into(),
                    },
                }]),
                tool_call_id: None,
            },
            finish_reason: Some("tool_calls".into()),
            model: "mock-model".into(),
        };
        let provider = SequenceMockProvider {
            config: test_provider_config(),
            responses: Arc::new(Mutex::new(vec![repeat(), repeat()])),
            captured_tools: Arc::new(Mutex::new(Vec::new())),
        };
        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".into(), Arc::new(provider));
        let llm = LlmClient::new(Arc::new(ProviderRegistry::new(providers, "mock".into())));
        let tools = ToolRegistry::new();
        let mcp = McpManager::new();
        let sender = DummySender;
        let mut config = test_loop_config();
        config.loop_detection_enabled = true;
        config.loop_detection_threshold = 2;
        config.interactive_loop_callback = true;
        let called = Arc::new(AtomicBool::new(false));
        let repeated_called = called.clone();
        let runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            None,
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            Some(Box::new(move |_, _, _, _| {
                repeated_called.store(true, Ordering::SeqCst);
                Box::pin(async { Some("executed".into()) })
            })),
        )
        .with_loop_handler(Box::new(|_, _, _| Box::pin(async { true })));
        let mut messages = MessageContainer::Plain(Vec::new());
        assert!(matches!(
            runner.run(&mut messages, "u", "c").await.unwrap(),
            LoopOutcome::FinalResponse(_)
        ));
        assert!(called.load(Ordering::SeqCst));
        if let MessageContainer::Plain(messages) = messages {
            assert_eq!(
                messages.iter().filter(|m| m.role == "tool").count(),
                1,
                "continue must not execute the detected duplicate batch"
            );
        }
    }

    #[tokio::test]
    async fn test_special_agent_tool_definitions_offered_and_whitelisted() {
        let tools = ToolRegistry::new();
        let captured_tools = Arc::new(Mutex::new(Vec::new()));
        let responses = Arc::new(Mutex::new(vec![]));

        let provider = SequenceMockProvider {
            config: test_provider_config(),
            responses,
            captured_tools: captured_tools.clone(),
        };

        let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
        providers.insert("mock".to_string(), Arc::new(provider));
        let registry = Arc::new(ProviderRegistry::new(providers, "mock".to_string()));
        let llm = LlmClient::new(registry);
        let mcp = McpManager::new();
        let config = test_loop_config();
        let sender = DummySender;

        let special_handler: ToolHandlerFn = Box::new(|_name, _args, _user_id, _chat_id| {
            Box::pin(async { Some("dummy".to_string()) })
        });

        // 1. With special_tool_handler and no whitelist: invoke_agent and spawn_agents offered
        let loop_runner = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config,
            None,
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            Some(special_handler),
        );

        let mut messages = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("hello".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let _ = loop_runner.run(&mut messages, "user-1", "chat-1").await;
        let offered = captured_tools.lock().await.clone();
        assert!(offered.iter().any(|t| t.function.name == "invoke_agent"));
        assert!(offered.iter().any(|t| t.function.name == "spawn_agents"));

        // 2. With whitelist that excludes special tools: they are filtered out
        let mut config2 = test_loop_config();
        config2.allowed_tools = Some(vec!["other_tool".to_string()]);
        let special_handler2: ToolHandlerFn = Box::new(|_name, _args, _user_id, _chat_id| {
            Box::pin(async { Some("dummy".to_string()) })
        });
        let loop_runner2 = AgenticLoop::new(
            &llm,
            &tools,
            &mcp,
            &config2,
            None,
            None,
            None,
            &sender,
            test_tool_ctx_factory(),
            Some(special_handler2),
        );

        let mut messages2 = MessageContainer::Plain(vec![ChatMessage {
            role: "user".to_string(),
            content: Some(MessageContent::Text("hello".to_string())),
            tool_calls: None,
            tool_call_id: None,
        }]);

        let _ = loop_runner2.run(&mut messages2, "user-1", "chat-1").await;
        let offered2 = captured_tools.lock().await.clone();
        assert!(!offered2.iter().any(|t| t.function.name == "invoke_agent"));
        assert!(!offered2.iter().any(|t| t.function.name == "spawn_agents"));
    }
}
