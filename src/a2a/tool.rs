//! Outbound A2A tool handler.
//!
//! Provides the `call_a2a_agent` tool which allows the agentic loop to contact
//! configured remote A2A peers via discovery, authentication, and task polling.

use anyhow::{bail, Context};
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::warn;

use crate::a2a::client::A2aClient;
use crate::config::{A2aOutboundConfig, A2aOutboundPeerConfig};
use crate::llm::{FunctionDefinition, ToolDefinition};
use crate::tool_registry::{ToolContext, ToolHandler, ToolResult};

pub const CALL_A2A_AGENT_TOOL_NAME: &str = "call_a2a_agent";

/// ToolHandler implementing `call_a2a_agent`.
pub struct CallA2aAgent {
    outbound: A2aOutboundConfig,
}

impl CallA2aAgent {
    pub fn new(outbound: A2aOutboundConfig) -> Self {
        Self { outbound }
    }

    /// Redact any sensitive tokens from error messages or output strings.
    fn sanitize_text(&self, text: &str) -> String {
        let mut sanitized = text.to_string();
        for peer in self.outbound.peers.values() {
            let token = peer.token.trim();
            if !token.is_empty() {
                sanitized = sanitized.replace(token, "[REDACTED]");
            }
        }
        // Also run generic supervisor secret redaction for bearer/token patterns
        crate::supervisor::redact::redact(&sanitized)
    }

    fn configured_peer_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.outbound.peers.keys().cloned().collect();
        names.sort();
        names
    }

    async fn execute_call(
        &self,
        peer_name: &str,
        prompt: &str,
        peer_cfg: &A2aOutboundPeerConfig,
    ) -> anyhow::Result<String> {
        let card = A2aClient::discover(peer_name, peer_cfg)
            .await
            .with_context(|| format!("failed to discover agent card for peer '{peer_name}'"))?;

        let client = A2aClient::from_card(card, peer_cfg)
            .await
            .with_context(|| format!("failed to initialize A2A client for peer '{peer_name}'"))?;

        let output = client
            .send_and_wait(prompt, peer_cfg)
            .await
            .with_context(|| format!("failed to send and wait on peer '{peer_name}'"))?;

        Ok(output)
    }
}

#[async_trait]
impl ToolHandler for CallA2aAgent {
    fn define(&self) -> Vec<ToolDefinition> {
        if self.outbound.peers.is_empty() {
            return Vec::new();
        }

        let valid_peers = self.configured_peer_names().join(", ");
        let desc = format!(
            "Send a task or prompt to a configured outbound Agent2Agent (A2A) peer and wait for completion. Configured peers: [{valid_peers}]."
        );

        vec![ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: CALL_A2A_AGENT_TOOL_NAME.to_string(),
                description: desc,
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "peer": {
                            "type": "string",
                            "description": "The name of the configured outbound A2A peer to call."
                        },
                        "prompt": {
                            "type": "string",
                            "description": "The message or task instructions to send to the remote agent."
                        }
                    },
                    "required": ["peer", "prompt"]
                }),
            },
        }]
    }

    async fn execute(&self, name: &str, args: Value, _ctx: ToolContext) -> ToolResult {
        if name != CALL_A2A_AGENT_TOOL_NAME {
            bail!("Unknown tool: {name}");
        }

        let peer_param = args["peer"].as_str().map(str::trim).unwrap_or("");
        let prompt = match args["prompt"].as_str() {
            Some(p) if !p.trim().is_empty() => p,
            _ => bail!("Missing or empty 'prompt' argument"),
        };

        let peer_cfg = match self.outbound.peers.get(peer_param) {
            Some(cfg) => cfg,
            None => {
                let valid_names = self.configured_peer_names();
                let peer_list = if valid_names.is_empty() {
                    "none configured".to_string()
                } else {
                    valid_names.join(", ")
                };
                bail!(
                    "Unknown or unconfigured outbound A2A peer '{peer_param}'. Configured peers: [{peer_list}]"
                );
            }
        };

        match self.execute_call(peer_param, prompt, peer_cfg).await {
            Ok(res) => Ok(self.sanitize_text(&res)),
            Err(e) => {
                let sanitized_err = self.sanitize_text(&format!("{:#}", e));
                warn!(peer = %peer_param, error = %sanitized_err, "call_a2a_agent execution failed");
                bail!("call_a2a_agent failed: {sanitized_err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel_registry::CancelRegistry;
    use crate::platform::sender::{MessageFormat, PlatformMessageId, PlatformSender};
    use crate::tool_registry::ToolUiMode;
    use a2a::agent_card::{AgentCard, AgentInterface};
    use a2a::types::{Message, Part, Role, SendMessageResponse, TRANSPORT_PROTOCOL_JSONRPC};
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    struct DummySender;
    #[async_trait]
    impl PlatformSender for DummySender {
        async fn send_message(
            &self,
            _chat_id: &str,
            _text: &str,
            _format: MessageFormat,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("test:1".to_string())
        }
        async fn send_file(
            &self,
            _chat_id: &str,
            _path: &Path,
            _caption: Option<&str>,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("test:1".to_string())
        }
        async fn show_cancel_button(
            &self,
            _chat_id: &str,
            _text: &str,
            _cancel_id: &str,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("test:1".to_string())
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

    fn test_context() -> ToolContext {
        ToolContext {
            sandbox_dir: PathBuf::from("/tmp"),
            home_dir: None,
            sender: Arc::new(DummySender),
            cancel_registry: Arc::new(CancelRegistry::new()),
            user_id: "test-user".into(),
            chat_id: "test-chat".into(),
            tool_ui_mode: ToolUiMode::Minimal,
        }
    }

    #[test]
    fn define_empty_when_no_peers() {
        let tool = CallA2aAgent::new(A2aOutboundConfig::default());
        let defs = tool.define();
        assert!(defs.is_empty());
    }

    #[test]
    fn define_contains_peers_and_parameters() {
        let mut outbound = A2aOutboundConfig::default();
        outbound.peers.insert(
            "remote-agent".into(),
            A2aOutboundPeerConfig {
                url: "http://localhost:9999".into(),
                token: "super-secret-token-12345".into(),
                timeout_secs: 10,
                poll_interval_ms: 100,
                poll_timeout_secs: 10,
            },
        );
        let tool = CallA2aAgent::new(outbound);
        let defs = tool.define();
        assert_eq!(defs.len(), 1);
        let def = &defs[0];
        assert_eq!(def.function.name, CALL_A2A_AGENT_TOOL_NAME);
        assert!(def.function.description.contains("remote-agent"));
        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "peer"));
        assert!(required.iter().any(|v| v == "prompt"));
        assert!(!format!("{def:?}").contains("super-secret-token-12345"));
    }

    #[tokio::test]
    async fn rejects_unknown_peer_fails_closed_without_token_leak() {
        let mut outbound = A2aOutboundConfig::default();
        outbound.peers.insert(
            "known-peer".into(),
            A2aOutboundPeerConfig {
                url: "http://localhost:9999".into(),
                token: "secret-token-xyz".into(),
                timeout_secs: 10,
                poll_interval_ms: 100,
                poll_timeout_secs: 10,
            },
        );
        let tool = CallA2aAgent::new(outbound);
        let err = tool
            .execute(
                CALL_A2A_AGENT_TOOL_NAME,
                json!({ "peer": "evil-unknown", "prompt": "hello" }),
                test_context(),
            )
            .await
            .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains("Unknown or unconfigured outbound A2A peer 'evil-unknown'"));
        assert!(msg.contains("known-peer"));
        assert!(!msg.contains("secret-token-xyz"));
    }

    #[tokio::test]
    async fn execute_successful_call_against_mock_server() {
        #[derive(Clone)]
        struct MockServerState {
            base_url: String,
            expected_token: String,
        }

        async fn handle_card(
            State(st): State<MockServerState>,
            headers: HeaderMap,
        ) -> Result<Json<AgentCard>, StatusCode> {
            let auth = headers.get("authorization").and_then(|h| h.to_str().ok());
            if auth != Some(&format!("Bearer {}", st.expected_token)) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(Json(AgentCard {
                name: "mock-remote".into(),
                description: "mock".into(),
                version: "1.0.0".into(),
                supported_interfaces: vec![AgentInterface {
                    url: format!("{}/jsonrpc", st.base_url),
                    protocol_binding: TRANSPORT_PROTOCOL_JSONRPC.to_string(),
                    protocol_version: "1.0".to_string(),
                    tenant: None,
                }],
                capabilities: Default::default(),
                default_input_modes: vec!["text/plain".into()],
                default_output_modes: vec!["text/plain".into()],
                skills: vec![],
                provider: None,
                documentation_url: None,
                icon_url: None,
                security_schemes: None,
                security_requirements: None,
                signatures: None,
            }))
        }

        async fn handle_jsonrpc(
            State(st): State<MockServerState>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Result<Json<Value>, StatusCode> {
            let auth = headers.get("authorization").and_then(|h| h.to_str().ok());
            if auth != Some(&format!("Bearer {}", st.expected_token)) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let id = body.get("id").cloned().unwrap_or(json!(1));
            let response = SendMessageResponse::Message(Message {
                message_id: "reply-msg-1".into(),
                context_id: None,
                task_id: None,
                role: Role::Agent,
                parts: vec![Part::text("Hello from remote A2A agent!")],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            });
            Ok(Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": response,
            })))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let expected_token = "valid-remote-token-secret-777".to_string();

        let state = MockServerState {
            base_url: base_url.clone(),
            expected_token: expected_token.clone(),
        };

        let app = Router::new()
            .route("/.well-known/agent-card.json", get(handle_card))
            .route("/jsonrpc", post(handle_jsonrpc))
            .with_state(state);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut outbound = A2aOutboundConfig::default();
        outbound.peers.insert(
            "partner".into(),
            A2aOutboundPeerConfig {
                url: base_url,
                token: expected_token.clone(),
                timeout_secs: 5,
                poll_interval_ms: 50,
                poll_timeout_secs: 5,
            },
        );

        let tool = CallA2aAgent::new(outbound);
        let result = tool
            .execute(
                CALL_A2A_AGENT_TOOL_NAME,
                json!({ "peer": "partner", "prompt": "ping" }),
                test_context(),
            )
            .await
            .unwrap();

        assert_eq!(result, "Hello from remote A2A agent!");
        assert!(!result.contains(&expected_token));
    }

    #[tokio::test]
    async fn discovery_failure_fails_closed_and_redacts_tokens() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let secret_token = "my-super-secret-auth-token-999".to_string();

        async fn handle_card_401() -> StatusCode {
            StatusCode::UNAUTHORIZED
        }

        let app = Router::new().route("/.well-known/agent-card.json", get(handle_card_401));

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut outbound = A2aOutboundConfig::default();
        outbound.peers.insert(
            "broken-peer".into(),
            A2aOutboundPeerConfig {
                url: base_url,
                token: secret_token.clone(),
                timeout_secs: 2,
                poll_interval_ms: 50,
                poll_timeout_secs: 2,
            },
        );

        let tool = CallA2aAgent::new(outbound);
        let err = tool
            .execute(
                CALL_A2A_AGENT_TOOL_NAME,
                json!({ "peer": "broken-peer", "prompt": "hi" }),
                test_context(),
            )
            .await
            .unwrap_err();

        let err_msg = format!("{err:#}");
        assert!(err_msg.contains("call_a2a_agent failed"));
        assert!(!err_msg.contains(&secret_token));
    }

    #[tokio::test]
    async fn timeout_handling_fails_closed_and_redacts() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let secret_token = "secret-timeout-token-xyz".to_string();

        async fn handle_slow_card() -> StatusCode {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            StatusCode::OK
        }

        let app = Router::new().route("/.well-known/agent-card.json", get(handle_slow_card));

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut outbound = A2aOutboundConfig::default();
        outbound.peers.insert(
            "slow-peer".into(),
            A2aOutboundPeerConfig {
                url: base_url,
                token: secret_token.clone(),
                timeout_secs: 1, // 1 second timeout
                poll_interval_ms: 10,
                poll_timeout_secs: 1,
            },
        );

        let tool = CallA2aAgent::new(outbound);
        let err = tool
            .execute(
                CALL_A2A_AGENT_TOOL_NAME,
                json!({ "peer": "slow-peer", "prompt": "hi" }),
                test_context(),
            )
            .await
            .unwrap_err();

        let err_msg = format!("{err:#}");
        assert!(err_msg.contains("call_a2a_agent failed"));
        assert!(!err_msg.contains(&secret_token));
    }

    #[test]
    fn redaction_removes_tokens_and_bearer_patterns() {
        let mut outbound = A2aOutboundConfig::default();
        outbound.peers.insert(
            "peer1".into(),
            A2aOutboundPeerConfig {
                url: "http://localhost:1234".into(),
                token: "token123456789".into(),
                timeout_secs: 5,
                poll_interval_ms: 50,
                poll_timeout_secs: 5,
            },
        );
        let tool = CallA2aAgent::new(outbound);
        let text_with_secret =
            "Error contacting peer: token123456789 with Bearer xyz987654321 and token: abc";
        let cleaned = tool.sanitize_text(text_with_secret);
        assert!(!cleaned.contains("token123456789"));
        assert!(!cleaned.contains("xyz987654321"));
        assert!(cleaned.contains("[REDACTED]"));
        assert!(cleaned.contains("Bearer ***"));
    }
}
