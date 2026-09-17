use std::sync::Arc;
use std::time::Duration;

use a2a::agent_card::AgentCard;
use a2a::types::{
    GetTaskRequest, Message, Part, Role, SendMessageRequest, SendMessageResponse, Task, TaskState,
    TRANSPORT_PROTOCOL_JSONRPC,
};
use a2a_client::auth::AuthInterceptor;
use a2a_client::jsonrpc::JsonRpcTransportFactory;
use a2a_client::{A2AClient, A2AClientFactory, Transport};
use anyhow::{Context, Result};
use reqwest_client::Client as ReqwestClient;

use crate::config::A2aOutboundPeerConfig;

pub struct A2aClient {
    pub card: AgentCard,
    pub sdk: A2AClient<Box<dyn Transport>>,
    pub timeout_secs: u64,
}

fn join_card_url(base_url: &str) -> Result<reqwest_client::Url> {
    let mut trimmed = base_url.trim();
    while trimmed.ends_with('/') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    let combined = format!("{trimmed}/.well-known/agent-card.json");
    combined
        .parse::<reqwest_client::Url>()
        .context("failed to parse discovery agent card URL")
}

impl A2aClient {
    pub async fn discover(name: &str, config: &A2aOutboundPeerConfig) -> Result<AgentCard> {
        config.validate(name)?;
        let http = ReqwestClient::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;
        let endpoint = join_card_url(&config.url)?;
        let response = http
            .get(endpoint)
            .bearer_auth(&config.token)
            .send()
            .await
            .context("agent card request failed")?;
        if !response.status().is_success() {
            anyhow::bail!("agent card request returned HTTP {}", response.status());
        }
        let card = response
            .json::<AgentCard>()
            .await
            .context("invalid agent card response")?;
        if !card.supported_interfaces.iter().any(|i| {
            i.protocol_binding == TRANSPORT_PROTOCOL_JSONRPC
                && i.protocol_version == "1.0"
                && reqwest_client::Url::parse(&i.url).is_ok_and(|url| {
                    matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                })
        }) {
            anyhow::bail!("agent card has no compatible JSON-RPC 1.0 interface with a valid URL");
        }
        Ok(card)
    }

    pub async fn from_card(card: AgentCard, config: &A2aOutboundPeerConfig) -> Result<Self> {
        config.validate("peer")?;
        let http = ReqwestClient::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .context("failed to construct reqwest client")?;
        let transport_factory = Arc::new(JsonRpcTransportFactory::new(Some(http)));
        let factory = A2AClientFactory::builder()
            .register(transport_factory)
            .with_interceptor(Arc::new(AuthInterceptor::bearer(&config.token)))
            .build();
        let sdk = factory
            .create_from_card(&card)
            .await
            .context("failed to create A2A client")?;
        Ok(Self {
            card,
            sdk,
            timeout_secs: config.timeout_secs,
        })
    }

    pub async fn send_text(&self, prompt: &str) -> Result<SendMessageResponse> {
        let request = SendMessageRequest {
            message: Message {
                message_id: uuid::Uuid::new_v4().to_string(),
                context_id: None,
                task_id: None,
                role: Role::User,
                parts: vec![Part::text(prompt)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            },
            configuration: None,
            metadata: None,
            tenant: None,
        };
        self.send_message(&request).await
    }

    pub async fn send_message(&self, req: &SendMessageRequest) -> Result<SendMessageResponse> {
        let fut = self.sdk.send_message(req);
        let resp = if self.timeout_secs > 0 {
            tokio::time::timeout(Duration::from_secs(self.timeout_secs), fut)
                .await
                .context("send_message timed out")?
        } else {
            fut.await
        }
        .context("failed to send A2A message")?;
        Ok(resp)
    }

    pub async fn get_task(&self, task_id: &str) -> Result<Task> {
        let request = GetTaskRequest {
            id: task_id.to_string(),
            history_length: None,
            tenant: None,
        };
        let fut = self.sdk.get_task(&request);
        let task = if self.timeout_secs > 0 {
            tokio::time::timeout(Duration::from_secs(self.timeout_secs), fut)
                .await
                .context("get_task timed out")?
        } else {
            fut.await
        }
        .context("failed to get A2A task")?;
        Ok(task)
    }

    pub async fn poll_task(
        &self,
        task_id: &str,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Task> {
        let start = tokio::time::Instant::now();
        loop {
            let task = self
                .get_task(task_id)
                .await
                .with_context(|| format!("failed to poll task '{task_id}'"))?;

            if task.status.state.is_terminal() {
                return match task.status.state {
                    TaskState::Completed => Ok(task),
                    TaskState::Failed => {
                        let err_msg = task
                            .status
                            .message
                            .as_ref()
                            .and_then(|m| m.text())
                            .unwrap_or("unknown error");
                        anyhow::bail!("task '{task_id}' failed: {err_msg}");
                    }
                    TaskState::Canceled => {
                        let err_msg = task
                            .status
                            .message
                            .as_ref()
                            .and_then(|m| m.text())
                            .unwrap_or("canceled");
                        anyhow::bail!("task '{task_id}' was canceled: {err_msg}");
                    }
                    other => {
                        let err_msg = task
                            .status
                            .message
                            .as_ref()
                            .and_then(|m| m.text())
                            .unwrap_or("terminal error");
                        anyhow::bail!("task '{task_id}' ended in state {other:?}: {err_msg}");
                    }
                };
            }

            if start.elapsed() >= timeout {
                anyhow::bail!(
                    "timed out polling task '{task_id}' after {:?}",
                    start.elapsed()
                );
            }

            let sleep_duration = interval.min(timeout.saturating_sub(start.elapsed()));
            tokio::time::sleep(sleep_duration).await;

            if start.elapsed() >= timeout {
                anyhow::bail!(
                    "timed out polling task '{task_id}' after {:?}",
                    start.elapsed()
                );
            }
        }
    }

    pub async fn send_and_wait(
        &self,
        prompt: &str,
        config: &A2aOutboundPeerConfig,
    ) -> Result<String> {
        let resp = self.send_text(prompt).await?;
        match resp {
            SendMessageResponse::Message(msg) => {
                let text = msg
                    .text()
                    .context("message response contained no text")?
                    .to_string();
                Ok(text)
            }
            SendMessageResponse::Task(task) => {
                let final_task = if task.status.state.is_terminal() {
                    match task.status.state {
                        TaskState::Completed => task,
                        TaskState::Failed => {
                            let err_msg = task
                                .status
                                .message
                                .as_ref()
                                .and_then(|m| m.text())
                                .unwrap_or("unknown error");
                            anyhow::bail!("task '{}' failed: {err_msg}", task.id);
                        }
                        TaskState::Canceled => {
                            let err_msg = task
                                .status
                                .message
                                .as_ref()
                                .and_then(|m| m.text())
                                .unwrap_or("canceled");
                            anyhow::bail!("task '{}' was canceled: {err_msg}", task.id);
                        }
                        other => {
                            let err_msg = task
                                .status
                                .message
                                .as_ref()
                                .and_then(|m| m.text())
                                .unwrap_or("terminal error");
                            anyhow::bail!("task '{}' ended in state {other:?}: {err_msg}", task.id);
                        }
                    }
                } else {
                    let interval = Duration::from_millis(config.poll_interval_ms.max(1));
                    let timeout = Duration::from_secs(config.poll_timeout_secs.max(1));
                    self.poll_task(&task.id, interval, timeout).await?
                };

                // Extract final text from task status message or history
                if let Some(msg) = &final_task.status.message {
                    if let Some(txt) = msg.text() {
                        return Ok(txt.to_string());
                    }
                }

                if let Some(history) = &final_task.history {
                    for msg in history.iter().rev() {
                        if msg.role == Role::Agent {
                            if let Some(txt) = msg.text() {
                                return Ok(txt.to_string());
                            }
                        }
                    }
                }

                anyhow::bail!("completed task '{}' had no text message", final_task.id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2a::agent_card::AgentInterface;
    use axum::routing::post;
    use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    #[test]
    fn rejects_invalid_outbound_peer_config() {
        let mut cfg = A2aOutboundPeerConfig::default();
        assert!(cfg.validate("peer").is_err());
        cfg.url = "ftp://example.test".into();
        cfg.token = "x".into();
        assert!(cfg.validate("peer").is_err());
        cfg.url = "https://example.test".into();
        cfg.timeout_secs = 0;
        assert!(cfg.validate("peer").is_err());
    }

    #[test]
    fn debug_redacts_outbound_token() {
        let cfg = A2aOutboundPeerConfig {
            token: "super-secret".into(),
            ..Default::default()
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn base_url_path_preservation() {
        assert_eq!(
            join_card_url("http://host/agent").unwrap().as_str(),
            "http://host/agent/.well-known/agent-card.json"
        );
        assert_eq!(
            join_card_url("http://host/agent/").unwrap().as_str(),
            "http://host/agent/.well-known/agent-card.json"
        );
        assert_eq!(
            join_card_url("http://host///agent///").unwrap().as_str(),
            "http://host///agent/.well-known/agent-card.json"
        );
        assert_eq!(
            join_card_url("https://example.com:8443/v1/bot")
                .unwrap()
                .as_str(),
            "https://example.com:8443/v1/bot/.well-known/agent-card.json"
        );
    }

    #[tokio::test]
    async fn discovery_times_out() {
        let app = Router::new().route(
            "/.well-known/agent-card.json",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                axum::Json(serde_json::json!({}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let cfg = A2aOutboundPeerConfig {
            url,
            token: "secret".into(),
            timeout_secs: 1,
            ..Default::default()
        };
        assert!(A2aClient::discover("peer", &cfg).await.is_err());
    }

    #[tokio::test]
    async fn discovery_sends_bearer_token() {
        let seen = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(
                "/.well-known/agent-card.json",
                get(
                    |State(seen): State<Arc<Mutex<Option<String>>>>, headers: HeaderMap| async move {
                        *seen.lock().unwrap() = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        axum::Json(serde_json::json!({
                            "name":"peer",
                            "description":"d",
                            "version":"1",
                            "supportedInterfaces":[{
                                "url":"http://127.0.0.1/jsonrpc",
                                "protocolBinding":"JSONRPC",
                                "protocolVersion":"1.0"
                            }],
                            "capabilities":{},
                            "defaultInputModes":["text/plain"],
                            "defaultOutputModes":["text/plain"],
                            "skills":[]
                        }))
                    },
                ),
            )
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let cfg = A2aOutboundPeerConfig {
            url,
            token: "secret".into(),
            ..Default::default()
        };
        let card = A2aClient::discover("peer", &cfg).await.unwrap();
        assert_eq!(card.name, "peer");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("Bearer secret"));
    }

    #[tokio::test]
    async fn discovery_rejects_malformed_card_json() {
        let app = Router::new().route(
            "/.well-known/agent-card.json",
            get(|| async { "not-valid-json" }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let cfg = A2aOutboundPeerConfig {
            url,
            token: "secret".into(),
            ..Default::default()
        };
        let err = A2aClient::discover("peer", &cfg).await.unwrap_err();
        assert!(err.to_string().contains("invalid agent card response"));
    }

    #[tokio::test]
    async fn discovery_rejects_incompatible_binding_or_version() {
        // Test 1: Incompatible binding (GRPC instead of JSONRPC)
        let app = Router::new().route(
            "/.well-known/agent-card.json",
            get(|| async {
                axum::Json(serde_json::json!({
                    "name":"peer",
                    "description":"d",
                    "version":"1",
                    "supportedInterfaces":[{
                        "url":"http://127.0.0.1/grpc",
                        "protocolBinding":"GRPC",
                        "protocolVersion":"1.0"
                    }],
                    "capabilities":{},
                    "defaultInputModes":["text/plain"],
                    "defaultOutputModes":["text/plain"],
                    "skills":[]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let cfg = A2aOutboundPeerConfig {
            url,
            token: "secret".into(),
            ..Default::default()
        };
        let err = A2aClient::discover("peer", &cfg).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("agent card has no compatible JSON-RPC 1.0 interface"));

        // Test 2: Incompatible version ("2.0")
        let app2 = Router::new().route(
            "/.well-known/agent-card.json",
            get(|| async {
                axum::Json(serde_json::json!({
                    "name":"peer",
                    "description":"d",
                    "version":"1",
                    "supportedInterfaces":[{
                        "url":"http://127.0.0.1/jsonrpc",
                        "protocolBinding":"JSONRPC",
                        "protocolVersion":"2.0"
                    }],
                    "capabilities":{},
                    "defaultInputModes":["text/plain"],
                    "defaultOutputModes":["text/plain"],
                    "skills":[]
                }))
            }),
        );
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url2 = format!("http://{}", listener2.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener2, app2).await;
        });
        let cfg2 = A2aOutboundPeerConfig {
            url: url2,
            token: "secret".into(),
            ..Default::default()
        };
        let err2 = A2aClient::discover("peer", &cfg2).await.unwrap_err();
        assert!(err2
            .to_string()
            .contains("agent card has no compatible JSON-RPC 1.0 interface"));

        // Test 3: Invalid URL (no host)
        let app3 = Router::new().route(
            "/.well-known/agent-card.json",
            get(|| async {
                axum::Json(serde_json::json!({
                    "name":"peer",
                    "description":"d",
                    "version":"1",
                    "supportedInterfaces":[{
                        "url":"relative-url",
                        "protocolBinding":"JSONRPC",
                        "protocolVersion":"1.0"
                    }],
                    "capabilities":{},
                    "defaultInputModes":["text/plain"],
                    "defaultOutputModes":["text/plain"],
                    "skills":[]
                }))
            }),
        );
        let listener3 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url3 = format!("http://{}", listener3.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener3, app3).await;
        });
        let cfg3 = A2aOutboundPeerConfig {
            url: url3,
            token: "secret".into(),
            ..Default::default()
        };
        let err3 = A2aClient::discover("peer", &cfg3).await.unwrap_err();
        assert!(err3
            .to_string()
            .contains("agent card has no compatible JSON-RPC 1.0 interface"));
    }

    fn test_agent_card(rpc_url: &str) -> AgentCard {
        AgentCard {
            name: "test-peer".into(),
            description: "A test peer".into(),
            version: "1.0.0".into(),
            supported_interfaces: vec![AgentInterface {
                url: rpc_url.to_string(),
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
        }
    }

    #[tokio::test]
    async fn direct_send_message_completed_message() {
        let app = Router::new().route(
            "/jsonrpc",
            post(|Json(req): Json<Value>| async move {
                let id = req.get("id").cloned().unwrap_or(json!(1));
                let method = req.get("method").and_then(Value::as_str).unwrap_or("");
                assert_eq!(method, "SendMessage");

                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "message": {
                            "messageId": "msg-resp-1",
                            "role": "ROLE_AGENT",
                            "parts": [{"text": "Hello from peer!"}]
                        }
                    }
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let rpc_url = format!("http://{addr}/jsonrpc");
        let card = test_agent_card(&rpc_url);
        let cfg = A2aOutboundPeerConfig {
            url: format!("http://{addr}"),
            token: "secret".into(),
            timeout_secs: 5,
            poll_interval_ms: 50,
            poll_timeout_secs: 5,
        };

        let client = A2aClient::from_card(card, &cfg).await.unwrap();
        let resp = client.send_text("Hello").await.unwrap();
        match resp {
            SendMessageResponse::Message(msg) => {
                assert_eq!(msg.text(), Some("Hello from peer!"));
                assert_eq!(msg.role, Role::Agent);
            }
            SendMessageResponse::Task(_) => panic!("expected Message response"),
        }

        let reply = client.send_and_wait("Hello", &cfg).await.unwrap();
        assert_eq!(reply, "Hello from peer!");
    }

    #[tokio::test]
    async fn direct_send_message_completed_task() {
        let app = Router::new().route(
            "/jsonrpc",
            post(|Json(req): Json<Value>| async move {
                let id = req.get("id").cloned().unwrap_or(json!(1));
                let method = req.get("method").and_then(Value::as_str).unwrap_or("");
                assert_eq!(method, "SendMessage");

                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "task": {
                            "id": "task-direct-1",
                            "contextId": "ctx-1",
                            "status": {
                                "state": "TASK_STATE_COMPLETED",
                                "message": {
                                    "messageId": "msg-done-1",
                                    "role": "ROLE_AGENT",
                                    "parts": [{"text": "Completed immediately!"}]
                                }
                            }
                        }
                    }
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let rpc_url = format!("http://{addr}/jsonrpc");
        let card = test_agent_card(&rpc_url);
        let cfg = A2aOutboundPeerConfig {
            url: format!("http://{addr}"),
            token: "secret".into(),
            timeout_secs: 5,
            poll_interval_ms: 50,
            poll_timeout_secs: 5,
        };

        let client = A2aClient::from_card(card, &cfg).await.unwrap();
        let reply = client.send_and_wait("Do something", &cfg).await.unwrap();
        assert_eq!(reply, "Completed immediately!");
    }

    #[tokio::test]
    async fn working_task_polled_to_completed() {
        let poll_count = Arc::new(Mutex::new(0));
        let poll_count_clone = poll_count.clone();

        let app = Router::new().route(
            "/jsonrpc",
            post(move |Json(req): Json<Value>| {
                let poll_count = poll_count_clone.clone();
                async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

                    if method == "SendMessage" {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "task": {
                                    "id": "task-poll-1",
                                    "contextId": "ctx-1",
                                    "status": {
                                        "state": "TASK_STATE_WORKING"
                                    }
                                }
                            }
                        }))
                    } else if method == "GetTask" {
                        let mut count = poll_count.lock().unwrap();
                        *count += 1;
                        let state = if *count >= 2 {
                            "TASK_STATE_COMPLETED"
                        } else {
                            "TASK_STATE_WORKING"
                        };
                        let message = if *count >= 2 {
                            Some(json!({
                                "messageId": "msg-done-2",
                                "role": "ROLE_AGENT",
                                "parts": [{"text": "Async work finished!"}]
                            }))
                        } else {
                            None
                        };

                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "id": "task-poll-1",
                                "contextId": "ctx-1",
                                "status": {
                                    "state": state,
                                    "message": message
                                }
                            }
                        }))
                    } else {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32601,
                                "message": "Method not found"
                            }
                        }))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let rpc_url = format!("http://{addr}/jsonrpc");
        let card = test_agent_card(&rpc_url);
        let cfg = A2aOutboundPeerConfig {
            url: format!("http://{addr}"),
            token: "secret".into(),
            timeout_secs: 5,
            poll_interval_ms: 10,
            poll_timeout_secs: 5,
        };

        let client = A2aClient::from_card(card, &cfg).await.unwrap();
        let reply = client.send_and_wait("Run async job", &cfg).await.unwrap();
        assert_eq!(reply, "Async work finished!");
        assert!(*poll_count.lock().unwrap() >= 2);
    }

    #[tokio::test]
    async fn polling_times_out() {
        let app = Router::new().route(
            "/jsonrpc",
            post(|Json(req): Json<Value>| async move {
                let id = req.get("id").cloned().unwrap_or(json!(1));
                let method = req.get("method").and_then(Value::as_str).unwrap_or("");

                if method == "GetTask" {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "id": "task-loop-1",
                            "contextId": "ctx-1",
                            "status": {
                                "state": "TASK_STATE_WORKING"
                            }
                        }
                    }))
                } else {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": "Method not found"
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let rpc_url = format!("http://{addr}/jsonrpc");
        let card = test_agent_card(&rpc_url);
        let cfg = A2aOutboundPeerConfig {
            url: format!("http://{addr}"),
            token: "secret".into(),
            timeout_secs: 5,
            poll_interval_ms: 10,
            poll_timeout_secs: 1,
        };

        let client = A2aClient::from_card(card, &cfg).await.unwrap();
        let err = client
            .poll_task(
                "task-loop-1",
                Duration::from_millis(10),
                Duration::from_millis(50),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("timed out polling task"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn terminal_failed_task_returns_error() {
        let app = Router::new().route(
            "/jsonrpc",
            post(|Json(req): Json<Value>| async move {
                let id = req.get("id").cloned().unwrap_or(json!(1));
                let method = req.get("method").and_then(Value::as_str).unwrap_or("");

                if method == "GetTask" {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "id": "task-fail-1",
                            "contextId": "ctx-1",
                            "status": {
                                "state": "TASK_STATE_FAILED",
                                "message": {
                                    "messageId": "err-1",
                                    "role": "ROLE_AGENT",
                                    "parts": [{"text": "database disk is full"}]
                                }
                            }
                        }
                    }))
                } else {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32601,
                            "message": "Method not found"
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let rpc_url = format!("http://{addr}/jsonrpc");
        let card = test_agent_card(&rpc_url);
        let cfg = A2aOutboundPeerConfig {
            url: format!("http://{addr}"),
            token: "secret".into(),
            timeout_secs: 5,
            poll_interval_ms: 10,
            poll_timeout_secs: 5,
        };

        let client = A2aClient::from_card(card, &cfg).await.unwrap();
        let err = client
            .poll_task(
                "task-fail-1",
                Duration::from_millis(10),
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("task 'task-fail-1' failed: database disk is full"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn missing_task_returns_error() {
        let app = Router::new().route(
            "/jsonrpc",
            post(|Json(req): Json<Value>| async move {
                let id = req.get("id").cloned().unwrap_or(json!(1));
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "task not found"
                    }
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let rpc_url = format!("http://{addr}/jsonrpc");
        let card = test_agent_card(&rpc_url);
        let cfg = A2aOutboundPeerConfig {
            url: format!("http://{addr}"),
            token: "secret".into(),
            timeout_secs: 5,
            poll_interval_ms: 10,
            poll_timeout_secs: 5,
        };

        let client = A2aClient::from_card(card, &cfg).await.unwrap();
        let err = client.get_task("nonexistent-task").await.unwrap_err();
        assert!(
            err.to_string().contains("task not found")
                || err.to_string().contains("failed to get A2A task"),
            "unexpected error: {err}"
        );

        let poll_err = client
            .poll_task(
                "nonexistent-task",
                Duration::from_millis(10),
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();
        assert!(
            poll_err.to_string().contains("nonexistent-task"),
            "unexpected error: {poll_err}"
        );
    }
}
