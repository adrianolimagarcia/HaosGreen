use anyhow::{Context, Result};
use rmcp::{
    model::{CallToolRequestParams, Tool as McpTool},
    service::RunningService,
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, ConfigureCommandExt,
        StreamableHttpClientTransport, TokioChildProcess,
    },
    ServiceExt,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::config::McpServerConfig;
use crate::llm::{FunctionDefinition, ToolDefinition};

// ── OAuth token refresh ────────────────────────────────────────────────────────

/// Response from the token endpoint when refreshing an access token.
#[derive(Deserialize)]
struct TokenRefreshResponse {
    access_token: String,
    /// Authorization servers rotate the refresh token on each use.
    #[serde(default)]
    refresh_token: Option<String>,
    /// Lifetime of the new access token in seconds.
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Returns true when the access token for an HTTP MCP server has expired or
/// will expire within the next 5 minutes.
pub fn token_needs_refresh(config: &McpServerConfig) -> bool {
    if config.refresh_token.is_none() || config.token_endpoint.is_none() {
        return false;
    }
    match config.token_expires_at {
        None => false,
        Some(expires_at) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            // Refresh if expiry is within the next 5 minutes (300 seconds)
            expires_at - now <= 300
        }
    }
}

pub const OAUTH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Queue rotated HTTP credentials until a replacement connection is ready.
/// Kept separate from refresh eligibility: a successful OAuth rotation advances expiry
/// even when the corresponding MCP handshake must be retried on a later tick.
pub async fn reconnect_refreshed_servers(
    manager: &McpManager,
    pending: &mut HashMap<String, McpServerConfig>,
    refreshed: Vec<McpServerConfig>,
) {
    for cfg in refreshed.into_iter().filter(|cfg| cfg.url.is_some()) {
        pending.insert(cfg.name.clone(), cfg);
    }
    let retries: Vec<_> = pending.values().cloned().collect();
    for cfg in retries {
        match manager.connect(&cfg).await {
            Ok(()) => {
                pending.remove(&cfg.name);
            }
            Err(e) => warn!(
                "MCP reconnect failed for '{}'; retrying next tick: {e:#}",
                cfg.name
            ),
        }
    }
}

pub const MCP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const MCP_TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
pub const OAUTH_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Exchange a refresh token for a new access token.
///
/// Uses HTTP Basic Auth with `oauth_client_id` : `oauth_client_secret` when a
/// client ID is present.  Returns the updated token fields.
pub async fn refresh_oauth_token(
    config: &McpServerConfig,
    http_client: &reqwest::Client,
) -> Result<(String, Option<String>, Option<i64>)> {
    refresh_oauth_token_with_timeout(config, http_client, OAUTH_REFRESH_TIMEOUT).await
}

async fn refresh_oauth_token_with_timeout(
    config: &McpServerConfig,
    http_client: &reqwest::Client,
    deadline: std::time::Duration,
) -> Result<(String, Option<String>, Option<i64>)> {
    tokio::time::timeout(deadline, async {
        let refresh_token = config
            .refresh_token
            .as_deref()
            .context("No refresh_token in config")?;
        let token_endpoint = config
            .token_endpoint
            .as_deref()
            .context("No token_endpoint in config")?;

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];

        let mut request = http_client.post(token_endpoint).form(&params);

        // Add HTTP Basic Auth when a client_id is available.
        if let Some(client_id) = &config.oauth_client_id {
            request = request.basic_auth(client_id, config.oauth_client_secret.as_deref());
        }

        let resp = request
            .send()
            .await
            .context("Token refresh request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "Token refresh failed ({status}) for '{}': {body}",
                config.name
            );
        }

        let tok: TokenRefreshResponse = resp
            .json()
            .await
            .context("Failed to parse token refresh response")?;

        let new_expires_at = tok.expires_in.map(|secs| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            now + secs as i64
        });

        Ok((tok.access_token, tok.refresh_token, new_expires_at))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Token refresh timed out for MCP server '{}'", config.name))?
}

/// Rewrite the `auth_token`, `refresh_token`, and `token_expires_at` fields for
/// a named `[[mcp_servers]]` entry inside `config.toml`, preserving all other
/// content.
///
/// Strategy: parse the TOML into a `toml::Value`, update the matching server
/// entry, and serialise back.  Comments are lost on round-trip, but the
/// functional data is fully preserved.  This is acceptable for a
/// machine-updated file.
pub async fn update_config_tokens(
    config_path: &Path,
    server_name: &str,
    auth_token: &str,
    new_refresh_token: Option<&str>,
    new_expires_at: Option<i64>,
) -> Result<()> {
    let content = tokio::fs::read_to_string(config_path)
        .await
        .with_context(|| format!("Failed to read {}", config_path.display()))?;

    let mut doc: toml::Value = content
        .parse()
        .with_context(|| format!("Failed to parse TOML from {}", config_path.display()))?;

    if let Some(servers) = doc.get_mut("mcp_servers").and_then(|v| v.as_array_mut()) {
        for server in servers.iter_mut() {
            if server
                .get("name")
                .and_then(|v| v.as_str())
                .map(|n| n == server_name)
                .unwrap_or(false)
            {
                if let toml::Value::Table(table) = server {
                    table.insert(
                        "auth_token".to_string(),
                        toml::Value::String(auth_token.to_string()),
                    );
                    if let Some(rt) = new_refresh_token {
                        table.insert(
                            "refresh_token".to_string(),
                            toml::Value::String(rt.to_string()),
                        );
                    }
                    if let Some(ea) = new_expires_at {
                        table.insert("token_expires_at".to_string(), toml::Value::Integer(ea));
                    }
                }
                break;
            }
        }
    }

    let new_content = toml::to_string_pretty(&doc).context("Failed to serialise updated config")?;
    tokio::fs::write(config_path, new_content)
        .await
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    debug!("Persisted refreshed token for MCP server '{server_name}'");
    Ok(())
}

/// Refresh tokens for every HTTP MCP server that is near expiry, writing the
/// new credentials back to `config_path`. Returns the configs of servers that
/// were successfully refreshed.
pub async fn refresh_expiring_tokens(
    configs: &mut [McpServerConfig],
    config_path: &Path,
    http_client: &reqwest::Client,
) -> Vec<McpServerConfig> {
    let mut refreshed_servers = Vec::new();
    for cfg in configs.iter_mut() {
        if cfg.url.is_none() || !token_needs_refresh(cfg) {
            continue;
        }
        info!(
            "Access token for MCP server '{}' is expiring; refreshing...",
            cfg.name
        );
        match refresh_oauth_token(cfg, http_client).await {
            Ok((new_token, new_rt, new_exp)) => {
                // Persist to disk first; only update in-memory state on success to
                // avoid a situation where the runtime uses a token that was never saved.
                match update_config_tokens(
                    config_path,
                    &cfg.name,
                    &new_token,
                    new_rt.as_deref(),
                    new_exp,
                )
                .await
                {
                    Ok(()) => {
                        cfg.auth_token = Some(new_token);
                        if new_rt.is_some() {
                            cfg.refresh_token = new_rt;
                        }
                        cfg.token_expires_at = new_exp;
                        refreshed_servers.push(cfg.clone());
                        info!("Token refreshed successfully for MCP server '{}'", cfg.name);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to persist refreshed token for '{}': {e:#}",
                            cfg.name
                        );
                    }
                }
            }
            Err(e) => {
                warn!("Token refresh failed for MCP server '{}': {e:#}", cfg.name);
            }
        }
    }
    refreshed_servers
}

/// Represents a connected MCP server with its tools
pub struct McpConnection {
    pub name: String,
    pub client: RunningService<rmcp::service::RoleClient, ()>,
    pub tools: Vec<McpTool>,
}

/// Manages multiple MCP server connections
pub struct McpManager {
    // Locks protect only immutable snapshots; never hold one across a network await.
    connections: RwLock<HashMap<String, Arc<McpConnection>>>,
}

impl Default for McpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl McpManager {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Connect to an MCP server — dispatches to HTTP or stdio based on config.
    pub async fn connect(&self, config: &McpServerConfig) -> Result<()> {
        self.connect_with_timeout(config, MCP_CONNECT_TIMEOUT).await
    }

    async fn connect_with_timeout(
        &self,
        config: &McpServerConfig,
        deadline: std::time::Duration,
    ) -> Result<()> {
        // Both initialization and all pages of tool discovery share one deadline.
        tokio::time::timeout(deadline, async {
            if config.url.is_some() {
                self.connect_http(config).await
            } else {
                self.connect_stdio(config).await
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("MCP connect timed out for '{}'", config.name))?
    }

    /// Connect to an HTTP-based MCP server using the Streamable HTTP transport.
    async fn connect_http(&self, config: &McpServerConfig) -> Result<()> {
        let url = config
            .url
            .as_deref()
            .context("HTTP MCP server config missing 'url'")?;

        info!("Connecting to HTTP MCP server '{}': {}", config.name, url);

        let mut transport_config = StreamableHttpClientTransportConfig::with_uri(url.to_string());

        // Only set the auth header when a non-empty token is provided.
        // Using unwrap_or_default() would pass an empty string, causing
        // reqwest to send "Authorization: Bearer " (empty token) which
        // remote servers (e.g. Notion) reject with 401 invalid_token.
        match &config.auth_token {
            Some(token) if !token.is_empty() => {
                transport_config = transport_config.auth_header(token.clone());
            }
            None => {
                tracing::debug!(
                    "HTTP MCP server '{}' has no auth_token configured; \
                     requests will be sent without an Authorization header",
                    config.name
                );
            }
            _ => {}
        }

        let transport = StreamableHttpClientTransport::from_config(transport_config);

        // `()` implements rmcp's `ServiceExt` as the default no-op client handler;
        // calling `.serve(transport)` on it returns a `RunningService` connected
        // to the given transport without any application-level request handling.
        let client = ().serve(transport).await.with_context(|| {
            format!("Failed to initialize HTTP MCP connection: {}", config.name)
        })?;

        self.register_client(config, client).await
    }

    /// Connect to a stdio-based MCP server via a child process.
    async fn connect_stdio(&self, config: &McpServerConfig) -> Result<()> {
        let command_str = config
            .command
            .as_deref()
            .context("Stdio MCP server config missing 'command'")?;

        info!(
            "Connecting to stdio MCP server '{}': {} {:?}",
            config.name, command_str, config.args
        );

        let args = config.args.clone();
        let env = config.env.clone();
        let cmd = command_str.to_string();

        let transport = TokioChildProcess::new(Command::new(&cmd).configure(move |c| {
            for arg in &args {
                c.arg(arg);
            }
            for (key, value) in &env {
                c.env(key, value);
            }
        }))
        .with_context(|| format!("Failed to start MCP server process: {}", config.name))?;

        // `()` is rmcp's default no-op client handler; see `connect_http` for details.
        let client = ()
            .serve(transport)
            .await
            .with_context(|| format!("Failed to initialize MCP connection: {}", config.name))?;

        self.register_client(config, client).await
    }

    /// Register a connected client, listing its tools and storing it.
    async fn register_client(
        &self,
        config: &McpServerConfig,
        client: RunningService<rmcp::service::RoleClient, ()>,
    ) -> Result<()> {
        let server_info = client.peer_info();
        info!(
            "Connected to MCP server '{}': {:?}",
            config.name, server_info
        );

        let tools = client
            .list_all_tools()
            .await
            .with_context(|| format!("Failed to list tools from MCP server: {}", config.name))?;

        info!(
            "MCP server '{}' provides {} tools",
            config.name,
            tools.len()
        );
        for tool in &tools {
            info!("  - {}: {:?}", tool.name, tool.description);
        }

        // Publish only after discovery succeeds; old snapshots survive in-flight calls.
        self.connections
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                config.name.clone(),
                Arc::new(McpConnection {
                    name: config.name.clone(),
                    client,
                    tools,
                }),
            );

        Ok(())
    }

    /// Connect to all configured MCP servers, logging errors but not failing
    pub async fn connect_all(&mut self, configs: &[McpServerConfig]) {
        for config in configs {
            if let Err(e) = self.connect(config).await {
                error!("Failed to connect to MCP server '{}': {:#}", config.name, e);
            }
        }
    }

    pub fn has_server(&self, name: &str) -> bool {
        self.connections
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(name)
    }

    fn connection_snapshots(&self) -> Vec<Arc<McpConnection>> {
        self.connections
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Number of connected MCP servers
    pub fn server_count(&self) -> usize {
        self.connections
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Get all MCP tools as OpenRouter-compatible tool definitions
    pub fn tool_definitions(&self) -> Vec<ToolDefinition> {
        let mut definitions = Vec::new();

        for connection in self.connection_snapshots() {
            for tool in &connection.tools {
                let parameters = tool.schema_as_json_value();
                definitions.push(ToolDefinition {
                    tool_type: "function".to_string(),
                    function: FunctionDefinition {
                        name: format!("mcp_{}_{}", connection.name, tool.name),
                        description: tool
                            .description
                            .as_deref()
                            .unwrap_or("MCP tool")
                            .to_string(),
                        parameters,
                    },
                });
            }
        }

        definitions
    }

    /// Find which MCP server owns a tool and call it
    pub async fn call_tool(&self, prefixed_name: &str, arguments: &Value) -> Result<String> {
        self.call_tool_with_timeout(prefixed_name, arguments, MCP_TOOL_TIMEOUT)
            .await
    }

    async fn call_tool_with_timeout(
        &self,
        prefixed_name: &str,
        arguments: &Value,
        deadline: std::time::Duration,
    ) -> Result<String> {
        // Tool names are prefixed with "mcp_{server_name}_{tool_name}"
        let without_mcp = prefixed_name
            .strip_prefix("mcp_")
            .context("MCP tool name must start with 'mcp_'")?;

        // Find the matching connection
        for connection in self.connection_snapshots() {
            let prefix = format!("{}_", connection.name);
            if let Some(tool_name) = without_mcp.strip_prefix(&prefix) {
                // Verify this tool exists on this server
                if connection
                    .tools
                    .iter()
                    .any(|t| t.name.as_ref() == tool_name)
                {
                    info!(
                        "Calling MCP tool '{}' on server '{}'",
                        tool_name, connection.name
                    );

                    let tool_name_owned: std::borrow::Cow<'static, str> =
                        std::borrow::Cow::Owned(tool_name.to_string());
                    let result = tokio::time::timeout(
                        deadline,
                        connection.client.call_tool(CallToolRequestParams {
                            meta: None,
                            name: tool_name_owned,
                            arguments: arguments.as_object().cloned(),
                            task: None,
                        }),
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "MCP tool '{}' timed out on '{}'",
                            tool_name,
                            connection.name
                        )
                    })?
                    .with_context(|| {
                        format!(
                            "Failed to call MCP tool '{}' on server '{}'",
                            tool_name, connection.name
                        )
                    })?;

                    // Extract text content from the result
                    let text_parts: Vec<String> = result
                        .content
                        .iter()
                        .filter_map(|c| c.raw.as_text().map(|t| t.text.clone()))
                        .collect();

                    if text_parts.is_empty() {
                        return Ok(format!("{:?}", result.content));
                    }
                    return Ok(text_parts.join("\n"));
                }
            }
        }

        anyhow::bail!("MCP tool not found: {}", prefixed_name)
    }

    /// Check if a tool name belongs to an MCP server
    pub fn is_mcp_tool(&self, name: &str) -> bool {
        name.starts_with("mcp_")
    }

    /// Shutdown all MCP connections
    #[allow(dead_code)]
    pub async fn shutdown(&mut self) {
        let connections = std::mem::take(
            self.connections
                .get_mut()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for (name, connection) in connections {
            info!("Shutting down MCP server: {}", name);
            // Cancellation token is shared with in-flight snapshot holders.
            connection.client.cancellation_token().cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpServerConfig;
    use std::collections::HashMap;

    fn base_config() -> McpServerConfig {
        McpServerConfig {
            name: "test".to_string(),
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: Some("https://example.com/mcp".to_string()),
            auth_token: Some("tok".to_string()),
            refresh_token: Some("rt".to_string()),
            token_expires_at: None,
            token_endpoint: Some("https://example.com/token".to_string()),
            oauth_client_id: None,
            oauth_client_secret: None,
        }
    }

    #[tokio::test]
    async fn http_rotation_retains_old_snapshot_and_bounds_discovery_and_calls() {
        use axum::{
            extract::State,
            http::{HeaderMap, StatusCode},
            response::IntoResponse,
            routing::post,
            Json, Router,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        async fn endpoint(
            State(mode): State<Arc<AtomicUsize>>,
            headers: HeaderMap,
            Json(request): Json<Value>,
        ) -> axum::response::Response {
            let method = request["method"].as_str().unwrap_or("");
            let state = mode.load(Ordering::SeqCst);
            if (state == 1 && method == "tools/list")
                || (state == 2 && method == "tools/call")
                || state == 3
            {
                std::future::pending::<()>().await;
            }
            if state == 4 {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            if request.get("id").is_none() {
                return StatusCode::ACCEPTED.into_response();
            }
            let result = match method {
                "initialize" => {
                    serde_json::json!({"protocolVersion":"2025-03-26", "capabilities":{"tools":{}}, "serverInfo":{"name":"fake","version":"1"}})
                }
                "tools/list" => {
                    serde_json::json!({"tools":[{"name":"echo","inputSchema":{"type":"object"}}]})
                }
                "tools/call" => {
                    serde_json::json!({"content":[{"type":"text","text": headers.get("authorization").unwrap().to_str().unwrap()}]})
                }
                _ => serde_json::json!({}),
            };
            Json(serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
                .into_response()
        }
        let mode = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = base_config();
        cfg.url = Some(format!("http://{}/mcp", listener.local_addr().unwrap()));
        let router = Router::new()
            .route("/mcp", post(endpoint))
            .route("/token", post(|| async { Json(serde_json::json!({"access_token":"rotated", "refresh_token":"rotated-refresh", "expires_in":3600})) }))
            .with_state(mode.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let manager = McpManager::new();
        let short = std::time::Duration::from_millis(150);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            manager.connect(&cfg).await.unwrap();
            assert_eq!(
                manager
                    .call_tool("mcp_test_echo", &serde_json::json!({}))
                    .await
                    .unwrap(),
                "Bearer tok"
            );
            cfg.token_endpoint = Some(cfg.url.as_ref().unwrap().replace("/mcp", "/token"));
            cfg.token_expires_at = Some(0);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.toml");
            tokio::fs::write(&path, "[[mcp_servers]]\nname = 'test'\n")
                .await
                .unwrap();
            let mut configs = vec![cfg.clone()];
            let refreshed =
                refresh_expiring_tokens(&mut configs, &path, &reqwest::Client::new()).await;
            assert_eq!(refreshed.len(), 1);
            assert!(!token_needs_refresh(&configs[0]));
            cfg = refreshed[0].clone();
            let mut pending = HashMap::new();
            mode.store(4, Ordering::SeqCst);
            reconnect_refreshed_servers(&manager, &mut pending, refreshed).await;
            assert_eq!(pending.len(), 1);
            mode.store(0, Ordering::SeqCst);
            // No refresh on this tick: advanced expiry must not suppress reconnect.
            let refreshed =
                refresh_expiring_tokens(&mut configs, &path, &reqwest::Client::new()).await;
            assert!(refreshed.is_empty());
            reconnect_refreshed_servers(&manager, &mut pending, refreshed).await;
            assert!(pending.is_empty());
            assert_eq!(
                manager
                    .call_tool("mcp_test_echo", &serde_json::json!({}))
                    .await
                    .unwrap(),
                "Bearer rotated"
            );
            cfg.auth_token = Some("failed-candidate".into());
            mode.store(1, Ordering::SeqCst);
            let arguments = serde_json::json!({});
            let (replacement, live_call) = tokio::join!(
                manager.connect_with_timeout(&cfg, short),
                manager.call_tool_with_timeout("mcp_test_echo", &arguments, short)
            );
            assert_eq!(live_call.unwrap(), "Bearer rotated");
            assert!(replacement.unwrap_err().to_string().contains("timed out"));
            assert_eq!(manager.server_count(), 1);
            assert_eq!(manager.tool_definitions().len(), 1);
            mode.store(0, Ordering::SeqCst);
            assert_eq!(
                manager
                    .call_tool("mcp_test_echo", &serde_json::json!({}))
                    .await
                    .unwrap(),
                "Bearer rotated"
            );
            cfg.auth_token = Some("rotated".into());
            manager.connect(&cfg).await.unwrap();
            assert_eq!(
                manager
                    .call_tool("mcp_test_echo", &serde_json::json!({}))
                    .await
                    .unwrap(),
                "Bearer rotated"
            );
            mode.store(2, Ordering::SeqCst);
            assert!(manager
                .call_tool_with_timeout("mcp_test_echo", &serde_json::json!({}), short)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out"));
            mode.store(3, Ordering::SeqCst);
            assert!(manager
                .connect_with_timeout(&cfg, short)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out"));
        })
        .await
        .expect("local MCP test must finish");
        server.abort();
    }

    #[test]
    fn polling_catches_refresh_window_before_expiry() {
        // Worst phase offset: expiry is just outside eligibility at a tick.
        assert_eq!(OAUTH_POLL_INTERVAL.as_secs(), 60);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut cfg = base_config();
        cfg.token_expires_at = Some(now + 301);
        assert!(!token_needs_refresh(&cfg));
        cfg.token_expires_at = Some(now + 301 - OAUTH_POLL_INTERVAL.as_secs() as i64);
        assert!(token_needs_refresh(&cfg));
        assert!(cfg.token_expires_at.unwrap() > now);
    }

    #[tokio::test]
    async fn stdio_handshake_stall_is_bounded() {
        let mut cfg = base_config();
        cfg.url = None;
        cfg.command = Some("sh".into());
        cfg.args = vec!["-c".into(), "read line; read line".into()];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            McpManager::new().connect_with_timeout(&cfg, std::time::Duration::from_millis(100)),
        )
        .await
        .expect("stdio handshake must finish");
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn oauth_deadline_includes_response_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = base_config();
        cfg.token_endpoint = Some(format!("http://{}/token", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n").await.unwrap();
            std::future::pending::<()>().await;
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            refresh_oauth_token_with_timeout(
                &cfg,
                &reqwest::Client::new(),
                std::time::Duration::from_millis(100),
            ),
        )
        .await
        .expect("OAuth body must not hang");
        server.abort();
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn test_no_refresh_without_refresh_token() {
        let mut cfg = base_config();
        cfg.refresh_token = None;
        assert!(!token_needs_refresh(&cfg));
    }

    #[test]
    fn test_no_refresh_without_token_endpoint() {
        let mut cfg = base_config();
        cfg.token_endpoint = None;
        assert!(!token_needs_refresh(&cfg));
    }

    #[test]
    fn test_no_refresh_when_no_expiry() {
        let cfg = base_config(); // token_expires_at == None
        assert!(!token_needs_refresh(&cfg));
    }

    #[test]
    fn test_needs_refresh_when_expired() {
        let mut cfg = base_config();
        // Set expiry 1 hour in the past
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 3600;
        cfg.token_expires_at = Some(past);
        assert!(token_needs_refresh(&cfg));
    }

    #[test]
    fn test_needs_refresh_when_expiring_within_5_min() {
        let mut cfg = base_config();
        // Set expiry 60 seconds from now (within 5-minute window)
        let soon = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 60;
        cfg.token_expires_at = Some(soon);
        assert!(token_needs_refresh(&cfg));
    }

    #[test]
    fn test_no_refresh_when_expiry_far_future() {
        let mut cfg = base_config();
        // Set expiry 1 hour from now
        let far = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;
        cfg.token_expires_at = Some(far);
        assert!(!token_needs_refresh(&cfg));
    }
}
