use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub telegram: TelegramConfig,
    pub openrouter: OpenRouterConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    #[serde(default = "default_memory_config")]
    pub memory: MemoryConfig,
    #[serde(default = "default_skills_config")]
    pub skills: SkillsConfig,
    #[serde(default = "default_agents_config")]
    pub agents: AgentsConfig,
    #[serde(default)]
    pub general: Option<GeneralConfig>,
    #[serde(default = "default_agent_config")]
    pub agent: AgentConfig,
    pub embedding: Option<EmbeddingApiConfig>,
    #[serde(default)]
    pub langsmith: Option<LangSmithConfig>,
    #[serde(default = "default_learning_config")]
    pub learning: LearningConfig,
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    #[serde(default)]
    pub subagents: SubagentsConfig,
    #[serde(default)]
    pub a2a: A2aConfig,
    #[serde(default)]
    pub web: WebConfig,
    /// Explicit provider sections (multi-provider mode). Optional —
    /// when empty, `build_providers()` synthesizes a single OpenRouter
    /// provider from the legacy `[openrouter]` section.
    #[serde(default)]
    pub provider: Vec<ProviderSection>,
    /// Fallback chain — additional provider/model names tried when
    /// the primary call fails.
    #[serde(default)]
    pub fallback: FallbackConfig,
    /// Absolute home root resolved at load time (not read from TOML).
    #[serde(skip)]
    pub resolved_home: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SupervisorConfig {
    #[serde(default = "default_autonomy_mode")]
    pub default_autonomy_mode: String,
    #[serde(default)]
    pub artifacts_dir: std::path::PathBuf,
    #[serde(default)]
    pub risk: RiskThresholdsConfig,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            default_autonomy_mode: default_autonomy_mode(),
            artifacts_dir: default_artifacts_dir(),
            risk: RiskThresholdsConfig::default(),
        }
    }
}

/// A2A (Agent2Agent) protocol settings.
///
/// Disabled by default. Enabling this opens a network listener; read the
/// *Security Context* and *Security Model* sections of
/// `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md` before
/// turning it on.
///
/// A peer that authenticates here can drive an agent that holds
/// `execute_command`, which runs `sh -c` with no validation of the command
/// string. The defaults below are restrictive for that reason.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct A2aConfig {
    /// Master switch. `false` means no listener is started at all.
    pub enabled: bool,
    /// Listen address. Defaults to loopback; raising this to a LAN address is
    /// a deliberate act.
    pub bind: String,
    /// Externally reachable base URL that peers should use to reach this
    /// Default: `<home>/haos-green.example.com` or similar.
    /// URL that remote agents will use to contact this agent.
    /// agent, e.g. `https://haos-green.example.com:8443`. It is what the Agent
    /// Card advertises verbatim in `supportedInterfaces[].url`.
    ///
    /// Required whenever `bind` names an unspecified address (`0.0.0.0`,
    /// `::`) or any other host a peer cannot route to: without it the card
    /// advertises the bind address itself, and a peer connecting to
    /// `0.0.0.0` reaches *its own* loopback rather than this agent. Startup
    /// logs a warning in that case.
    ///
    /// When unset, the URL is derived from the address the listener actually
    /// bound (so an ephemeral `bind` port advertises the real port).
    pub public_url: Option<String>,
    /// Maximum A2A tasks executing concurrently. Excess tasks queue.
    pub max_concurrent_tasks: usize,
    /// Transport security. Only `"none"` (or an absent key) is accepted:
    /// TLS is not implemented yet, and anything else is rejected at startup
    /// rather than silently served as plaintext. Reserved for the TLS phase.
    pub tls: String,
    /// Certificate path for TLS. Reserved for the TLS phase; setting it is an
    /// error today, because the listener would otherwise serve plaintext to an
    /// operator who believes TLS is on.
    pub tls_cert: Option<String>,
    /// Private-key path for TLS. Reserved for the TLS phase; see `tls_cert`.
    pub tls_key: Option<String>,
    /// Agent Card metadata.
    pub card: A2aCardConfig,
    /// Known peers, keyed by peer name. A request whose token matches no entry
    /// here is rejected. An empty map means nobody can connect.
    pub peers: HashMap<String, A2aPeerConfig>,
    /// Outbound peers this agent may contact.
    #[serde(default)]
    pub outbound: A2aOutboundConfig,
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8443".to_string(),
            public_url: None,
            max_concurrent_tasks: 4,
            tls: "none".to_string(),
            tls_cert: None,
            tls_key: None,
            card: A2aCardConfig::default(),
            peers: HashMap::new(),
            outbound: A2aOutboundConfig::default(),
        }
    }
}

impl A2aConfig {
    /// Validate the security-relevant parts of the `[a2a]` block.
    ///
    /// Every condition checked here already fails closed at request time; the
    /// point of validating up front is that the failure is *loud* and happens
    /// once at startup instead of silently on every request. Callers must not
    /// start the listener when this returns `Err`, but must keep running the
    /// Telegram bot: an A2A misconfiguration is not a reason to lose the bot.
    ///
    /// Peers are visited in name order so that the error reported for a config
    /// with several problems is stable across runs (`peers` is a `HashMap`,
    /// whose iteration order is randomized per process).
    ///
    /// A non-loopback `bind` is only warned about, never rejected: the design
    /// allows raising the bind, it just must be a deliberate act.
    pub fn validate(&self) -> Result<()> {
        self.validate_public_url()?;
        self.validate_tls()?;
        self.validate_peers()?;
        self.validate_outbound()?;
        if self.max_concurrent_tasks == 0 {
            anyhow::bail!(
                "[a2a] max_concurrent_tasks must be at least 1 (0 would refuse every task)"
            );
        }
        self.warn_on_non_loopback_bind();
        Ok(())
    }

    /// `public_url` is advertised verbatim in the Agent Card, so a value with no
    /// scheme (e.g. `haos-green.example.com:8443`) would be served as-is and no
    /// peer could ever reach it — the same silent-discovery breakage I1 fixes
    /// for the derived URL. Reject it up front rather than ship a dead card.
    fn validate_public_url(&self) -> Result<()> {
        if let Some(url) = self
            .public_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            let parsed = url
                .parse::<reqwest::Url>()
                .map_err(|e| anyhow::anyhow!("[a2a].public_url = {url:?} is malformed: {e}"))?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                bail!("[a2a].public_url = {url:?} must be an http(s) URL with a host");
            }
        }
        Ok(())
    }

    /// TLS is documented in the design spec but not implemented. Accepting
    /// `tls = "rustls"` and then serving plaintext HTTP would be a silent
    /// downgrade, so any request for it is refused instead.
    fn validate_tls(&self) -> Result<()> {
        let mode = self.tls.trim();
        if !mode.is_empty() && !mode.eq_ignore_ascii_case("none") {
            bail!(
                "[a2a].tls = {mode:?} is not supported: TLS is not implemented yet, and \
                 starting the listener anyway would serve plaintext to a peer that expects \
                 TLS. Set `tls = \"none\"` (or remove the key) and terminate TLS at a reverse \
                 proxy in front of this listener."
            );
        }
        if self
            .tls_cert
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
            || self
                .tls_key
                .as_deref()
                .is_some_and(|p| !p.trim().is_empty())
        {
            bail!(
                "[a2a].tls_cert / [a2a].tls_key are set but TLS is not implemented yet; the \
                 listener would serve plaintext. Remove them (or set `tls = \"none\"`) and \
                 terminate TLS at a reverse proxy in front of this listener."
            );
        }
        Ok(())
    }

    fn validate_peers(&self) -> Result<()> {
        let mut names: Vec<&String> = self.peers.keys().collect();
        names.sort();

        // token -> peer that already claimed it.
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for name in names {
            let peer = &self.peers[name];

            if peer.token.trim().is_empty() {
                bail!(
                    "A2A peer '{name}' has an empty token: it can never authenticate, because \
                     an empty configured token is refused by design. Give the peer a token or \
                     remove the block."
                );
            }
            if let Some(other) = seen.insert(peer.token.as_str(), name.as_str()) {
                bail!(
                    "A2A peers '{other}' and '{name}' share the same token: a request carrying \
                     it matches both, so which peer's ip allowlist and tools policy applies \
                     would depend on HashMap iteration order. Every request is refused with \
                     500 until one of the two tokens is changed."
                );
            }
            if peer.ip.is_empty() {
                bail!(
                    "A2A peer '{name}' has an empty `ip` list: every request from it is refused \
                     with 403. List at least one IP or CIDR block, or remove the block."
                );
            }
            for entry in &peer.ip {
                if entry.parse::<IpNet>().is_err() && entry.parse::<IpAddr>().is_err() {
                    bail!(
                        "A2A peer '{name}' has an `ip` entry {entry:?} that is neither an IP \
                         address nor a CIDR block: it is ignored, so it can never match. \
                         Expected e.g. \"10.0.0.5\" or \"192.168.1.0/24\"."
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_outbound(&self) -> Result<()> {
        let mut names: Vec<&String> = self.outbound.peers.keys().collect();
        names.sort();
        for name in names {
            self.outbound.peers[name].validate(name)?;
        }
        Ok(())
    }
    fn warn_on_non_loopback_bind(&self) {
        match self.bind.parse::<SocketAddr>() {
            Ok(addr) if !addr.ip().is_loopback() => {
                tracing::warn!(
                    bind = %addr,
                    "A2A: binding to a non-loopback address exposes the listener beyond this \
                     host. This is a deliberate act per the design's Security Model: every \
                     peer must still present a valid token from an allowlisted address."
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    bind = %self.bind,
                    error = %e,
                    "A2A: [a2a].bind is not a literal `host:port`; the non-loopback check was \
                     skipped. Prefer a literal address so this check and the advertised URL are \
                     exact."
                );
            }
        }
    }
}

/// Web dashboard configuration.
///
/// Secrets (the password hash and the bearer token) live in
/// `<home>/web-auth.toml`, never here, because `config.toml` is the file
/// users copy, share, and paste into issues.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Off by default: a dashboard that can run shell commands must never
    /// appear because a config file omitted a key.
    pub enabled: bool,
    pub bind: String,
    /// Externally reachable URL.
    ///
    /// When it is https, session cookies get the `Secure` flag. **Unset means
    /// no `Secure` flag** — not "derive from the bound address", which is what
    /// this comment used to claim and what the code has never done. The bound
    /// address cannot settle it: a listener on `127.0.0.1:8787` behind a
    /// TLS-terminating proxy is served over https, and the same address
    /// without a proxy is not, so the only honest default is to leave the flag
    /// off. An https deployment that omits `public_url` therefore gets a
    /// session cookie without `Secure`; set it.
    ///
    /// It is also the host this dashboard answers to: a request whose `Host`
    /// header is neither this host nor the bound address (nor `localhost`,
    /// `127.0.0.1`, `[::1]` on the bound port) is refused with 403.
    pub public_url: Option<String>,
    pub session_ttl_hours: u64,
    /// Empty means any source IP may attempt login. Non-empty is a strict
    /// allowlist, enforced before authentication.
    pub allow_ips: Vec<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8787".to_string(),
            public_url: None,
            session_ttl_hours: 12,
            allow_ips: Vec::new(),
        }
    }
}

impl WebConfig {
    /// Validate the `[web]` block.
    ///
    /// Callers must not start the listener when this returns `Err`, but must
    /// keep running the Telegram bot: a dashboard misconfiguration is not a
    /// reason to lose the bot. Every condition here also fails closed at
    /// request time; the point of checking up front is that the failure is
    /// *loud* and happens once at startup instead of silently per request.
    ///
    /// A non-loopback `bind` is deliberately not rejected — the design allows
    /// raising it — but `spawn()` warns about it.
    pub fn validate(&self) -> Result<()> {
        use std::net::ToSocketAddrs;

        if self.bind.trim().parse::<SocketAddr>().is_err() && self.bind.to_socket_addrs().is_err() {
            bail!("web.bind '{0}' is not a valid address", self.bind.trim());
        }

        if self.session_ttl_hours == 0 {
            bail!("web.session_ttl_hours must be at least 1");
        }

        if let Some(url) = self
            .public_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                bail!("web.public_url '{url}' must start with http:// or https://");
            }
        }

        for entry in &self.allow_ips {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                bail!("web.allow_ips contains an empty entry");
            }
            if trimmed.parse::<IpNet>().is_err() && trimmed.parse::<IpAddr>().is_err() {
                bail!("web.allow_ips entry '{trimmed}' is not an IP address or CIDR range");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct A2aCardConfig {
    pub name: String,
    pub description: String,
    pub version: String,
}

impl Default for A2aCardConfig {
    fn default() -> Self {
        Self {
            name: "HaosGreen".to_string(),
            description: "Self-hosted Telegram AI assistant".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct A2aOutboundConfig {
    #[serde(default)]
    pub peers: HashMap<String, A2aOutboundPeerConfig>,
}

pub const MAX_A2A_SEND_TIMEOUT_SECS: u64 = 300;

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct A2aOutboundPeerConfig {
    pub url: String,
    pub token: String,
    pub timeout_secs: u64,
    /// Optional deadline for the complete synchronous SendMessage request.
    /// `None` preserves `timeout_secs`; values must be 1..=MAX_A2A_SEND_TIMEOUT_SECS.
    #[serde(default)]
    pub send_timeout_secs: Option<u64>,
    pub poll_interval_ms: u64,
    pub poll_timeout_secs: u64,
}

impl fmt::Debug for A2aOutboundPeerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("A2aOutboundPeerConfig")
            .field("url", &self.url)
            .field("token", &"[REDACTED]")
            .field("timeout_secs", &self.timeout_secs)
            .field("send_timeout_secs", &self.send_timeout_secs)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("poll_timeout_secs", &self.poll_timeout_secs)
            .finish()
    }
}
impl Default for A2aOutboundPeerConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            timeout_secs: 30,
            send_timeout_secs: None,
            poll_interval_ms: 250,
            poll_timeout_secs: 60,
        }
    }
}

impl A2aOutboundPeerConfig {
    pub fn validate(&self, name: &str) -> Result<()> {
        let parsed = self
            .url
            .trim()
            .parse::<reqwest::Url>()
            .map_err(|e| anyhow::anyhow!("A2A outbound peer '{name}' url is malformed: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            bail!("A2A outbound peer '{name}' url must be an http(s) URL with a host");
        }
        if self.token.trim().is_empty() {
            bail!("A2A outbound peer '{name}' token must not be empty");
        }
        if self.timeout_secs < 1 {
            bail!("A2A outbound peer '{name}' timeout_secs must be at least 1");
        }
        if let Some(send_timeout_secs) = self.send_timeout_secs {
            if send_timeout_secs == 0 || send_timeout_secs > MAX_A2A_SEND_TIMEOUT_SECS {
                bail!("A2A outbound peer '{name}' send_timeout_secs must be between 1 and {MAX_A2A_SEND_TIMEOUT_SECS}");
            }
        }
        if self.poll_interval_ms < 1 {
            bail!("A2A outbound peer '{name}' poll_interval_ms must be at least 1");
        }
        if self.poll_timeout_secs < 1 {
            bail!("A2A outbound peer '{name}' poll_timeout_secs must be at least 1");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct A2aPeerConfig {
    /// Bearer token this peer must present.
    pub token: String,
    /// Allowed source addresses: exact IPs (`10.0.0.5`) or CIDR blocks
    /// (`192.168.1.0/24`). Empty means no address is allowed.
    #[serde(default)]
    pub ip: Vec<String>,
    /// Tool allowlist for this peer. `None` applies the conservative default
    /// list (`src/a2a/policy.rs`); `Some(["*"])` grants every tool, including
    /// shell; an explicit list is used verbatim.
    ///
    /// # Do not forward this `Option` into `LoopConfig.allowed_tools`
    ///
    /// The two `None`s mean opposite things. Here, `None` means *the
    /// conservative default*. In `LoopConfig.allowed_tools`
    /// (`src/loop_runner.rs:33`) `None` means *no restriction at all* — every
    /// tool is offered and executable. Always resolve through
    /// `policy::resolve_allowed_tools` first, which returns a concrete
    /// `Vec<String>`.
    #[serde(default)]
    pub tools: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SubagentsConfig {
    /// Default tool whitelist for ad-hoc subagents.
    /// When None, defaults to sandbox tools only (read_file, write_file, list_files, execute_command).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_tools: Option<Vec<String>>,
}

/// Risk-threshold gates that govern when the supervisor may auto-execute a
/// task vs. require explicit user approval.
///
/// Defaults preserve the M1–M6 behavior (Medium-risk tasks auto-execute);
/// flip individual fields in `config.toml` to tighten the gate.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct RiskThresholdsConfig {
    #[serde(default)]
    pub require_approval_for_low: bool,
    #[serde(default)]
    pub require_approval_for_medium: bool,
    /// When `true`, only Low-risk tasks may auto-execute; Medium escalates to
    /// `RequireApproval`. Defaults to `false` to stay backward-compatible
    /// with the M1–M6 policy where Medium-risk tasks auto-execute.
    #[serde(default)]
    pub auto_execute_only_low: bool,
}

fn default_autonomy_mode() -> String {
    "standard".to_string()
}

fn default_artifacts_dir() -> std::path::PathBuf {
    std::path::PathBuf::new()
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmbeddingApiConfig {
    pub api_key: String,
    #[serde(default = "default_embedding_base_url")]
    pub base_url: String,
    #[serde(default = "default_embedding_model")]
    pub model: String,
    #[serde(default = "default_embedding_dimensions")]
    pub dimensions: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub allowed_user_ids: Vec<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenRouterConfig {
    pub api_key: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,
    /// Whether the configured model supports vision (image inputs).
    /// When true, images are sent as base64-encoded content parts.
    /// When false, a fallback message is returned indicating vision is not supported.
    #[serde(default)]
    pub supports_vision: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum ProviderType {
    #[serde(rename = "openrouter")]
    OpenRouter,
    #[serde(rename = "openai_compatible")]
    OpenAICompatible,
    #[serde(rename = "ollama")]
    Ollama,
}

#[allow(clippy::derivable_impls)]
impl Default for ProviderType {
    fn default() -> Self {
        Self::OpenRouter
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderSection {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: ProviderType,
    pub base_url: String,
    pub api_key: Option<String>,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub supports_vision: bool,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    pub discover_models: bool,
    #[serde(default = "default_context_window")]
    pub context_window: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FallbackConfig {
    #[serde(default)]
    pub chain: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SandboxConfig {
    #[serde(default)]
    pub allowed_directory: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct McpServerConfig {
    pub name: String,
    /// Command to run for stdio-based MCP servers (e.g. "uvx", "npx").
    /// Required for stdio servers; omit for HTTP servers.
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    /// URL for HTTP-based MCP servers using the Streamable HTTP transport.
    /// Required for HTTP servers; omit for stdio servers.
    /// The API key may be embedded as a query parameter (e.g. `?exaApiKey=KEY`)
    /// or provided separately via `auth_token`.
    #[serde(default)]
    pub url: Option<String>,
    /// Bearer token sent in the `Authorization` header for HTTP servers.
    /// Used with `url`; ignored for stdio servers.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// OAuth 2.0 refresh token for long-lived connections.
    /// When set, the bot will automatically exchange this for a new `auth_token`
    /// before the current one expires and persist the updated token to `config.toml`.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix timestamp (seconds since epoch) at which the current `auth_token`
    /// expires.  Derived from the `expires_in` field of the token response.
    #[serde(default)]
    pub token_expires_at: Option<i64>,
    /// OAuth 2.0 token endpoint used for refresh-token exchanges.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// OAuth 2.0 client ID used when authenticating refresh-token requests.
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    /// OAuth 2.0 client secret (if applicable) used alongside `oauth_client_id`.
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MemoryConfig {
    #[serde(default)]
    pub database_path: PathBuf,
    #[serde(default = "default_rag_limit")]
    pub rag_limit: usize,
    #[serde(default = "default_max_raw_messages")]
    pub max_raw_messages: usize,
    #[serde(default = "default_summarize_threshold")]
    #[allow(dead_code)]
    pub summarize_threshold: usize,
    #[serde(default = "default_summarize_cron")]
    #[allow(dead_code)]
    pub summarize_cron: String,
    /// When `true`, an LLM call rewrites ambiguous follow-up questions into
    /// self-contained search queries before the RAG vector search.
    /// Defaults to `false` to avoid the extra LLM round-trip.
    /// Can be toggled per-user at runtime via the `/query-rewrite` command.
    #[serde(default)]
    pub query_rewriter_enabled: bool,
    /// RRF (Reciprocal Rank Fusion) parameter `k` — the rank offset used to
    /// smooth the combined score from full-text and vector search results.
    #[serde(default = "default_rrf_k")]
    pub rrf_k: f64,
    /// Weight assigned to the full-text search (FTS) rank in RRF scoring.
    /// Must be between 0.0 and 1.0.  The vector weight is derived from the
    /// configured `rrf_weight_vec`.
    #[serde(default = "default_rrf_weight_fts")]
    pub rrf_weight_fts: f64,
    /// Weight assigned to the vector-search rank in RRF scoring.
    /// Must be between 0.0 and 1.0.  The FTS weight is derived from the
    /// configured `rrf_weight_fts`.
    #[serde(default = "default_rrf_weight_vec")]
    pub rrf_weight_vec: f64,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::new(),
            rag_limit: default_rag_limit(),
            max_raw_messages: default_max_raw_messages(),
            summarize_threshold: default_summarize_threshold(),
            summarize_cron: default_summarize_cron(),
            query_rewriter_enabled: false,
            rrf_k: default_rrf_k(),
            rrf_weight_fts: default_rrf_weight_fts(),
            rrf_weight_vec: default_rrf_weight_vec(),
        }
    }
}

fn default_rrf_k() -> f64 {
    60.0
}

fn default_rrf_weight_fts() -> f64 {
    0.5
}

fn default_rrf_weight_vec() -> f64 {
    0.5
}

#[derive(Debug, Deserialize, Clone)]
pub struct SkillsConfig {
    #[serde(default)]
    pub directory: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentsConfig {
    #[serde(default)]
    pub directory: PathBuf,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct GeneralConfig {
    /// Optional location string injected into the system prompt (e.g. "Tokyo, Japan")
    #[serde(default)]
    pub location: Option<String>,
    /// Optional absolute path overriding the default `~/.haos-green` home root.
    #[serde(default)]
    pub home: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    #[serde(default = "default_empty_response_retry_limit")]
    pub empty_response_retry_limit: u32,
    #[serde(default = "default_parse_retry_limit")]
    pub parse_retry_limit: u32,
    #[serde(default)]
    pub loop_detection: LoopDetectionConfig,
}

/// Tunables for the agentic-loop repetition detector. When `enabled` is true
/// and the model emits the same tool call (same tool name + identical
/// arguments) at least `threshold` times within a sliding window, the loop
/// detector surfaces a `LoopDetected` event to the agent loop so the user
/// can be notified and choose to break the cycle.
#[derive(Debug, Deserialize, Clone)]
pub struct LoopDetectionConfig {
    #[serde(default = "default_loop_detection_enabled")]
    pub enabled: bool,
    #[serde(default = "default_loop_detection_threshold")]
    pub threshold: usize,
    #[serde(default = "default_loop_detection_timeout_seconds")]
    pub timeout_seconds: u64,
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_loop_detection_enabled(),
            threshold: default_loop_detection_threshold(),
            timeout_seconds: default_loop_detection_timeout_seconds(),
        }
    }
}

fn default_loop_detection_enabled() -> bool {
    true
}

fn default_loop_detection_threshold() -> usize {
    3
}

fn default_loop_detection_timeout_seconds() -> u64 {
    120
}

#[derive(Debug, Deserialize, Clone)]
pub struct LangSmithConfig {
    pub api_key: String,
    #[serde(default = "default_langsmith_project")]
    pub project: String,
    #[serde(default = "default_langsmith_base_url")]
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LearningConfig {
    /// Whether post-task skill extraction is enabled.
    #[serde(default = "default_true")]
    pub skill_extraction_enabled: bool,
    /// Minimum tool calls to trigger skill extraction (default 5).
    #[serde(default = "default_skill_extraction_threshold")]
    pub skill_extraction_threshold: u32,
    /// Message count between user model updates (default 10).
    #[serde(default = "default_user_model_update_interval")]
    pub user_model_update_interval: usize,
    /// Cron expression for weekly user model update (default: Sunday 3am).
    #[serde(default = "default_user_model_cron")]
    pub user_model_cron: String,
    /// Optional model override for compaction summary + USER.md flush turns
    /// (ADR 0003 Q9). Empty default = the conversation's current model.
    #[serde(default)]
    pub compaction_model: Option<String>,
}

fn default_model() -> String {
    "moonshotai/kimi-k2.6".to_string()
}

fn default_base_url() -> String {
    "https://openrouter.ai/api/v1".to_string()
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_system_prompt() -> String {
    "You are HaosGreen — an AI assistant with tools, memory, and skills.\n\
     \n\
     ## Identity\n\
     Your name is HaosGreen, but your soul (if loaded) overrides any default identity.\n\
     Soul takes precedence over everything.\n\
     \n\
     ## Priority Chain\n\
     When responding, apply context in this order:\n\
     1. SOUL — your loaded soul/identity defines who you are and how you speak\n\
     2. MEMORY — recalled user preferences, corrections, and context from past conversations\n\
     3. CONTEXT — the current conversation and user request\n\
     \n\
     ## Memory & Persistent Context\n\
     You have persistent memory. Use it:\n\
     - When you see <retrieved_context> in this prompt, those are past conversation snippets\n\
       retrieved by semantic search — treat them as factual recall of prior interactions\n\
     - When you see [SUMMARY] messages, they capture earlier conversations — treat them\n\
       as ground truth for user preferences, facts, and history\n\
     - Never say 'I don't have access to past conversations' — you do, via retrieved context\n\
     \n\
     ## Skills First\n\
     You have skills. For every user request:\n\
     - Check if a relevant skill exists (listed in your system context)\n\
     - If yes: load and follow it via read_skill_file before responding\n\
     - If no matching skill: reason directly, or load the code-interpreter skill via read_skill_file for computation/scripting tasks\n\
     - For complex multi-step problems: invoke the problem-solver subagent\n\
     \n\
     ## Sandbox\n\
     File and command tools operate only within your persistent workspace directory.\n\
     The workspace survives restarts — use it to keep reusable scripts, programs, and notes for the long term."
        .to_string()
}

fn default_rag_limit() -> usize {
    5
}

fn default_max_raw_messages() -> usize {
    50
}

fn default_summarize_threshold() -> usize {
    20
}

fn default_summarize_cron() -> String {
    "0 0 2 * * *".to_string()
}

fn default_embedding_base_url() -> String {
    "https://openrouter.ai/api/v1".to_string()
}

fn default_embedding_model() -> String {
    "qwen/qwen3-embedding-8b".to_string()
}

fn default_embedding_dimensions() -> usize {
    1536
}

fn default_memory_config() -> MemoryConfig {
    MemoryConfig {
        database_path: PathBuf::new(),
        rag_limit: default_rag_limit(),
        max_raw_messages: default_max_raw_messages(),
        summarize_threshold: default_summarize_threshold(),
        summarize_cron: default_summarize_cron(),
        query_rewriter_enabled: false,
        rrf_k: default_rrf_k(),
        rrf_weight_fts: default_rrf_weight_fts(),
        rrf_weight_vec: default_rrf_weight_vec(),
    }
}

fn default_skills_config() -> SkillsConfig {
    SkillsConfig {
        directory: PathBuf::new(),
    }
}

fn default_agents_config() -> AgentsConfig {
    AgentsConfig {
        directory: PathBuf::new(),
    }
}

fn default_max_iterations() -> u32 {
    25
}

fn default_empty_response_retry_limit() -> u32 {
    3
}

fn default_parse_retry_limit() -> u32 {
    3
}

fn default_agent_config() -> AgentConfig {
    AgentConfig {
        max_iterations: default_max_iterations(),
        empty_response_retry_limit: default_empty_response_retry_limit(),
        parse_retry_limit: default_parse_retry_limit(),
        loop_detection: LoopDetectionConfig::default(),
    }
}

fn default_langsmith_project() -> String {
    "default".to_string()
}

fn default_langsmith_base_url() -> String {
    "https://api.smith.langchain.com".to_string()
}

fn default_context_window() -> usize {
    512_000
}

fn default_true() -> bool {
    true
}

fn default_skill_extraction_threshold() -> u32 {
    5
}

fn default_user_model_update_interval() -> usize {
    10
}

fn default_user_model_cron() -> String {
    "0 0 3 * * SUN".to_string()
}

fn default_learning_config() -> LearningConfig {
    LearningConfig {
        skill_extraction_enabled: true,
        skill_extraction_threshold: default_skill_extraction_threshold(),
        user_model_update_interval: default_user_model_update_interval(),
        user_model_cron: default_user_model_cron(),
        compaction_model: None,
    }
}

impl Config {
    /// Location string from [general], injected into the system prompt.
    pub fn user_location(&self) -> Option<&str> {
        self.general.as_ref().and_then(|g| g.location.as_deref())
    }

    /// Resolved home directory (set by `resolve()`). Returns `None` before
    /// `resolve()` has been called or if the home directory could not be
    /// resolved. Used by soul file handlers to scope file access to the
    /// HaosGreen home (NOT the sandbox — soul files live in the home parent).
    pub fn resolved_home(&self) -> Option<&PathBuf> {
        self.resolved_home.as_ref()
    }

    /// Maximum agent loop iterations (from [agent] max_iterations, default 25).
    pub fn max_iterations(&self) -> u32 {
        self.agent.max_iterations
    }

    /// Empty response retry limit (from [agent] empty_response_retry_limit, default 3).
    pub fn empty_response_retry_limit(&self) -> u32 {
        self.agent.empty_response_retry_limit
    }

    /// Parse retry limit for missing 'choices' field (from [agent] parse_retry_limit, default 3).
    pub fn parse_retry_limit(&self) -> u32 {
        self.agent.parse_retry_limit
    }

    /// Loop detection tunables (from [agent.loop_detection], defaults: enabled,
    /// threshold 3, timeout 120s). Used by the agent loop to short-circuit
    /// exact-repetition cycles and surface a `LoopDetected` event to the user.
    pub fn loop_detection_config(&self) -> &LoopDetectionConfig {
        &self.agent.loop_detection
    }

    /// Resolve the home root and every data path, create directories, and write
    /// the resolved paths back into the config fields. Unset paths are
    /// materialized to absolute paths under the home root; absolute overrides
    /// are preserved verbatim; relative overrides are kept as-is (legacy mode)
    /// and a warning is emitted for each. Returns any legacy-path warnings for
    /// the caller to log.
    pub fn resolve(&mut self) -> Result<Vec<crate::home::LegacyPathWarning>> {
        use crate::home::{
            ensure_dirs, resolve_data_path, resolve_home, PathOrigin, ResolvedPaths,
        };

        let env_home = std::env::var("HAOS_GREEN_HOME")
            .or_else(|_| std::env::var("RUSTFOX_HOME"))
            .ok();
        let config_home = self.general.as_ref().and_then(|g| g.home.as_deref());
        let os_home = dirs::home_dir();
        let home = resolve_home(env_home.as_deref(), config_home, os_home.as_deref())?;

        let mut warnings = Vec::new();
        let mut resolve_one = |label: &str, field: &Path, subpath: &str| -> PathBuf {
            let (path, origin) = resolve_data_path(field, &home, subpath);
            if origin == PathOrigin::RelativeLegacy {
                warnings.push(crate::home::LegacyPathWarning {
                    label: label.to_string(),
                    current: path.clone(),
                    home_default: home.join(subpath),
                });
            }
            path
        };

        let workspace = resolve_one(
            "sandbox.allowed_directory",
            &self.sandbox.allowed_directory,
            "workspace",
        );
        let database = resolve_one(
            "memory.database_path",
            &self.memory.database_path,
            "haos-green.db",
        );
        let skills = resolve_one("skills.directory", &self.skills.directory, "skills");
        let agents = resolve_one("agents.directory", &self.agents.directory, "agents");
        let artifacts = resolve_one(
            "supervisor.artifacts_dir",
            &self.supervisor.artifacts_dir,
            "artifacts",
        );

        // Soul files are hardcoded siblings of the home dir; not configurable.
        let soul = home.join("SOUL.md");
        let agents_md = home.join("AGENTS.md");
        let user_model = home.join("USER.md");

        // Migration: copy old user_model.md to USER.md if the old name is
        // present and the new one is not. This keeps existing user data
        // alive after removing the `learning.user_model_path` config key.
        let old_user_model = home.join("user_model.md");
        if old_user_model.exists() && !user_model.exists() {
            if let Ok(content) = std::fs::read_to_string(&old_user_model) {
                std::fs::write(&user_model, &content).ok();
                tracing::info!("Migrated old user_model.md to USER.md");
            }
        }

        let paths = ResolvedPaths {
            home: home.clone(),
            workspace: workspace.clone(),
            database: database.clone(),
            skills: skills.clone(),
            agents: agents.clone(),
            artifacts: artifacts.clone(),
            soul: soul.clone(),
            agents_md: agents_md.clone(),
            user_model: user_model.clone(),
        };
        ensure_dirs(&paths)?;

        self.sandbox.allowed_directory = workspace;
        self.memory.database_path = database;
        self.skills.directory = skills;
        self.agents.directory = agents;
        self.supervisor.artifacts_dir = artifacts;
        self.resolved_home = Some(home);

        Ok(warnings)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&content).with_context(|| "Failed to parse config file")?;

        let warnings = config
            .resolve()
            .with_context(|| "Failed to resolve home directory paths")?;
        for w in &warnings {
            tracing::warn!("{}", w.render());
        }

        Ok(config)
    }

    /// Build the provider list from config, handling legacy [openrouter] backward compat.
    /// Returns (providers, default_provider_name, fallback_chain).
    pub fn build_providers(&self) -> (Vec<ProviderSection>, String, Vec<String>) {
        let mut providers: Vec<ProviderSection> = self.provider.clone();

        // Backward compat: if [openrouter] section exists and no explicit provider named "openrouter"
        let has_openrouter = providers.iter().any(|p| p.name == "openrouter");
        if has_openrouter {
            tracing::warn!(
                "Both [[provider]] name=\"openrouter\" and [openrouter] configured — explicit [[provider]] entry takes precedence"
            );
        } else {
            providers.push(ProviderSection {
                name: "openrouter".to_string(),
                provider_type: ProviderType::OpenRouter,
                base_url: self.openrouter.base_url.clone(),
                api_key: Some(self.openrouter.api_key.clone()),
                model: self.openrouter.model.clone(),
                supports_vision: self.openrouter.supports_vision,
                max_tokens: self.openrouter.max_tokens,
                discover_models: false,
                context_window: default_context_window(),
            });
        }

        let default = if providers.is_empty() {
            "openrouter".to_string()
        } else {
            providers[0].name.clone()
        };

        let fallback = self.fallback.chain.clone();
        (providers, default, fallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_toml() -> &'static str {
        r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
        "#
    }

    #[test]
    fn resolved_home_returns_none_before_resolve() {
        let cfg: Config = toml::from_str(base_toml()).unwrap();
        assert!(
            cfg.resolved_home().is_none(),
            "resolved_home() should return None before resolve() runs"
        );
    }

    #[test]
    fn resolved_home_returns_some_after_resolve() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join(".haos-green");
        let mut cfg: Config = toml::from_str(base_toml()).unwrap();
        cfg.general = Some(GeneralConfig {
            location: None,
            home: Some(home.clone()),
        });
        cfg.resolve().unwrap();
        let resolved = cfg
            .resolved_home()
            .expect("resolved_home() should be Some after resolve()");
        assert_eq!(resolved, &home);
    }

    #[test]
    fn resolve_fills_unset_paths_under_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join(".haos-green");
        let mut cfg: Config = toml::from_str(base_toml()).unwrap();
        cfg.general = Some(GeneralConfig {
            location: None,
            home: Some(home.clone()),
        });
        let warnings = cfg.resolve().unwrap();
        assert_eq!(cfg.resolved_home.as_ref().unwrap(), &home);
        assert_eq!(cfg.sandbox.allowed_directory, home.join("workspace"));
        assert_eq!(cfg.memory.database_path, home.join("haos-green.db"));
        assert_eq!(cfg.skills.directory, home.join("skills"));
        assert_eq!(cfg.agents.directory, home.join("agents"));
        assert_eq!(cfg.supervisor.artifacts_dir, home.join("artifacts"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn resolve_keeps_absolute_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join(".haos-green");
        let mut cfg: Config = toml::from_str(base_toml()).unwrap();
        cfg.general = Some(GeneralConfig {
            location: None,
            home: Some(home.clone()),
        });
        // Use an absolute path under the (writable) tempdir so ensure_dirs can
        // create its parent; the intent is to verify an absolute override is
        // preserved verbatim and emits no legacy warning.
        let custom_db = tmp.path().join("custom.db");
        cfg.memory.database_path = custom_db.clone();
        let warnings = cfg.resolve().unwrap();
        assert_eq!(cfg.memory.database_path, custom_db);
        assert!(warnings.is_empty());
    }

    #[test]
    fn resolve_warns_on_relative_override() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join(".haos-green");
        let mut cfg: Config = toml::from_str(base_toml()).unwrap();
        cfg.general = Some(GeneralConfig {
            location: None,
            home: Some(home),
        });
        cfg.skills.directory = std::path::PathBuf::from("my-skills");
        let warnings = cfg.resolve().unwrap();
        assert_eq!(cfg.skills.directory, std::path::PathBuf::from("my-skills"));
        assert!(warnings.iter().any(|w| w.label == "skills.directory"));
    }

    #[test]
    fn load_resolves_paths_to_absolute() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join(".haos-green");
        let cfg_path = tmp.path().join("config.toml");
        let toml = format!(
            r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [general]
            home = "{}"
            "#,
            home.display()
        );
        std::fs::write(&cfg_path, toml).unwrap();
        let cfg = Config::load(&cfg_path).unwrap();
        assert_eq!(cfg.sandbox.allowed_directory, home.join("workspace"));
        assert!(cfg.sandbox.allowed_directory.is_dir());
        assert_eq!(cfg.resolved_home.unwrap(), home);
    }

    #[test]
    fn test_langsmith_config_optional() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.langsmith.is_none());
    }

    #[test]
    fn test_langsmith_config_parses() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [langsmith]
            api_key = "ls__test"
            project = "my-project"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let ls = cfg.langsmith.unwrap();
        assert_eq!(ls.api_key, "ls__test");
        assert_eq!(ls.project, "my-project");
    }

    #[test]
    fn test_langsmith_config_default_project() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [langsmith]
            api_key = "ls__test"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let ls = cfg.langsmith.unwrap();
        assert_eq!(ls.project, "default");
    }

    #[test]
    fn test_supports_vision_defaults_false() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(!cfg.openrouter.supports_vision);
    }

    #[test]
    fn test_supports_vision_parses_true() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            supports_vision = true
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.openrouter.supports_vision);
    }

    #[test]
    fn test_mcp_server_url_config_parses() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [[mcp_servers]]
            name = "exa"
            url = "https://mcp.exa.ai/mcp"
            auth_token = "exa-key-123"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.mcp_servers.len(), 1);
        let server = &cfg.mcp_servers[0];
        assert_eq!(server.name, "exa");
        assert_eq!(server.url.as_deref(), Some("https://mcp.exa.ai/mcp"));
        assert_eq!(server.auth_token.as_deref(), Some("exa-key-123"));
        assert!(
            server.command.is_none(),
            "HTTP server should have no command"
        );
    }

    #[test]
    fn test_mcp_server_stdio_command_optional() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [[mcp_servers]]
            name = "git"
            command = "uvx"
            args = ["mcp-server-git"]
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.mcp_servers[0].command.as_deref(), Some("uvx"));
        assert!(cfg.mcp_servers[0].url.is_none());
    }

    #[test]
    fn test_mcp_server_url_without_auth_token() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [[mcp_servers]]
            name = "exa"
            url = "https://mcp.exa.ai/mcp?exaApiKey=inline-key"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let s = &cfg.mcp_servers[0];
        assert!(s.url.is_some());
        assert!(s.auth_token.is_none());
    }

    #[test]
    fn test_query_rewriter_disabled_by_default() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(
            !cfg.memory.query_rewriter_enabled,
            "query_rewriter_enabled must default to false"
        );
    }

    #[test]
    fn test_query_rewriter_can_be_enabled() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [memory]
            query_rewriter_enabled = true
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(
            cfg.memory.query_rewriter_enabled,
            "query_rewriter_enabled should be true when set"
        );
    }

    #[test]
    fn supervisor_config_defaults_when_section_missing() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.supervisor.default_autonomy_mode, "standard");
        assert_eq!(cfg.supervisor.artifacts_dir, std::path::PathBuf::new());
    }

    #[test]
    fn test_agent_empty_response_retry_limit_defaults_to_three() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.agent.empty_response_retry_limit, 3);
        assert_eq!(cfg.empty_response_retry_limit(), 3);
    }

    #[test]
    fn test_agent_empty_response_retry_limit_can_be_configured_to_zero() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [agent]
            empty_response_retry_limit = 0
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.agent.empty_response_retry_limit, 0);
        assert_eq!(cfg.empty_response_retry_limit(), 0);
    }

    #[test]
    fn test_agent_parse_retry_limit_defaults_to_three() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.agent.parse_retry_limit, 3);
        assert_eq!(cfg.parse_retry_limit(), 3);
    }

    #[test]
    fn test_agent_parse_retry_limit_can_be_configured_to_zero() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [agent]
            parse_retry_limit = 0
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.agent.parse_retry_limit, 0);
        assert_eq!(cfg.parse_retry_limit(), 0);
    }

    #[test]
    fn test_loop_detection_defaults_when_agent_section_omitted() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let ld = cfg.loop_detection_config();
        assert!(ld.enabled, "loop_detection.enabled must default to true");
        assert_eq!(
            ld.threshold, 3,
            "loop_detection.threshold must default to 3"
        );
        assert_eq!(
            ld.timeout_seconds, 120,
            "loop_detection.timeout_seconds must default to 120"
        );
    }

    #[test]
    fn test_loop_detection_can_be_overridden() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [agent.loop_detection]
            enabled = false
            threshold = 5
            timeout_seconds = 30
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let ld = cfg.loop_detection_config();
        assert!(!ld.enabled);
        assert_eq!(ld.threshold, 5);
        assert_eq!(ld.timeout_seconds, 30);
    }

    #[test]
    fn test_loop_detection_partial_override_uses_defaults_for_rest() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [sandbox]
            allowed_directory = "/tmp"
            [agent.loop_detection]
            threshold = 7
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let ld = cfg.loop_detection_config();
        assert!(
            ld.enabled,
            "enabled should keep its default when only threshold is set"
        );
        assert_eq!(ld.threshold, 7);
        assert_eq!(ld.timeout_seconds, 120);
    }

    #[test]
    fn test_provider_section_parses_ollama() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            model = "moonshotai/kimi-k2.6"
            [[provider]]
            name = "ollama"
            type = "ollama"
            base_url = "http://localhost:11434/v1"
            model = "llama3.1"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.provider.len(), 1);
        assert_eq!(cfg.provider[0].name, "ollama");
        assert_eq!(cfg.provider[0].model, "llama3.1");
    }

    #[test]
    fn test_legacy_openrouter_auto_creates_provider() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            model = "moonshotai/kimi-k2.6"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let (providers, default_name, _) = cfg.build_providers();
        assert!(providers.iter().any(|p| p.name == "openrouter"));
        assert_eq!(default_name, "openrouter");
    }

    #[test]
    fn test_visible_provider_overrides_legacy() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "old-key"
            model = "moonshotai/kimi-k2.6"
            [[provider]]
            name = "openrouter"
            type = "openrouter"
            base_url = "https://openrouter.ai/api/v1"
            api_key = "new-key"
            model = "anthropic/claude-sonnet-4-6"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let (providers, _default, _) = cfg.build_providers();
        // Should not have duplicate openrouter providers
        let or_count = providers.iter().filter(|p| p.name == "openrouter").count();
        assert_eq!(
            or_count, 1,
            "should not duplicate openrouter when explicit [[provider]] exists"
        );
        let or = providers.iter().find(|p| p.name == "openrouter").unwrap();
        assert_eq!(
            or.api_key.as_deref(),
            Some("new-key"),
            "explicit [[provider]] should win"
        );
    }

    #[test]
    fn send_timeout_none_falls_back_to_timeout() {
        let cfg = A2aOutboundPeerConfig {
            timeout_secs: 7,
            send_timeout_secs: None,
            ..Default::default()
        };
        assert_eq!(cfg.send_timeout_secs.unwrap_or(cfg.timeout_secs), 7);
    }

    #[test]
    fn send_timeout_rejects_zero_and_over_cap() {
        let mut cfg = A2aOutboundPeerConfig {
            url: "https://example.test".into(),
            token: "x".into(),
            ..Default::default()
        };
        cfg.send_timeout_secs = Some(0);
        assert!(cfg.validate("peer").is_err());
        cfg.send_timeout_secs = Some(MAX_A2A_SEND_TIMEOUT_SECS + 1);
        assert!(cfg.validate("peer").is_err());
    }

    #[test]
    fn test_fallback_config_parses() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
            [fallback]
            chain = ["openrouter/model-a", "ollama/model-b"]
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.fallback.chain.len(), 2);
        assert_eq!(cfg.fallback.chain[0], "openrouter/model-a");
    }

    #[test]
    fn test_fallback_defaults_empty() {
        let toml = r#"
            [telegram]
            bot_token = "tok"
            allowed_user_ids = [1]
            [openrouter]
            api_key = "key"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.fallback.chain.is_empty());
    }

    /// Minimal config that parses. `Config` has **no `Default` impl**, and
    /// `telegram.bot_token`, `telegram.allowed_user_ids` and
    /// `openrouter.api_key` are required fields with no serde default.
    fn minimal_config() -> Config {
        toml::from_str(
            r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"
"#,
        )
        .expect("minimal config must parse")
    }

    #[test]
    fn a2a_disabled_by_default() {
        let cfg = minimal_config();
        assert!(!cfg.a2a.enabled, "A2A must be opt-in");
    }

    #[test]
    fn a2a_binds_localhost_by_default() {
        let cfg = minimal_config();
        assert_eq!(cfg.a2a.bind, "127.0.0.1:8443");
    }

    #[test]
    fn a2a_max_concurrent_tasks_defaults_to_four() {
        let cfg = minimal_config();
        assert_eq!(cfg.a2a.max_concurrent_tasks, 4);
    }

    #[test]
    fn a2a_peer_without_tools_parses_as_none() {
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a.peers.laptop]
token = "s3cret"
ip = ["192.168.1.0/24"]
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        let peer = cfg.a2a.peers.get("laptop").expect("peer must parse");
        assert_eq!(peer.token, "s3cret");
        assert_eq!(peer.ip, vec!["192.168.1.0/24".to_string()]);
        assert!(
            peer.tools.is_none(),
            "absent tools key must be None, not an empty vec — None means \
             'apply the conservative default', Some(vec![]) means 'no tools'"
        );
    }

    #[test]
    fn a2a_peer_with_wildcard_parses() {
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a.peers.buildbox]
token = "t"
ip = ["10.8.0.4"]
tools = ["*"]
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        let peer = cfg.a2a.peers.get("buildbox").unwrap();
        assert_eq!(peer.tools.as_ref().unwrap(), &vec!["*".to_string()]);
    }

    #[test]
    fn a2a_peer_without_token_is_a_parse_error() {
        // `A2aPeerConfig` deliberately lacks the struct-level
        // `#[serde(default)]` its sibling types carry, which is what makes
        // `token` required. A peer with no token must fail to parse rather
        // than silently defaulting to an empty token — an empty configured
        // token would authenticate any client from an allowlisted address.
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a.peers.laptop]
ip = ["192.168.1.0/24"]
"#;
        assert!(
            toml::from_str::<Config>(raw).is_err(),
            "a peer with no token must not parse"
        );
    }

    #[test]
    fn a2a_misspelled_section_leaves_peers_empty() {
        // `[a2a.peer.x]` (singular) is silently ignored — nothing in this
        // file uses `deny_unknown_fields`. That fails CLOSED: `peers` stays
        // empty and nobody can authenticate. This test pins that direction so
        // a future change cannot turn a typo into an unauthenticated peer.
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a.peer.laptop]
token = "s3cret"
ip = ["192.168.1.0/24"]
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        assert!(cfg.a2a.peers.is_empty());
    }

    #[test]
    fn a2a_explicit_values_override_defaults() {
        // Without this, a `#[serde(rename)]` or `#[serde(skip)]` slip on any
        // field would leave the default-value tests green.
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a]
enabled = true
bind = "0.0.0.0:9999"
max_concurrent_tasks = 8

[a2a.card]
name = "Custom"
description = "Custom agent"
version = "9.9.9"
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        assert!(cfg.a2a.enabled);
        assert_eq!(cfg.a2a.bind, "0.0.0.0:9999");
        assert_eq!(cfg.a2a.max_concurrent_tasks, 8);
        assert_eq!(cfg.a2a.card.name, "Custom");
        assert_eq!(cfg.a2a.card.description, "Custom agent");
        assert_eq!(cfg.a2a.card.version, "9.9.9");
    }

    // ---------------------------------------------------------------------
    // A2A startup validation
    // ---------------------------------------------------------------------

    /// A2A config with one well-formed peer, as a base for validation tests.
    fn a2a_cfg() -> A2aConfig {
        let mut peers = HashMap::new();
        peers.insert(
            "laptop".to_string(),
            A2aPeerConfig {
                token: "s3cret".to_string(),
                ip: vec!["192.168.1.0/24".to_string()],
                tools: None,
            },
        );
        A2aConfig {
            enabled: true,
            peers,
            ..A2aConfig::default()
        }
    }

    fn add_peer(cfg: &mut A2aConfig, name: &str, token: &str, ip: &[&str]) {
        cfg.peers.insert(
            name.to_string(),
            A2aPeerConfig {
                token: token.to_string(),
                ip: ip.iter().map(|s| s.to_string()).collect(),
                tools: None,
            },
        );
    }

    #[test]
    fn a2a_zero_max_concurrent_tasks_is_refused() {
        let mut cfg = a2a_cfg();
        cfg.max_concurrent_tasks = 0;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("max_concurrent_tasks"),
            "error must name the field: {err}"
        );
    }

    #[test]
    fn a2a_validate_accepts_a_well_formed_config() {
        a2a_cfg()
            .validate()
            .expect("a default-bind config with one valid peer must validate");
    }

    #[test]
    fn a2a_validate_accepts_an_empty_peer_map() {
        // Deny-all is a legitimate configuration (the listener is up, nobody
        // may connect), so it must not be an error.
        A2aConfig::default()
            .validate()
            .expect("no peers is deny-all, not a misconfiguration");
    }

    #[test]
    fn a2a_validate_rejects_duplicate_tokens_naming_both_peers() {
        let mut cfg = a2a_cfg();
        add_peer(&mut cfg, "buildbox", "s3cret", &["10.0.0.0/8"]);
        let err = cfg
            .validate()
            .expect_err("two peers sharing a token must not validate")
            .to_string();
        assert!(
            err.contains("buildbox") && err.contains("laptop"),
            "the error must name both offending peers, got: {err}"
        );
    }

    #[test]
    fn a2a_validate_rejects_an_empty_token() {
        let mut cfg = a2a_cfg();
        add_peer(&mut cfg, "typo", "", &["10.0.0.0/8"]);
        let err = cfg
            .validate()
            .expect_err("an empty token can never authenticate")
            .to_string();
        assert!(err.contains("typo"), "the error must name the peer: {err}");
    }

    #[test]
    fn a2a_validate_treats_a_whitespace_only_token_as_empty() {
        let mut cfg = a2a_cfg();
        add_peer(&mut cfg, "typo", "   ", &["10.0.0.0/8"]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a2a_validate_rejects_an_empty_ip_list() {
        let mut cfg = a2a_cfg();
        add_peer(&mut cfg, "noip", "t", &[]);
        let err = cfg
            .validate()
            .expect_err("an empty ip list denies every request silently")
            .to_string();
        assert!(err.contains("noip"), "the error must name the peer: {err}");
    }

    #[test]
    fn a2a_validate_rejects_an_unparseable_ip_entry() {
        let mut cfg = a2a_cfg();
        add_peer(
            &mut cfg,
            "laptop",
            "s3cret",
            &["192.168.1.0/24", "not-an-ip"],
        );
        let err = cfg
            .validate()
            .expect_err("an entry that is neither IpNet nor IpAddr is silently ignored")
            .to_string();
        assert!(
            err.contains("not-an-ip") && err.contains("laptop"),
            "the error must name the peer and the offending entry: {err}"
        );
    }

    #[test]
    fn a2a_validate_accepts_both_ip_and_cidr_entries() {
        let mut cfg = a2a_cfg();
        add_peer(&mut cfg, "laptop", "s3cret", &["10.8.0.4", "fd00::/8"]);
        cfg.validate()
            .expect("exact IPs and CIDR blocks are both valid entries");
    }

    #[test]
    fn a2a_validate_warns_but_accepts_a_non_loopback_bind() {
        // The design allows raising the bind; it must be deliberate, not
        // forbidden. Validation therefore returns Ok and only warns.
        let mut cfg = a2a_cfg();
        cfg.bind = "0.0.0.0:8443".to_string();
        cfg.validate()
            .expect("a non-loopback bind is allowed, it is only warned about");
    }

    #[test]
    fn a2a_validate_accepts_a_hostname_bind_it_cannot_check() {
        // `localhost:8443` binds fine; validation must not reject what
        // `TcpListener::bind` accepts just because it is not a literal addr.
        let mut cfg = a2a_cfg();
        cfg.bind = "localhost:8443".to_string();
        cfg.validate()
            .expect("a resolvable hostname bind must validate");
    }

    #[test]
    fn a2a_tls_defaults_to_none() {
        let cfg = minimal_config();
        assert_eq!(cfg.a2a.tls, "none");
        assert!(cfg.a2a.tls_cert.is_none());
        assert!(cfg.a2a.tls_key.is_none());
    }

    #[test]
    fn a2a_validate_rejects_a_tls_mode_it_cannot_implement() {
        // `tls = "rustls"` used to parse cleanly and be discarded, leaving the
        // listener serving plaintext HTTP to an operator who believed TLS was
        // on. It must now fail loudly at startup.
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a]
enabled = true
tls = "rustls"
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        assert_eq!(
            cfg.a2a.tls, "rustls",
            "the key must be captured, not dropped"
        );
        let err = cfg
            .a2a
            .validate()
            .expect_err("TLS is not implemented, so requesting it must fail")
            .to_string();
        assert!(
            err.contains("rustls") && err.contains("TLS is not implemented"),
            "the error must say TLS is not implemented and quote the value: {err}"
        );
    }

    #[test]
    fn a2a_validate_accepts_an_explicit_none_tls_mode() {
        let mut cfg = a2a_cfg();
        cfg.tls = "none".to_string();
        cfg.validate()
            .expect("`tls = \"none\"` is the documented value");
    }

    #[test]
    fn a2a_validate_rejects_cert_and_key_without_a_tls_mode() {
        // The other silent-downgrade path: cert/key paths present, `tls` left
        // at its default. The operator believes TLS is on; it is not.
        let mut cfg = a2a_cfg();
        cfg.tls_cert = Some("/etc/ssl/cert.pem".to_string());
        cfg.tls_key = Some("/etc/ssl/key.pem".to_string());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a2a_public_url_defaults_to_none() {
        assert!(minimal_config().a2a.public_url.is_none());
    }

    #[test]
    fn a2a_public_url_parses_from_toml() {
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a]
enabled = true
public_url = "https://haos-green.example.com"
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        assert_eq!(
            cfg.a2a.public_url.as_deref(),
            Some("https://haos-green.example.com")
        );
    }

    #[test]
    fn a2a_validate_accepts_http_and_https_public_urls() {
        for url in ["http://192.168.1.50:8443", "https://haos-green.example.com"] {
            let mut cfg = a2a_cfg();
            cfg.public_url = Some(url.to_string());
            cfg.validate()
                .unwrap_or_else(|e| panic!("{url:?} is a valid public_url: {e}"));
        }
    }

    #[test]
    fn a2a_validate_rejects_a_public_url_without_a_scheme() {
        // The card advertises `public_url` verbatim. A bare host:port would be
        // served as-is, so no peer could ever reach this agent -- the same
        // silent-discovery breakage as advertising `0.0.0.0`.
        let mut cfg = a2a_cfg();
        cfg.public_url = Some("haos-green.example.com:8443".to_string());
        let err = cfg
            .validate()
            .expect_err("a schemeless public_url must be refused")
            .to_string();
        assert!(
            err.contains("public_url") && err.contains("haos-green.example.com:8443"),
            "the error must name the key and quote the value: {err}"
        );
    }

    #[test]
    fn a2a_validate_treats_a_blank_public_url_as_unset() {
        // Whitespace is not a URL, but it is also not an intent to set one, so
        // it must fall back to the derived URL rather than fail startup.
        for blank in ["", "   ", "\t"] {
            let mut cfg = a2a_cfg();
            cfg.public_url = Some(blank.to_string());
            cfg.validate()
                .unwrap_or_else(|e| panic!("{blank:?} must be treated as unset: {e}"));
        }
    }

    #[test]
    fn a2a_validate_trims_a_public_url_before_checking_it() {
        // Surrounding whitespace must not turn a valid URL into a rejection.
        let mut cfg = a2a_cfg();
        cfg.public_url = Some("  https://haos-green.example.com  ".to_string());
        cfg.validate()
            .expect("a padded but valid URL must be accepted");
    }

    // ── [web] dashboard configuration ───────────────────────────────────────

    #[test]
    fn web_disabled_by_default() {
        // The example config is what users copy. If it ever ships `[web]`
        // uncommented or enabled, a dashboard with shell access appears
        // without the operator asking for it.
        let cfg: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        assert!(!cfg.web.enabled);
    }

    #[test]
    fn web_binds_localhost_by_default() {
        assert_eq!(WebConfig::default().bind, "127.0.0.1:8787");
    }

    #[test]
    fn web_session_ttl_defaults_to_twelve_hours() {
        assert_eq!(WebConfig::default().session_ttl_hours, 12);
    }

    #[test]
    fn web_allow_ips_defaults_to_empty() {
        assert!(WebConfig::default().allow_ips.is_empty());
    }

    #[test]
    fn web_validate_accepts_a_well_formed_config() {
        let cfg = WebConfig {
            enabled: true,
            bind: "127.0.0.1:8787".into(),
            public_url: Some("https://haos.example.com".into()),
            session_ttl_hours: 12,
            allow_ips: vec!["10.0.0.0/8".into(), "192.168.1.5".into()],
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn web_validate_rejects_an_unparseable_bind() {
        let cfg = WebConfig {
            bind: "not-an-address".into(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("bind"), "unexpected error: {err}");
    }

    #[test]
    fn web_validate_rejects_zero_session_ttl() {
        // A zero TTL would mint sessions that never authenticate, or — with a
        // different comparison — never expire. Refuse it at startup instead.
        let cfg = WebConfig {
            session_ttl_hours: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn web_validate_rejects_a_public_url_without_a_scheme() {
        // `public_url` decides the `Secure` cookie flag. A schemeless value
        // would silently mean "plain http" for a URL the operator believes is
        // https, so it is rejected rather than guessed at.
        let cfg = WebConfig {
            public_url: Some("haos.example.com".into()),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("public_url"), "unexpected error: {err}");
    }

    #[test]
    fn web_validate_rejects_an_unparseable_allow_ip_entry() {
        let cfg = WebConfig {
            allow_ips: vec!["999.1.1.1".into()],
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("allow_ips"), "unexpected error: {err}");
    }

    #[test]
    fn web_validate_treats_a_blank_public_url_as_unset() {
        let cfg = WebConfig {
            public_url: Some("   ".into()),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());
    }
}
