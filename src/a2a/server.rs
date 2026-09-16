//! A2A HTTP listener.

use crate::a2a::auth::{authenticate, AuthError};
use crate::a2a::card::build_agent_card;
use crate::config::A2aConfig;
use crate::skills::SkillRegistry;
use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

/// Shared state for the A2A listener.
pub struct A2aState {
    pub config: A2aConfig,
    pub skills: SkillRegistry,
    /// Base URL advertised in the Agent Card. Resolved once, after the
    /// listener has bound, so it reflects the address that was actually bound
    /// (see `resolve_endpoint_url`); it is never mutated afterwards.
    pub endpoint_url: String,
}

/// Build the shared listener state.
pub fn build_state(config: A2aConfig, skills: SkillRegistry, endpoint_url: &str) -> Arc<A2aState> {
    Arc::new(A2aState {
        config,
        skills,
        endpoint_url: endpoint_url.to_string(),
    })
}

/// Resolve the base URL the Agent Card advertises to peers.
///
/// `[a2a].public_url` wins when set. Otherwise the URL is derived from `bound`
/// — the address the listener *actually* bound, not `config.bind` verbatim.
/// That matters for an ephemeral `bind` (`127.0.0.1:0`), which would otherwise
/// advertise port 0, and it turns a hostname bind (`localhost:8443`) into the
/// concrete address it resolved to.
///
/// An unspecified bind (`0.0.0.0`, `::`) is advertised as-is but warned about:
/// the card is served either way, and a remote peer connecting to `0.0.0.0`
/// would reach its own loopback rather than this agent. Substituting a
/// guessed hostname would be worse than saying so. Loopback binds are not
/// warned about — a peer running on this same host is a supported setup, and
/// warning on the default configuration would be noise.
pub fn resolve_endpoint_url(config: &A2aConfig, bound: SocketAddr) -> String {
    if let Some(url) = config
        .public_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        return url.to_string();
    }

    let derived = format!("http://{bound}");
    if bound.ip().is_unspecified() {
        warn!(
            bind = %bound,
            advertised = %derived,
            "A2A: the advertised endpoint URL is not reachable by a remote peer, because \
             [a2a].bind is an unspecified address — a peer connecting to it reaches its own \
             loopback. Set [a2a].public_url to this host's externally reachable base URL."
        );
    }
    derived
}

/// Build the A2A router.
///
/// `/.well-known/agent-card.json` is public by design — A2A clients fetch the
/// card before authenticating. Every other route requires a valid peer.
///
/// A 2 MB body limit is applied to guard against unbounded payloads.
pub fn router(state: Arc<A2aState>) -> Router {
    Router::new()
        .route("/.well-known/agent-card.json", get(agent_card_handler))
        .route("/jsonrpc", post(jsonrpc_handler))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state)
}

/// Serve the Agent Card. Public, unauthenticated.
async fn agent_card_handler(State(state): State<Arc<A2aState>>) -> impl IntoResponse {
    let card = build_agent_card(&state.config.card, &state.skills, &state.endpoint_url);
    Json(card)
}

/// JSON-RPC endpoint. Phase 1 authenticates and then refuses, because no
/// executor exists yet. Returning 501 rather than 200 is deliberate: a client
/// must not believe a task was accepted.
async fn jsonrpc_handler(
    State(state): State<Arc<A2aState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_bearer(Some(v)));

    match authenticate(&state.config, bearer, addr.ip()) {
        Ok(identity) => {
            info!(
                peer = %identity.name,
                tools = identity.allowed_tools.len(),
                "A2A peer authenticated; no executor implemented yet (Phase 2)"
            );
            (
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "No A2A method is implemented yet"
                    }
                })),
            )
        }
        Err(AuthError::MissingToken) => {
            warn!(peer_ip = %addr.ip(), "A2A request without a bearer token");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
        }
        Err(AuthError::InvalidToken) => {
            warn!(peer_ip = %addr.ip(), "A2A request with an unknown token");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
        }
        Err(AuthError::AmbiguousToken) => {
            // Misconfiguration, not a client error: two peers share a token.
            // 500 is deliberate so it shows up as a server-side fault rather
            // than being mistaken for a bad credential.
            warn!(
                peer_ip = %addr.ip(),
                "A2A request refused: two peers share the same token"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({})),
            )
        }
        Err(AuthError::IpNotAllowed) => {
            warn!(peer_ip = %addr.ip(), "A2A peer authenticated from a disallowed address");
            (StatusCode::FORBIDDEN, Json(serde_json::json!({})))
        }
    }
}

/// Extract the token from an `Authorization: Bearer <token>` header value.
fn parse_bearer(header: Option<&str>) -> Option<&str> {
    let value = header?.trim_start();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Start the A2A listener and return the address it bound.
///
/// The bind address is resolved before spawning so a configuration error
/// surfaces at startup rather than silently inside a detached task.
///
/// The advertised URL is resolved *after* the bind and the state is built from
/// it, so `A2aState.endpoint_url` always names the real port — an ephemeral
/// `bind` of `127.0.0.1:0` advertises the port the OS assigned, never port 0.
/// Building the state here rather than taking it from the caller is what lets
/// `endpoint_url` stay an immutable `String`: nothing needs to mutate it, so
/// no `OnceLock`/`RwLock` is required.
pub async fn spawn(config: A2aConfig, skills: SkillRegistry) -> Result<SocketAddr> {
    let addr = config.bind.clone();

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("A2A: failed to bind {addr}"))?;

    let local = listener
        .local_addr()
        .context("A2A: could not read the bound address")?;

    let endpoint_url = resolve_endpoint_url(&config, local);
    info!(address = %local, advertised = %endpoint_url, "A2A listener started");

    let app = router(build_state(config, skills, &endpoint_url));

    tokio::spawn(async move {
        // `into_make_service_with_connect_info` is required for the
        // `ConnectInfo<SocketAddr>` extractor the auth path depends on.
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            warn!(error = %e, "A2A listener stopped with an error");
        }
    });

    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{A2aCardConfig, A2aConfig, A2aPeerConfig};
    use crate::skills::SkillRegistry;
    use std::collections::HashMap;

    fn test_config() -> A2aConfig {
        let mut peers = HashMap::new();
        peers.insert(
            "laptop".to_string(),
            A2aPeerConfig {
                token: "s3cret".to_string(),
                ip: vec!["127.0.0.0/8".to_string()],
                tools: None,
            },
        );
        A2aConfig {
            enabled: true,
            bind: "127.0.0.1:0".to_string(),
            card: A2aCardConfig::default(),
            peers,
            ..A2aConfig::default()
        }
    }

    #[test]
    fn parse_bearer_extracts_the_token() {
        assert_eq!(parse_bearer(Some("Bearer s3cret")), Some("s3cret"));
    }

    #[test]
    fn parse_bearer_is_case_insensitive_on_the_scheme() {
        assert_eq!(parse_bearer(Some("bearer s3cret")), Some("s3cret"));
    }

    #[test]
    fn parse_bearer_rejects_a_missing_scheme() {
        assert_eq!(parse_bearer(Some("s3cret")), None);
    }

    #[test]
    fn parse_bearer_rejects_a_different_scheme() {
        assert_eq!(parse_bearer(Some("Basic s3cret")), None);
    }

    #[test]
    fn parse_bearer_handles_absence() {
        assert_eq!(parse_bearer(None), None);
    }

    #[test]
    fn parse_bearer_trims_surrounding_whitespace() {
        assert_eq!(parse_bearer(Some("Bearer  s3cret ")), Some("s3cret"));
        assert_eq!(parse_bearer(Some("  Bearer s3cret")), Some("s3cret"));
    }

    #[test]
    fn router_builds_without_panicking() {
        let state = build_state(test_config(), SkillRegistry::new(), "http://localhost:8443");
        let _router = router(state);
    }

    // ---------------------------------------------------------------------
    // Advertised endpoint URL
    // ---------------------------------------------------------------------

    fn bound(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn advertised_url_uses_the_actual_bound_port_not_port_zero() {
        // `test_config()` binds "127.0.0.1:0". The OS picks the real port;
        // advertising the literal `bind` would put `:0` in the Agent Card and
        // no peer could ever reach it.
        let cfg = test_config();
        assert!(
            cfg.bind.ends_with(":0"),
            "precondition: bind asks for port 0"
        );
        let url = resolve_endpoint_url(&cfg, bound("127.0.0.1:54321"));
        assert_eq!(url, "http://127.0.0.1:54321");
        assert!(!url.ends_with(":0"), "port 0 must never be advertised");
    }

    #[test]
    fn advertised_url_keeps_the_bound_host() {
        let mut cfg = test_config();
        cfg.bind = "192.168.1.5:8443".to_string();
        assert_eq!(
            resolve_endpoint_url(&cfg, bound("192.168.1.5:8443")),
            "http://192.168.1.5:8443"
        );
    }

    #[test]
    fn advertised_url_brackets_an_ipv6_address() {
        let mut cfg = test_config();
        cfg.bind = "[::1]:8443".to_string();
        assert_eq!(
            resolve_endpoint_url(&cfg, bound("[::1]:8443")),
            "http://[::1]:8443"
        );
    }

    #[test]
    fn public_url_overrides_the_derived_url() {
        let mut cfg = test_config();
        cfg.public_url = Some("https://rustfox.example.com:8443".to_string());
        assert_eq!(
            resolve_endpoint_url(&cfg, bound("0.0.0.0:54321")),
            "https://rustfox.example.com:8443"
        );
    }

    #[test]
    fn public_url_is_trimmed() {
        let mut cfg = test_config();
        cfg.public_url = Some("  https://rustfox.example.com  ".to_string());
        assert_eq!(
            resolve_endpoint_url(&cfg, bound("127.0.0.1:54321")),
            "https://rustfox.example.com"
        );
    }

    #[test]
    fn blank_public_url_falls_back_to_the_derived_url() {
        // `public_url = ""` is a common way to disable a key; it must not
        // produce an empty `url` in the card.
        let mut cfg = test_config();
        cfg.public_url = Some("   ".to_string());
        assert_eq!(
            resolve_endpoint_url(&cfg, bound("127.0.0.1:54321")),
            "http://127.0.0.1:54321"
        );
    }

    #[test]
    fn unspecified_bind_is_advertised_verbatim_and_warned_about() {
        // No hostname is invented: the operator gets the warning and sets
        // `public_url`. This test pins the value; the warning is asserted by
        // reading the source of `resolve_endpoint_url`, since capturing
        // `tracing` output needs a subscriber the test suite does not install.
        let mut cfg = test_config();
        cfg.bind = "0.0.0.0:8443".to_string();
        let url = resolve_endpoint_url(&cfg, bound("0.0.0.0:8443"));
        assert_eq!(url, "http://0.0.0.0:8443");
        assert!(bound("0.0.0.0:8443").ip().is_unspecified());
    }
}
