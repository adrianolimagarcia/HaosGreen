//! A2A HTTP listener.

use crate::a2a::auth::{authenticate, AuthError};
use crate::a2a::card::build_agent_card;
use crate::config::A2aConfig;
use crate::skills::SkillRegistry;
use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, State},
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

/// Build the A2A router.
///
/// `/.well-known/agent-card.json` is public by design — A2A clients fetch the
/// card before authenticating. Every other route requires a valid peer.
pub fn router(state: Arc<A2aState>) -> Router {
    Router::new()
        .route("/.well-known/agent-card.json", get(agent_card_handler))
        .route("/jsonrpc", post(jsonrpc_handler))
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
    let value = header?;
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

/// Start the A2A listener. Returns once the listener is bound; the serving
/// task runs in the background.
///
/// The bind address is resolved before spawning so a configuration error
/// surfaces at startup rather than silently inside a detached task.
pub async fn spawn(state: Arc<A2aState>) -> Result<()> {
    let addr = state.config.bind.clone();
    let app = router(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("A2A: failed to bind {addr}"))?;

    let local = listener
        .local_addr()
        .context("A2A: could not read the bound address")?;

    info!(address = %local, "A2A listener started");

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

    Ok(())
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
    }

    #[test]
    fn router_builds_without_panicking() {
        let state = build_state(test_config(), SkillRegistry::new(), "http://localhost:8443");
        let _router = router(state);
    }
}
