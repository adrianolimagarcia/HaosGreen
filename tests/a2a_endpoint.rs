//! End-to-end checks for the A2A listener: the card is public, everything
//! else is refused without a valid peer.

use rustfox::a2a::server::{build_state, router};
use rustfox::config::{A2aCardConfig, A2aConfig, A2aPeerConfig};
use rustfox::skills::SkillRegistry;
use std::collections::HashMap;

fn config() -> A2aConfig {
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
        card: A2aCardConfig {
            name: "RustFox".to_string(),
            description: "test".to_string(),
            version: "1.0.2".to_string(),
        },
        peers,
        ..A2aConfig::default()
    }
}

/// Bind an ephemeral port and return its base URL plus a shutdown handle.
async fn start() -> (String, tokio::task::JoinHandle<()>) {
    let state = build_state(config(), SkillRegistry::new(), "http://placeholder");
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn agent_card_is_public() {
    let (base, handle) = start().await;
    let resp = reqwest::get(format!("{base}/.well-known/agent-card.json"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the card must be fetchable without auth"
    );

    let card: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(card["name"], "RustFox");
    assert!(card["supportedInterfaces"].is_array());
    assert!(card["securitySchemes"]["bearer"].is_object());
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_without_token_is_401() {
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_with_bad_token_is_401() {
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("wrong")
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_with_valid_token_reaches_the_handler() {
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("s3cret")
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"}))
        .send()
        .await
        .unwrap();
    // 501, not 200: authenticated, but no executor exists in Phase 1. A 200
    // here would mean a client believes a task was accepted when it was not.
    assert_eq!(resp.status(), 501);
    handle.abort();
}
