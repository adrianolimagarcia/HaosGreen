//! End-to-end checks for the A2A listener: the card is public, everything
//! else is refused without a valid peer.

use rustfox::a2a::server::{build_state, router, spawn};
use rustfox::a2a::NoopExecutor;
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
    let state = build_state(
        config(),
        SkillRegistry::new(),
        "http://placeholder",
        NoopExecutor,
        a2a_server::InMemoryTaskStore::new(),
    );
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
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "SendMessage"}))
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
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "SendMessage"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_with_a_valid_token_passes_the_auth_gate() {
    // The 501 stub is gone; the SDK's JSON-RPC router now serves this path.
    // `NoopExecutor` emits an empty stream, so a SendMessage produces no
    // terminal event and the SDK reports an internal error -- but crucially
    // NOT 401/403, which would mean the auth gate rejected a valid token.
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("s3cret")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": {"message": {"messageId": "m1", "role": "ROLE_USER",
                                   "parts": [{"text": "hi"}]}}
        }))
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        401,
        "a valid token must not be rejected as unauthenticated"
    );
    assert_ne!(
        resp.status(),
        403,
        "a valid token from an allowed IP must not be rejected"
    );
    handle.abort();
}

#[tokio::test]
async fn an_unknown_method_is_method_not_found() {
    // Pins the v1.0 naming: the v0.3.0 `message/send` must NOT be accepted.
    let (base, handle) = start().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("s3cret")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["code"], -32601,
        "v0.3.0 method names must be rejected: {body}"
    );
    handle.abort();
}

/// `config()` binds `127.0.0.1:0`. The card must advertise the port the OS
/// actually assigned — advertising `:0` makes the endpoint unreachable.
#[tokio::test]
async fn card_advertises_the_real_port_for_an_ephemeral_bind() {
    let addr = spawn(
        config(),
        SkillRegistry::new(),
        NoopExecutor,
        a2a_server::InMemoryTaskStore::new(),
    )
    .await
    .expect("binding an ephemeral loopback port must succeed");
    assert_ne!(addr.port(), 0, "the OS must have assigned a real port");

    let card: serde_json::Value =
        reqwest::get(format!("http://{addr}/.well-known/agent-card.json"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let url = card["supportedInterfaces"][0]["url"]
        .as_str()
        .expect("the card must carry an interface URL");
    assert_eq!(
        url,
        format!("http://{addr}"),
        "the advertised URL must match the address that was actually bound"
    );
    assert!(!url.ends_with(":0"), "port 0 must never be advertised");
}

/// `public_url` is what an operator sets when the bind address is not
/// reachable by peers; it must win over the derived URL verbatim.
#[tokio::test]
async fn public_url_overrides_the_advertised_url() {
    let mut cfg = config();
    cfg.public_url = Some("https://rustfox.example.com:8443".to_string());
    let addr = spawn(
        cfg,
        SkillRegistry::new(),
        NoopExecutor,
        a2a_server::InMemoryTaskStore::new(),
    )
    .await
    .unwrap();

    let card: serde_json::Value =
        reqwest::get(format!("http://{addr}/.well-known/agent-card.json"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        card["supportedInterfaces"][0]["url"],
        "https://rustfox.example.com:8443"
    );
}
