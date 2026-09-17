//! Embedded web dashboard.
//!
//! Phase 1 (foundation) lives here: the `[web]` configuration, credential
//! storage, sessions, the source-IP/login gates, the request guard, and the
//! listener. Phase 2 adds [`chat`] (the bounded chat session store) and
//! [`routes::chat`] (chat sessions and the SSE message stream). The remaining
//! route modules are added by the later tasks of
//! `docs/superpowers/plans/2026-09-16-haos-green-web-dashboard.md`.
//!
//! Two properties of this module are load-bearing:
//!
//! * A dashboard failure must never take the Telegram bot down. `spawn` is
//!   therefore fallible and its error is logged by the caller, mirroring how
//!   `a2a::server::spawn` is treated in `main.rs`.
//! * The listener is served with `into_make_service_with_connect_info`, which
//!   the `guard` middleware requires for its `ConnectInfo<SocketAddr>`
//!   extractor. Without it every request fails with a 500.

pub mod auth;
pub mod chat;
pub mod logs;
pub mod middleware;
pub mod routes;
pub mod state;

use anyhow::{bail, Context, Result};
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tower_http::trace::TraceLayer;

use crate::agent::Agent;
use crate::config::WebConfig;
use crate::supervisor::Supervisor;
use auth::{Credentials, IpGate, LoginLimiter, SessionStore};
use state::WebState;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLE_CSS: &str = include_str!("assets/style.css");

/// Build the dashboard router. Separated from `spawn` so tests can drive the
/// router without binding a socket.
///
/// Three layers, and where each one is applied is a security boundary:
///
/// * `host_and_headers` wraps **everything**, so no route — static, login or
///   protected — answers a request whose `Host` is not this dashboard's.
/// * `public_router` (login) and the static assets are wrapped in their own
///   gates. Login is reachable without a session because it *mints* sessions,
///   so it re-applies the source-IP gate and the CSRF check as a layer. The
///   static assets are compile-time constants, so they take the IP gate alone.
/// * Everything else is mounted **inside** `guard`, which adds the
///   session/bearer check on top of the same IP and CSRF gates.
///
/// `bound` is the address the listener actually holds, not `config.bind`:
/// tests bind `127.0.0.1:0`, so the accepted `Host` port has to come from the
/// bound `SocketAddr` or it would be `0`.
pub fn router(state: WebState, bound: SocketAddr) -> Router {
    let allowed_hosts = middleware::AllowedHosts::new(&state.config, bound);

    // Static assets: no session, no CSRF, but the allowlist still applies.
    let assets = Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/style.css", get(serve_style_css))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::ip_gate,
        ));

    let protected =
        Router::new()
            .merge(routes::router())
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                middleware::guard,
            ));

    Router::new()
        .merge(assets)
        .merge(routes::public_router(state.clone()))
        .merge(protected)
        .layer(axum::middleware::from_fn_with_state(
            allowed_hosts,
            middleware::host_and_headers,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn serve_index() -> axum::response::Html<&'static str> {
    axum::response::Html(INDEX_HTML)
}

async fn serve_app_js() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        APP_JS,
    )
}

async fn serve_style_css() -> impl axum::response::IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/css")], STYLE_CSS)
}

/// Assemble the shared state.
///
/// `agent`, `supervisor` and `logs` are optional so the foundation is testable
/// without constructing any of them: `Agent::new` takes the whole configuration
/// surface, `Supervisor` needs a live database connection, and the log buffer
/// only has content once the tracing layer that feeds it has been installed.
/// Routes that need them call `WebState::agent_or_unavailable` /
/// `supervisor_or_unavailable` / `logs_or_unavailable`, which return 503 rather
/// than panicking.
fn build_state(
    config: WebConfig,
    home: PathBuf,
    agent: Option<Arc<Agent>>,
    supervisor: Option<Arc<Supervisor>>,
    logs: Option<Arc<logs::LogBuffer>>,
    a2a: Option<Arc<routes::a2a::A2aWebState>>,
) -> Result<WebState> {
    config.validate()?;
    let credentials_path = home.join("web-auth.toml");
    let credentials = Credentials::load_or_create(&credentials_path)?;

    if credentials.uses_default_password {
        tracing::warn!(
            "web: the dashboard is using the default password 'admin'. Change it in \
             Settings before exposing the port to any network you do not fully trust."
        );
    }

    Ok(WebState {
        ip_gate: Arc::new(RwLock::new(IpGate::new(&config.allow_ips)?)),
        sessions: Arc::new(SessionStore::new(Duration::from_secs(
            config.session_ttl_hours.saturating_mul(3600),
        ))),
        limiter: Arc::new(Mutex::new(LoginLimiter::new())),
        credentials: Arc::new(Mutex::new(credentials)),
        credentials_path,
        chat: Arc::new(chat::ChatSessionStore::new()),
        logs,
        a2a,
        config,
        agent,
        supervisor,
    })
}

/// Start the dashboard listener and return the address it bound.
///
/// A failure here is logged by the caller and must never take the Telegram bot
/// down, mirroring how the A2A listener is treated.
///
/// `logs` is the **same** `Arc<LogBuffer>` the `LogLayer` installed in
/// `main.rs` writes into. Handing the dashboard its own buffer would compile,
/// run, and show an operator a permanently empty log view.
///
/// `a2a` carries what `main.rs` observed about the A2A listener. It is a
/// parameter rather than something the dashboard reads for itself: the outcome
/// is only knowable where the listener was started, and a dashboard that
/// guessed at it would report a status nobody observed.
pub async fn spawn(
    config: WebConfig,
    home: PathBuf,
    agent: Arc<Agent>,
    supervisor: Arc<Supervisor>,
    logs: Arc<logs::LogBuffer>,
    a2a: Option<Arc<routes::a2a::A2aWebState>>,
) -> Result<SocketAddr> {
    // The flag is authoritative here too, not only at the call site: a caller
    // that forgets to check `enabled` must not be able to open the port.
    if !config.enabled {
        bail!("web dashboard is disabled in [web].enabled");
    }

    let bind = config.bind.clone();
    let state = build_state(config, home, Some(agent), Some(supervisor), Some(logs), a2a)?;
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind web dashboard to {bind}"))?;
    let addr = listener.local_addr()?;

    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "web: the dashboard is bound to a non-loopback address; anyone who can reach it \
             and guess the password gets shell execution"
        );
    }

    // A non-loopback bind is only reachable by name, and a name is not in the
    // accepted `Host` set unless `public_url` says so. Warn rather than reject:
    // the operator may legitimately be using a literal address.
    let has_public_url = state
        .config
        .public_url
        .as_deref()
        .map(str::trim)
        .is_some_and(|url| !url.is_empty());
    if !addr.ip().is_loopback() && !has_public_url {
        tracing::warn!(
            %addr,
            "web: the dashboard is bound to a non-loopback address with no [web].public_url set; \
             requests whose Host is not the bound address, localhost, 127.0.0.1 or [::1] are \
             refused with 403, so a browser reaching it by name will be rejected"
        );
    }

    tracing::info!("  Web dashboard: http://{addr}");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router(state, addr).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = %e, "web dashboard listener stopped");
        }
    });

    Ok(addr)
}

/// Build and bind a dashboard for tests, with a throwaway home directory and
/// without an `Agent` or a `Supervisor`, using the default configuration.
///
/// `into_make_service_with_connect_info` is not optional: the guard's
/// `ConnectInfo<SocketAddr>` extractor fails without it, and every request
/// would answer 500.
#[doc(hidden)]
pub async fn spawn_for_test(home: PathBuf) -> Result<(SocketAddr, ())> {
    spawn_for_test_with(home, WebConfig::default()).await
}

/// [`spawn_for_test`] with a caller-supplied configuration.
///
/// This exists because `spawn_for_test` hardcodes the default `WebConfig`: a
/// regression that hardcoded, say, `secure = false` on the session cookie would
/// keep every integration test green, since not one of them could configure a
/// `public_url`. `enabled` is forced on and the listener always binds
/// `127.0.0.1:0` — a fixed port would make the suite flaky — but `public_url`,
/// `allow_ips` and `session_ttl_hours` are honoured exactly as given.
#[doc(hidden)]
pub async fn spawn_for_test_with(home: PathBuf, config: WebConfig) -> Result<(SocketAddr, ())> {
    spawn_for_test_with_agent(home, config, None).await
}

/// [`spawn_for_test_with`] with an agent attached.
///
/// The live SSE test needs a dashboard whose `agent` handle is `Some`: the send
/// route answers 503 without one, so a test that never wires an agent would
/// prove nothing about streaming. `Supervisor` stays `None` — no chat route
/// touches it.
#[doc(hidden)]
pub async fn spawn_for_test_with_agent(
    home: PathBuf,
    config: WebConfig,
    agent: Option<Arc<Agent>>,
) -> Result<(SocketAddr, ())> {
    spawn_for_test_with_handles(home, config, agent, None, None, None).await
}

/// [`spawn_for_test_with_agent`] with a supervisor attached.
///
/// The supervisor routes answer 503 without one, so a test that never wires a
/// supervisor would prove nothing about the task surface — the same reason
/// `spawn_for_test_with_agent` exists for the chat stream. `Supervisor` needs
/// only an in-memory store and an artifacts directory (`new_for_test`), so the
/// integration harness can build a real one. The `agent` handle stays `None`:
/// no supervisor route touches it.
#[doc(hidden)]
pub async fn spawn_for_test_with_supervisor(
    home: PathBuf,
    config: WebConfig,
    supervisor: Option<Arc<Supervisor>>,
) -> Result<(SocketAddr, ())> {
    spawn_for_test_with_handles(home, config, None, supervisor, None, None).await
}

/// [`spawn_for_test_with`] with a live log buffer attached.
///
/// The log routes answer 503 without one, and the buffer has to be the
/// caller's: the tests push into it and then read the result back over HTTP,
/// which is the only way to show that the routes and the buffer are the same
/// object. The three `spawn_for_test_with_*` entry points above deliberately
/// wire **no** buffer, so they double as the "dashboard started without logs"
/// harness.
#[doc(hidden)]
pub async fn spawn_for_test_with_logs(
    home: PathBuf,
    config: WebConfig,
    logs: Arc<logs::LogBuffer>,
) -> Result<(SocketAddr, ())> {
    spawn_for_test_with_handles(home, config, None, None, Some(logs), None).await
}

/// [`spawn_for_test_with`] with the A2A surface attached.
///
/// The A2A routes answer 503 without one, and the state carries the listener
/// outcome the status route reports, so a test that never wires it would prove
/// nothing about either. The state is built by the caller because the outcome
/// it holds is an *observation* — `start_listener` is what produces it, and a
/// test that wants the failure path calls it with a configuration that really
/// fails to bind.
#[doc(hidden)]
pub async fn spawn_for_test_with_a2a(
    home: PathBuf,
    config: WebConfig,
    a2a: Arc<routes::a2a::A2aWebState>,
) -> Result<(SocketAddr, ())> {
    spawn_for_test_with_handles(home, config, None, None, None, Some(a2a)).await
}

/// The shared body of the `spawn_for_test_with_*` entry points.
async fn spawn_for_test_with_handles(
    home: PathBuf,
    mut config: WebConfig,
    agent: Option<Arc<Agent>>,
    supervisor: Option<Arc<Supervisor>>,
    logs: Option<Arc<logs::LogBuffer>>,
    a2a: Option<Arc<routes::a2a::A2aWebState>>,
) -> Result<(SocketAddr, ())> {
    config.enabled = true;
    let state = build_state(config, home, agent, supervisor, logs, a2a)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router(state, addr).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok((addr, ()))
}
