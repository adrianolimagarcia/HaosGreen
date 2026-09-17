//! Embedded web dashboard.
//!
//! Phase 1 (foundation) lives here: the `[web]` configuration, credential
//! storage, sessions, the source-IP/login gates, the request guard, and the
//! listener. The route modules are added by the later tasks of
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
use state::{WebState, LOG_BUFFER_CAPACITY};

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLE_CSS: &str = include_str!("assets/style.css");

/// Build the dashboard router. Separated from `spawn` so tests can drive the
/// router without binding a socket.
///
/// `routes::public_router()` is merged **outside** the guard layer: a route
/// mounted there is reachable without a session, which is exactly what login
/// needs and exactly what every other route must not have. `/api/auth/login`
/// is the only route on it, and it re-applies the source-IP gate and the CSRF
/// check itself — the guard does not run for it at all.
pub fn router(state: WebState) -> Router {
    let protected =
        Router::new()
            .merge(routes::router())
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                middleware::guard,
            ));

    Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/style.css", get(serve_style_css))
        .merge(routes::public_router())
        .merge(protected)
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
/// `agent` and `supervisor` are optional so the foundation is testable without
/// constructing either: `Agent::new` takes the whole configuration surface and
/// `Supervisor` needs a live database connection. Routes that need them call
/// `WebState::agent_or_unavailable` / `supervisor_or_unavailable`, which return
/// 503 rather than panicking.
fn build_state(
    config: WebConfig,
    home: PathBuf,
    agent: Option<Arc<Agent>>,
    supervisor: Option<Arc<Supervisor>>,
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
        logs: Arc::new(logs::LogBuffer::new(LOG_BUFFER_CAPACITY)),
        config,
        agent,
        supervisor,
    })
}

/// Start the dashboard listener and return the address it bound.
///
/// A failure here is logged by the caller and must never take the Telegram bot
/// down, mirroring how the A2A listener is treated.
pub async fn spawn(
    config: WebConfig,
    home: PathBuf,
    agent: Arc<Agent>,
    supervisor: Arc<Supervisor>,
) -> Result<SocketAddr> {
    // The flag is authoritative here too, not only at the call site: a caller
    // that forgets to check `enabled` must not be able to open the port.
    if !config.enabled {
        bail!("web dashboard is disabled in [web].enabled");
    }

    let bind = config.bind.clone();
    let state = build_state(config, home, Some(agent), Some(supervisor))?;
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

    tracing::info!("  Web dashboard: http://{addr}");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = %e, "web dashboard listener stopped");
        }
    });

    Ok(addr)
}

/// Build and bind a dashboard for tests, with a throwaway home directory and
/// without an `Agent` or a `Supervisor`.
///
/// `into_make_service_with_connect_info` is not optional: the guard's
/// `ConnectInfo<SocketAddr>` extractor fails without it, and every request
/// would answer 500.
#[doc(hidden)]
pub async fn spawn_for_test(home: PathBuf) -> Result<(SocketAddr, ())> {
    let config = WebConfig {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        ..Default::default()
    };
    let state = build_state(config, home, None, None)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok((addr, ()))
}
