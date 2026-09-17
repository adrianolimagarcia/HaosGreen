//! Shared handles for the dashboard route modules.
//!
//! `WebState` is cloned into every request, so every field is an `Arc`. The
//! `agent`, `supervisor` and `logs` handles are optional on purpose: the
//! dashboard's foundation (auth, settings, static assets) must be runnable and
//! testable without constructing an `Agent` — its constructor takes the whole
//! configuration surface — or a `Supervisor`, which needs a live database, or
//! without a `LogBuffer`, which only exists once `main.rs` has installed the
//! tracing layer that feeds it.
//! Routes that genuinely need them return `503 Service Unavailable` when they
//! are absent instead of panicking, so a partially wired dashboard degrades
//! instead of killing the process that also serves Telegram.

use crate::agent::Agent;
use crate::config::WebConfig;
use crate::supervisor::Supervisor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use super::auth::{Credentials, IpGate, LoginLimiter, SessionStore};
use super::chat::ChatSessionStore;
use super::logs::LogBuffer;

#[derive(Clone)]
pub struct WebState {
    pub config: WebConfig,
    /// Password hash and bearer state. Behind a `Mutex` because the settings
    /// routes mutate it in place.
    pub credentials: Arc<Mutex<Credentials>>,
    pub sessions: Arc<SessionStore>,
    pub limiter: Arc<Mutex<LoginLimiter>>,
    /// Behind an `RwLock` because `PUT /api/settings/allow-ips` replaces the
    /// whole gate. Reads happen on every request and never block each other;
    /// a write is a whole-struct swap, so a request can never observe a
    /// half-updated allowlist.
    pub ip_gate: Arc<RwLock<IpGate>>,
    /// `None` when the dashboard was started without an agent (tests, and any
    /// future caller that only wants the operational surfaces).
    pub agent: Option<Arc<Agent>>,
    /// `None` when the dashboard was started without a supervisor.
    pub supervisor: Option<Arc<Supervisor>>,
    /// Where `Credentials` is persisted. Kept here so the settings routes can
    /// save a password change without re-deriving the home directory.
    pub credentials_path: PathBuf,
    /// Chat histories, one per dashboard session.
    ///
    /// Lives here rather than behind the `agent` handle because it is pure
    /// in-memory bookkeeping: `POST /api/chat/sessions` and the history read
    /// work on a dashboard that was started without an agent, and only the
    /// routes that actually *run* the agent return 503.
    pub chat: Arc<ChatSessionStore>,
    /// Bounded ring buffer of recent tracing events (Phase 4).
    ///
    /// `None` when the dashboard was started without one. The routes read the
    /// **same** `Arc` the `tracing_subscriber::Layer` installed in `main.rs`
    /// writes to: a buffer of the dashboard's own would be permanently empty,
    /// which is exactly the kind of failure that looks like "no logs yet".
    pub logs: Option<Arc<LogBuffer>>,
    /// The A2A surface (Phase 5): the inbound peers as configured, the live
    /// outbound peers, and what `main.rs` observed about the listener.
    ///
    /// The outbound peers are held behind the **same** shared handle
    /// `main.rs` gives `call_a2a_agent`, so `PUT /api/a2a/outbound` reaches the
    /// running agent as well as `config.toml`. It is a handle and not a copy
    /// for exactly that reason.
    ///
    /// `None` when the dashboard was started without A2A wiring. It carries
    /// tokens — they are what the fingerprints are derived from — so it is
    /// never serialized; the route module builds its responses from structs
    /// that have no field able to hold one.
    pub a2a: Option<Arc<super::routes::a2a::A2aWebState>>,
    /// Factory for process-shutdown subscriptions shared with active SSE streams.
    /// The sender remains owned by the process supervisor, never by routes.
    pub shutdown: Arc<dyn Fn() -> tokio::sync::broadcast::Receiver<()> + Send + Sync>,
}

/// Number of tracing events retained for the dashboard log view.
///
/// **This is not a bound in bytes, and on its own it never was.** An entry count
/// bounds how many entries are retained, not how much memory they occupy: 2000
/// entries of an arbitrary message size is an arbitrary amount of memory. The
/// bytes are bounded by [`crate::web::logs::MAX_MESSAGE_BYTES`] (applied at
/// capture) and by [`crate::web::logs::DEFAULT_MAX_BYTES`] (the ring's byte
/// budget, evicted oldest-first), which together cap the ring at
/// `min(capacity × per-entry size, max_bytes)` — 4 MiB at this capacity.
pub const LOG_BUFFER_CAPACITY: usize = 2000;

impl WebState {
    /// The agent, or a 503 body explaining why it is missing.
    ///
    /// Phase 2's chat routes call this rather than unwrapping the field.
    pub fn agent_or_unavailable(
        &self,
    ) -> Result<Arc<Agent>, (axum::http::StatusCode, &'static str)> {
        self.agent.clone().ok_or((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the dashboard was started without an agent",
        ))
    }

    /// The supervisor, or a 503 body explaining why it is missing.
    pub fn supervisor_or_unavailable(
        &self,
    ) -> Result<Arc<Supervisor>, (axum::http::StatusCode, &'static str)> {
        self.supervisor.clone().ok_or((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the dashboard was started without a supervisor",
        ))
    }

    /// The log buffer, or a 503 body explaining why it is missing.
    ///
    /// Same contract as [`Self::agent_or_unavailable`] and
    /// [`Self::supervisor_or_unavailable`]: a dashboard wired without logs
    /// degrades to 503 rather than reporting an empty log, which would be
    /// indistinguishable from a quiet process.
    pub fn logs_or_unavailable(
        &self,
    ) -> Result<Arc<LogBuffer>, (axum::http::StatusCode, &'static str)> {
        self.logs.clone().ok_or((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the dashboard was started without a log buffer",
        ))
    }

    /// The A2A state, or a 503 body explaining why it is missing.
    ///
    /// Same contract again: a dashboard wired without A2A must say so rather
    /// than report an empty peer list, which would be indistinguishable from a
    /// configuration with no peers.
    pub fn a2a_or_unavailable(
        &self,
    ) -> Result<Arc<super::routes::a2a::A2aWebState>, (axum::http::StatusCode, &'static str)> {
        self.a2a.clone().ok_or((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the dashboard was started without A2A wiring",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::DEFAULT_USERNAME;

    /// A state with neither an agent nor a supervisor, i.e. exactly what
    /// `spawn_for_test` builds.
    fn state_without_agent_or_supervisor() -> WebState {
        WebState {
            config: WebConfig::default(),
            credentials: Arc::new(Mutex::new(Credentials {
                username: DEFAULT_USERNAME.to_string(),
                password_hash: String::new(),
                bearer_enabled: false,
                bearer_token_hash: String::new(),
                uses_default_password: true,
            })),
            sessions: Arc::new(SessionStore::new(std::time::Duration::from_secs(3600))),
            limiter: Arc::new(Mutex::new(LoginLimiter::new())),
            ip_gate: Arc::new(RwLock::new(IpGate::new(&[]).unwrap())),
            agent: None,
            supervisor: None,
            credentials_path: PathBuf::from("/nonexistent/web-auth.toml"),
            chat: Arc::new(ChatSessionStore::new()),
            logs: Some(Arc::new(LogBuffer::new(16))),
            a2a: None,
            shutdown: Arc::new(|| tokio::sync::broadcast::channel(1).0.subscribe()),
        }
    }

    #[test]
    fn a_state_without_an_agent_degrades_to_503_instead_of_panicking() {
        let state = state_without_agent_or_supervisor();

        // `Agent` and `Supervisor` are not `Debug`, so the error is destructured
        // rather than asserted with `unwrap_err()`.
        let Err((status, message)) = state.agent_or_unavailable() else {
            panic!("a state with no agent must not hand one out");
        };
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(message.contains("agent"));

        let Err((status, message)) = state.supervisor_or_unavailable() else {
            panic!("a state with no supervisor must not hand one out");
        };
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(message.contains("supervisor"));

        let Err((status, message)) = state.a2a_or_unavailable() else {
            panic!("a state with no A2A wiring must not hand one out");
        };
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(message.contains("A2A"));
    }
}
