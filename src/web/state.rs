//! Shared handles for the dashboard route modules.
//!
//! `WebState` is cloned into every request, so every field is an `Arc`. The
//! `agent` and `supervisor` handles are optional on purpose: the dashboard's
//! foundation (auth, settings, static assets) must be runnable and testable
//! without constructing an `Agent` — its constructor takes the whole
//! configuration surface — or a `Supervisor`, which needs a live database.
//! Routes that genuinely need them return `503 Service Unavailable` when they
//! are absent instead of panicking, so a partially wired dashboard degrades
//! instead of killing the process that also serves Telegram.

use crate::agent::Agent;
use crate::config::WebConfig;
use crate::supervisor::Supervisor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use super::auth::{Credentials, IpGate, LoginLimiter, SessionStore};
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
    /// Bounded ring buffer of recent tracing events (Phase 4 feeds it; the
    /// handle lives here so `WebState` does not have to change again).
    pub logs: Arc<LogBuffer>,
}

/// Number of tracing events retained for the dashboard log view.
///
/// Bounded so the dashboard can never be the cause of unbounded memory growth
/// (design spec §5.3).
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
            logs: Arc::new(LogBuffer::new(16)),
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
    }
}
