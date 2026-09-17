//! Dashboard settings: the password, the bearer token, and the IP allowlist.
//!
//! Every route here is on the guarded router, so a caller has already passed
//! the source-IP gate, the CSRF check, and the session/bearer check.
//!
//! The three invariants this module exists to protect:
//!
//! * `GET /api/settings` never returns a password hash, a bearer hash, or a
//!   bearer token. The response is built from a struct that has no field able
//!   to carry one, rather than from a `json!({...})` literal that a later edit
//!   could extend by accident.
//! * A bearer token is returned exactly once, by the call that mints it, and
//!   only its SHA-256 digest is persisted.
//! * A rejected write changes nothing: a malformed allowlist entry leaves the
//!   previous list in place, and a failed save rolls the in-memory credentials
//!   back to what the file still holds.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::web::auth::{hash_password_async, verify_password_async, IpGate};
use crate::web::state::WebState;

pub fn router() -> Router<WebState> {
    Router::new()
        .route("/api/settings", get(read_settings))
        .route("/api/settings/password", post(change_password))
        .route("/api/settings/bearer", post(set_bearer))
        .route("/api/settings/allow-ips", put(replace_allow_ips))
}

/// The non-secret half of the credential file, plus the live configuration.
#[derive(Serialize)]
struct SettingsResponse {
    username: String,
    uses_default_password: bool,
    bearer_enabled: bool,
    /// A short fingerprint of the active bearer token, so an operator can tell
    /// which token is live after the one-time reveal has passed.
    ///
    /// This is a prefix of a SHA-256 digest of a 256-bit random token: it
    /// identifies a token the operator already holds and cannot help an
    /// attacker search the token space. The full hash is never returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    bearer_fingerprint: Option<String>,
    /// The **live** allowlist, not the one `config.toml` was read with: a
    /// `PUT` replaces it for the life of the process.
    allow_ips: Vec<String>,
    session_ttl_hours: u64,
}

#[derive(Deserialize)]
struct PasswordChange {
    current: String,
    new: String,
}

#[derive(Deserialize)]
struct BearerToggle {
    enabled: bool,
}

#[derive(Serialize)]
struct BearerResponse {
    enabled: bool,
    /// Present only on the response that mints the token. There is no route
    /// that can return it a second time.
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Deserialize)]
struct AllowIpsRequest {
    allow_ips: Vec<String>,
}

#[derive(Serialize)]
struct AllowIpsResponse {
    allow_ips: Vec<String>,
    /// True when the list restricts nothing, i.e. any source IP may attempt a
    /// login (design spec §4.4). The shell states that asymmetry explicitly so
    /// an operator is never misled into reading an empty list as a lockout.
    empty: bool,
}

async fn read_settings(State(state): State<WebState>) -> Response {
    let (username, uses_default_password, bearer_enabled, bearer_fingerprint) = {
        let Ok(creds) = state.credentials.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
        };
        (
            creds.username.clone(),
            creds.uses_default_password,
            creds.bearer_enabled,
            creds.bearer_fingerprint(),
        )
    };

    let allow_ips = match state.ip_gate.read() {
        Ok(gate) => gate.entries().to_vec(),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "allowlist unavailable").into_response()
        }
    };

    Json(SettingsResponse {
        username,
        uses_default_password,
        bearer_enabled,
        bearer_fingerprint,
        allow_ips,
        session_ttl_hours: state.config.session_ttl_hours,
    })
    .into_response()
}

async fn change_password(
    State(state): State<WebState>,
    Json(body): Json<PasswordChange>,
) -> Response {
    if body.new.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "the new password must not be empty",
        )
            .into_response();
    }

    // Clone the stored hash out of the guard and drop the guard *before*
    // awaiting. Two independent reasons: `std::sync::MutexGuard` is not `Send`,
    // so a guard alive across the `.await` does not compile; and the guard's
    // bearer path takes this same mutex on every request, so holding it across
    // ~100 ms of Argon2 (verify + hash) stalled every concurrent request.
    let stored_hash = {
        let Ok(creds) = state.credentials.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
        };
        let stored_hash = creds.password_hash.clone();
        drop(creds);
        stored_hash
    };

    if !verify_password_async(&body.current, &stored_hash).await {
        // No secret material in the message: not the hash, and not the
        // submitted password.
        tracing::warn!("web: rejected a password change, the current password did not match");
        return (StatusCode::FORBIDDEN, "current password is incorrect").into_response();
    }

    // Hashed outside the lock, then installed under it: `set_password_hash`
    // exists for exactly this split.
    let new_hash = match hash_password_async(&body.new).await {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(error = %e, "web: password hashing failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not change the password",
            )
                .into_response();
        }
    };

    let Ok(mut creds) = state.credentials.lock() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
    };

    // Compare-and-swap. The verification above ran outside the lock, so the
    // stored hash could have changed between it and this acquisition; without
    // this check a caller holding only the *old* password could overwrite the
    // new one. A changed hash means the `current` we verified is stale.
    if creds.password_hash != stored_hash {
        tracing::warn!("web: rejected a password change, the password changed underneath it");
        return (
            StatusCode::CONFLICT,
            "the password changed while this request was in flight",
        )
            .into_response();
    }

    // Snapshot first so a persistence failure leaves memory and the credential
    // file agreeing with each other. Sessions are deliberately left alone: the
    // plan requires a password change to keep the operator logged in.
    let previous = creds.clone();
    creds.set_password_hash(&body.new, new_hash);

    if let Err(e) = creds.save(&state.credentials_path) {
        *creds = previous;
        tracing::error!(
            error = %e,
            "web: the password change could not be persisted; the in-memory password was rolled back"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not change the password",
        )
            .into_response();
    }

    tracing::info!("web: dashboard password changed");
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn set_bearer(State(state): State<WebState>, Json(body): Json<BearerToggle>) -> Response {
    let Ok(mut creds) = state.credentials.lock() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
    };

    let previous = creds.clone();

    // Enabling always mints a *new* token and invalidates the old one. There is
    // no "show me the token again" path, so re-enabling is the operator's only
    // way to recover from losing it — and rotating on demand is the safer
    // default for a credential that can never be read back.
    let token = if body.enabled {
        match creds.enable_bearer() {
            Ok(token) => Some(token),
            Err(e) => {
                *creds = previous;
                tracing::error!(error = %e, "web: bearer token generation failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "could not enable bearer")
                    .into_response();
            }
        }
    } else {
        creds.disable_bearer();
        None
    };

    if let Err(e) = creds.save(&state.credentials_path) {
        *creds = previous;
        tracing::error!(
            error = %e,
            "web: the bearer change could not be persisted; the in-memory state was rolled back"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not persist the bearer change",
        )
            .into_response();
    }

    // `enabled` only: the token itself is never logged.
    tracing::info!(enabled = body.enabled, "web: bearer authentication toggled");

    Json(BearerResponse {
        enabled: body.enabled,
        token,
    })
    .into_response()
}

async fn replace_allow_ips(
    State(state): State<WebState>,
    Json(body): Json<AllowIpsRequest>,
) -> Response {
    // In memory only, per the plan: this does not rewrite `config.toml`, so the
    // change lasts until the process restarts. Making that persistent is a
    // deliberate operator decision, not something a dashboard click should do
    // to a file that also holds the API keys.
    //
    // Parse before touching the live gate: an invalid entry must be a 400 that
    // changes nothing, never a partially applied list.
    let gate = match IpGate::new(&body.allow_ips) {
        Ok(gate) => gate,
        Err(e) => {
            tracing::warn!(error = %e, "web: rejected an IP allowlist update");
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };

    let entries = gate.entries().to_vec();
    let empty = gate.is_empty();

    match state.ip_gate.write() {
        Ok(mut current) => *current = gate,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "allowlist unavailable").into_response()
        }
    }

    // No addresses in the log line: the count and the semantics are enough to
    // audit the change, and an allowlist can name internal networks.
    tracing::info!(entries = entries.len(), empty, "web: IP allowlist replaced");

    Json(AllowIpsResponse {
        allow_ips: entries,
        empty,
    })
    .into_response()
}
