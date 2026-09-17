//! Login and logout.
//!
//! The split between [`public_router`] and [`router`] is the whole point of
//! this module: login mints a session and therefore cannot require one, so it
//! is mounted outside the `guard` layer and re-applies the CSRF check itself.
//! Logout requires a session like every other protected route.

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::web::auth::verify_password;
use crate::web::middleware::{csrf_ok, ip_permitted, session_from_cookies, SESSION_COOKIE};
use crate::web::state::WebState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub ok: bool,
    /// Lets the shell raise the "you are still on the default password"
    /// banner immediately after login, without a second round trip.
    pub uses_default_password: bool,
}

/// Routes reachable **without** a session.
///
/// Mounted outside the `guard` layer by `web::router`, which is why every
/// handler here has to enforce CSRF for itself.
pub fn public_router() -> Router<WebState> {
    Router::new().route("/api/auth/login", post(login))
}

/// Routes that require a session, like every other protected route.
pub fn router() -> Router<WebState> {
    Router::new().route("/api/auth/logout", post(logout))
}

/// Build the `Set-Cookie` value for a session.
///
/// `Secure` is conditional on `public_url` being https: claiming `Secure` on a
/// plain-HTTP bind would make the browser drop the cookie and turn a working
/// local dashboard into an unexplainable login loop.
fn session_cookie_header(session: &str, secure: bool, ttl_hours: u64) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        ttl_hours.saturating_mul(3600)
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// A cookie that tells the browser to drop the session it is holding.
fn expired_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

async fn login(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = addr.ip();

    // This route is outside `guard`, so it re-applies the source-IP gate and
    // the CSRF check itself, in the order the guard uses them.
    //
    // The IP gate first: without it a source outside `allow_ips` could still
    // reach the one endpoint where passwords are guessed, which is exactly what
    // design spec §4.4 says must not happen.
    if !ip_permitted(&state, ip) {
        tracing::warn!(%ip, "web: rejected a login from a source outside allow_ips");
        return (StatusCode::FORBIDDEN, "source address not permitted").into_response();
    }

    // Forgetting this check would silently reopen CSRF on the one route that
    // hands out sessions.
    if !csrf_ok(&headers) {
        return (StatusCode::FORBIDDEN, "missing CSRF header").into_response();
    }

    // The limiter runs before the password is verified, so a locked-out source
    // cannot keep spending Argon2 work (or probing passwords) from here.
    {
        let Ok(mut limiter) = state.limiter.lock() else {
            // A poisoned limiter is a denial, never a bypass.
            return (StatusCode::INTERNAL_SERVER_ERROR, "limiter unavailable").into_response();
        };
        if limiter.check(ip).is_err() {
            tracing::warn!(%ip, "web: login blocked by rate limit");
            return (StatusCode::TOO_MANY_REQUESTS, "too many attempts").into_response();
        }
    }

    let (ok, uses_default_password) = {
        let Ok(creds) = state.credentials.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
        };
        let user_ok = creds.username == body.username;
        let pass_ok = verify_password(&body.password, &creds.password_hash);
        // `&`, not `&&`: both comparisons always run, so a wrong username and a
        // wrong password cost the same. With `&&` a wrong username would skip
        // the Argon2 verification entirely and answer in microseconds, which is
        // an oracle for "this username is the right one".
        (user_ok & pass_ok, creds.uses_default_password)
    };

    if !ok {
        if let Ok(mut limiter) = state.limiter.lock() {
            limiter.record_failure(ip);
        }
        // Never log the submitted password, and never say which half was wrong.
        tracing::warn!(%ip, "web: failed login attempt");
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    if let Ok(mut limiter) = state.limiter.lock() {
        limiter.record_success(ip);
    }

    let session = state.sessions.create();
    let secure = state
        .config
        .public_url
        .as_deref()
        .map(|url| url.trim().to_ascii_lowercase().starts_with("https://"))
        .unwrap_or(false);
    let cookie = session_cookie_header(&session, secure, state.config.session_ttl_hours);

    tracing::info!(%ip, "web: login succeeded");

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            ok: true,
            uses_default_password,
        }),
    )
        .into_response()
}

async fn logout(State(state): State<WebState>, headers: HeaderMap) -> Response {
    if let Some(id) = session_from_cookies(&headers) {
        state.sessions.destroy(&id);
    }
    (
        StatusCode::OK,
        [(header::SET_COOKIE, expired_session_cookie())],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_cookie_is_hardened() {
        let cookie = session_cookie_header("abc123", false, 12);
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=abc123")));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Secure"), "plain HTTP: {cookie}");
        assert!(
            cookie.contains("Max-Age=43200"),
            "12 hours in seconds: {cookie}"
        );
    }

    #[test]
    fn the_session_cookie_gains_secure_when_the_public_url_is_https() {
        assert!(session_cookie_header("abc123", true, 1).contains("; Secure"));
    }

    #[test]
    fn the_expired_cookie_expires_immediately_and_keeps_the_flags() {
        let cookie = expired_session_cookie();
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=;")));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
    }
}
