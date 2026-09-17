//! Login and logout.
//!
//! The split between [`public_router`] and [`router`] is the whole point of
//! this module: login mints a session and therefore cannot require one, so it
//! is mounted outside the `guard` layer. `routes::public_router` wraps it in
//! `middleware::public_guard` — the source-IP gate and the CSRF check — as a
//! *layer*, so both run before axum extracts the JSON body. Logout requires a
//! session like every other protected route.

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::web::auth::verify_password_async;
use crate::web::middleware::{session_from_cookies, SESSION_COOKIE};
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
/// The caller (`web::routes::public_router`) wraps the result in the IP and
/// CSRF layers. This function deliberately does not apply them itself: it has
/// no `WebState` to give the middleware, and the wrapping lives one level up so
/// that a route added here cannot be mounted without it.
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
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = addr.ip();

    // The source-IP gate and the CSRF check are **not** here: they are applied
    // by `web::routes::public_router` as a layer, so they run before axum's
    // `Json` extractor. Written here they would run after it, which handed a
    // source outside `allow_ips` a 415/400/422 — a 422 that names the expected
    // fields — and let it make the server parse up to 2 MB of JSON per request
    // without ever consuming a rate-limit slot.

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

    // Copy everything the comparison needs out of the guard, then drop it
    // before awaiting. Two reasons, in order of severity: `std::sync::MutexGuard`
    // is not `Send`, so holding it across the `.await` below does not compile;
    // and the password check is Argon2 on the blocking pool (~50 ms), so a lock
    // held across it would stall the guard's bearer path — which takes the same
    // mutex — for every concurrent request.
    let (user_ok, password_hash, uses_default_password) = {
        let Ok(creds) = state.credentials.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
        };
        // Constant-time, unlike `creds.username == body.username`; see
        // `Credentials::verify_username`.
        let user_ok = creds.verify_username(&body.username);
        let password_hash = creds.password_hash.clone();
        let uses_default_password = creds.uses_default_password;
        drop(creds);
        (user_ok, password_hash, uses_default_password)
    };

    let pass_ok = verify_password_async(&body.password, &password_hash).await;

    // `&`, not `&&`: both comparisons always run, so a wrong username and a
    // wrong password cost the same. With `&&` a wrong username would skip the
    // Argon2 verification entirely and answer in microseconds, which is an
    // oracle for "this username is the right one".
    let ok = user_ok & pass_ok;

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

    // The store fails closed on a poisoned mutex. Honour the caller contract on
    // `SessionStore::create`: answer 500 and send **no** `Set-Cookie`. A 200
    // carrying a session id the store never recorded is an unexplained login
    // loop — the browser holds a cookie that can never authenticate and every
    // retry fails the same way.
    let session = match state.sessions.create() {
        Ok(session) => session,
        Err(e) => {
            tracing::error!(
                error = %e,
                "web: the session could not be recorded; refusing to hand out a session"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create a session",
            )
                .into_response();
        }
    };
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
