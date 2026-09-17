//! The request guard: source-IP gate, CSRF, then session or bearer.
//!
//! The guard is applied to the *protected* router only. Routes that must be
//! reachable without a session (login) are merged outside it and therefore
//! re-apply the IP gate **and** the CSRF check themselves — see `web::routes`.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};

use super::state::WebState;

pub const SESSION_COOKIE: &str = "haos_session";
pub const CSRF_HEADER: &str = "x-haos-green-csrf";

/// True when `ip` passes the live allowlist.
///
/// Shared by [`guard`] and by the public login route. Login is merged outside
/// the guard layer — it mints sessions, so it cannot require one — which means
/// that without this call it would be the single endpoint a source outside
/// `allow_ips` could still reach, and it is precisely the endpoint where
/// passwords are guessed. Design spec §4.4: a non-empty list is enforced
/// *before authentication runs*.
///
/// A poisoned lock is a denial, never a bypass.
pub fn ip_permitted(state: &WebState, ip: IpAddr) -> bool {
    state
        .ip_gate
        .read()
        .map(|gate| gate.permits(ip))
        .unwrap_or(false)
}

/// Mutating methods require the CSRF header.
///
/// `SameSite=Strict` already blocks cross-site form posts in current browsers,
/// but it is a browser behaviour, not a server-side guarantee. Requiring the
/// header means the protection holds even if a browser ignores the attribute
/// or the request arrives from a non-browser client replaying a cookie.
pub fn requires_csrf(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

pub fn csrf_ok(headers: &HeaderMap) -> bool {
    headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

pub fn session_from_cookies(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

/// Extract the token from an `Authorization` header.
///
/// RFC 7235 makes the auth scheme case-insensitive, so `bearer`, `Bearer` and
/// `BEARER` are all valid. Matching only the exact spelling `Bearer` would be
/// fail-*closed* (an unrecognised scheme is refused) but it is still wrong: a
/// client that writes `bearer` gets a 401 with no explanation.
///
/// This mirrors `a2a::server::parse_bearer`, the in-repo precedent. It is
/// duplicated rather than shared on purpose: the dashboard must not depend on
/// the A2A module for its own authentication, and both copies are pinned by
/// tests, including the fail-closed cases (`Bearer` with no token, an empty
/// token, an unknown scheme).
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let value = raw.trim_start();
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

/// Gate every request: source IP, then CSRF, then session or bearer.
///
/// Order matters. The IP check runs before authentication so a denied source
/// cannot even probe whether a password is correct. The CSRF check runs before
/// the session check so a cross-site request never reaches a handler even with
/// a valid cookie.
pub async fn guard(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    if !ip_permitted(&state, ip) {
        tracing::warn!(%ip, "web: rejected a request from a source outside allow_ips");
        return (StatusCode::FORBIDDEN, "source address not permitted").into_response();
    }

    let method = request.method().clone();
    let headers = request.headers().clone();

    if requires_csrf(&method) && !csrf_ok(&headers) {
        return (StatusCode::FORBIDDEN, "missing CSRF header").into_response();
    }

    let session_ok = session_from_cookies(&headers)
        .map(|id| state.sessions.validate(&id))
        .unwrap_or(false);

    let bearer_ok = bearer_token(&headers)
        .map(|token| {
            state
                .credentials
                .lock()
                .map(|c| c.verify_bearer(token))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if session_ok || bearer_ok {
        return next.run(request).await;
    }

    (StatusCode::UNAUTHORIZED, "authentication required").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    // The plan's tests name `HeaderValue` unqualified; the implementation does
    // not need it, so the import lives with the tests that use it.
    use axum::http::HeaderValue;

    #[test]
    fn csrf_header_is_required_on_mutating_methods() {
        assert!(requires_csrf(&Method::POST));
        assert!(requires_csrf(&Method::PUT));
        assert!(requires_csrf(&Method::PATCH));
        assert!(requires_csrf(&Method::DELETE));
    }

    #[test]
    fn csrf_header_is_not_required_on_read_methods() {
        assert!(!requires_csrf(&Method::GET));
        assert!(!requires_csrf(&Method::HEAD));
        assert!(!requires_csrf(&Method::OPTIONS));
    }

    #[test]
    fn a_missing_csrf_header_is_rejected() {
        let headers = HeaderMap::new();
        assert!(!csrf_ok(&headers));
    }

    #[test]
    fn a_present_csrf_header_is_accepted() {
        let mut headers = HeaderMap::new();
        headers.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        assert!(csrf_ok(&headers));
    }

    #[test]
    fn a_wrong_csrf_value_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(CSRF_HEADER, HeaderValue::from_static("0"));
        assert!(!csrf_ok(&headers));
    }

    #[test]
    fn session_cookie_is_extracted_from_a_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=x; haos_session=abc123; more=y"),
        );
        assert_eq!(session_from_cookies(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn a_cookie_header_without_the_session_cookie_yields_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=x"),
        );
        assert!(session_from_cookies(&headers).is_none());
    }

    /// Build a header map carrying one `Authorization` value.
    fn authorization(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static(value),
        );
        headers
    }

    #[test]
    fn the_bearer_scheme_is_matched_case_insensitively() {
        // RFC 7235. `Bearer` was the only accepted spelling before this test
        // existed, which rejected perfectly valid clients.
        for value in [
            "Bearer abc123",
            "bearer abc123",
            "BEARER abc123",
            "BeArEr abc123",
        ] {
            assert_eq!(
                bearer_token(&authorization(value)),
                Some("abc123"),
                "{value:?} must be accepted"
            );
        }
    }

    #[test]
    fn bearer_token_tolerates_surrounding_whitespace() {
        assert_eq!(
            bearer_token(&authorization("  Bearer   abc123  ")),
            Some("abc123")
        );
        assert_eq!(bearer_token(&authorization("Bearer\tabc123")), None);
    }

    #[test]
    fn bearer_parsing_fails_closed() {
        for value in [
            "",               // no header value
            "Bearer",         // no separator
            "Bearer ",        // empty token
            "Bearer    ",     // whitespace-only token
            "Basic abc123",   // wrong scheme
            "Bearerx abc123", // scheme prefix that must not match
            "Token abc123",   // unrelated scheme
            "abc123",         // token with no scheme at all
        ] {
            assert_eq!(
                bearer_token(&authorization(value)),
                None,
                "{value:?} must not yield a token"
            );
        }

        assert_eq!(bearer_token(&HeaderMap::new()), None, "no header at all");
    }
}
