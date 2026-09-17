//! The request guard: source-IP gate, CSRF, then session or bearer.
//!
//! Three layers live here, and `web::router` decides where each one runs:
//!
//! * [`host_and_headers`] wraps **every** response. It rejects a request whose
//!   `Host` header is not this dashboard's (DNS rebinding — see [`AllowedHosts`])
//!   and stamps the security headers on whatever comes back.
//! * [`guard`] wraps the *protected* router: source IP, CSRF, then session or
//!   bearer.
//! * [`public_guard`] and [`ip_gate`] wrap the two routers that are reachable
//!   without a session (login, and the static assets). They run the same checks
//!   **as middleware, before axum's extractors**, so a denied source is refused
//!   before the body of a `Json` request is parsed.
//!
//! Nothing here reads a handler's body, and no handler re-implements a check
//! that a layer already runs: two copies of a security check is how one of them
//! silently stops being applied.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};

use super::state::WebState;
use crate::config::WebConfig;

pub const SESSION_COOKIE: &str = "haos_session";
pub const CSRF_HEADER: &str = "x-haos-green-csrf";

/// The port a `Host` header without an explicit port implies.
///
/// The dashboard serves plain HTTP; TLS is the reverse proxy's job. A
/// port-less `Host` therefore means port 80, and comparing it against the
/// bound port is what makes `Host: 127.0.0.1` fail on a listener bound to
/// 8787.
const DEFAULT_HTTP_PORT: u16 = 80;

/// Every response carries this policy.
///
/// `default-src 'self'` is safe for this shell because it loads exactly three
/// same-origin resources and contains no inline `<script>`, no inline
/// `<style>`, and no inline event-handler attribute: the UI is assembled with
/// `document.createElement` and `textContent`. `frame-ancestors 'none'` is the
/// CSP spelling of `X-Frame-Options: DENY`, which is sent alongside it for
/// browsers that do not implement the directive.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; frame-ancestors 'none'";

/// Add the response headers the dashboard always sends.
///
/// Applied to every response, including the ones this module rejects, so a
/// 403 cannot be framed, sniffed, or used to leak the dashboard's URL through
/// a `Referer`.
///
/// # `Cache-Control: no-store` is not optional here
///
/// Every response this dashboard sends is either session-scoped or carries log
/// content: `GET /api/logs` and `/api/logs/stream` return the process's own log
/// (targets, paths, task ids, error text), the settings route returns the
/// configuration surface, and the login response carries a `Set-Cookie` that a
/// cache would happily replay to the next client. A cached copy of any of them
/// outlives the session that authorised it — a shared proxy, or a browser
/// history restore, is enough.
///
/// `Vary: Cookie` is the companion: these responses depend on the session
/// cookie, and a cache that does not know that may serve one session's body to
/// another. It is set on every response for the same reason `no-store` is — the
/// layer that stamps it does not know which handler produced the response, and
/// a rule that has to be remembered per route is a rule that will be forgotten
/// by the next route.
///
/// The cost is that the three static assets are re-fetched rather than served
/// from cache. They are ~230 KB, they are served by the same process that
/// already answered the request, and correctness of the rule above is worth
/// more than the round trip.
pub fn harden(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::VARY, HeaderValue::from_static("Cookie"));
}

/// The `Host` values this listener answers to.
///
/// # Why the `Host` header is the whole defence against DNS rebinding
///
/// The dashboard binds to loopback by default and ships with the password
/// `admin`/`admin`. An attacker page at `http://evil.example:8787/` whose
/// hostname re-resolves to `127.0.0.1` reaches the dashboard **from the
/// operator's own browser**, so the request arrives over loopback: `allow_ips`
/// never sees a foreign source, and the CSRF custom header is no obstacle
/// either, because the attacker's JavaScript is same-origin with the rebound
/// hostname and may send any header it likes. The session cookie is not
/// readable by the attacker, but a rebound page does not need to read it to
/// drive the API.
///
/// The one thing the browser will not let the attacker forge is `Host`: it is
/// derived from the URL the page was loaded from. So a request that carries a
/// `Host` this dashboard does not answer to is refused before any handler —
/// or any extractor — runs.
#[derive(Clone, Debug)]
pub struct AllowedHosts {
    /// Host from `public_url`, accepted on any port (or on `public_port` when
    /// the URL names one explicitly).
    public_host: Option<String>,
    public_port: Option<u16>,
    /// Hosts accepted only together with the bound port.
    local_hosts: Vec<String>,
    /// The port the listener actually bound.
    port: u16,
}

impl AllowedHosts {
    /// Derive the accepted hosts from the configuration and the **bound**
    /// address.
    ///
    /// The port comes from `bound`, never from the `bind` string: tests bind
    /// `127.0.0.1:0` and receive an ephemeral port, so a port taken from the
    /// configuration would be `0` and would match nothing.
    pub fn new(config: &WebConfig, bound: SocketAddr) -> Self {
        let mut local_hosts = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        push_host(&mut local_hosts, &bound.ip().to_string());
        // The configured host as well, so a listener deliberately bound to one
        // address (`bind = "192.168.1.5:8787"`) answers to the host an operator
        // would actually type. Only the host is taken from the string; the port
        // still comes from `bound`.
        if let Ok(configured) = config.bind.trim().parse::<SocketAddr>() {
            push_host(&mut local_hosts, &configured.ip().to_string());
        }

        let (public_host, public_port) = config
            .public_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .and_then(|url| url.parse::<reqwest::Url>().ok())
            .and_then(|url| {
                url.host_str().map(|host| {
                    // `Url::host_str` renders an IPv6 host bracketed
                    // (`[::1]`); the rest of this module compares bare.
                    let host = host.trim_start_matches('[').trim_end_matches(']');
                    (host.to_ascii_lowercase(), url.port())
                })
            })
            .map_or((None, None), |(host, port)| (Some(host), port));

        Self {
            public_host,
            public_port,
            local_hosts,
            port: bound.port(),
        }
    }

    /// True when `host_header` names this dashboard.
    pub fn permits(&self, host_header: &str) -> bool {
        let Some((host, port)) = split_host_port(host_header) else {
            return false;
        };
        let host = host.to_ascii_lowercase();

        if let Some(public_host) = &self.public_host {
            if host == *public_host && self.public_port.is_none_or(|expected| expected == port) {
                return true;
            }
        }

        self.local_hosts.contains(&host) && port == self.port
    }

    /// The hosts accepted with the bound port, for diagnostics.
    #[cfg(test)]
    fn local_hosts(&self) -> &[String] {
        &self.local_hosts
    }
}

fn push_host(hosts: &mut Vec<String>, host: &str) {
    let host = host.to_ascii_lowercase();
    if !host.is_empty() && !hosts.contains(&host) {
        hosts.push(host);
    }
}

/// Split a `Host` header into `(host, port)`, or `None` when it is not a plain
/// `host` or `host:port`.
///
/// Anything else — userinfo (`user@host`), a path, whitespace, a bare
/// unbracketed IPv6 literal, a non-numeric port — is refused rather than
/// interpreted. No browser sends such a value, and guessing at one is how a
/// validator ends up agreeing with an attacker.
fn split_host_port(value: &str) -> Option<(String, u16)> {
    // Leading and trailing OWS is stripped by the HTTP parser (RFC 7230
    // §3.2.4), so it is stripped here too rather than treated as a mismatch.
    let value = value.trim();
    if value.is_empty() || value.len() > 255 {
        return None;
    }
    if value
        .chars()
        .any(|c| c.is_ascii_whitespace() || matches!(c, '@' | '/' | '\\' | ',' | ';' | '?' | '#'))
    {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]` or `[::1]:8787`. Returned without the
        // brackets, because that is the form `IpAddr` and the configured hosts
        // use.
        let (host, rest) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match rest {
            "" => DEFAULT_HTTP_PORT,
            _ => rest.strip_prefix(':')?.parse().ok()?,
        };
        return Some((host.to_string(), port));
    }

    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (value, DEFAULT_HTTP_PORT),
    };

    // A `:` left in the host is an unbracketed IPv6 literal, which is not a
    // legal `Host` value.
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host.to_string(), port))
}

/// Reject a request whose `Host` is not this dashboard's, and stamp the
/// security headers on every response.
///
/// Outermost layer, so it covers the static assets and the login route as well
/// as the protected routes.
pub async fn host_and_headers(
    State(allowed): State<AllowedHosts>,
    request: Request,
    next: Next,
) -> Response {
    let verdict = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|host| (host.to_string(), allowed.permits(host)));

    match verdict {
        Some((_, true)) => {
            let mut response = next.run(request).await;
            harden(&mut response);
            response
        }
        Some((host, false)) => {
            tracing::warn!(
                host = %host,
                "web: rejected a request whose Host header is not this dashboard's"
            );
            refused("host not permitted")
        }
        None => {
            // HTTP/1.1 requires `Host`, and a request without one cannot be
            // checked at all — which is exactly the rebinding case.
            tracing::warn!("web: rejected a request with no usable Host header");
            refused("host not permitted")
        }
    }
}

/// A 403 carrying the security headers.
fn refused(body: &'static str) -> Response {
    let mut response = (StatusCode::FORBIDDEN, body).into_response();
    harden(&mut response);
    response
}

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
///
/// `pub(crate)` rather than private because `routes::logs` re-checks the
/// credential of an already-open SSE stream: `guard` authorises a stream once,
/// at connect, and the stream has to be able to ask the same question again when
/// the session behind it goes away.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
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

/// Gate a route that needs no session: source IP, then CSRF.
///
/// Applied to the public router (login) as a layer rather than from inside the
/// handler, and that placement is the point. **All extractors run before the
/// handler body**, so a check written inside `login` ran *after* axum had
/// already parsed up to 2 MB of JSON and answered 415/400/422 on a malformed
/// body — including a 422 that names the expected fields. A source outside
/// `allow_ips` could therefore make the dashboard parse megabytes of JSON per
/// request, and none of those attempts consumed a rate-limit slot. As a layer
/// this runs before the body is touched, so a denied source gets 403 and
/// nothing else, whatever it sent.
pub async fn public_guard(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    if !ip_permitted(&state, ip) {
        tracing::warn!(%ip, "web: rejected a public request from a source outside allow_ips");
        return (StatusCode::FORBIDDEN, "source address not permitted").into_response();
    }

    if requires_csrf(request.method()) && !csrf_ok(request.headers()) {
        return (StatusCode::FORBIDDEN, "missing CSRF header").into_response();
    }

    next.run(request).await
}

/// Gate the static assets on the source-IP allowlist only.
///
/// `GET /`, `/app.js` and `/style.css` need no session and no CSRF header —
/// they are compile-time constants with no per-user data — but they must not
/// be served to a source the allowlist refuses. The UI states that a non-empty
/// list refuses "every other source … before authentication runs — including
/// the login page", and design spec §4.4 claims strict enforcement; without
/// this layer a denied source still received the whole dashboard shell, so both
/// claims overstated the guarantee.
pub async fn ip_gate(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    if !ip_permitted(&state, ip) {
        tracing::warn!(%ip, "web: rejected a static asset request from a source outside allow_ips");
        return (StatusCode::FORBIDDEN, "source address not permitted").into_response();
    }

    next.run(request).await
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

    // ── Host validation ─────────────────────────────────────────────────────

    /// The default test listener: loopback, ephemeral port.
    fn bound() -> SocketAddr {
        "127.0.0.1:41234".parse().unwrap()
    }

    fn allowed(config: &WebConfig) -> AllowedHosts {
        AllowedHosts::new(config, bound())
    }

    #[test]
    fn a_foreign_host_is_rejected() {
        // The DNS-rebinding case: the browser is talking to a hostname the
        // attacker controls which resolves to 127.0.0.1. The request arrives
        // over loopback, so nothing else in the stack can tell it apart.
        let hosts = allowed(&WebConfig::default());
        for host in [
            "evil.example:41234",
            "evil.example",
            "attacker.test:41234",
            // A suffix is not the same host.
            "127.0.0.1.evil.example:41234",
            // Nor is a prefix.
            "evil.example.127.0.0.1:41234",
        ] {
            assert!(!hosts.permits(host), "{host:?} must be refused");
        }
    }

    #[test]
    fn the_bound_address_is_accepted() {
        let hosts = allowed(&WebConfig::default());
        assert!(hosts.permits("127.0.0.1:41234"));
    }

    #[test]
    fn the_ephemeral_bound_port_is_what_is_accepted() {
        // `spawn_for_test` configures `127.0.0.1:0` and binds an ephemeral
        // port. Taking the port from the configuration instead of the bound
        // `SocketAddr` would accept `:0` and refuse the port the client is
        // actually connected to, which is every integration test.
        let config = WebConfig {
            bind: "127.0.0.1:0".to_string(),
            ..Default::default()
        };
        let hosts = allowed(&config);
        assert!(
            hosts.permits("127.0.0.1:41234"),
            "the bound port must be accepted"
        );
        assert!(
            !hosts.permits("127.0.0.1:0"),
            "the configured port must not be"
        );
    }

    #[test]
    fn the_loopback_names_are_accepted_with_the_bound_port() {
        let hosts = allowed(&WebConfig::default());
        for host in ["localhost:41234", "127.0.0.1:41234", "[::1]:41234"] {
            assert!(hosts.permits(host), "{host:?} must be accepted");
        }
        assert!(hosts.local_hosts().contains(&"localhost".to_string()));
    }

    #[test]
    fn a_loopback_host_on_the_wrong_port_is_rejected() {
        let hosts = allowed(&WebConfig::default());
        for host in ["localhost:8787", "127.0.0.1:80", "[::1]:443"] {
            assert!(!hosts.permits(host), "{host:?} must be refused");
        }
    }

    #[test]
    fn a_portless_host_means_port_80() {
        // The dashboard serves plain HTTP, so `Host: 127.0.0.1` means port 80
        // and must not match a listener bound to 41234...
        let hosts = allowed(&WebConfig::default());
        assert!(!hosts.permits("127.0.0.1"));

        // ...but it must match one that is bound to 80.
        let on_eighty = AllowedHosts::new(&WebConfig::default(), "127.0.0.1:80".parse().unwrap());
        assert!(on_eighty.permits("127.0.0.1"));
        assert!(on_eighty.permits("localhost"));
    }

    #[test]
    fn the_configured_bind_host_is_accepted() {
        // `bind = "192.168.1.5:8787"` has to answer `Host: 192.168.1.5:<port>`,
        // which is what an operator on that network types.
        let config = WebConfig {
            bind: "192.168.1.5:8787".to_string(),
            ..Default::default()
        };
        let hosts = AllowedHosts::new(&config, "192.168.1.5:8787".parse().unwrap());
        assert!(hosts.permits("192.168.1.5:8787"));
        assert!(!hosts.permits("192.168.1.6:8787"));
    }

    #[test]
    fn the_public_url_host_is_accepted() {
        // The reverse-proxy case: the proxy forwards the public hostname, and
        // the listener behind it is on loopback with a different port.
        let config = WebConfig {
            public_url: Some("https://haos.example.com".to_string()),
            ..Default::default()
        };
        let hosts = allowed(&config);
        assert!(
            hosts.permits("haos.example.com"),
            "the configured public host must be accepted"
        );
        assert!(
            hosts.permits("haos.example.com:8443"),
            "a public_url with no explicit port accepts any port"
        );
        assert!(
            hosts.permits("127.0.0.1:41234"),
            "the bound address must keep working alongside public_url"
        );
        assert!(!hosts.permits("evil.example:41234"));
    }

    #[test]
    fn a_public_url_port_is_required_when_it_names_one() {
        let config = WebConfig {
            public_url: Some("https://haos.example.com:8443".to_string()),
            ..Default::default()
        };
        let hosts = allowed(&config);
        assert!(hosts.permits("haos.example.com:8443"));
        assert!(!hosts.permits("haos.example.com:9443"));
    }

    #[test]
    fn a_malformed_host_header_is_refused() {
        let hosts = allowed(&WebConfig::default());
        for host in [
            "",
            "   ",
            "user@127.0.0.1:41234", // userinfo
            "127.0.0.1:41234/x",    // path
            "127.0.0.1 :41234",     // interior space
            "127.0.0.1:4123a",      // non-numeric port
            "127.0.0.1:",           // empty port
            ":41234",               // empty host
            "::1:41234",            // unbracketed IPv6
            "127.0.0.1:99999",      // port out of range
            "[::1:41234",           // unterminated bracket
        ] {
            assert!(
                !hosts.permits(host),
                "{host:?} must be refused rather than interpreted"
            );
        }
    }

    #[test]
    fn the_host_match_is_case_insensitive() {
        let config = WebConfig {
            public_url: Some("https://Haos.Example.com".to_string()),
            ..Default::default()
        };
        let hosts = allowed(&config);
        assert!(hosts.permits("haos.example.com"));
        assert!(hosts.permits("HAOS.EXAMPLE.COM"));
        assert!(hosts.permits("LocalHost:41234"));
    }

    #[test]
    fn a_blank_public_url_is_treated_as_unset() {
        let config = WebConfig {
            public_url: Some("   ".to_string()),
            ..Default::default()
        };
        let hosts = allowed(&config);
        assert!(hosts.permits("127.0.0.1:41234"));
        assert!(!hosts.permits("haos.example.com"));
    }

    #[test]
    fn split_host_port_reads_the_forms_a_browser_sends() {
        assert_eq!(
            split_host_port("127.0.0.1:8787"),
            Some(("127.0.0.1".to_string(), 8787))
        );
        assert_eq!(
            split_host_port("localhost"),
            Some(("localhost".to_string(), DEFAULT_HTTP_PORT))
        );
        assert_eq!(
            split_host_port("[::1]:8787"),
            Some(("::1".to_string(), 8787))
        );
        assert_eq!(
            split_host_port("[::1]"),
            Some(("::1".to_string(), DEFAULT_HTTP_PORT))
        );
        assert_eq!(split_host_port("[::1]:8787:1"), None);
    }

    // ── Security headers ────────────────────────────────────────────────────

    #[test]
    fn the_security_headers_are_stamped_on_a_response() {
        let mut response = (StatusCode::OK, "body").into_response();
        harden(&mut response);
        let headers = response.headers();

        assert_eq!(
            headers
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some(CONTENT_SECURITY_POLICY)
        );
        assert_eq!(
            headers
                .get(header::X_FRAME_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
    }

    #[test]
    fn the_content_security_policy_forbids_framing() {
        assert!(CONTENT_SECURITY_POLICY.contains("default-src 'self'"));
        assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
    }

    /// Nothing this dashboard sends may be cached.
    ///
    /// A response carrying log content, the settings surface, or a `Set-Cookie`
    /// that outlives the session that authorised it is exactly what a shared
    /// cache or a browser's back button would replay.
    #[test]
    fn every_response_is_uncacheable_and_varies_on_the_session_cookie() {
        let mut response = (StatusCode::OK, "log content").into_response();
        harden(&mut response);
        let headers = response.headers();

        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "a response that can carry a credential or a log line must not be storable"
        );
        assert_eq!(
            headers.get(header::VARY).and_then(|v| v.to_str().ok()),
            Some("Cookie"),
            "the body depends on the session cookie, and a cache has to know that"
        );
    }

    /// The headers go on refusals too: a 401 or a 403 is a response a cache can
    /// store just as happily as a 200.
    #[test]
    fn a_refusal_is_uncacheable_too() {
        let response = refused("host not permitted");
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    #[test]
    fn a_refusal_carries_the_security_headers() {
        // A 403 is a response too: an attacker page that frames the dashboard
        // must not get a frameable rejection either.
        let response = refused("host not permitted");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().contains_key(header::X_FRAME_OPTIONS));
        assert!(response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY));
    }
}
