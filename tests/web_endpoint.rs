//! Integration tests for the embedded web dashboard.
//!
//! Every test binds an ephemeral port and speaks real HTTP. No mocks: the
//! value of these tests is that the auth gate, the cookie handling, and the
//! JSON shapes are exercised end to end.
//!
//! # Cookie handling
//!
//! reqwest's `cookies` feature is deliberately not enabled — it would pull in
//! the `cookie` crate for the benefit of a handful of tests — so every test
//! carries the `Set-Cookie` value explicitly instead of using a cookie store.
//! That is also closer to what the assertions are about: the tests check the
//! cookie the server actually set, not a client-side approximation of it.

/// Start the dashboard on an ephemeral port with a throwaway home directory.
///
/// The `TempDir` is returned so it outlives the server: dropping it would
/// delete `web-auth.toml` underneath a running listener.
async fn spawn_test_server() -> (String, tempfile::TempDir) {
    spawn_test_server_with(haos_green::config::WebConfig::default()).await
}

/// Start the dashboard with a caller-supplied configuration.
///
/// `spawn_for_test` hardcodes the default `WebConfig`, so without this entry
/// point no test in this file could set a `public_url` — and a regression that
/// hardcoded `secure = false` on the session cookie would keep all of them
/// green.
async fn spawn_test_server_with(
    config: haos_green::config::WebConfig,
) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _handle) = haos_green::web::spawn_for_test_with(dir.path().to_path_buf(), config)
        .await
        .expect("dashboard should start");
    (format!("http://{addr}"), dir)
}

/// The socket address behind a `http://host:port` base URL.
fn socket_addr(base: &str) -> std::net::SocketAddr {
    base.strip_prefix("http://")
        .expect("the test base URL is http://")
        .parse()
        .expect("the test base URL carries a socket address")
}

/// Send a hand-written HTTP/1.1 request and return the raw response text.
///
/// `reqwest` derives `Host` from the URL and offers no way to lie about it, so
/// the only way to exercise the `Host` check is to write the request by hand.
/// `Connection: close` makes the server close, which is what ends the read.
async fn raw_request(addr: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

/// The status code from the first line of a raw HTTP response.
fn raw_status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {response:?}"))
}

/// Assert the four headers every response must carry.
fn assert_security_headers(response: &reqwest::Response) {
    let headers = response.headers();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };

    assert_eq!(
        header("content-security-policy"),
        "default-src 'self'; frame-ancestors 'none'",
        "every response must carry the CSP"
    );
    assert_eq!(header("x-frame-options"), "DENY");
    assert_eq!(header("x-content-type-options"), "nosniff");
    assert_eq!(header("referrer-policy"), "no-referrer");
}

/// Replace the live allowlist with `entries` and assert the update succeeded.
///
/// Every test that needs a denied source has to get there through this: the
/// gate is only reachable from an authenticated request while the list is still
/// empty.
async fn replace_allow_ips(base: &str, cookie: &str, entries: &[&str]) {
    let resp = reqwest::Client::new()
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, cookie)
        .json(&serde_json::json!({ "allow_ips": entries }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the allowlist update itself must be allowed"
    );
}

/// The session cookie (name=value only) from a login response.
fn session_cookie(response: &reqwest::Response) -> String {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.split(';').next())
        .unwrap_or_default()
        .to_string()
}

/// Log in as `admin` with `password` and return the session cookie.
///
/// Panics on a non-200 so a test that depends on being logged in fails at the
/// login step rather than three assertions later.
async fn login_and_get_cookie(base: &str, password: &str) -> String {
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login with {password:?} should succeed");
    let cookie = session_cookie(&resp);
    assert!(
        cookie.starts_with("haos_session="),
        "login must set the session cookie, got {cookie:?}"
    );
    cookie
}

/// Enable bearer authentication and return the one-time token.
async fn enable_bearer_and_get_token(base: &str, cookie: &str) -> String {
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/settings/bearer"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, cookie)
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["token"]
        .as_str()
        .expect("enabling bearer must return the token once")
        .to_string()
}

// ── The guard ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_protected_route_without_a_session_is_unauthorized() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn a_mutating_request_without_the_csrf_header_is_forbidden() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/settings/password"))
        .json(&serde_json::json!({"current": "admin", "new": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a mutating request must be refused before the session check runs"
    );
}

#[tokio::test]
async fn a_mutating_request_with_the_csrf_header_still_needs_a_session() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/settings/password"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"current": "admin", "new": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "passing the CSRF check must not bypass authentication"
    );
}

#[tokio::test]
async fn every_protected_route_refuses_an_unauthenticated_caller() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // Every route on the guarded router — including the two that were never
    // exercised without a session before (`logout` and `bearer`). The CSRF
    // header is sent on all of them so the request reaches the authentication
    // check rather than being stopped by the CSRF gate first: this test is
    // about authentication.
    let cases: [(&str, &str, Option<serde_json::Value>); 24] = [
        ("GET", "/api/settings", None),
        (
            "POST",
            "/api/settings/password",
            Some(serde_json::json!({"current": "admin", "new": "x"})),
        ),
        (
            "POST",
            "/api/settings/bearer",
            Some(serde_json::json!({"enabled": true})),
        ),
        (
            "PUT",
            "/api/settings/allow-ips",
            Some(serde_json::json!({"allow_ips": []})),
        ),
        ("POST", "/api/auth/logout", None),
        // The chat surface. `POST /api/chat/sessions` mints a session, so it is
        // the one route where a missing guard would be a real hole rather than
        // an information leak.
        ("POST", "/api/chat/sessions", None),
        ("GET", "/api/chat/sessions", None),
        ("GET", "/api/chat/sessions/nope/messages", None),
        (
            "POST",
            "/api/chat/sessions/nope/messages",
            Some(serde_json::json!({"message": "hi"})),
        ),
        ("POST", "/api/chat/sessions/nope/cancel", None),
        // The supervisor surface (Phase 3). `POST /api/supervisor/tasks` starts
        // work on the operator's behalf, so it is the third route where a
        // missing guard would be a real hole rather than an information leak.
        ("GET", "/api/supervisor/tasks", None),
        ("GET", "/api/supervisor/tasks/nope", None),
        (
            "POST",
            "/api/supervisor/tasks",
            Some(serde_json::json!({"text": "summarize the readme"})),
        ),
        ("POST", "/api/supervisor/tasks/nope/pause", None),
        ("POST", "/api/supervisor/tasks/nope/resume", None),
        ("POST", "/api/supervisor/tasks/nope/cancel", None),
        ("POST", "/api/supervisor/tasks/nope/approve", None),
        // The log surface (Phase 4). The log is the most revealing thing the
        // dashboard holds — targets, paths, task ids, error text — so a missing
        // guard here would leak more than any other route.
        ("GET", "/api/logs", None),
        ("GET", "/api/logs/stream", None),
        // The A2A surface (Phase 5). The listings name every peer and its
        // allowed addresses, the `PUT` rewrites outbound configuration, and
        // the test route makes the server issue an outbound request carrying a
        // configured peer token — the fourth route where a missing guard would
        // be a real hole rather than an information leak.
        ("GET", "/api/a2a/status", None),
        ("GET", "/api/a2a/peers", None),
        ("GET", "/api/a2a/outbound", None),
        (
            "PUT",
            "/api/a2a/outbound",
            Some(serde_json::json!({"peers": {}})),
        ),
        (
            "POST",
            "/api/a2a/test",
            Some(serde_json::json!({"peer": "beta"})),
        ),
    ];

    for (method, path, body) in cases {
        let mut request = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{base}{path}"),
            )
            .header("x-haos-green-csrf", "1");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            401,
            "{method} {path} without a session must be 401, got {}",
            response.status()
        );
    }
}

// ── Login and logout ────────────────────────────────────────────────────────

#[tokio::test]
async fn login_without_the_csrf_header_is_forbidden() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "login must also demand the CSRF header");
}

#[tokio::test]
async fn login_with_a_wrong_password_is_rejected() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn login_with_a_wrong_username_is_rejected_the_same_way() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "root", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("username") && !body.contains("password"),
        "the failure must not say which half was wrong, got {body:?}"
    );
}

#[tokio::test]
async fn login_with_the_default_password_yields_a_working_session() {
    let (base, _dir) = spawn_test_server().await;

    let login = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = session_cookie(&login);
    assert!(
        cookie.starts_with("haos_session="),
        "login must set the session cookie, got {cookie:?}"
    );

    let settings = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(settings.status(), 200);
    let body: serde_json::Value = settings.json().await.unwrap();
    assert_eq!(body["uses_default_password"], true);
}

#[tokio::test]
async fn the_session_cookie_is_httponly_strict_and_path_scoped() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    let raw = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("haos_session="))
        .expect("login must set haos_session")
        .to_string();

    assert!(raw.contains("HttpOnly"), "cookie must be HttpOnly: {raw}");
    assert!(
        raw.contains("SameSite=Strict"),
        "cookie must be SameSite=Strict: {raw}"
    );
    assert!(raw.contains("Path=/"), "cookie must be path-scoped: {raw}");
    assert!(raw.contains("Max-Age="), "cookie must expire: {raw}");
    assert!(
        !raw.contains("Secure"),
        "a plain-HTTP bind must not claim Secure: {raw}"
    );
}

/// An https `public_url` must put `Secure` on the session cookie.
///
/// This is the only test that can catch it: every other test in this file runs
/// on the default configuration, where `public_url` is unset, so a regression
/// that hardcoded `secure = false` — or that ignored `public_url` entirely —
/// would leave all of them green. It is also the reason
/// `spawn_for_test_with` exists.
#[tokio::test]
async fn an_https_public_url_puts_secure_on_the_session_cookie() {
    let config = haos_green::config::WebConfig {
        public_url: Some("https://haos.example.com".to_string()),
        ..Default::default()
    };
    let (base, _dir) = spawn_test_server_with(config).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login must still work behind the proxy");

    let raw = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("haos_session="))
        .expect("login must set haos_session")
        .to_string();

    assert!(
        raw.contains("; Secure"),
        "an https public_url must mark the session cookie Secure, got {raw:?}"
    );
    assert!(raw.contains("HttpOnly"), "cookie must stay HttpOnly: {raw}");
    assert!(
        raw.contains("SameSite=Strict"),
        "cookie must stay SameSite=Strict: {raw}"
    );
}

#[tokio::test]
async fn logout_invalidates_the_session() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let logout = reqwest::Client::new()
        .post(format!("{base}/api/auth/logout"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 200);

    let after = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        401,
        "a destroyed session must not authenticate"
    );
}

#[tokio::test]
async fn repeated_wrong_passwords_lock_the_source_out() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let mut statuses = Vec::new();
    for _ in 0..6 {
        let resp = client
            .post(format!("{base}/api/auth/login"))
            .header("x-haos-green-csrf", "1")
            .json(&serde_json::json!({"username": "admin", "password": "nope"}))
            .send()
            .await
            .unwrap();
        statuses.push(resp.status().as_u16());
    }

    // The first five attempts must be answered 401, not 429. Asserting only the
    // sixth status would also pass for a limiter that refused everything from
    // the first request — a denial of service on the operator, and a change no
    // one would notice from the last element alone.
    assert_eq!(
        &statuses[..5],
        [401, 401, 401, 401, 401],
        "the attempts below the threshold must be 401: {statuses:?}"
    );
    assert_eq!(
        statuses[5], 429,
        "the source must be rate limited after repeated failures: {statuses:?}"
    );
}

#[tokio::test]
async fn a_locked_out_source_cannot_log_in_with_the_right_password() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::new();
    for _ in 0..5 {
        let _ = client
            .post(format!("{base}/api/auth/login"))
            .header("x-haos-green-csrf", "1")
            .json(&serde_json::json!({"username": "admin", "password": "nope"}))
            .send()
            .await
            .unwrap();
    }
    let resp = client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "the limiter must run before the password is verified"
    );
}

// ── Settings ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn settings_never_expose_a_password_or_bearer_hash() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let token = enable_bearer_and_get_token(&base, &cookie).await;

    let raw = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    for forbidden in [
        "password_hash",
        "argon2",
        "bearer_token_hash",
        token.as_str(),
    ] {
        assert!(
            !raw.contains(forbidden),
            "GET /api/settings leaked {forbidden:?}: {raw}"
        );
    }

    // The substring checks above cannot catch a secret that is renamed on the
    // way out, so the key set is pinned too: any extra field is a leak until
    // this list is deliberately extended.
    let body: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("settings must be a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "allow_ips",
            "bearer_enabled",
            "bearer_fingerprint",
            "session_ttl_hours",
            "username",
            "uses_default_password"
        ],
        "GET /api/settings must expose exactly these fields: {raw}"
    );

    // The fingerprint is a label, not the credential. Assert it is short, and
    // assert the full digest is absent: a 64-hex-character run anywhere in the
    // body would mean the stored hash leaked, which the substring checks above
    // cannot catch because they only look for the key name.
    let fingerprint = body["bearer_fingerprint"]
        .as_str()
        .expect("bearer_fingerprint must be a string when bearer is enabled");
    assert_eq!(
        fingerprint.len(),
        6,
        "a fingerprint must stay short: {fingerprint}"
    );
    assert!(
        fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "a fingerprint must be hex: {fingerprint}"
    );
    assert!(
        !has_hex_run(&raw, 64),
        "GET /api/settings must not contain a full 64-hex-character digest: {raw}"
    );
}

/// True when `haystack` contains a run of at least `len` consecutive hex digits.
fn has_hex_run(haystack: &str, len: usize) -> bool {
    let mut run = 0usize;
    for ch in haystack.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[tokio::test]
async fn changing_the_password_invalidates_the_old_one() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let changed = reqwest::Client::new()
        .post(format!("{base}/api/settings/password"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"current": "admin", "new": "a-better-secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), 200);

    let old = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), 401, "the default password must stop working");

    let new = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "a-better-secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(new.status(), 200, "the new password must work");
}

#[tokio::test]
async fn changing_the_password_requires_the_current_one() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/api/settings/password"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"current": "wrong", "new": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // The rejected attempt must not have changed anything.
    let still_default = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(still_default.status(), 200);
}

#[tokio::test]
async fn enabling_bearer_returns_the_token_exactly_once() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let token = enable_bearer_and_get_token(&base, &cookie).await;
    assert!(!token.is_empty());

    // The token authenticates without a cookie...
    let ok = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // ...and reading settings back never returns it again.
    let again: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        again.get("token").is_none(),
        "the bearer token must not be readable. `again[\"token\"].is_null()` would \
         also pass for a response carrying an explicit `\"token\": null`, which is \
         a shape no client should have to handle: {again}"
    );
}

#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let token = enable_bearer_and_get_token(&base, &cookie).await;

    // RFC 7235: the auth scheme is case-insensitive. `reqwest`'s
    // `bearer_auth` always writes `Bearer`, so the variants are set by hand.
    for scheme in ["bearer", "BEARER", "BeArEr"] {
        let resp = reqwest::Client::new()
            .get(format!("{base}/api/settings"))
            .header(reqwest::header::AUTHORIZATION, format!("{scheme} {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "scheme {scheme:?} must be accepted");
    }
}

#[tokio::test]
async fn a_bad_bearer_token_is_still_rejected() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let token = enable_bearer_and_get_token(&base, &cookie).await;

    let cases = [
        format!("Bearer {}", "0".repeat(token.len())),
        format!("Bearer {token}x"),
        format!("Basic {token}"),
        format!("Bearerx {token}"),
        "Bearer".to_string(),
        "Bearer ".to_string(),
        String::new(),
    ];
    for header in cases {
        let resp = reqwest::Client::new()
            .get(format!("{base}/api/settings"))
            .header(reqwest::header::AUTHORIZATION, header.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "authorization {header:?} must not authenticate"
        );
    }
}

#[tokio::test]
async fn bearer_tokens_do_not_authenticate_while_bearer_is_disabled() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let token = enable_bearer_and_get_token(&base, &cookie).await;

    let disabled = reqwest::Client::new()
        .post(format!("{base}/api/settings/bearer"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status(), 200);

    let resp = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "a revoked token must not authenticate");
}

#[tokio::test]
async fn the_allowlist_can_be_replaced_and_reports_its_semantics() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let replaced = client
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"allow_ips": ["127.0.0.1", "10.0.0.0/8"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), 200);
    let body: serde_json::Value = replaced.json().await.unwrap();
    assert_eq!(
        body["empty"], false,
        "a populated list must not read as empty"
    );
    assert_eq!(body["allow_ips"][0], "127.0.0.1");

    let read_back: serde_json::Value = client
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        read_back["allow_ips"],
        serde_json::json!(["127.0.0.1", "10.0.0.0/8"]),
        "GET must report the live allowlist, not the startup one"
    );

    // Back to the permissive default, which the UI has to explain.
    let cleared = client
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"allow_ips": []}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = cleared.json().await.unwrap();
    assert_eq!(body["empty"], true);
}

#[tokio::test]
async fn a_malformed_allowlist_entry_is_rejected_without_replacing_the_list() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let good = client
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"allow_ips": ["127.0.0.0/8"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(good.status(), 200);

    let bad = client
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"allow_ips": ["999.1.1.1"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    let read_back: serde_json::Value = client
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        read_back["allow_ips"],
        serde_json::json!(["127.0.0.0/8"]),
        "a rejected update must leave the previous allowlist in place"
    );
}

#[tokio::test]
async fn a_new_allowlist_is_enforced_on_the_very_next_request() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    // A list that does not contain the loopback address the test client is
    // connecting from. The update itself succeeds, and the source is then
    // locked out before authentication — which is exactly the fail-closed
    // behaviour the empty-list asymmetry in the spec is about.
    let replaced = reqwest::Client::new()
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"allow_ips": ["10.0.0.0/8"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), 200);

    let after = reqwest::Client::new()
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        403,
        "the replaced allowlist must apply to the next request"
    );
}

#[tokio::test]
async fn the_allowlist_cannot_be_replaced_without_a_session() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"allow_ips": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn a_source_outside_the_allowlist_cannot_attempt_a_login() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    // Lock the loopback address out. The update itself is allowed because the
    // list is still empty when it is made.
    let replaced = reqwest::Client::new()
        .put(format!("{base}/api/settings/allow-ips"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({"allow_ips": ["10.0.0.0/8"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), 200);

    // The login route is mounted *outside* the guard, so this only holds
    // because the handler re-applies the IP gate itself. Without that call the
    // answer here is 200, and the allowlist is a lock on every door except the
    // one that hands out sessions.
    let denied = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        403,
        "a source outside allow_ips must not be able to log in"
    );
}

/// A denied source must be refused before its body is parsed.
///
/// The IP gate and the CSRF check used to live in the login handler, and every
/// extractor runs before a handler body — so a denied source got its 415/400/422
/// from `Json` first, including a 422 whose body names the expected fields, and
/// could make the server parse up to 2 MB of JSON per request without consuming
/// a rate-limit slot. As a layer, the gate runs first and the answer is 403 for
/// whatever was sent.
#[tokio::test]
async fn a_disallowed_source_is_refused_before_its_body_is_parsed() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    replace_allow_ips(&base, &cookie, &["10.0.0.0/8"]).await;

    let client = reqwest::Client::new();
    let bodies = [
        // Valid JSON, wrong shape: without the layer this is a 422 naming the
        // fields the handler expects.
        ("application/json", "{}".to_string()),
        // Not JSON at all: without the layer this is a 400.
        ("application/json", "not json".to_string()),
        // No content type: without the layer this is a 415.
        ("text/plain", "username=admin&password=admin".to_string()),
    ];

    for (content_type, body) in bodies {
        let response = client
            .post(format!("{base}/api/auth/login"))
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "a denied source must get 403 for {content_type} {body:?}, not an \
             extractor error, got {}",
            response.status()
        );
    }
}

/// The same ordering for CSRF: a missing header is a 403, not a 422.
#[tokio::test]
async fn a_login_without_the_csrf_header_is_forbidden_before_parsing() {
    let (base, _dir) = spawn_test_server().await;
    let response = reqwest::Client::new()
        .post(format!("{base}/api/auth/login"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        403,
        "the CSRF layer must run before the Json extractor"
    );
}

// ── Static assets ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_login_page_is_reachable_without_authentication() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new().get(&base).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("HaosGreen"));
}

#[tokio::test]
async fn the_embedded_assets_are_served_with_their_content_types() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let js = client.get(format!("{base}/app.js")).send().await.unwrap();
    assert_eq!(js.status(), 200);
    let js_type = js
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        js_type.contains("javascript"),
        "app.js must be served as javascript, got {js_type:?}"
    );

    let css = client
        .get(format!("{base}/style.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(css.status(), 200);
    let css_type = css
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        css_type.contains("text/css"),
        "style.css must be served as text/css, got {css_type:?}"
    );
}

/// The static assets are behind the source-IP allowlist too.
///
/// They are merged on the root router rather than on the guarded one — they
/// need no session and no CSRF header, because they are compile-time constants
/// with no per-user data — so without an explicit gate a source outside
/// `allow_ips` still received the whole dashboard shell. The UI states that a
/// non-empty list refuses "every other source … before authentication runs —
/// including the login page", and design spec §4.4 claims strict enforcement;
/// both claims were overstated while `/` answered 200.
#[tokio::test]
async fn the_static_assets_are_refused_to_a_source_outside_the_allowlist() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    replace_allow_ips(&base, &cookie, &["10.0.0.0/8"]).await;

    let client = reqwest::Client::new();
    for path in ["/", "/app.js", "/style.css"] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(
            response.status(),
            403,
            "GET {path} must be refused to a source outside allow_ips, got {}",
            response.status()
        );
        let body = response.text().await.unwrap();
        assert!(
            !body.contains("HaosGreen") && !body.contains("haos_session"),
            "GET {path} must not leak the shell to a refused source: {body:?}"
        );
    }
}

// ── Host validation and security headers ────────────────────────────────────

/// A request whose `Host` is not this dashboard's is refused.
///
/// The DNS-rebinding case: the dashboard binds to loopback and ships with
/// `admin`/`admin`, so an attacker page whose hostname re-resolves to
/// `127.0.0.1` reaches it from the operator's own browser. The request arrives
/// over loopback, so `allow_ips` cannot see it, and the CSRF header is no
/// obstacle because the attacker's JavaScript is same-origin with the rebound
/// hostname. `Host` is the one thing the browser will not let the attacker
/// forge — so it is the check.
#[tokio::test]
async fn a_request_with_a_foreign_host_header_is_forbidden() {
    let (base, _dir) = spawn_test_server().await;
    let addr = socket_addr(&base);

    // The rebound page is served on the same port, which is what makes it
    // same-origin with the dashboard it is attacking.
    for host in [
        format!("evil.example:{}", addr.port()),
        "evil.example".to_string(),
        // Neither a suffix nor a prefix of an accepted host may match.
        format!("127.0.0.1.evil.example:{}", addr.port()),
        format!("evil.example.127.0.0.1:{}", addr.port()),
        // A loopback literal on the wrong port is a different origin.
        "127.0.0.1:1".to_string(),
    ] {
        let response = raw_request(
            addr,
            &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(
            raw_status(&response),
            403,
            "Host: {host} must be refused, got {response:?}"
        );
    }
}

/// ...and the hosts a browser actually sends for this listener are accepted.
#[tokio::test]
async fn a_request_with_an_accepted_host_header_succeeds() {
    let (base, _dir) = spawn_test_server().await;
    let addr = socket_addr(&base);

    for host in [
        format!("127.0.0.1:{}", addr.port()),
        format!("localhost:{}", addr.port()),
        format!("[::1]:{}", addr.port()),
    ] {
        let response = raw_request(
            addr,
            &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(
            raw_status(&response),
            200,
            "Host: {host} must be accepted, got {response:?}"
        );
    }
}

/// A request with no `Host` at all cannot be checked, so it is refused.
#[tokio::test]
async fn a_request_without_a_host_header_is_forbidden() {
    let (base, _dir) = spawn_test_server().await;
    let addr = socket_addr(&base);
    let response = raw_request(addr, "GET / HTTP/1.0\r\n\r\n").await;
    assert_eq!(
        raw_status(&response),
        403,
        "a request with no Host cannot be validated and must be refused: {response:?}"
    );
}

#[tokio::test]
async fn the_security_headers_are_on_static_and_authenticated_responses() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // A static asset, with no session.
    let shell = client.get(&base).send().await.unwrap();
    assert_eq!(shell.status(), 200);
    assert_security_headers(&shell);

    // An authenticated API response.
    let cookie = login_and_get_cookie(&base, "admin").await;
    let settings = client
        .get(format!("{base}/api/settings"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(settings.status(), 200);
    assert_security_headers(&settings);

    // The login response itself, which is the one that carries a credential.
    let login = client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    assert_security_headers(&login);
}

// ── Chat sessions ───────────────────────────────────────────────────────────

/// Log in and create a chat session, returning the session cookie and the id.
///
/// The test harness starts the dashboard **without** an agent (`spawn_for_test`
/// passes `None`), which is exactly what makes the session CRUD routes testable:
/// they are pure in-memory bookkeeping. The routes that actually run the agent
/// answer 503 here, and that is asserted on purpose.
async fn chat_session(base: &str) -> (String, String) {
    let cookie = login_and_get_cookie(base, "admin").await;
    let response = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "creating a session must succeed");
    let body: serde_json::Value = response.json().await.unwrap();
    let id = body["id"]
        .as_str()
        .expect("creating a session must return its id")
        .to_string();
    assert!(!id.is_empty());
    (cookie, id)
}

#[tokio::test]
async fn chat_requires_authentication() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions"))
        .header("x-haos-green-csrf", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn creating_a_chat_session_without_the_csrf_header_is_forbidden() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn creating_a_chat_session_returns_an_id_that_the_listing_reports() {
    let (base, _dir) = spawn_test_server().await;
    let (cookie, id) = chat_session(&base).await;

    let listing = reqwest::Client::new()
        .get(format!("{base}/api/chat/sessions"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(listing.status(), 200);
    let body: serde_json::Value = listing.json().await.unwrap();
    let sessions = body["sessions"]
        .as_array()
        .expect("the listing must carry a `sessions` array");
    assert_eq!(sessions.len(), 1, "got {sessions:?}");
    assert_eq!(sessions[0]["id"], serde_json::json!(id));
    assert_eq!(sessions[0]["turns"], serde_json::json!(0));
}

#[tokio::test]
async fn a_new_chat_session_has_an_empty_history() {
    let (base, _dir) = spawn_test_server().await;
    let (cookie, id) = chat_session(&base).await;

    let response = reqwest::Client::new()
        .get(format!("{base}/api/chat/sessions/{id}/messages"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["messages"],
        serde_json::json!([]),
        "a fresh session must have no history"
    );
}

#[tokio::test]
async fn an_unknown_chat_session_is_not_found_on_every_route() {
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    // A typo must be a 404, never a silently created conversation. The send and
    // cancel routes are checked too: both run the session check before the
    // agent check, so the answer is "not found" rather than "unavailable".
    let cases: [(&str, &str, Option<serde_json::Value>); 3] = [
        ("GET", "/api/chat/sessions/missing/messages", None),
        (
            "POST",
            "/api/chat/sessions/missing/messages",
            Some(serde_json::json!({"message": "hello"})),
        ),
        ("POST", "/api/chat/sessions/missing/cancel", None),
    ];

    for (method, path, body) in cases {
        let mut request = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{base}{path}"),
            )
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::COOKIE, &cookie);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            404,
            "{method} {path} with an unknown session id"
        );
    }

    // And nothing was created behind the caller's back.
    let listing = client
        .get(format!("{base}/api/chat/sessions"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = listing.json().await.unwrap();
    assert_eq!(body["sessions"], serde_json::json!([]));
}

#[tokio::test]
async fn sending_a_message_without_an_agent_is_unavailable() {
    let (base, _dir) = spawn_test_server().await;
    let (cookie, id) = chat_session(&base).await;

    let response = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions/{id}/messages"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "message": "hello" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        503,
        "a dashboard started without an agent must degrade, not panic"
    );
    let body = response.text().await.unwrap();
    assert!(
        body.contains("agent"),
        "the 503 body must say what is missing, got {body:?}"
    );
}

#[tokio::test]
async fn cancelling_without_an_agent_is_unavailable() {
    let (base, _dir) = spawn_test_server().await;
    let (cookie, id) = chat_session(&base).await;

    let response = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions/{id}/cancel"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
}

#[tokio::test]
async fn an_empty_chat_message_is_rejected() {
    let (base, _dir) = spawn_test_server().await;
    let (cookie, id) = chat_session(&base).await;

    let response = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions/{id}/messages"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "message": "   " }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "a whitespace-only message must be refused before the agent is consulted"
    );
}

// ── Supervisor ──────────────────────────────────────────────────────────────
//
// Unlike the chat tests, these run against a dashboard whose `supervisor` handle
// is `Some`: every supervisor route answers 503 without one, so a test that
// never wires a supervisor would prove nothing about the task surface.
//
// The supervisor is built here rather than stubbed. `Supervisor::new_for_test`
// needs only an in-memory SQLite store and an artifacts directory, and
// `register_test_reasoning_backend` supplies the one backend the plan needs — so
// a real `submit`, a real transition, and a real `execute_now` all run.

/// A supervisor over an in-memory store, with a reasoning backend registered.
///
/// Without the backend `execute_now` would have nothing to run and every
/// lifecycle test would end up asserting on an internal error. The store is
/// passed in rather than created here so a test can reach the same connection
/// and break it.
fn test_supervisor(
    artifacts: &std::path::Path,
    memory: &haos_green::memory::MemoryStore,
) -> std::sync::Arc<haos_green::supervisor::Supervisor> {
    let mut supervisor = haos_green::supervisor::Supervisor::new_for_test(
        artifacts.to_path_buf(),
        memory.connection(),
    );
    supervisor.register_test_reasoning_backend(|prompt| async move { Ok(format!("ran:{prompt}")) });
    std::sync::Arc::new(supervisor)
}

/// Start the dashboard with a live supervisor attached, and hand back the
/// handle so a test can seed tasks and assert on the persisted state.
async fn spawn_test_server_with_supervisor() -> (
    String,
    tempfile::TempDir,
    std::sync::Arc<haos_green::supervisor::Supervisor>,
) {
    let dir = tempfile::tempdir().unwrap();
    // The store itself can be dropped here: `connection()` hands out an owned
    // `Arc<Mutex<Connection>>`, and that is what the supervisor keeps.
    let memory = haos_green::memory::MemoryStore::open_in_memory().expect("open a memory store");
    let supervisor = test_supervisor(&dir.path().join("artifacts"), &memory);
    let (addr, _handle) = haos_green::web::spawn_for_test_with_supervisor(
        dir.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        Some(supervisor.clone()),
    )
    .await
    .expect("the dashboard should start with a supervisor");
    (format!("http://{addr}"), dir, supervisor)
}

/// Every supervisor route, as `(method, path, body)`.
///
/// One list, used by both the 401 and the 503 sweep, so a route added to the
/// module and forgotten here is a route that is not covered by either.
fn supervisor_routes() -> Vec<(&'static str, &'static str, Option<serde_json::Value>)> {
    vec![
        ("GET", "/api/supervisor/tasks", None),
        ("GET", "/api/supervisor/tasks/nope", None),
        (
            "POST",
            "/api/supervisor/tasks",
            Some(serde_json::json!({"text": "summarize the readme"})),
        ),
        ("POST", "/api/supervisor/tasks/nope/pause", None),
        ("POST", "/api/supervisor/tasks/nope/resume", None),
        ("POST", "/api/supervisor/tasks/nope/cancel", None),
        ("POST", "/api/supervisor/tasks/nope/approve", None),
    ]
}

/// Submit a task through the API and return its id.
async fn submit_supervisor_task(base: &str, cookie: &str, text: &str) -> String {
    let response = reqwest::Client::new()
        .post(format!("{base}/api/supervisor/tasks"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, cookie)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "submitting a task should succeed");
    let body: serde_json::Value = response.json().await.unwrap();
    body["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("a submit must return a task id: {body}"))
        .to_string()
}

/// POST a lifecycle action on a supervisor task.
async fn supervisor_action(base: &str, cookie: &str, id: &str, action: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/api/supervisor/tasks/{id}/{action}"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn every_supervisor_route_returns_503_without_a_supervisor() {
    // The default harness wires no supervisor, which is the Phase 1 contract:
    // the dashboard must degrade to a named 503, never panic.
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    for (method, path, body) in supervisor_routes() {
        let mut request = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{base}{path}"),
            )
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::COOKIE, &cookie);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            503,
            "{method} {path} without a supervisor must be 503, got {}",
            response.status()
        );
        let message = response.text().await.unwrap();
        assert!(
            message.contains("supervisor"),
            "{method} {path} must name the missing wiring, got {message:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_supervisor_task_id_is_not_found() {
    let (base, _dir, _supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let detail = client
        .get(format!("{base}/api/supervisor/tasks/nope"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 404, "an unknown id must be a 404");
    let body = detail.text().await.unwrap();
    // The body is asserted, not just the status: an unregistered route answers
    // 404 with an empty body too, so a status-only assertion would pass on a
    // dashboard where the route does not exist at all.
    assert!(
        body.contains("unknown supervisor task"),
        "a 404 must say the task is unknown, got {body:?}"
    );
    assert!(
        !body.contains("\"task\""),
        "a 404 must not be an empty task object, got {body:?}"
    );

    for action in ["pause", "resume", "cancel", "approve"] {
        let response = supervisor_action(&base, &cookie, "nope", action).await;
        assert_eq!(
            response.status(),
            404,
            "POST .../nope/{action} on an unknown id must be 404, got {}",
            response.status()
        );
        let body = response.text().await.unwrap();
        assert!(
            body.contains("unknown supervisor task"),
            "POST .../nope/{action} must say the task is unknown, got {body:?}"
        );
    }
}

#[tokio::test]
async fn submitting_a_blank_supervisor_task_is_rejected() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    for text in ["", "   ", "\n\t "] {
        let response = reqwest::Client::new()
            .post(format!("{base}/api/supervisor/tasks"))
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::COOKIE, &cookie)
            .json(&serde_json::json!({ "text": text }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            400,
            "a blank task text ({text:?}) must be a 400, got {}",
            response.status()
        );
    }

    // A body with no `text` field never reaches the handler: axum's `Json`
    // extractor rejects it first, with 422. Pinned so that rejection is a
    // decision rather than a surprise.
    let malformed = reqwest::Client::new()
        .post(format!("{base}/api/supervisor/tasks"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "nope": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        malformed.status(),
        422,
        "a body with no `text` field is rejected by the extractor"
    );

    // Refused before the supervisor was reached: a 400 that still created a
    // task would be a 400 in name only.
    assert!(
        supervisor.store().list_recent(20).await.unwrap().is_empty(),
        "a rejected submit must not create a task"
    );
}

#[tokio::test]
async fn supervisor_mutations_require_the_csrf_header() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;

    let mut paths = vec!["/api/supervisor/tasks".to_string()];
    for action in ["pause", "resume", "cancel", "approve"] {
        paths.push(format!("/api/supervisor/tasks/{id}/{action}"));
    }

    for path in paths {
        let response = reqwest::Client::new()
            .post(format!("{base}{path}"))
            .header(reqwest::header::COOKIE, &cookie)
            .json(&serde_json::json!({ "text": "summarize the readme" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "POST {path} without the CSRF header must be refused, got {}",
            response.status()
        );
    }

    // Nothing was submitted and no lifecycle action ran.
    assert_eq!(supervisor.store().list_recent(20).await.unwrap().len(), 1);
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Route
    );
}

#[tokio::test]
async fn a_supervisor_task_can_be_submitted_listed_read_and_driven() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    // Submit. `submit` classifies, routes and stops, so the task is parked in
    // ROUTE rather than executed — the response has to say so.
    let submitted = client
        .post(format!("{base}/api/supervisor/tasks"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "text": "summarize the readme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(submitted.status(), 200);
    let submitted: serde_json::Value = submitted.json().await.unwrap();
    assert_eq!(
        submitted["outcome"],
        serde_json::json!("auto_execute_planned")
    );
    assert_eq!(submitted["state"], serde_json::json!("ROUTE"));
    let id = submitted["task_id"]
        .as_str()
        .expect("a task id")
        .to_string();

    // Listed.
    let listed = client
        .get(format!("{base}/api/supervisor/tasks"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    let listed: serde_json::Value = listed.json().await.unwrap();
    let tasks = listed["tasks"].as_array().expect("a tasks array");
    assert_eq!(tasks.len(), 1, "got {listed}");
    assert_eq!(tasks[0]["id"], serde_json::json!(id));
    assert_eq!(tasks[0]["state"], serde_json::json!("ROUTE"));
    assert!(tasks[0]["title"].is_string(), "got {listed}");
    assert!(tasks[0]["task_type"].is_string(), "got {listed}");
    assert!(tasks[0]["risk_level"].is_string(), "got {listed}");
    assert!(tasks[0]["priority"].is_number(), "got {listed}");

    // Detail: the task plus its jobs, transitions and artifacts.
    let detail = client
        .get(format!("{base}/api/supervisor/tasks/{id}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let detail: serde_json::Value = detail.json().await.unwrap();
    assert_eq!(detail["task"]["id"], serde_json::json!(id));
    assert_eq!(detail["task"]["state"], serde_json::json!("ROUTE"));
    assert_eq!(
        detail["task"]["user_request"],
        serde_json::json!("summarize the readme")
    );
    assert!(detail["jobs"].is_array(), "got {detail}");
    let transitions = detail["transitions"]
        .as_array()
        .expect("a transitions array");
    assert_eq!(
        transitions.len(),
        2,
        "submit records exactly Intake -> Classify -> Route for an auto-executed task, got {detail}"
    );
    assert_eq!(transitions[0]["from"], serde_json::json!("INTAKE"));
    assert_eq!(transitions[0]["to"], serde_json::json!("CLASSIFY"));
    assert_eq!(transitions[1]["from"], serde_json::json!("CLASSIFY"));
    assert_eq!(transitions[1]["to"], serde_json::json!("ROUTE"));
    let artifacts = detail["artifacts"].as_array().expect("an artifacts array");
    assert!(
        artifacts
            .iter()
            .any(|a| a["kind"] == serde_json::json!("intake")),
        "the intake artifact must be listed, got {detail}"
    );

    // Pause.
    let paused = supervisor_action(&base, &cookie, &id, "pause").await;
    assert_eq!(paused.status(), 200);
    let paused: serde_json::Value = paused.json().await.unwrap();
    assert_eq!(paused["state"], serde_json::json!("PAUSED"));
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Paused
    );

    // Pausing twice is a conflict with the task's current state.
    let again = supervisor_action(&base, &cookie, &id, "pause").await;
    assert_eq!(again.status(), 409);
    let message = again.text().await.unwrap();
    assert!(
        message.contains("Paused"),
        "the conflict must name the state: {message:?}"
    );

    // Resume runs the plan to completion.
    let resumed = supervisor_action(&base, &cookie, &id, "resume").await;
    assert_eq!(resumed.status(), 200);
    let resumed: serde_json::Value = resumed.json().await.unwrap();
    assert_eq!(resumed["state"], serde_json::json!("DONE"));
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Done
    );
}

/// A state refusal is a conflict with the task's current state, not a server
/// fault. This is the test that would catch a blanket `500` on the lifecycle
/// routes — and, equally, a blanket `409` on a genuine internal failure.
#[tokio::test]
async fn a_refused_supervisor_lifecycle_action_is_409_not_500() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    // `submit` leaves the task in ROUTE. `resume` only accepts a PAUSED task,
    // so this is refused even though ROUTE -> Execute is a legal edge.
    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;
    let response = supervisor_action(&base, &cookie, &id, "resume").await;
    assert_eq!(
        response.status(),
        409,
        "resuming a task that is not paused must be a conflict"
    );
    let message = response.text().await.unwrap();
    assert!(
        message.contains("Route"),
        "the conflict must name the current state: {message:?}"
    );
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Route,
        "a refused action must not change the state"
    );

    // A finished task accepts none of the three lifecycle actions.
    supervisor.execute_now(&id).await.unwrap();
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Done
    );
    for action in ["pause", "cancel", "approve"] {
        let response = supervisor_action(&base, &cookie, &id, action).await;
        assert_eq!(
            response.status(),
            409,
            "{action} on a DONE task must be a conflict, got {}",
            response.status()
        );
        let message = response.text().await.unwrap();
        assert!(
            message.contains("Done"),
            "{action} must name the current state, got {message:?}"
        );
    }
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Done
    );
}

/// The listing ignores any client-supplied limit.
///
/// **This test cannot prove the clamp**, and the earlier version of it implied
/// that it could: the route passes the constant `MAX_RECENT_TASKS`, so deleting
/// `.clamp()` from `TaskStore::list_recent` leaves an assertion of "25 tasks in
/// the store, 20 rows on the wire" green. The proof of the clamp is the store
/// unit test `the_clamp_is_the_only_thing_that_bounds_a_caller_supplied_limit`,
/// which calls the store with a limit it is not supposed to honour.
///
/// What *this* test can prove is the property the HTTP surface owns: there is no
/// way to ask the route for more than the bound, whatever a caller puts in the
/// query string.
#[tokio::test]
async fn the_supervisor_listing_ignores_a_client_supplied_limit() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;

    for i in 0..25 {
        let task = haos_green::supervisor::task::Task::new(&format!("task {i}"), "req");
        supervisor
            .store()
            .create(&task, "web", "dashboard", None)
            .await
            .unwrap();
    }

    let cookie = login_and_get_cookie(&base, "admin").await;
    for query in ["", "?limit=1000", "?limit=100&limit=500", "?limit=-1"] {
        let listed = reqwest::Client::new()
            .get(format!("{base}/api/supervisor/tasks{query}"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), 200, "GET /api/supervisor/tasks{query}");
        let listed: serde_json::Value = listed.json().await.unwrap();
        assert_eq!(
            listed["tasks"].as_array().unwrap().len(),
            20,
            "GET /api/supervisor/tasks{query} must stay bounded at 20: {listed}"
        );
    }
}

/// Two concurrent `resume`s of the same task must start the plan **once**.
///
/// This is the bug both reviewers found, at the boundary where it was observed:
/// the four lifecycle routes are read-check-write across separate lock
/// acquisitions, so two requests could both pass the check and both run the
/// plan — two `Paused -> Execute` audit edges, two sets of job rows, two
/// artifact rows for the same paths.
///
/// # What this test proves, and what it does not
///
/// It proves the **composed contract** at the HTTP boundary: whatever the
/// interleaving, exactly one `resume` is accepted, every other answer is a
/// conflict rather than a fault, and the task is left with one audit edge and
/// one set of jobs. That assertion is deterministic *after* the fix, because
/// only one request can win the compare-and-swap.
///
/// It is **not** the proof of the compare-and-swap, and must not be read as one.
/// The window that made the bug possible is between the route's pre-check and
/// the supervisor call, and the server — not the test — decides whether two
/// requests land in it. Measured: with the compare-and-swap reverted to the
/// unconditional `UPDATE`, this test still passed, because the in-flight guard
/// covered the duplicate run. The deterministic proofs are the multi-threaded
/// unit tests
/// `supervisor::store::tests::concurrent_duplicate_transitions_let_exactly_one_win`
/// and `supervisor::tests::concurrent_resumes_start_the_plan_exactly_once`,
/// which fail reliably under that same mutation.
///
/// The runtime flavour matters. Every other supervisor test in this file is on
/// the default current-thread runtime, where the requests only interleave at
/// `await` points and the registered backend never yields — which is why the
/// old suite could not see this at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_resumes_of_a_supervisor_task_start_it_once() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;
    let paused = supervisor_action(&base, &cookie, &id, "pause").await;
    assert_eq!(
        paused.status(),
        200,
        "the task must be paused to be resumable"
    );

    let mut requests = Vec::new();
    for _ in 0..8 {
        let base = base.clone();
        let cookie = cookie.clone();
        let id = id.clone();
        requests.push(tokio::spawn(async move {
            supervisor_action(&base, &cookie, &id, "resume")
                .await
                .status()
                .as_u16()
        }));
    }
    let mut statuses = Vec::new();
    for request in requests {
        statuses.push(request.await.expect("a client task must not panic"));
    }

    let accepted = statuses.iter().filter(|status| **status == 200).count();
    assert_eq!(
        accepted, 1,
        "exactly one resume may be accepted, got {statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|status| *status == 200 || *status == 409),
        "every other resume must be a conflict, not a fault: {statuses:?}"
    );

    let trail = supervisor.store().transitions(&id).await.unwrap();
    let resumed = trail
        .iter()
        .filter(|r| {
            r.from == haos_green::supervisor::task::TaskStatus::Paused
                && r.to == haos_green::supervisor::task::TaskStatus::Execute
        })
        .count();
    assert_eq!(
        resumed, 1,
        "the audit trail must not carry duplicate edges: {trail:?}"
    );

    let task = supervisor.store().get(&id).await.unwrap().unwrap();
    let planned = haos_green::supervisor::planner::Planner::new()
        .plan(&task)
        .jobs
        .len();
    assert_eq!(
        supervisor.store().jobs_for_task(&id).await.unwrap().len(),
        planned,
        "the task must have exactly one set of jobs"
    );
}

/// A row that exists but cannot be mapped is a **fault**, not a missing task.
///
/// `TaskStore::get` used to fold a row-mapping failure into `Ok(None)`, so a
/// corrupt `state` was answered as 404 "unknown supervisor task" for a task
/// sitting in the database — while `list_recent` propagated the identical error
/// as a 500. A 404 sends the operator looking for a task that is right there.
#[tokio::test]
async fn a_corrupt_supervisor_task_row_is_a_server_fault_not_a_missing_task() {
    let dir = tempfile::tempdir().unwrap();
    let memory = haos_green::memory::MemoryStore::open_in_memory().expect("open a memory store");
    let supervisor = test_supervisor(&dir.path().join("artifacts"), &memory);
    let (addr, _handle) = haos_green::web::spawn_for_test_with_supervisor(
        dir.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        Some(supervisor.clone()),
    )
    .await
    .expect("the dashboard should start with a supervisor");
    let base = format!("http://{addr}");
    let cookie = login_and_get_cookie(&base, "admin").await;

    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;

    // The row reads fine to begin with, so the assertion below is about the
    // corruption and not about a task that never existed.
    let healthy = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks/{id}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(healthy.status(), 200);

    // The row stays: only its `state` stops mapping.
    memory
        .connection()
        .lock()
        .await
        .execute(
            "UPDATE sup_tasks SET state='\"NOT_A_STATE\"' WHERE id=?1",
            [&id],
        )
        .unwrap();

    let broken = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks/{id}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        broken.status(),
        500,
        "a task whose row does not map is a server fault, not a 404"
    );
    let body = broken.text().await.unwrap();
    assert!(
        !body.contains("unknown supervisor task"),
        "the task is not unknown: {body:?}"
    );
    assert!(
        !body.contains("sup_tasks") && !body.contains("NOT_A_STATE"),
        "the response must not carry the SQL error chain: {body:?}"
    );

    // The lifecycle routes read the same row in their pre-check, so they must
    // answer 500 too — not 404, and not a 409 blaming the task's state.
    for action in ["pause", "cancel", "approve"] {
        let response = supervisor_action(&base, &cookie, &id, action).await;
        assert_eq!(
            response.status(),
            500,
            "{action} on an unreadable row must be a fault, got {}",
            response.status()
        );
    }
}

/// Job text is scrubbed **before it is stored**, so it comes back scrubbed.
///
/// The reviewers demonstrated the gap end to end: `ArtifactManager::write_text`
/// runs the summary through `redact::redact`, `TaskStore::update_job_status` did
/// not, so the same text was `api_key=***` on disk and the raw value in
/// `sup_jobs` — which this route served. Reachability is concrete:
/// `ShellBackend`'s summary is the command's stdout.
#[tokio::test]
async fn a_job_summary_and_error_are_redacted_in_the_task_detail() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;

    let job = haos_green::supervisor::job::Job::new(
        &id,
        haos_green::supervisor::job::JobType::ShellJob,
        "shell",
        "echo hello",
    );
    supervisor.store().create_job(&job).await.unwrap();
    supervisor
        .store()
        .update_job_status(
            &job.id,
            haos_green::supervisor::job::JobStatus::Succeeded,
            Some("stdout: api_key=<CAMPO_API_KEY_4d1f8ab3_8>"),
            Some("failed with Bearer ZZBEARERTOKEN"),
        )
        .await
        .unwrap();

    let detail = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks/{id}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let body = detail.text().await.unwrap();
    assert!(
        !body.contains("CAMPO_API_KEY") && !body.contains("ZZBEARERTOKEN"),
        "a secret reached the API: {body}"
    );
    assert!(
        body.contains("api_key=***") && body.contains("Bearer ***"),
        "the text must still be readable, with the values scrubbed: {body}"
    );
}

/// The detail route ships a job **projection**, not the store row.
///
/// `Job::workspace` is never assigned anywhere in the supervisor and
/// `Job::input_context` is written only by the MCP backend, which `main.rs`
/// does not register — so both are dropped rather than shipped as permanent
/// `null`s. `timeout_secs` / `retry_max` / `retry_count` / `allow_tools` are
/// orchestrator internals, and `prompt` duplicates `goal`.
#[tokio::test]
async fn the_task_detail_projects_its_jobs_instead_of_shipping_the_store_row() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;

    let mut job = haos_green::supervisor::job::Job::new(
        &id,
        haos_green::supervisor::job::JobType::ShellJob,
        "shell",
        "echo hello",
    );
    job.prompt = Some("echo hello".into());
    job.workspace = Some("/home/op/.haos-green/supervisor/workspaces/x".into());
    job.input_context = serde_json::json!({"api_key": "ZZINPUTCONTEXTLEAK"});
    job.allow_tools = vec!["shell".into()];
    job.timeout_secs = 900;
    job.retry_max = 3;
    supervisor.store().create_job(&job).await.unwrap();

    let detail = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks/{id}"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
    let detail: serde_json::Value = detail.json().await.unwrap();
    let jobs = detail["jobs"].as_array().expect("a jobs array");
    assert_eq!(jobs.len(), 1, "got {detail}");
    let mut keys: Vec<&str> = jobs[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["backend", "goal", "id", "job_type", "status"],
        "the job projection must be exactly this: {detail}"
    );
    let rendered = detail.to_string();
    assert!(
        !rendered.contains("ZZINPUTCONTEXTLEAK")
            && !rendered.contains("input_context")
            && !rendered.contains("workspace")
            && !rendered.contains("retry_max"),
        "the raw store row must not reach the wire: {rendered}"
    );
}

/// The route validates the trimmed text and stores the trimmed text.
///
/// `IntakeRouter::normalize` also trims, so the persisted `user_request` was
/// already trimmed before this test existed — it is a regression guard on the
/// value the API round-trips, not evidence that the route was the only thing
/// standing between the caller and an untrimmed row.
#[tokio::test]
async fn a_supervisor_task_stores_the_trimmed_request() {
    let (base, _dir, supervisor) = spawn_test_server_with_supervisor().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let id = submit_supervisor_task(&base, &cookie, "   summarize the readme   ").await;
    let task = supervisor.store().get(&id).await.unwrap().unwrap();
    assert_eq!(task.user_request, "summarize the readme");
    assert_eq!(task.title, "summarize the readme");
}

/// The other half of the 409/500 distinction: a genuine internal failure must
/// be a 500, on every supervisor route, and its body must not carry the error
/// chain. This is the test that fails if the routes blanket-map every error to
/// a conflict.
#[tokio::test]
async fn a_supervisor_database_failure_is_500_not_409() {
    let dir = tempfile::tempdir().unwrap();
    let memory = haos_green::memory::MemoryStore::open_in_memory().expect("open a memory store");
    let supervisor = test_supervisor(&dir.path().join("artifacts"), &memory);
    let (addr, _handle) = haos_green::web::spawn_for_test_with_supervisor(
        dir.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        Some(supervisor.clone()),
    )
    .await
    .expect("the dashboard should start with a supervisor");
    let base = format!("http://{addr}");
    let cookie = login_and_get_cookie(&base, "admin").await;

    // A real task, submitted while the store still works. It lands in ROUTE,
    // which permits pause, cancel and approve.
    let id = submit_supervisor_task(&base, &cookie, "summarize the readme").await;

    // Break only the audit table. `sup_tasks` is intact, so the task is still
    // readable and its state still permits the actions below — which is what
    // makes the fault reachable *after* the 409 pre-check has passed. Dropping
    // `sup_tasks` instead would fail the pre-check first and prove nothing
    // about this branch.
    memory
        .connection()
        .lock()
        .await
        .execute("DROP TABLE sup_transitions", [])
        .unwrap();

    // The listing does not touch that table, so it still works: the fault is
    // targeted, not a blanket failure.
    let listed = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200, "the listing must still work");

    for action in ["pause", "cancel", "approve"] {
        let response = supervisor_action(&base, &cookie, &id, action).await;
        assert_eq!(
            response.status(),
            500,
            "{action} on a permitted task whose audit write fails must be a server fault, got {}",
            response.status()
        );
        let body = response.text().await.unwrap();
        assert!(
            !body.contains("sup_transitions") && !body.contains("INSERT"),
            "the response must not carry the SQL error chain: {body:?}"
        );
    }
    assert_eq!(
        supervisor.state(&id).await.unwrap(),
        haos_green::supervisor::task::TaskStatus::Route,
        "a failed action must not change the state"
    );

    // Now break the table every supervisor read goes through. The body of that
    // error carries the SQL statement, so the response must not.
    //
    // The children go first: `sup_transitions` and friends carry a foreign key
    // to `sup_tasks`, and SQLite refuses to drop a parent that still has
    // referencing rows.
    {
        let conn = memory.connection();
        let conn = conn.lock().await;
        for table in ["sup_jobs", "sup_artifacts", "sup_transitions"] {
            let _ = conn.execute(&format!("DROP TABLE {table}"), []);
        }
        conn.execute("DROP TABLE sup_tasks", []).unwrap();
    }

    let listed = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        listed.status(),
        500,
        "a broken store must be a server fault"
    );
    let body = listed.text().await.unwrap();
    assert!(
        !body.contains("sup_tasks") && !body.contains("SELECT"),
        "the response must not carry the SQL error chain: {body:?}"
    );

    // With the task table gone the pre-check itself fails, so every lifecycle
    // route answers 500 — and must not blame the task's state for it.
    for action in ["pause", "resume", "cancel", "approve"] {
        let response = supervisor_action(&base, &cookie, "whatever", action).await;
        assert_eq!(
            response.status(),
            500,
            "{action} on a broken store must be a server fault, got {}",
            response.status()
        );
    }
}

// ── Logs (Phase 4) ──────────────────────────────────────────────────────────
//
// These run against a dashboard whose `logs` handle is `Some` and is the very
// `Arc` the test holds. Pushing into that buffer and reading the result back
// over HTTP is the only way to show that the route and the buffer are the same
// object; a dashboard with a buffer of its own would answer 200 with an empty
// list and every other assertion here would still pass.

/// Start the dashboard with a log buffer of `capacity` and hand the buffer back.
async fn spawn_test_server_with_logs(
    capacity: usize,
) -> (
    String,
    tempfile::TempDir,
    std::sync::Arc<haos_green::web::logs::LogBuffer>,
) {
    let dir = tempfile::tempdir().unwrap();
    let buffer = std::sync::Arc::new(haos_green::web::logs::LogBuffer::new(capacity));
    let (addr, _handle) = haos_green::web::spawn_for_test_with_logs(
        dir.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        buffer.clone(),
    )
    .await
    .expect("the dashboard should start with a log buffer");
    (format!("http://{addr}"), dir, buffer)
}

/// `GET /api/logs` with the session cookie attached.
async fn get_logs(base: &str, cookie: &str, query: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{base}/api/logs{query}"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap()
}

/// Read the SSE body until `wanted` complete frames have arrived, then parse.
///
/// Reading the whole body is not an option — the stream never ends — and a
/// timeout is required so a stream that produces nothing fails the test rather
/// than hanging the suite.
async fn read_sse_frames(
    response: reqwest::Response,
    wanted: usize,
    timeout: std::time::Duration,
) -> Vec<(String, String)> {
    use futures::StreamExt;

    let mut stream = response.bytes_stream();
    let mut raw = String::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if raw.matches("\n\n").count() >= wanted {
            return parse_sse(&raw);
        }
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => raw.push_str(&String::from_utf8_lossy(&chunk)),
            Ok(Some(Err(error))) => panic!("the log stream failed: {error}"),
            Ok(None) => return parse_sse(&raw),
            Err(_) => {
                panic!("timed out waiting for {wanted} SSE frames; the stream carried {raw:?}")
            }
        }
    }
}

/// Log in over a raw socket, so this test owns every connection it opens.
///
/// `login_and_get_cookie` leaves a pooled `reqwest` connection behind, and the
/// disconnect test counts `Arc` references to the buffer: a connection the
/// server has not finished tearing down holds one, which would make the count
/// ambiguous. `Connection: close` plus a socket the test reads to EOF leaves
/// nothing open.
async fn login_over_a_raw_socket(addr: std::net::SocketAddr) -> String {
    let body = r#"{"username":"admin","password":"admin"}"#;
    let request = format!(
        "POST /api/auth/login HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         x-haos-green-csrf: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = raw_request(addr, &request).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the raw-socket login must succeed: {response:?}"
    );
    response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_string())
        .expect("login must set a session cookie")
}

#[tokio::test]
async fn every_log_route_returns_503_without_a_buffer() {
    // The default harness wires no log buffer, which is the contract every
    // optional handle in `WebState` follows: an empty log is indistinguishable
    // from a quiet process, so an unwired dashboard must say so.
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    for path in ["/api/logs", "/api/logs/stream"] {
        let response = reqwest::Client::new()
            .get(format!("{base}{path}"))
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            503,
            "GET {path} without a log buffer must be 503, got {}",
            response.status()
        );
        let body = response.text().await.unwrap();
        assert!(
            body.contains("log buffer"),
            "the 503 body must name the missing handle, got {body:?}"
        );
    }
}

#[tokio::test]
async fn the_log_limit_is_clamped_and_never_trusted() {
    // Capacity 4 and ten entries pushed: every request below is answered from a
    // ring that holds exactly four, so "the limit was honoured" and "the ring
    // was dumped" are different answers.
    let (base, _dir, buffer) = spawn_test_server_with_logs(4).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    for i in 0..10 {
        buffer.push(haos_green::web::logs::LogEntry::new(
            "INFO",
            "haos_green::test",
            &format!("line {i}"),
        ));
    }

    // A small limit is honoured.
    let response = get_logs(&base, &cookie, "?limit=2").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["entries"].as_array().unwrap().len(), 2, "got {body}");
    assert_eq!(body["capacity"], serde_json::json!(4), "got {body}");

    // A huge limit is clamped by the ring, not honoured.
    let response = get_logs(&base, &cookie, "?limit=100000").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["entries"].as_array().unwrap().len(),
        4,
        "a huge limit must not be able to ask for more than the ring holds: {body}"
    );

    // Zero is legal and returns nothing.
    let response = get_logs(&base, &cookie, "?limit=0").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["entries"].as_array().unwrap().is_empty(),
        "limit=0 must return no entries: {body}"
    );
    assert_eq!(body["capacity"], serde_json::json!(4));

    // Absent means the default, which is larger than the ring here.
    let response = get_logs(&base, &cookie, "").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["entries"].as_array().unwrap().len(), 4);

    // Garbage is rejected, never silently defaulted.
    for query in ["?limit=abc", "?limit=-1", "?limit=", "?limit=1.5"] {
        let response = get_logs(&base, &cookie, query).await;
        assert_eq!(
            response.status(),
            400,
            "GET /api/logs{query} must be rejected, got {}",
            response.status()
        );
        let body = response.text().await.unwrap();
        assert!(body.contains("limit"), "got {body:?}");
    }
}

#[tokio::test]
async fn the_log_limit_has_a_hard_maximum_that_does_not_depend_on_the_ring() {
    // A ring configured larger than the hard maximum must still not be
    // dumpable in one request: the ceiling is the response size, not the
    // buffer's capacity.
    let (base, _dir, buffer) = spawn_test_server_with_logs(5000).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    for i in 0..1500 {
        buffer.push(haos_green::web::logs::LogEntry::new(
            "INFO",
            "haos_green::test",
            &format!("line {i}"),
        ));
    }

    let response = get_logs(&base, &cookie, "?limit=100000").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1000,
        "the hard maximum must cap a response even when the ring is bigger: got {}",
        entries.len()
    );
    assert_eq!(body["capacity"], serde_json::json!(5000));

    // The entries are the newest 1000, oldest first: 500..1499.
    assert_eq!(entries[0]["message"], serde_json::json!("line 500"));
    assert_eq!(entries[999]["message"], serde_json::json!("line 1499"));
}

#[tokio::test]
async fn a_wrapped_log_read_is_bounded_and_ordered() {
    let (base, _dir, buffer) = spawn_test_server_with_logs(4).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    for i in 0..10 {
        buffer.push(haos_green::web::logs::LogEntry::new(
            "INFO",
            "haos_green::test",
            &format!("line {i}"),
        ));
    }

    let response = get_logs(&base, &cookie, "").await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let messages: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["message"].as_str().unwrap())
        .collect();

    assert_eq!(
        messages,
        vec!["line 6", "line 7", "line 8", "line 9"],
        "a wrapped ring must return the newest entries, oldest first: {body}"
    );
    assert_eq!(body["entries"][0]["level"], serde_json::json!("INFO"));
    assert_eq!(
        body["entries"][0]["target"],
        serde_json::json!("haos_green::test")
    );
    assert!(
        body["entries"][0]["timestamp"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "every entry carries a timestamp: {body}"
    );
}

#[tokio::test]
async fn the_log_stream_delivers_entries_pushed_after_it_connects() {
    let (base, _dir, buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    // History: pushed before the stream exists, so it is not a live event.
    buffer.push(haos_green::web::logs::LogEntry::new(
        "INFO",
        "haos_green::test",
        "before the stream",
    ));

    let response = reqwest::Client::new()
        .get(format!("{base}/api/logs/stream"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "the stream route must answer 200");
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "the stream route must answer with SSE, got {content_type:?}"
    );

    // The response head is in, so the tail's cursor was read before it: both of
    // these are guaranteed to be delivered.
    buffer.push(haos_green::web::logs::LogEntry::new(
        "INFO",
        "haos_green::test",
        "live one",
    ));
    // A message carrying everything that could break the SSE framing: a bare
    // newline, a `data:` line and an `event:` line.
    buffer.push(haos_green::web::logs::LogEntry::new(
        "WARN",
        "haos_green::test",
        "live two\ndata: injected\n\nevent: injected",
    ));

    let events = read_sse_frames(response, 2, std::time::Duration::from_secs(5)).await;
    let logs: Vec<serde_json::Value> = events
        .iter()
        .filter(|(kind, _)| kind == "log")
        .map(|(_, data)| {
            serde_json::from_str(data)
                .unwrap_or_else(|e| panic!("the log event must carry JSON: {e}: {data:?}"))
        })
        .collect();

    assert_eq!(
        logs.len(),
        2,
        "exactly two log events, one per pushed entry — a message containing \
         `data:`/`event:` lines must not be able to forge extra frames: {events:?}"
    );
    assert_eq!(
        logs[0]["message"].as_str().unwrap(),
        "live one",
        "the stream must not replay history: {events:?}"
    );
    assert_eq!(
        logs[1]["message"].as_str().unwrap(),
        "live two\ndata: injected\n\nevent: injected",
        "the newline must survive the round trip intact: {events:?}"
    );
    assert_eq!(logs[1]["level"].as_str().unwrap(), "WARN");
    assert_eq!(logs[1]["target"].as_str().unwrap(), "haos_green::test");
}

/// A tail must not outlive the tab that opened it.
///
/// The stream's task holds its own `Arc<LogBuffer>`, so the buffer's strong
/// count is a direct observation of whether that task is still alive: it is
/// above the idle floor while the stream is open, and back at the floor once
/// the client disconnects. Both connections are raw sockets the test owns, so
/// nothing else can be holding a reference.
#[tokio::test]
async fn the_log_stream_task_stops_when_the_client_disconnects() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let buffer = std::sync::Arc::new(haos_green::web::logs::LogBuffer::new(16));
    let (addr, _handle) = haos_green::web::spawn_for_test_with_logs(
        dir.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        buffer.clone(),
    )
    .await
    .expect("the dashboard should start with a log buffer");
    let base = format!("http://{addr}");

    let cookie = login_over_a_raw_socket(addr).await;

    // The login socket is closed by now (`Connection: close`, read to EOF).
    // Wait for the count to settle so the baseline is the idle floor.
    let mut baseline = std::sync::Arc::strong_count(&buffer);
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let now = std::sync::Arc::strong_count(&buffer);
        if now == baseline {
            break;
        }
        baseline = now;
    }

    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET /api/logs/stream HTTP/1.1\r\nHost: {addr}\r\nCookie: {cookie}\r\n\
         Connection: close\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), socket.read(&mut byte))
            .await
            .expect("the response head must arrive")
            .unwrap();
        assert_ne!(
            read,
            0,
            "the connection closed before the head: {:?}",
            String::from_utf8_lossy(&head)
        );
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the stream must open: {head:?}"
    );

    // The tail task is alive and holding the buffer.
    let streaming = std::sync::Arc::strong_count(&buffer);
    assert!(
        streaming > baseline,
        "the tail task must hold the buffer while the stream is open: \
         {streaming} vs a baseline of {baseline}"
    );

    // Close the client. Nothing else in this test owns a connection.
    drop(socket);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let now = std::sync::Arc::strong_count(&buffer);
        if now == baseline {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the tail task is still holding the log buffer {now} vs {baseline} \
             ten seconds after the client disconnected — a leaked task per \
             abandoned tab"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // The dashboard still works afterwards: the leaked task would not have
    // broken this, but a stream that took the process down would.
    let response = get_logs(&base, &cookie, "").await;
    assert_eq!(response.status(), 200);
}

// ── What the log view must never serve ──────────────────────────────────────

/// A configured secret that reaches the ring must not reach the browser, on
/// either the history route or the live stream.
///
/// The shape rules alone cannot catch this one. A `reqwest` transport error
/// renders the request URL, and a Telegram bot token lives in that URL's *path*
/// — `https://api.telegram.org/bot<token>/sendMessage` has no key, no separator
/// and no `sk-` prefix, so nothing about it looks like a credential. It is
/// caught because `main.rs` registers every configured secret by value at
/// startup, and this test performs that same registration.
#[tokio::test]
async fn a_configured_secret_in_a_logged_url_never_reaches_the_dashboard() {
    let (base, _dir, buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    // Built at runtime so this file never carries a credential-shaped literal,
    // and unique to this test: the registry is process-global.
    let token = format!("{}{}", "8123456789:AAH", "zz_capture_probe_1f4c9d");
    assert!(
        haos_green::supervisor::redact::register_secret(&token),
        "the startup registration must accept a configured token"
    );

    // Open the live stream first: the entry is pushed once the response head is
    // in, so the tail is guaranteed to deliver it.
    let response = client
        .get(format!("{base}/api/logs/stream"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    buffer.push(haos_green::web::logs::LogEntry::new(
        "ERROR",
        "haos_green::platform::telegram",
        &format!("error sending request for url (https://api.telegram.org/bot{token}/sendMessage)"),
    ));
    // The same value in a message with no shape a rule can recognise: no key, no
    // separator, no `bot` prefix, no `sk-`. Only the by-value registration can
    // catch this one, which is what makes this test a test of the registration
    // rather than of the shape rules.
    buffer.push(haos_green::web::logs::LogEntry::new(
        "WARN",
        "haos_green::a2a::client",
        &format!("the peer rejected the credential {token}"),
    ));

    let events = read_sse_frames(response, 2, std::time::Duration::from_secs(5)).await;
    let payloads: Vec<String> = events
        .iter()
        .filter(|(kind, _)| kind == "log")
        .map(|(_, data)| data.clone())
        .collect();
    assert_eq!(
        payloads.len(),
        2,
        "the stream must deliver both entries: {events:?}"
    );
    for data in &payloads {
        assert!(
            !data.contains(&token),
            "the live stream served the token: {data}"
        );
    }
    assert!(
        payloads[0].contains("api.telegram.org"),
        "the diagnostic value of the message must survive: {}",
        payloads[0]
    );
    assert!(
        payloads[1].contains("the peer rejected the credential"),
        "the message must survive with only the credential masked: {}",
        payloads[1]
    );

    let body = get_logs(&base, &cookie, "").await.text().await.unwrap();
    assert!(
        !body.contains(&token),
        "the history route served the token: {body}"
    );
    assert!(body.contains("api.telegram.org"), "{body}");
}

/// A ring that has stopped recording must say so, on both routes.
///
/// `push` and the readers all treat a poisoned lock as "do nothing", which on
/// its own is indistinguishable from a quiet process: the routes would answer
/// 200 with the entries from before the poison and an operator would see a log
/// that simply stopped.
#[tokio::test]
async fn a_poisoned_log_buffer_is_a_503_and_not_an_empty_log() {
    let (base, _dir, buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    buffer.push(haos_green::web::logs::LogEntry::new(
        "INFO",
        "haos_green::test",
        "recorded before the poison",
    ));

    // The ring works, so a 503 after the poison cannot be a route that was
    // broken all along.
    let response = get_logs(&base, &cookie, "").await;
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(body.contains("recorded before the poison"), "{body}");

    buffer.poison_for_test();

    let response = get_logs(&base, &cookie, "").await;
    assert_eq!(
        response.status(),
        503,
        "a ring that stopped recording must not answer 200 with a stale list"
    );
    let body = response.text().await.unwrap();
    assert!(
        body.contains("poisoned"),
        "the refusal must say why: {body}"
    );

    let response = reqwest::Client::new()
        .get(format!("{base}/api/logs/stream"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        503,
        "the stream must refuse a ring that is not recording either"
    );
}

/// A client cannot open an unbounded number of live tails.
///
/// Each stream is a task plus a 128-slot channel of serialized entries, and the
/// route is behind nothing but a session: without a cap, one authenticated
/// client decides how much memory the dashboard's tail costs.
///
/// The refusal is **429**, not 503: the log view treats 503 as terminal, so a
/// transient limit answered that way would disable the view in that tab
/// permanently.
#[tokio::test]
async fn the_number_of_live_log_streams_is_capped() {
    let (base, _dir, _buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let stream = |client: &reqwest::Client, cookie: &str| {
        client
            .get(format!("{base}/api/logs/stream"))
            .header(reqwest::header::COOKIE, cookie)
            .send()
    };

    let mut open = Vec::new();
    for index in 0..haos_green::web::logs::MAX_LOG_STREAMS {
        let response = stream(&client, &cookie).await.unwrap();
        assert_eq!(
            response.status(),
            200,
            "stream {index} is inside the cap and must open"
        );
        open.push(response);
    }

    let refused = stream(&client, &cookie).await.unwrap();
    assert_eq!(
        refused.status(),
        429,
        "the stream past the cap must be refused as a transient condition, \
         not as an unavailable feature"
    );
    assert_eq!(
        refused
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("5"),
        "a 429 must tell the client when to come back"
    );

    // Dropping a stream closes its connection, which drops the response body,
    // which returns the permit. Nothing else in this test owns a stream.
    drop(open.pop());

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let response = stream(&client, &cookie).await.unwrap();
        if response.status() == 200 {
            break;
        }
        assert_eq!(response.status(), 429);
        assert!(
            std::time::Instant::now() < deadline,
            "a closed stream never returned its permit"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Logging out ends a stream that is already open.
///
/// The guard authorises a stream once, at connect. Without a re-check, a
/// destroyed session would keep receiving the process's log — targets, paths,
/// task ids, error text — for as long as the tab stayed open.
#[tokio::test]
async fn an_open_log_stream_ends_when_its_session_is_destroyed() {
    let (base, _dir, buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let streaming = client
        .get(format!("{base}/api/logs/stream"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(streaming.status(), 200);

    let logout = client
        .post(format!("{base}/api/auth/logout"))
        .header(reqwest::header::COOKIE, &cookie)
        .header("x-haos-green-csrf", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 200, "the logout must succeed");

    // The stream must end on its own. Reading the body to EOF is the
    // observation: a stream that is still live never reaches EOF, and this
    // fails on the timeout instead of hanging the suite.
    let tail = tokio::time::timeout(std::time::Duration::from_secs(15), streaming.text()).await;
    assert!(
        tail.is_ok(),
        "the stream outlived the session that authorised it"
    );

    // And a fresh request with the dead cookie is refused, so the stream really
    // did end because the session is gone.
    assert_eq!(get_logs(&base, &cookie, "").await.status(), 401);

    // The buffer is untouched by any of this.
    buffer.push(haos_green::web::logs::LogEntry::new(
        "INFO",
        "haos_green::test",
        "still recording",
    ));
    assert!(!buffer.is_empty());
}

/// Nothing the dashboard sends may be cached.
///
/// The log routes are the clearest case: a cached copy of the process's log
/// outlives the session that authorised it, and a shared proxy or a browser's
/// restored history is enough to serve it to someone else.
#[tokio::test]
async fn the_log_routes_are_never_cached() {
    let (base, _dir, _buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let history = get_logs(&base, &cookie, "").await;
    assert_eq!(history.status(), 200);
    assert_eq!(
        history
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "the log history must not be storable"
    );
    assert_eq!(
        history
            .headers()
            .get(reqwest::header::VARY)
            .and_then(|value| value.to_str().ok()),
        Some("Cookie"),
        "the body depends on the session cookie"
    );

    let streaming = client
        .get(format!("{base}/api/logs/stream"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(streaming.status(), 200);
    assert_eq!(
        streaming
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "the live stream must not be storable"
    );

    // The refusal path carries them too: a cache stores a 401 as happily as a
    // 200.
    let anonymous = get_logs(&base, "", "").await;
    assert_eq!(anonymous.status(), 401);
    assert_eq!(
        anonymous
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

/// One enormous log line cannot be served whole.
///
/// The ring bounds entries by count *and* by bytes, and the per-message cap is
/// applied at capture with an explicit marker — a log view that silently
/// returned a prefix would be worse than one that says how much it dropped.
#[tokio::test]
async fn an_enormous_log_message_is_served_truncated_and_says_so() {
    let (base, _dir, buffer) = spawn_test_server_with_logs(16).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let huge = "L".repeat(haos_green::web::logs::MAX_MESSAGE_BYTES * 4);
    buffer.push(haos_green::web::logs::LogEntry::new(
        "INFO",
        "haos_green::test",
        &huge,
    ));

    let body = get_logs(&base, &cookie, "").await.text().await.unwrap();
    assert!(
        body.len() < huge.len(),
        "the served message must be capped: {} bytes for a {} byte message",
        body.len(),
        huge.len()
    );
    assert!(
        body.contains("more characters]"),
        "the truncation must be explicit"
    );
}

// ── Live chat streaming (opt-in) ────────────────────────────────────────────
//
// Nothing on the agent path is stubbed here. The test builds a real
// `haos_green::agent::Agent` (the same 17-argument construction
// `tests/a2a_e2e_live.rs` uses), attaches it to the real dashboard router,
// serves it on an ephemeral loopback port, and drives it with a real HTTP
// request over a real SSE stream.
//
// Two gates, because this cannot pass on a machine without the endpoint:
//
// 1. `#[ignore]` — plain `cargo test` never picks it up.
// 2. A runtime check of `HAOS_GREEN_WEB_LIVE=1` — even an explicit `--ignored`
//    run exits early with a printed message when it is unset, so CI passes with
//    the variable unset.
//
// Run it with:
//
// ```text
// HAOS_GREEN_WEB_LIVE=1 cargo test --test web_endpoint -- --ignored --nocapture
// ```
//
// The provider is an OpenAI-compatible server at `LIVE_LLM_BASE_URL` accepting
// any non-empty `Bearer` token.

/// OpenAI-compatible endpoint the live test talks to.
const LIVE_LLM_BASE_URL: &str = "http://127.0.0.1:8790/v1";
/// Verified-working model on that endpoint.
const LIVE_LLM_MODEL: &str = "a6api_DeepSeek-V4-Flash-0731";
/// Trivial prompt: no tool call is needed, so the loop terminates on its first
/// iteration with a final text response.
const LIVE_PROMPT: &str = "Reply with the single word: pong";

/// A `PlatformSender` that drops everything on the floor.
///
/// `Agent::new` needs one; the trivial prompt calls no tool.
struct LiveNoopSender;

#[async_trait::async_trait]
impl haos_green::platform::sender::PlatformSender for LiveNoopSender {
    async fn send_message(
        &self,
        _chat_id: &str,
        _text: &str,
        _format: haos_green::platform::sender::MessageFormat,
    ) -> anyhow::Result<haos_green::platform::sender::PlatformMessageId> {
        Ok("noop:1".to_string())
    }

    async fn send_file(
        &self,
        _chat_id: &str,
        _path: &std::path::Path,
        _caption: Option<&str>,
    ) -> anyhow::Result<haos_green::platform::sender::PlatformMessageId> {
        Ok("noop:1".to_string())
    }

    async fn show_cancel_button(
        &self,
        _chat_id: &str,
        _text: &str,
        _cancel_id: &str,
    ) -> anyhow::Result<haos_green::platform::sender::PlatformMessageId> {
        Ok("noop:1".to_string())
    }

    async fn edit_message(
        &self,
        _chat_id: &str,
        _message_id: &haos_green::platform::sender::PlatformMessageId,
        _text: &str,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn delete_message(
        &self,
        _chat_id: &str,
        _message_id: &haos_green::platform::sender::PlatformMessageId,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn notify_shutdown(&self, _chat_id: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Write a `config.toml` whose home directory lives inside `dir`.
///
/// `[general].home` is an absolute path inside the temp dir, so `Config::resolve`
/// materializes the whole home tree there and no global state is touched — this
/// file never calls `std::env::set_var`, which is process-global and would race
/// with the other tests in this binary.
fn write_live_config(dir: &std::path::Path) -> std::path::PathBuf {
    let home = dir.join("home");
    let workspace = home.join("workspace");
    let path = dir.join("config.toml");
    let toml = format!(
        r#"
[general]
home = "{home}"

[telegram]
bot_token = "test-token"
allowed_user_ids = [1]

[openrouter]
api_key = "test-key"
base_url = "{LIVE_LLM_BASE_URL}"
model = "{LIVE_LLM_MODEL}"
max_tokens = 512

[agent]
max_iterations = 4

[sandbox]
allowed_directory = "{workspace}"
"#,
        home = home.display(),
        workspace = workspace.display(),
    );
    std::fs::write(&path, toml).expect("write config.toml");
    path
}

/// Construct the real `Agent` exactly as `src/main.rs` does, minus the pieces
/// that need a live Telegram bot.
async fn build_live_agent(
    config_path: &std::path::Path,
    memory: &haos_green::memory::MemoryStore,
) -> std::sync::Arc<haos_green::agent::Agent> {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let config = haos_green::config::Config::load(config_path).expect("load generated config");

    let (sections, default_provider, _fallback) = config.build_providers();
    let registry = Arc::new(
        haos_green::provider::build_registry(
            &sections,
            &default_provider,
            config.parse_retry_limit(),
        )
        .expect("build the provider registry"),
    );

    let skills_rw = Arc::new(tokio::sync::RwLock::new(
        haos_green::skills::SkillRegistry::new(),
    ));
    let agents_rw = Arc::new(tokio::sync::RwLock::new(
        haos_green::skills::SkillRegistry::new(),
    ));
    let restart_pending = Arc::new(AtomicBool::new(false));
    let soul_updated = Arc::new(AtomicBool::new(false));

    let mut tool_registry = haos_green::tool_registry::ToolRegistry::new();
    tool_registry.register(Box::new(haos_green::builtin_tools::BuiltinTools::new(
        config.skills.directory.clone(),
        skills_rw.clone(),
        restart_pending.clone(),
        soul_updated.clone(),
    )));
    tool_registry.register(Box::new(haos_green::memory_tools::MemoryTools::new(
        memory.clone(),
    )));
    tool_registry.register(Box::new(haos_green::skill_tools::SkillTools::new(
        config.skills.directory.clone(),
        config.agents.directory.clone(),
        skills_rw.clone(),
        agents_rw.clone(),
    )));
    // `execute_command` lives in its own handler; without it the registry would
    // not match what `src/main.rs` builds.
    tool_registry.register(Box::new(haos_green::command_tool::CommandTool::new(
        config.sandbox.allowed_directory.clone(),
        Arc::new(haos_green::cancel_registry::CancelRegistry::new()),
        Arc::new(LiveNoopSender),
    )));

    let task_store = haos_green::scheduler::reminders::ScheduledTaskStore::new(memory.connection());
    let scheduler = Arc::new(
        haos_green::scheduler::Scheduler::new()
            .await
            .expect("create the scheduler"),
    );
    let (job_tx, _job_rx) =
        tokio::sync::mpsc::unbounded_channel::<haos_green::agent::ScheduledJobRequest>();
    let langsmith = Arc::new(haos_green::langsmith::LangSmithClient::new(None));
    let cancel_registry = Arc::new(haos_green::cancel_registry::CancelRegistry::new());
    let sender: Arc<dyn haos_green::platform::sender::PlatformSender> = Arc::new(LiveNoopSender);

    // `Arc::new_cyclic` so the agent can hold a `Weak<Agent>` without leaking.
    Arc::new_cyclic(|weak| {
        haos_green::agent::Agent::new(
            config,
            registry,
            haos_green::mcp::McpManager::new(),
            memory.clone(),
            haos_green::skills::SkillRegistry::new(),
            haos_green::skills::SkillRegistry::new(),
            task_store,
            Arc::clone(&scheduler),
            weak.clone(),
            job_tx,
            langsmith,
            config_path.to_path_buf(),
            cancel_registry,
            tool_registry,
            sender,
            restart_pending,
            soul_updated,
        )
    })
}

/// The `(event, data)` pairs in an SSE body.
///
/// Comment lines (`:` — the keep-alive) and unknown fields are ignored, and a
/// frame's `data:` lines are joined with newlines exactly as the SSE spec
/// specifies.
fn parse_sse(body: &str) -> Vec<(String, String)> {
    let mut events = Vec::new();
    let mut kind = String::new();
    let mut data: Vec<String> = Vec::new();

    let flush = |kind: &mut String, data: &mut Vec<String>, events: &mut Vec<(String, String)>| {
        if !kind.is_empty() || !data.is_empty() {
            events.push((std::mem::take(kind), data.join("\n")));
            data.clear();
        }
    };

    for line in body.lines() {
        if line.is_empty() {
            flush(&mut kind, &mut data, &mut events);
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            kind = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
    }
    flush(&mut kind, &mut data, &mut events);
    events
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a live OpenAI-compatible LLM on 127.0.0.1:8790; \
            run with: HAOS_GREEN_WEB_LIVE=1 cargo test --test web_endpoint -- --ignored --nocapture"]
async fn a_live_chat_message_streams_tokens_and_exactly_one_done_event() {
    if std::env::var("HAOS_GREEN_WEB_LIVE").as_deref() != Ok("1") {
        println!(
            "SKIP: HAOS_GREEN_WEB_LIVE is not set to 1 — this test needs a live LLM at \
             {LIVE_LLM_BASE_URL}.\nRun it with:\n    \
             HAOS_GREEN_WEB_LIVE=1 cargo test --test web_endpoint -- --ignored --nocapture"
        );
        return;
    }

    // The temp dir must outlive the whole test: the config, the resolved home
    // and the sandbox all live inside it.
    let tmp = tempfile::tempdir().expect("create a temp dir");
    let config_path = write_live_config(tmp.path());
    let memory = haos_green::memory::MemoryStore::open_in_memory().expect("open a memory store");
    let agent = build_live_agent(&config_path, &memory).await;

    // The policy, checked against a real agent rather than a stub. An empty
    // policy means "no tools" to the loop, and the wildcard trap the design spec
    // fell into would produce exactly that — silently.
    let policy = haos_green::web::routes::chat::web_tool_policy_for(&agent);
    let live: Vec<String> = agent
        .all_tool_definitions()
        .into_iter()
        .map(|definition| definition.function.name)
        .collect();
    assert!(
        !policy.is_empty(),
        "the live agent's policy must not be empty: {policy:?}"
    );
    assert_eq!(
        policy, live,
        "the policy must be exactly the registry plus MCP definitions"
    );
    assert!(
        !policy
            .iter()
            .any(|tool| tool == "invoke_agent" || tool == "spawn_agents"),
        "subagent dispatch must not be reachable from the dashboard: {policy:?}"
    );
    println!("live tool policy: {} tools", policy.len());

    let (addr, _handle) = haos_green::web::spawn_for_test_with_agent(
        tmp.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        Some(agent),
    )
    .await
    .expect("the dashboard should start with an agent");
    let base = format!("http://{addr}");

    let cookie = login_and_get_cookie(&base, "admin").await;
    let (_, id) = {
        let response = reqwest::Client::new()
            .post(format!("{base}/api/chat/sessions"))
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::COOKIE, &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        (
            cookie.clone(),
            body["id"].as_str().expect("an id").to_string(),
        )
    };

    let response = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions/{id}/messages"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "message": LIVE_PROMPT }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "the send route must start a stream");
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "the send route must answer with SSE, got {content_type:?}"
    );

    let body = response.text().await.expect("read the SSE body");
    println!("--- SSE body ---\n{body}\n--- end ---");
    let events = parse_sse(&body);
    assert!(!events.is_empty(), "the stream must carry events");

    let tokens: Vec<&str> = events
        .iter()
        .filter(|(kind, _)| kind == "token")
        .map(|(_, data)| data.as_str())
        .collect();
    let done: Vec<&(String, String)> = events.iter().filter(|(kind, _)| kind == "done").collect();
    let errors: Vec<&(String, String)> =
        events.iter().filter(|(kind, _)| kind == "error").collect();

    assert!(
        errors.is_empty(),
        "a live run must not report an error: {errors:?}"
    );
    assert!(
        !tokens.is_empty(),
        "the stream must contain at least one token event, got {events:?}"
    );
    assert_eq!(
        done.len(),
        1,
        "the stream must contain exactly one terminal done event, got {events:?}"
    );

    let done_payload: serde_json::Value =
        serde_json::from_str(&done[0].1).expect("the done event carries JSON");
    let final_text = done_payload["text"].as_str().unwrap_or_default();
    assert!(
        !final_text.is_empty(),
        "the done event must carry the assistant's text: {done_payload}"
    );
    // Every streamed chunk must be part of the final answer: a `select!` that
    // raced the join handle would truncate the stream and this would catch it.
    assert_eq!(
        tokens.concat(),
        final_text,
        "the concatenated tokens must reconstruct the final response"
    );

    // The run is persisted: the user turn and the assistant reply.
    let history = reqwest::Client::new()
        .get(format!("{base}/api/chat/sessions/{id}/messages"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(history.status(), 200);
    let history: serde_json::Value = history.json().await.unwrap();
    let messages = history["messages"].as_array().expect("a messages array");
    assert_eq!(messages.len(), 2, "got {history}");
    assert_eq!(messages[0]["role"], serde_json::json!("user"));
    assert_eq!(messages[0]["content"], serde_json::json!(LIVE_PROMPT));
    assert_eq!(messages[1]["role"], serde_json::json!("assistant"));
    assert_eq!(messages[1]["content"], serde_json::json!(final_text));

    println!("live assistant reply: {final_text}");

    // A second message on the same session must be accepted. This is the only
    // place that can observe that the "a run is in flight" claim is released
    // when a stream ends: a leaked claim would answer 409 here forever.
    let second = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions/{id}/messages"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "message": LIVE_PROMPT }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        200,
        "the run claim must be released when a stream ends"
    );
    let second_body = second.text().await.expect("read the second SSE body");
    let second_events = parse_sse(&second_body);
    assert!(
        second_events.iter().any(|(kind, _)| kind == "done"),
        "the second run must also terminate with a done event, got {second_events:?}"
    );
    assert!(
        !second_events.iter().any(|(kind, _)| kind == "error"),
        "the second run must not report an error, got {second_events:?}"
    );

    let history = reqwest::Client::new()
        .get(format!("{base}/api/chat/sessions/{id}/messages"))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    let history: serde_json::Value = history.json().await.unwrap();
    let messages = history["messages"].as_array().expect("a messages array");
    assert_eq!(
        messages.len(),
        4,
        "both turns of the conversation must be retained: {history}"
    );
    assert_eq!(messages[2]["role"], serde_json::json!("user"));
    assert_eq!(messages[3]["role"], serde_json::json!("assistant"));

    // The cancel route, against a real agent with no run in flight: it must
    // answer rather than 404/503, and it must report that there was nothing to
    // cancel. (A run that is actually in flight is not exercised here: it would
    // need a prompt that reliably takes long enough to cancel, which is a
    // timing-dependent test.)
    let cancel = reqwest::Client::new()
        .post(format!("{base}/api/chat/sessions/{id}/cancel"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(cancel.status(), 200);
    let cancel: serde_json::Value = cancel.json().await.unwrap();
    assert_eq!(cancel["cancelled"], serde_json::json!(false));
}

// ── A2A (Phase 5) ───────────────────────────────────────────────────────────
//
// The A2A surface is the only one that makes the server issue an outbound
// request on the caller's behalf, so these tests are as much about what does
// *not* happen as about the JSON shapes. The two properties that matter most:
//
// * a response body never contains a configured token, in either direction, and
// * `POST /api/a2a/test` cannot be aimed at a host the operator did not
//   configure — the route takes a peer *name*, and a name that does not exist
//   is a 404 with no request leaving the process.

/// The inbound peer's token. Recognisable so a leak is unmistakable.
const A2A_INBOUND_TOKEN: &str = "inbound-peer-token-1f4c9a";
/// The outbound peer's token.
const A2A_OUTBOUND_TOKEN: &str = "outbound-peer-token-7b2e30";

/// A configuration with two inbound peers and one outbound peer, all carrying
/// recognisable tokens.
///
/// Every peer is one `A2aConfig::validate` accepts, so this configuration can
/// be handed to the real `start_listener` — the status tests need a
/// configuration whose *only* problem is the bind.
///
/// `enabled` is left off: the listener outcome is supplied separately by each
/// test, which is the point of the status route.
fn a2a_config() -> haos_green::config::A2aConfig {
    use haos_green::config::{A2aOutboundPeerConfig, A2aPeerConfig};
    use std::collections::HashMap;

    let mut peers = HashMap::new();
    peers.insert(
        "laptop".to_string(),
        A2aPeerConfig {
            token: A2A_INBOUND_TOKEN.to_string(),
            ip: vec!["10.0.0.5".to_string(), "192.168.1.0/24".to_string()],
            tools: None,
        },
    );
    peers.insert(
        "server".to_string(),
        A2aPeerConfig {
            token: "second-inbound-peer-token".to_string(),
            ip: vec!["10.0.0.6".to_string()],
            tools: Some(vec!["read_file".to_string()]),
        },
    );

    let mut outbound = HashMap::new();
    outbound.insert(
        "beta".to_string(),
        A2aOutboundPeerConfig {
            url: "http://127.0.0.1:9".to_string(),
            token: A2A_OUTBOUND_TOKEN.to_string(),
            timeout_secs: 2,
            ..A2aOutboundPeerConfig::default()
        },
    );

    haos_green::config::A2aConfig {
        peers,
        outbound: haos_green::config::A2aOutboundConfig { peers: outbound },
        ..haos_green::config::A2aConfig::default()
    }
}

/// The outcome of a listener that bound successfully.
fn a2a_started() -> haos_green::web::routes::a2a::A2aListenerOutcome {
    haos_green::web::routes::a2a::A2aListenerOutcome::Started {
        bound: "127.0.0.1:8443".parse().unwrap(),
        advertised_url: "https://haos.example.com:8443".to_string(),
    }
}

/// A `config.toml` with the properties the surgical-edit test needs: comments of
/// every kind (whole-line, inline, a box-drawing separator), unrelated sections
/// both before and after the outbound peers, and the outbound peer the dashboard
/// is configured with.
///
/// The token matches [`A2A_OUTBOUND_TOKEN`], so the file and the in-memory
/// configuration agree the way a real startup would leave them.
fn a2a_config_toml() -> String {
    format!(
        r#"# HaosGreen configuration.
# The comments in this file belong to the operator; the dashboard must not eat them.
[telegram]
bot_token = "telegram-secret-token"   # inline comment, kept
allowed_user_ids = [1]

# ── A2A ──────────────────────────────────────────────────────────────
[a2a]
enabled = false

[a2a.card]
name = "HaosGreen"

[a2a.outbound.peers.beta]
url = "http://127.0.0.1:9"    # the old url
token = "{A2A_OUTBOUND_TOKEN}"
timeout_secs = 2

# The web dashboard.
[web]
enabled = true
bind = "127.0.0.1:8787"
"#
    )
}

/// Write the fixture into `dir` and return its path.
///
/// **Every test's configuration file lives inside a `tempfile::TempDir`.** The
/// route now writes to whatever path it was handed, and pointing it at a real
/// `config.toml` would destroy the operator's credentials.
fn write_config_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, a2a_config_toml()).expect("the fixture should be writable");
    path
}

/// The shared outbound handle `main.rs` would create for `config`.
fn shared_outbound(
    config: &haos_green::config::A2aConfig,
) -> haos_green::a2a::SharedOutboundConfig {
    std::sync::Arc::new(tokio::sync::RwLock::new(config.outbound.clone()))
}

/// An `A2aWebState` whose configuration file is `<dir>/config.toml`.
fn a2a_state_in(
    dir: &std::path::Path,
    config: haos_green::config::A2aConfig,
    outcome: haos_green::web::routes::a2a::A2aListenerOutcome,
) -> haos_green::web::routes::a2a::A2aWebState {
    let outbound = shared_outbound(&config);
    a2a_state_with_handle(dir, config, outcome, outbound)
}

/// The same, around a handle the caller keeps so it can observe what the route
/// wrote into it.
fn a2a_state_with_handle(
    dir: &std::path::Path,
    config: haos_green::config::A2aConfig,
    outcome: haos_green::web::routes::a2a::A2aListenerOutcome,
    outbound: haos_green::a2a::SharedOutboundConfig,
) -> haos_green::web::routes::a2a::A2aWebState {
    haos_green::web::routes::a2a::A2aWebState::new(
        config,
        outcome,
        outbound,
        dir.join("config.toml"),
    )
}

/// Start a dashboard with the A2A surface wired, a real `config.toml` fixture in
/// a temp directory, and a listener that bound successfully.
async fn spawn_test_server_with_a2a(
    config: haos_green::config::A2aConfig,
) -> (String, tempfile::TempDir) {
    spawn_test_server_with_a2a_and_outcome(config, a2a_started()).await
}

/// The same, with a listener outcome the caller chooses.
async fn spawn_test_server_with_a2a_and_outcome(
    config: haos_green::config::A2aConfig,
    outcome: haos_green::web::routes::a2a::A2aListenerOutcome,
) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    write_config_fixture(dir.path());
    let state = a2a_state_in(dir.path(), config, outcome);
    spawn_test_server_with_a2a_state(state, dir).await
}

/// Start a dashboard with an A2A state the caller built.
///
/// The directory is passed in rather than created here because the state has to
/// be pointed at the fixture inside it before the server starts.
async fn spawn_test_server_with_a2a_state(
    state: haos_green::web::routes::a2a::A2aWebState,
    dir: tempfile::TempDir,
) -> (String, tempfile::TempDir) {
    let (addr, _handle) = haos_green::web::spawn_for_test_with_a2a(
        dir.path().to_path_buf(),
        haos_green::config::WebConfig::default(),
        std::sync::Arc::new(state),
    )
    .await
    .expect("the dashboard should start with A2A wiring");
    (format!("http://{addr}"), dir)
}

/// Every A2A route, as `(method, path, body)`.
///
/// One list, used by both the 503 and the CSRF sweeps, so a route added to the
/// module and forgotten here is a route that is covered by neither.
fn a2a_routes() -> Vec<(&'static str, &'static str, Option<serde_json::Value>)> {
    vec![
        ("GET", "/api/a2a/status", None),
        ("GET", "/api/a2a/peers", None),
        ("GET", "/api/a2a/outbound", None),
        (
            "PUT",
            "/api/a2a/outbound",
            Some(serde_json::json!({"peers": {}})),
        ),
        (
            "POST",
            "/api/a2a/test",
            Some(serde_json::json!({"peer": "beta"})),
        ),
    ]
}

/// A TCP listener that counts every connection it accepts.
///
/// This is what gives the "no outbound request" assertions teeth: the count is
/// only meaningful if the same harness is *observed* counting a request that
/// really was made, which each test does by testing a configured peer last.
///
/// Each accepted connection is answered with a 404 so a real request finishes
/// immediately instead of waiting for the peer's timeout.
async fn spawn_connection_recorder() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the recorder");
    let addr = listener.local_addr().expect("recorder address");
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            // The request is deliberately not parsed: the test only cares that
            // it arrived.
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.shutdown().await;
        }
    });

    (format!("http://{addr}"), count)
}

/// A TCP listener that accepts connections and never answers them.
///
/// The accepted streams are held open for the life of the task: dropping one
/// would turn "the peer is black-holed" into "the peer closed the connection",
/// which is a different failure and would not exercise the timeout.
async fn spawn_black_hole() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the black hole");
    let addr = listener.local_addr().expect("black-hole address");

    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            held.push(stream);
        }
    });

    format!("http://{addr}")
}

/// `PUT` the given peer map and return the response.
async fn put_outbound(base: &str, cookie: &str, peers: serde_json::Value) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("{base}/api/a2a/outbound"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, cookie)
        .json(&serde_json::json!({ "peers": peers }))
        .send()
        .await
        .unwrap()
}

/// `GET` a route and return `(status, body)`.
async fn get_body(base: &str, cookie: &str, path: &str) -> (u16, String) {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

#[tokio::test]
async fn every_a2a_route_returns_503_without_a2a_wiring() {
    // The default harness wires no A2A state, which is the contract every
    // optional handle in `WebState` follows: a named 503, never an empty peer
    // list that looks like a configuration with no peers.
    let (base, _dir) = spawn_test_server().await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    for (method, path, body) in a2a_routes() {
        let mut request = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{base}{path}"),
            )
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::COOKIE, &cookie);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            503,
            "{method} {path} without A2A wiring must be 503, got {}",
            response.status()
        );
        let message = response.text().await.unwrap();
        assert!(
            message.contains("A2A"),
            "{method} {path} must name the missing wiring, got {message:?}"
        );
    }
}

#[tokio::test]
async fn the_mutating_a2a_routes_require_the_csrf_header() {
    let (base, _dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    for (method, path, body) in a2a_routes() {
        if method == "GET" {
            continue;
        }
        let mut request = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{base}{path}"),
            )
            .header(reqwest::header::COOKIE, &cookie);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            403,
            "{method} {path} without the CSRF header must be 403, got {}",
            response.status()
        );
    }
}

#[tokio::test]
async fn the_status_route_reports_the_address_that_was_bound_and_the_url_advertised() {
    // The two are reported separately on purpose: the advertised URL is what
    // the Agent Card tells peers to use, and it is `[a2a].public_url` when set,
    // which need not be the bound address at all.
    let (base, _dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let (status, body) = get_body(&base, &cookie, "/api/a2a/status").await;
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");

    assert_eq!(body["state"], serde_json::json!("started"));
    assert_eq!(
        body["enabled"],
        serde_json::json!(true),
        "a listener that started was necessarily enabled"
    );
    assert_eq!(body["bound"], serde_json::json!("127.0.0.1:8443"));
    assert_eq!(
        body["advertised_url"],
        serde_json::json!("https://haos.example.com:8443")
    );
    assert_eq!(body["inbound_peers"], serde_json::json!(2));
    assert_eq!(body["outbound_peers"], serde_json::json!(1));
    assert!(
        body.get("failure").is_none(),
        "a started listener has no failure to report: {body}"
    );
}

#[tokio::test]
async fn the_status_route_reports_a_disabled_listener_without_erroring() {
    let config = a2a_config();
    let (base, _dir) = spawn_test_server_with_a2a_and_outcome(
        config,
        haos_green::web::routes::a2a::A2aListenerOutcome::Disabled,
    )
    .await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let (status, body) = get_body(&base, &cookie, "/api/a2a/status").await;
    assert_eq!(status, 200, "disabled is an answer, not an error");
    let body: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(body["state"], serde_json::json!("disabled"));
    assert_eq!(body["enabled"], serde_json::json!(false));
    assert!(body.get("bound").is_none());
    assert!(body.get("advertised_url").is_none());
    assert!(body.get("failure").is_none());
}

#[tokio::test]
async fn the_status_route_reports_a_listener_that_could_not_bind() {
    // The failure path, exercised through the real wiring: `start_listener`
    // binds a port that is already taken, so the outcome it returns is an
    // observation of a genuine bind failure rather than a hand-made value.
    // A status route that always said "started" would fail here.
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupy a port");
    let taken = occupied.local_addr().expect("the occupied address");

    let memory = haos_green::memory::MemoryStore::open_in_memory().expect("open a memory store");
    let store = haos_green::a2a::SqliteTaskStore::new(memory.connection());

    let config = haos_green::config::A2aConfig {
        enabled: true,
        bind: taken.to_string(),
        ..a2a_config()
    };

    let outcome = haos_green::web::routes::a2a::start_listener(
        &config,
        haos_green::skills::SkillRegistry::new(),
        haos_green::a2a::NoopExecutor,
        store,
    )
    .await;

    let reason = match &outcome {
        haos_green::web::routes::a2a::A2aListenerOutcome::Failed { reason } => reason.clone(),
        other => panic!("binding an occupied port must be reported as a failure, got {other:?}"),
    };
    assert!(
        reason.contains("bind"),
        "the reason must name the failed bind, got {reason:?}"
    );

    let (base, _dir) = spawn_test_server_with_a2a_and_outcome(config, outcome).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let (status, body) = get_body(&base, &cookie, "/api/a2a/status").await;
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(
        body["state"],
        serde_json::json!("failed"),
        "a listener that never started must not be reported as running: {body}"
    );
    assert_eq!(body["enabled"], serde_json::json!(true));
    assert!(
        body.get("bound").is_none(),
        "a listener that never bound has no address to report: {body}"
    );
    assert!(
        body["failure"]
            .as_str()
            .is_some_and(|failure| failure.contains("bind")),
        "the failure must be reported, got {body}"
    );
}

#[tokio::test]
async fn the_status_route_reports_an_invalid_configuration_as_a_failure() {
    // The other way a listener never starts: `A2aConfig::validate` refuses the
    // configuration before the bind. The dashboard must say so rather than
    // reporting "disabled" (which would suggest the operator turned it off) or
    // "started" (which would be a lie).
    let mut peers = std::collections::HashMap::new();
    peers.insert(
        "broken".to_string(),
        haos_green::config::A2aPeerConfig {
            token: String::new(),
            ip: vec!["10.0.0.5".to_string()],
            tools: None,
        },
    );
    let config = haos_green::config::A2aConfig {
        enabled: true,
        peers,
        ..haos_green::config::A2aConfig::default()
    };

    let memory = haos_green::memory::MemoryStore::open_in_memory().expect("open a memory store");
    let store = haos_green::a2a::SqliteTaskStore::new(memory.connection());
    let outcome = haos_green::web::routes::a2a::start_listener(
        &config,
        haos_green::skills::SkillRegistry::new(),
        haos_green::a2a::NoopExecutor,
        store,
    )
    .await;

    match &outcome {
        haos_green::web::routes::a2a::A2aListenerOutcome::Failed { reason } => assert!(
            reason.contains("empty token"),
            "the reason must explain the refusal, got {reason:?}"
        ),
        other => panic!("an invalid configuration must be a failure, got {other:?}"),
    }

    let (base, _dir) = spawn_test_server_with_a2a_and_outcome(config, outcome).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let (_, body) = get_body(&base, &cookie, "/api/a2a/status").await;
    let body: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(body["state"], serde_json::json!("failed"));
    assert!(
        body["failure"]
            .as_str()
            .is_some_and(|failure| failure.contains("empty token")),
        "the refusal must reach the dashboard, got {body}"
    );
}

#[tokio::test]
async fn no_a2a_response_body_contains_a_configured_token() {
    // The token is the one secret this surface handles, and it must not appear
    // in *any* response — not in a listing, not in a status, not in the body of
    // the call that accepts a new one, and not in a failed connection test.
    let (recorder, _connections) = spawn_connection_recorder().await;
    let mut config = a2a_config();
    config
        .outbound
        .peers
        .get_mut("beta")
        .expect("the beta peer")
        .url = recorder.clone();

    let (base, _dir) = spawn_test_server_with_a2a(config.clone()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let mut bodies: Vec<(String, String)> = Vec::new();
    for path in ["/api/a2a/status", "/api/a2a/peers", "/api/a2a/outbound"] {
        let (status, body) = get_body(&base, &cookie, path).await;
        assert_eq!(status, 200, "{path} should answer");
        bodies.push((path.to_string(), body));
    }

    // The `PUT` that *accepts* tokens must not return them either.
    let replaced = put_outbound(
        &base,
        &cookie,
        serde_json::json!({
            "beta": { "url": recorder, "token": A2A_OUTBOUND_TOKEN },
            "gamma": { "url": "http://127.0.0.1:9", "token": "gamma-secret-token" },
        }),
    )
    .await;
    assert_eq!(replaced.status(), 200, "the update should be accepted");
    bodies.push((
        "PUT /api/a2a/outbound".to_string(),
        replaced.text().await.unwrap(),
    ));

    // A connection test against a peer that answers 404: a failing test is
    // exactly where an error chain would carry a header value.
    let tested = client
        .post(format!("{base}/api/a2a/test"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "peer": "beta" }))
        .send()
        .await
        .unwrap();
    assert_eq!(tested.status(), 200);
    let tested_body = tested.text().await.unwrap();
    assert!(
        tested_body.contains("\"ok\":false"),
        "the recorder answers 404, so the test must report a failure: {tested_body}"
    );
    bodies.push(("POST /api/a2a/test".to_string(), tested_body));

    for (where_, body) in &bodies {
        for token in [
            A2A_INBOUND_TOKEN,
            A2A_OUTBOUND_TOKEN,
            "second-inbound-peer-token",
            "gamma-secret-token",
        ] {
            assert!(
                !body.contains(token),
                "{where_} returned a configured token: {body}"
            );
        }
    }

    // …and the fingerprints are there, so "no token" is not being achieved by
    // returning nothing at all.
    let peers = &bodies[1].1;
    let peers: serde_json::Value = serde_json::from_str(peers).expect("a JSON body");
    let laptop = peers["peers"]
        .as_array()
        .expect("a peers array")
        .iter()
        .find(|peer| peer["name"] == serde_json::json!("laptop"))
        .expect("the laptop peer");
    assert!(
        laptop["token_fingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.len() == 6),
        "every peer must carry a short fingerprint: {laptop}"
    );
    let outbound = &bodies[2].1;
    let outbound: serde_json::Value = serde_json::from_str(outbound).expect("a JSON body");
    assert!(
        outbound["peers"][0]["token_fingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.len() == 6),
        "an outbound peer must carry a short fingerprint: {outbound}"
    );
}

#[tokio::test]
async fn the_peers_route_reports_the_policies_that_actually_apply() {
    let mut config = a2a_config();
    // Empty `ip` means *no address at all* here, the opposite of
    // `[web].allow_ips`. `A2aConfig::validate` refuses such a peer at startup,
    // so it only exists in a state a test built by hand — and the route must
    // still report it truthfully rather than invent an allowlist or drop it.
    config.peers.insert(
        "nowhere".to_string(),
        haos_green::config::A2aPeerConfig {
            token: "third-inbound-peer-token".to_string(),
            ip: Vec::new(),
            tools: Some(vec![]),
        },
    );

    let (base, _dir) = spawn_test_server_with_a2a(config).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let (status, body) = get_body(&base, &cookie, "/api/a2a/peers").await;
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
    let peers = body["peers"].as_array().expect("a peers array");
    assert_eq!(peers.len(), 3, "every configured peer must be listed");
    // Sorted, so the response is stable across runs.
    let names: Vec<&str> = peers.iter().filter_map(|p| p["name"].as_str()).collect();
    assert_eq!(names, vec!["laptop", "nowhere", "server"]);

    let laptop = &peers[0];
    assert_eq!(
        laptop["allowed_ips"],
        serde_json::json!(["10.0.0.5", "192.168.1.0/24"])
    );
    assert_eq!(
        laptop["allows_no_address"],
        serde_json::json!(false),
        "a peer with addresses does not deny everything"
    );
    assert_eq!(laptop["tools"]["configured"], serde_json::Value::Null);
    assert_eq!(laptop["tools"]["source"], serde_json::json!("default"));

    // The fail-closed case: an empty A2A allowlist denies every address, the
    // opposite of an empty `[web].allow_ips`.
    let nowhere = &peers[1];
    assert_eq!(nowhere["allowed_ips"], serde_json::json!([]));
    assert_eq!(
        nowhere["allows_no_address"],
        serde_json::json!(true),
        "an empty A2A ip list must be reported as denying every address"
    );
    assert_eq!(
        nowhere["tools"]["effective"],
        serde_json::json!([]),
        "an explicit empty tool list grants nothing"
    );

    let server = &peers[2];
    assert_eq!(server["tools"]["source"], serde_json::json!("explicit"));
    assert_eq!(
        server["tools"]["effective"],
        serde_json::json!(["read_file"])
    );

    // The asymmetry is stated in the body, so a reader cannot carry the web
    // semantics over to A2A (or the other way round for the tool policies).
    let ip_note = body["ip_allowlist_semantics"]
        .as_str()
        .expect("the ip semantics note");
    assert!(ip_note.contains("empty list allows no address"));
    assert!(ip_note.contains("[web].allow_ips"));
    let tool_note = body["tool_policy_semantics"]
        .as_str()
        .expect("the tool policy note");
    assert!(tool_note.contains("execute_command"));
    assert!(tool_note.contains("allowed_tools"));
}

#[tokio::test]
async fn a_rejected_outbound_update_leaves_the_previous_configuration_intact() {
    let (base, _dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let (_, before) = get_body(&base, &cookie, "/api/a2a/outbound").await;

    // One bad peer and one perfectly good one: the good one must not be
    // installed either. A partially applied update is the failure this guards,
    // so the good peer is named "alpha" — it sorts *before* the bad one, which
    // is the order a non-atomic implementation would apply them in.
    let rejected = put_outbound(
        &base,
        &cookie,
        serde_json::json!({
            "alpha": { "url": "http://127.0.0.1:9", "token": "alpha-token" },
            "beta": { "url": "not-a-url", "token": "replacement-token" },
        }),
    )
    .await;
    assert_eq!(rejected.status(), 400, "a malformed url must be refused");

    let (_, after) = get_body(&base, &cookie, "/api/a2a/outbound").await;
    let after_json: serde_json::Value = serde_json::from_str(&after).expect("a JSON body");
    let names: Vec<&str> = after_json["peers"]
        .as_array()
        .expect("a peers array")
        .iter()
        .filter_map(|peer| peer["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["beta"],
        "a rejected update must not add or remove peers: {after_json}"
    );
    assert_eq!(
        after_json["peers"][0]["url"],
        serde_json::json!("http://127.0.0.1:9"),
        "the previous url must survive a rejected update"
    );

    // The fingerprint is the observable proxy for "the token did not change":
    // it is derived from the token, so an unchanged fingerprint means the
    // replacement token was not installed.
    let before: serde_json::Value = serde_json::from_str(&before).expect("a JSON body");
    assert_eq!(
        before["peers"][0]["token_fingerprint"], after_json["peers"][0]["token_fingerprint"],
        "the previous token must survive a rejected update"
    );
}

/// `text` with its `[a2a.outbound.peers]` table removed.
///
/// `toml_edit` round-trips a document it has not changed byte-for-byte, so
/// comparing the two strings of a before/after pair compares every *other* byte
/// of the file — comments, blank lines and all.
fn without_outbound_peers(text: &str) -> String {
    let mut document: toml_edit::DocumentMut = text.parse().expect("valid TOML");
    if let Some(table) = document
        .get_mut("a2a")
        .and_then(toml_edit::Item::as_table_mut)
        .and_then(|a2a| a2a.get_mut("outbound"))
        .and_then(toml_edit::Item::as_table_mut)
    {
        table.remove("peers");
    }
    document.to_string()
}

/// The names of any temporary files left in `dir`.
///
/// The dashboard also writes `web-auth.toml` there, so this filters rather than
/// counting: the property is "no leftover from the atomic write", not "the
/// directory holds one file".
fn temporary_files(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("the directory should be readable")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".tmp"))
        .collect()
}

/// The `[a2a]` section of a written `config.toml`, deserialized the way
/// `Config::load` deserializes it.
///
/// This is what makes "persistent" a measurement rather than a claim: the file
/// the route wrote has to load back into the same configuration type the process
/// starts from.
#[derive(serde::Deserialize)]
struct ReloadedConfig {
    a2a: haos_green::config::A2aConfig,
}

/// The peer names in a written `config.toml`, sorted.
fn reloaded_peer_names(path: &std::path::Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("the config file should be readable");
    let reloaded: ReloadedConfig =
        toml::from_str(&text).expect("the file the route wrote must still be loadable");
    let mut names: Vec<String> = reloaded.a2a.outbound.peers.keys().cloned().collect();
    names.sort();
    names
}

/// A `ToolContext` for driving the real `call_a2a_agent` handler.
fn a2a_tool_context() -> haos_green::tool_registry::ToolContext {
    haos_green::tool_registry::ToolContext {
        sandbox_dir: std::path::PathBuf::from("/tmp"),
        home_dir: None,
        sender: std::sync::Arc::new(LiveNoopSender),
        cancel_registry: std::sync::Arc::new(haos_green::cancel_registry::CancelRegistry::new()),
        user_id: "operator".to_string(),
        chat_id: "dashboard".to_string(),
        tool_ui_mode: haos_green::tool_registry::ToolUiMode::Minimal,
    }
}

#[tokio::test]
async fn an_outbound_update_reports_that_it_is_saved_and_live() {
    let (base, dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let response = put_outbound(
        &base,
        &cookie,
        serde_json::json!({ "gamma": { "url": "http://127.0.0.1:9", "token": "gamma-token" } }),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("a JSON body");

    assert_eq!(
        body["persistent"],
        serde_json::json!(true),
        "the peers are in config.toml now, and the response has to say so: {body}"
    );
    assert_eq!(
        body["restart_reverts"],
        serde_json::json!(false),
        "a restart reads the file this route wrote: {body}"
    );
    assert_eq!(
        body["affects_running_agent"],
        serde_json::json!(true),
        "the running call_a2a_agent tool reads the handle this route wrote: {body}"
    );

    // The prose has to be true as well, not just the flags: a UI renders it.
    let semantics = body["semantics"].as_str().expect("the semantics note");
    assert!(semantics.contains("config.toml"), "{semantics}");
    assert!(semantics.contains("atomic"), "{semantics}");
    assert!(semantics.contains("call_a2a_agent"), "{semantics}");
    assert!(
        semantics.contains("permissions"),
        "the note must mention that permissions are kept: {semantics}"
    );
    assert!(
        !semantics.contains("non-goal") && !semantics.contains("in memory"),
        "the old, now-false wording is still there: {semantics}"
    );

    let tokens = body["token_semantics"].as_str().expect("the token note");
    assert!(
        tokens.contains("omits"),
        "an omitted token keeps the stored one, and the note must say so: {tokens}"
    );
    assert!(
        tokens.contains("400"),
        "an explicitly empty token is still refused, and the note must say so: {tokens}"
    );

    // The GET reports the same three flags, so the two halves of the route
    // cannot disagree.
    let (status, fetched) = get_body(&base, &cookie, "/api/a2a/outbound").await;
    assert_eq!(status, 200);
    let fetched: serde_json::Value = serde_json::from_str(&fetched).expect("a JSON body");
    for field in ["persistent", "restart_reverts", "affects_running_agent"] {
        assert_eq!(
            fetched[field], body[field],
            "{field} differs between GET and PUT"
        );
    }

    // No filesystem path is leaked into a response body. The semantics prose
    // names the file, which is fine; the directory it lives in is not.
    let body_text = body.to_string();
    assert!(
        !body_text.contains(&dir.path().display().to_string()),
        "a response body must not carry the configuration directory: {body_text}"
    );
}

#[tokio::test]
async fn an_outbound_update_reaches_the_running_call_a2a_agent_tool() {
    // The property the shared handle exists for, and it is observed through the
    // *tool*, never through the dashboard's own copy: reading
    // `/api/a2a/outbound` back would pass against the old, unshared code.
    use haos_green::tool_registry::ToolHandler;

    let dir = tempfile::tempdir().unwrap();
    write_config_fixture(dir.path());

    // `main.rs` builds one handle and hands it to both the tool and the state.
    let config = a2a_config();
    let outbound = shared_outbound(&config);
    let tool = haos_green::a2a::CallA2aAgent::new(std::sync::Arc::clone(&outbound));
    let state = a2a_state_with_handle(
        dir.path(),
        config,
        a2a_started(),
        std::sync::Arc::clone(&outbound),
    );
    let (base, _dir) = spawn_test_server_with_a2a_state(state, dir).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let before = tool.define();
    assert_eq!(before.len(), 1, "the tool is offered while a peer exists");
    assert!(
        before[0].function.description.contains("beta"),
        "the tool starts with the configured peer: {}",
        before[0].function.description
    );
    assert!(!before[0].function.description.contains("gamma"));

    let response = put_outbound(
        &base,
        &cookie,
        serde_json::json!({ "gamma": { "url": "http://127.0.0.1:9", "token": "gamma-token" } }),
    )
    .await;
    assert_eq!(response.status(), 200);

    // The tool, asked again, describes the peers the PUT installed.
    let after = tool.define();
    assert_eq!(after.len(), 1);
    assert!(
        after[0].function.description.contains("gamma"),
        "the tool must see the peer the dashboard installed: {}",
        after[0].function.description
    );
    assert!(
        !after[0].function.description.contains("beta"),
        "the tool must not still see the peer the PUT removed: {}",
        after[0].function.description
    );

    // A real invocation resolves the peer through that same handle. Getting
    // past the lookup and failing at the network is the proof the lookup
    // succeeded: nothing is listening on 127.0.0.1:9.
    let error = tool
        .execute(
            "call_a2a_agent",
            serde_json::json!({ "peer": "gamma", "prompt": "ping" }),
            a2a_tool_context(),
        )
        .await
        .expect_err("the peer is unreachable, so the call must fail");
    let message = format!("{error:#}");
    assert!(
        !message.contains("Unknown or unconfigured"),
        "the installed peer must be found by the tool: {message}"
    );

    // And the peer the PUT removed is unknown to the tool as well.
    let error = tool
        .execute(
            "call_a2a_agent",
            serde_json::json!({ "peer": "beta", "prompt": "ping" }),
            a2a_tool_context(),
        )
        .await
        .expect_err("a removed peer must not be callable");
    assert!(
        format!("{error:#}").contains("Unknown or unconfigured outbound A2A peer 'beta'"),
        "{error:#}"
    );
}

#[tokio::test]
async fn an_outbound_update_rewrites_only_the_outbound_table_of_a_real_config_file() {
    let (base, dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let config_path = dir.path().join("config.toml");
    let before = std::fs::read_to_string(&config_path).expect("the fixture");

    let response = put_outbound(
        &base,
        &cookie,
        serde_json::json!({
            "delta": {
                "url": "http://127.0.0.1:9100",
                "token": "delta-token",
                "timeout_secs": 7,
                "poll_interval_ms": 111,
                "poll_timeout_secs": 222,
            },
        }),
    )
    .await;
    assert_eq!(response.status(), 200);

    let after = std::fs::read_to_string(&config_path).expect("the rewritten file");
    assert_ne!(before, after, "the file must have been rewritten");

    // Everything outside `[a2a.outbound.peers]` is byte-identical. This is what
    // "surgical" means, and it is why the edit does not go through serde.
    assert_eq!(
        without_outbound_peers(&before),
        without_outbound_peers(&after),
        "the edit changed something other than [a2a.outbound.peers]\n--- after ---\n{after}"
    );

    for comment in [
        "# HaosGreen configuration.",
        "# The comments in this file belong to the operator; the dashboard must not eat them.",
        "# inline comment, kept",
        "# ── A2A ──",
        "# The web dashboard.",
    ] {
        assert!(
            after.contains(comment),
            "the comment {comment:?} was lost:\n{after}"
        );
    }

    // The new peer is there with the values that were sent, and the peer the
    // PUT did not mention is gone rather than merged.
    assert!(after.contains("[a2a.outbound.peers.delta]"), "{after}");
    assert!(after.contains("timeout_secs = 7"), "{after}");
    assert!(after.contains("poll_interval_ms = 111"), "{after}");
    assert!(after.contains("poll_timeout_secs = 222"), "{after}");
    assert!(
        !after.contains(A2A_OUTBOUND_TOKEN),
        "the replaced peer's token must be gone from the file:\n{after}"
    );

    // And the file loads back into the same type the process starts from, so
    // "persistent" is a measurement rather than a claim.
    assert_eq!(reloaded_peer_names(&config_path), vec!["delta".to_string()]);

    // The atomic write left nothing behind.
    assert!(
        temporary_files(dir.path()).is_empty(),
        "a temporary file survived a successful write: {:?}",
        temporary_files(dir.path())
    );
}

#[tokio::test]
async fn a_failed_write_leaves_the_file_and_the_running_agent_unchanged() {
    let (base, dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let config_path = dir.path().join("config.toml");

    // A file the route cannot parse is a write that cannot happen. The route
    // must not guess at it, must not partially apply it, and must not report
    // success.
    let unparseable = "# a config this route cannot understand\n[a2a\nenabled =\n";
    std::fs::write(&config_path, unparseable).expect("write the fixture");
    let before_bytes = std::fs::read(&config_path).expect("read the fixture");

    let (_, live_before) = get_body(&base, &cookie, "/api/a2a/outbound").await;

    let response = put_outbound(
        &base,
        &cookie,
        serde_json::json!({ "gamma": { "url": "http://127.0.0.1:9", "token": "gamma-token" } }),
    )
    .await;
    assert_eq!(
        response.status(),
        500,
        "a write that did not happen must not be reported as saved"
    );
    let body = response.text().await.unwrap();
    assert!(
        !body.contains(&dir.path().display().to_string()),
        "the failure body must not carry a path: {body}"
    );
    assert!(
        body.contains("nothing was changed"),
        "the failure must say the configuration was left alone: {body}"
    );

    assert_eq!(
        std::fs::read(&config_path).expect("read the fixture"),
        before_bytes,
        "a failed write must leave the file byte-identical"
    );

    let (_, live_after) = get_body(&base, &cookie, "/api/a2a/outbound").await;
    assert_eq!(
        live_before, live_after,
        "a failed write must leave the in-memory configuration unchanged too"
    );

    assert!(
        temporary_files(dir.path()).is_empty(),
        "a failed write must leave no temporary file: {:?}",
        temporary_files(dir.path())
    );
}

#[cfg(unix)]
#[tokio::test]
async fn an_outbound_update_keeps_the_configuration_files_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let (base, dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let config_path = dir.path().join("config.toml");

    // `config.toml` holds the Telegram token, the OpenRouter key and every peer
    // token, so an owner-only file is the normal case.
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod the fixture");
    assert_eq!(
        std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the fixture must start owner-only for this test to mean anything"
    );

    let response = put_outbound(
        &base,
        &cookie,
        serde_json::json!({ "gamma": { "url": "http://127.0.0.1:9", "token": "gamma-token" } }),
    )
    .await;
    assert_eq!(response.status(), 200);

    let mode = std::fs::metadata(&config_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "the replacement must carry the original file's mode, got {mode:o}"
    );
}

#[tokio::test]
async fn two_concurrent_outbound_updates_produce_a_valid_file_and_a_matching_memory() {
    let (base, dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let config_path = dir.path().join("config.toml");

    // Both requests are in flight before either is awaited, twice, so the
    // read-modify-write really does race.
    for round in 0..2 {
        let first = put_outbound(
            &base,
            &cookie,
            serde_json::json!({ "alpha": { "url": "http://127.0.0.1:9", "token": "alpha-token" } }),
        );
        let second = put_outbound(
            &base,
            &cookie,
            serde_json::json!({ "omega": { "url": "http://127.0.0.1:9", "token": "omega-token" } }),
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.status(), 200, "round {round}");
        assert_eq!(second.status(), 200, "round {round}");

        // The file is still valid TOML that loads back, and it holds exactly one
        // of the two outcomes — never a mixture, never a truncation.
        let names = reloaded_peer_names(&config_path);
        assert!(
            names == vec!["alpha".to_string()] || names == vec!["omega".to_string()],
            "round {round}: the file must hold one of the two peer sets, got {names:?}"
        );

        // And the running configuration agrees with the file. This is the part
        // the mutex is for: without it the last in-memory swap and the last
        // rename can be different requests.
        let (_, body) = get_body(&base, &cookie, "/api/a2a/outbound").await;
        let body: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
        let mut live: Vec<String> = body["peers"]
            .as_array()
            .expect("a peers array")
            .iter()
            .filter_map(|peer| peer["name"].as_str().map(str::to_string))
            .collect();
        live.sort();
        assert_eq!(
            live, names,
            "round {round}: the running configuration and the file must agree"
        );
    }

    assert!(
        temporary_files(dir.path()).is_empty(),
        "no temporary file may survive: {:?}",
        temporary_files(dir.path())
    );
}

#[tokio::test]
async fn an_outbound_update_keeps_a_token_that_was_not_supplied() {
    let (base, _dir) = spawn_test_server_with_a2a(a2a_config()).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let (_, before) = get_body(&base, &cookie, "/api/a2a/outbound").await;
    let before: serde_json::Value = serde_json::from_str(&before).expect("a JSON body");
    let fingerprint = before["peers"][0]["token_fingerprint"].clone();

    let response = put_outbound(
        &base,
        &cookie,
        serde_json::json!({ "beta": { "url": "http://127.0.0.1:9000" } }),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("a JSON body");

    assert_eq!(
        body["peers"][0]["url"],
        serde_json::json!("http://127.0.0.1:9000")
    );
    assert_eq!(
        body["peers"][0]["token_fingerprint"], fingerprint,
        "an omitted token must keep the stored one rather than clearing it"
    );

    // An *explicitly* empty token is not "keep the existing one": it is an
    // empty credential, and it must be refused rather than silently clearing a
    // working one.
    let emptied = put_outbound(
        &base,
        &cookie,
        serde_json::json!({ "beta": { "url": "http://127.0.0.1:9000", "token": "" } }),
    )
    .await;
    assert_eq!(emptied.status(), 400, "an empty token must be refused");

    let (_, after) = get_body(&base, &cookie, "/api/a2a/outbound").await;
    let after: serde_json::Value = serde_json::from_str(&after).expect("a JSON body");
    assert_eq!(
        after["peers"][0]["token_fingerprint"], fingerprint,
        "a refused update must leave the stored token in place"
    );
}

#[tokio::test]
async fn the_test_route_refuses_an_unknown_peer_or_a_url_shaped_body() {
    let (recorder, connections) = spawn_connection_recorder().await;
    let mut config = a2a_config();
    config
        .outbound
        .peers
        .get_mut("beta")
        .expect("the beta peer")
        .url = recorder.clone();
    config
        .outbound
        .peers
        .get_mut("beta")
        .expect("the beta peer")
        .timeout_secs = 5;

    let (base, _dir) = spawn_test_server_with_a2a(config).await;
    let cookie = login_and_get_cookie(&base, "admin").await;
    let client = reqwest::Client::new();

    let post = |body: serde_json::Value| {
        let request = client
            .post(format!("{base}/api/a2a/test"))
            .header("x-haos-green-csrf", "1")
            .header(reqwest::header::COOKIE, &cookie)
            .json(&body);
        async move { request.send().await.unwrap() }
    };

    // 1. A URL in the `peer` field is a *name* that does not exist.
    let url_shaped = post(serde_json::json!({ "peer": recorder.clone() })).await;
    let url_shaped_status = url_shaped.status();
    let url_shaped_body = url_shaped.text().await.unwrap();

    // 2. A body that carries a `url` at all is rejected outright.
    let with_url = post(serde_json::json!({ "peer": "beta", "url": recorder.clone() })).await;
    let with_url_status = with_url.status();

    // 3. A body with no peer at all.
    let no_peer = post(serde_json::json!({ "url": recorder.clone() })).await;
    let no_peer_status = no_peer.status();

    // 4. An unknown name, plainly.
    let unknown = post(serde_json::json!({ "peer": "gamma" })).await;
    let unknown_status = unknown.status();

    // The network assertion comes first on purpose: it is the property that
    // matters, and a mutation that let the caller choose the URL would fail
    // here rather than on an HTTP status assertion.
    use std::sync::atomic::Ordering;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "no refused request may reach the network"
    );

    assert_eq!(
        url_shaped_status, 404,
        "a URL-shaped peer name must not be treated as an address"
    );
    assert!(
        !url_shaped_body.contains("127.0.0.1"),
        "the refusal must not reflect the caller's input: {url_shaped_body:?}"
    );
    assert!(
        with_url_status.is_client_error(),
        "a body carrying a url must be refused, got {with_url_status}"
    );
    assert!(
        no_peer_status.is_client_error(),
        "a body with no peer must be refused, got {no_peer_status}"
    );
    assert_eq!(unknown_status, 404);

    // …and the recorder does count a real request, so the zero above is a
    // measurement rather than a broken counter.
    let real = post(serde_json::json!({ "peer": "beta" })).await;
    assert_eq!(real.status(), 200);
    let real: serde_json::Value = real.json().await.unwrap();
    assert_eq!(
        real["ok"],
        serde_json::json!(false),
        "the recorder answers 404, so discovery fails: {real}"
    );
    assert!(
        real["error"]
            .as_str()
            .is_some_and(|error| error.contains("404")),
        "the failure must name the HTTP status: {real}"
    );
    assert!(
        connections.load(Ordering::SeqCst) >= 1,
        "the recorder must have observed the one request that was made"
    );
}

#[tokio::test]
async fn a_black_holed_peer_cannot_pin_the_connection_test() {
    // The peer's own `timeout_secs` is operator-controlled and may be a day;
    // the dashboard's cap is what bounds the request. The elapsed time is
    // asserted, not just the message, because "timed out" could also be the
    // peer's own timeout firing.
    let black_hole = spawn_black_hole().await;
    let mut config = a2a_config();
    {
        let peer = config
            .outbound
            .peers
            .get_mut("beta")
            .expect("the beta peer");
        peer.url = black_hole;
        peer.timeout_secs = 3600;
    }

    let dir = tempfile::tempdir().unwrap();
    write_config_fixture(dir.path());
    let state = a2a_state_in(dir.path(), config, a2a_started())
        .with_connection_test_timeout(std::time::Duration::from_secs(1));
    let (base, _dir) = spawn_test_server_with_a2a_state(state, dir).await;
    let cookie = login_and_get_cookie(&base, "admin").await;

    let started = std::time::Instant::now();
    let response = reqwest::Client::new()
        .post(format!("{base}/api/a2a/test"))
        .header("x-haos-green-csrf", "1")
        .header(reqwest::header::COOKIE, &cookie)
        .json(&serde_json::json!({ "peer": "beta" }))
        .send()
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["ok"], serde_json::json!(false));
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("timed out")),
        "a black-holed peer must be reported as a timeout: {body}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the test must be bounded by the dashboard's cap, not the peer's 3600s \
         setting; it took {elapsed:?}"
    );
}
