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
    let cases: [(&str, &str, Option<serde_json::Value>); 10] = [
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
