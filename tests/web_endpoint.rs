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
    let dir = tempfile::tempdir().unwrap();
    let (addr, _handle) = haos_green::web::spawn_for_test(dir.path().to_path_buf())
        .await
        .expect("dashboard should start");
    (format!("http://{addr}"), dir)
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
    let mut last = 0;
    for _ in 0..6 {
        let resp = client
            .post(format!("{base}/api/auth/login"))
            .header("x-haos-green-csrf", "1")
            .json(&serde_json::json!({"username": "admin", "password": "nope"}))
            .send()
            .await
            .unwrap();
        last = resp.status().as_u16();
    }
    assert_eq!(
        last, 429,
        "the source must be rate limited after repeated failures"
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
        again["token"].is_null(),
        "the bearer token must not be readable"
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
