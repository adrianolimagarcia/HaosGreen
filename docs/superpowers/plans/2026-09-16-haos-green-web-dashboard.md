# HaosGreen Web Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an embedded Axum web dashboard for HaosGreen covering chat, supervisor, logs, and A2A surfaces, behind password authentication, with a neuromorphic light-green frontend and no build step.

**Architecture:** A new `src/web/` module owns its own Axum listener, started from `main.rs` beside the existing A2A listener and sharing the already-constructed `Agent`, `MemoryStore` connection, and `Supervisor`. Credentials live in `<home>/web-auth.toml` (mode 0600), never in `config.toml`. Route modules are split by surface; a shared middleware layer enforces IP allowlist, session authentication, and CSRF before any handler runs. Frontend assets are plain HTML/CSS/JS embedded with `include_str!`.

**Tech Stack:** Rust 2021, Axum 0.8, Tokio, argon2 0.5 (new), ipnet 2 (existing), subtle 2 (existing), serde/serde_json, tracing, vanilla HTML/CSS/JS.

**Spec:** `docs/superpowers/specs/2026-09-16-haos-green-web-dashboard-design.md`

---

## File structure

| Path | Responsibility |
|---|---|
| `src/web/mod.rs` | `WebConfig` wiring, `spawn()`, router and layer assembly |
| `src/web/auth.rs` | Argon2id hashing, credential file I/O, session store, bearer, IP allowlist, login rate limiting |
| `src/web/middleware.rs` | Axum middleware: IP gate, session auth, CSRF |
| `src/web/state.rs` | `WebState` shared handles |
| `src/web/logs.rs` | `tracing_subscriber::Layer` + bounded ring buffer |
| `src/web/routes/mod.rs` | Router construction |
| `src/web/routes/auth_routes.rs` | login, logout, session probe |
| `src/web/routes/settings.rs` | password change, bearer toggle, IP allowlist |
| `src/web/routes/chat.rs` | chat sessions + SSE |
| `src/web/routes/supervisor.rs` | task listing and lifecycle |
| `src/web/routes/logs.rs` | log query + SSE |
| `src/web/routes/a2a.rs` | status, peers, connection test |
| `src/web/assets/index.html` | Single-page shell |
| `src/web/assets/style.css` | Neuromorphic design system |
| `src/web/assets/app.js` | Router, API client, views |
| `src/config.rs` | `WebConfig` + validation (modified) |
| `src/main.rs` | Dashboard spawn wiring (modified) |
| `src/supervisor/store.rs` | `list_recent` (modified) |

Conventions to follow throughout:
- `anyhow::Result` with `.context()`, `anyhow::bail!()` for early returns.
- Secrets are never formatted into logs or error strings.
- Tests that guard a security property must be shown to have teeth by mutating the implementation.

---

# Phase 1 — Foundation, authentication, and frontend shell

## Task 1: Add the argon2 dependency and the `[web]` config section

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/config.rs`
- Test: `src/config.rs` (unit tests)

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` in `src/config.rs`:

```rust
#[test]
fn web_disabled_by_default() {
    let cfg: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
    assert!(!cfg.web.enabled);
}

#[test]
fn web_binds_localhost_by_default() {
    assert_eq!(WebConfig::default().bind, "127.0.0.1:8787");
}

#[test]
fn web_session_ttl_defaults_to_twelve_hours() {
    assert_eq!(WebConfig::default().session_ttl_hours, 12);
}

#[test]
fn web_allow_ips_defaults_to_empty() {
    assert!(WebConfig::default().allow_ips.is_empty());
}

#[test]
fn web_validate_accepts_a_well_formed_config() {
    let cfg = WebConfig {
        enabled: true,
        bind: "127.0.0.1:8787".into(),
        public_url: Some("https://haos.example.com".into()),
        session_ttl_hours: 12,
        allow_ips: vec!["10.0.0.0/8".into(), "192.168.1.5".into()],
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn web_validate_rejects_an_unparseable_bind() {
    let cfg = WebConfig { bind: "not-an-address".into(), ..Default::default() };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("bind"), "unexpected error: {err}");
}

#[test]
fn web_validate_rejects_zero_session_ttl() {
    let cfg = WebConfig { session_ttl_hours: 0, ..Default::default() };
    assert!(cfg.validate().is_err());
}

#[test]
fn web_validate_rejects_a_public_url_without_a_scheme() {
    let cfg = WebConfig {
        public_url: Some("haos.example.com".into()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("public_url"), "unexpected error: {err}");
}

#[test]
fn web_validate_rejects_an_unparseable_allow_ip_entry() {
    let cfg = WebConfig { allow_ips: vec!["999.1.1.1".into()], ..Default::default() };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("allow_ips"), "unexpected error: {err}");
}

#[test]
fn web_validate_treats_a_blank_public_url_as_unset() {
    let cfg = WebConfig { public_url: Some("   ".into()), ..Default::default() };
    assert!(cfg.validate().is_ok());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::tests::web_`
Expected: FAIL — `WebConfig` does not exist.

- [ ] **Step 3: Add the dependency**

In `Cargo.toml`, under the OAuth/PKCE helpers group:

```toml
# Argon2id password hashing for the web dashboard
argon2 = "0.5"
```

- [ ] **Step 4: Implement `WebConfig`**

In `src/config.rs`, add `web` to the `Config` struct next to `a2a`:

```rust
#[serde(default)]
pub web: WebConfig,
```

Then add the type:

```rust
/// Web dashboard configuration.
///
/// Secrets (the password hash and the bearer token) live in
/// `<home>/web-auth.toml`, never here, because `config.toml` is the file
/// users copy, share, and paste into issues.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Off by default: a dashboard that can run shell commands must never
    /// appear because a config file omitted a key.
    pub enabled: bool,
    pub bind: String,
    /// Externally reachable URL. When it is https, session cookies get the
    /// `Secure` flag. Unset means "derive from the bound address".
    pub public_url: Option<String>,
    pub session_ttl_hours: u64,
    /// Empty means any source IP may attempt login. Non-empty is a strict
    /// allowlist, enforced before authentication.
    pub allow_ips: Vec<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8787".to_string(),
            public_url: None,
            session_ttl_hours: 12,
            allow_ips: Vec::new(),
        }
    }
}

impl WebConfig {
    pub fn validate(&self) -> Result<()> {
        use std::net::ToSocketAddrs;

        if self.bind.trim().parse::<std::net::SocketAddr>().is_err()
            && self.bind.to_socket_addrs().is_err()
        {
            bail!("web.bind '{0}' is not a valid address", self.bind.trim());
        }

        if self.session_ttl_hours == 0 {
            bail!("web.session_ttl_hours must be at least 1");
        }

        if let Some(url) = self.public_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            let lower = url.to_ascii_lowercase();
            if !(lower.starts_with("http://") || lower.starts_with("https://")) {
                bail!("web.public_url '{url}' must start with http:// or https://");
            }
        }

        for entry in &self.allow_ips {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                bail!("web.allow_ips contains an empty entry");
            }
            if trimmed.parse::<ipnet::IpNet>().is_err()
                && trimmed.parse::<std::net::IpAddr>().is_err()
            {
                bail!("web.allow_ips entry '{trimmed}' is not an IP address or CIDR range");
            }
        }

        Ok(())
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib config::tests::web_`
Expected: PASS (9 tests).

- [ ] **Step 6: Document the section**

Add to `config.example.toml`, after the `[a2a]` block:

```toml
# ── Web Dashboard (optional) ────────────────────────────────────────────────
#
# An embedded dashboard with chat, supervisor, log, and A2A views.
#
# SECURITY: an authenticated dashboard user runs the same agent as the Telegram
# operator, including shell execution. It ships DISABLED, binds to loopback,
# and starts with the password `admin`/`admin`. Change the password in the
# dashboard Settings page before exposing the port to anything.
#
# [web]
# enabled = false
# bind = "127.0.0.1:8787"
# public_url = ""            # e.g. "https://haos.example.com"; enables Secure cookies
# session_ttl_hours = 12
# allow_ips = []             # empty = any source IP; non-empty = strict allowlist
#                            # entries may be single IPs or CIDR ranges
```

- [ ] **Step 7: Run the full gates and commit**

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
git add Cargo.toml Cargo.lock src/config.rs config.example.toml
git commit -m "feat(web): add dashboard configuration"
```

---

## Task 2: Credential storage with Argon2id

**Files:**
- Create: `src/web/mod.rs`
- Create: `src/web/auth.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/web/auth.rs` with only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_round_trips() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
    }

    #[test]
    fn verify_rejects_a_wrong_password() {
        let hash = hash_password("correct horse").unwrap();
        assert!(!verify_password("wrong horse", &hash));
    }

    #[test]
    fn verify_rejects_a_malformed_hash_instead_of_panicking() {
        assert!(!verify_password("anything", "not-a-phc-string"));
    }

    #[test]
    fn hashes_are_salted_so_equal_passwords_differ() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn default_credentials_are_created_when_no_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let creds = Credentials::load_or_create(&path).unwrap();
        assert_eq!(creds.username, DEFAULT_USERNAME);
        assert!(creds.uses_default_password);
        assert!(verify_password(DEFAULT_PASSWORD, &creds.password_hash));
    }

    #[test]
    fn credential_file_is_written_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        Credentials::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credentials must not be group/world readable");
    }

    #[test]
    fn an_existing_password_survives_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        creds.set_password("a-new-secret").unwrap();
        creds.save(&path).unwrap();

        let reloaded = Credentials::load_or_create(&path).unwrap();
        assert!(verify_password("a-new-secret", &reloaded.password_hash));
        assert!(!reloaded.uses_default_password);
    }

    #[test]
    fn uses_default_password_is_true_only_for_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        assert!(creds.uses_default_password);
        creds.set_password("something-else").unwrap();
        assert!(!creds.uses_default_password);
    }

    #[test]
    fn bearer_token_is_stored_only_as_a_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        let token = creds.enable_bearer().unwrap();
        assert!(!token.is_empty());

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(&token), "the raw bearer token must never hit disk");
        assert!(creds.verify_bearer(&token));
        assert!(!creds.verify_bearer("some-other-token"));
    }

    #[test]
    fn bearer_is_disabled_until_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        assert!(!creds.bearer_enabled);
        creds.enable_bearer().unwrap();
        assert!(creds.bearer_enabled);
        creds.disable_bearer().unwrap();
        assert!(!creds.bearer_enabled);
        assert!(!creds.verify_bearer("anything"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::auth`
Expected: FAIL — module does not exist. Add `pub mod web;` to `src/lib.rs` and `pub mod auth;` to `src/web/mod.rs` first so the compiler reaches the tests.

- [ ] **Step 3: Implement credential storage**

Above the test module in `src/web/auth.rs`:

```rust
use anyhow::{Context, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::path::Path;
use subtle::ConstantTimeEq;

pub const DEFAULT_USERNAME: &str = "admin";
pub const DEFAULT_PASSWORD: &str = "admin";

/// Persisted dashboard credentials.
///
/// The bearer token is stored as a SHA-256 hex digest, not as the token
/// itself: the operator sees the token exactly once, at generation time, and
/// afterwards the process can only verify it. A leaked credential file
/// therefore does not yield a usable bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password_hash: String,
    #[serde(default)]
    pub bearer_enabled: bool,
    #[serde(default)]
    pub bearer_token_hash: String,
    /// Not persisted. Recomputed on load by verifying the default password.
    #[serde(skip)]
    pub uses_default_password: bool,
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        // A malformed stored hash is a denial, never a panic and never an
        // accidental accept.
        Err(_) => false,
    }
}

fn hash_bearer(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl Credentials {
    /// Load credentials, creating the default `admin`/`admin` pair on first
    /// run. The file is written mode 0600 before any content lands in it.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let mut creds: Credentials = toml::from_str(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            creds.uses_default_password = verify_password(DEFAULT_PASSWORD, &creds.password_hash);
            return Ok(creds);
        }

        let creds = Credentials {
            username: DEFAULT_USERNAME.to_string(),
            password_hash: hash_password(DEFAULT_PASSWORD)?,
            bearer_enabled: false,
            bearer_token_hash: String::new(),
            uses_default_password: true,
        };
        creds.save(path)?;
        Ok(creds)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self).context("failed to serialize credentials")?;
        write_owner_only(path, &body)
    }

    pub fn set_password(&mut self, password: &str) -> Result<()> {
        self.password_hash = hash_password(password)?;
        self.uses_default_password = password == DEFAULT_PASSWORD;
        Ok(())
    }

    /// Generate and store a new bearer token, returning it so the caller can
    /// display it once. It is never readable again.
    pub fn enable_bearer(&mut self) -> Result<String> {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.bearer_token_hash = hash_bearer(&token);
        self.bearer_enabled = true;
        Ok(token)
    }

    pub fn disable_bearer(&mut self) {
        self.bearer_enabled = false;
        self.bearer_token_hash.clear();
    }

    pub fn verify_bearer(&self, presented: &str) -> bool {
        if !self.bearer_enabled || self.bearer_token_hash.is_empty() {
            return false;
        }
        let expected = self.bearer_token_hash.as_bytes();
        let actual = hash_bearer(presented);
        expected.ct_eq(actual.as_bytes()).into()
    }
}

/// Write a file that only its owner can read, creating it with that mode
/// rather than chmod-ing after the fact so the content is never briefly
/// world-readable.
pub fn write_owner_only(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib web::auth`
Expected: PASS (10 tests).

- [ ] **Step 5: Prove the default-password test has teeth**

Temporarily change `set_password` to always set `self.uses_default_password = false`, run `cargo test --lib web::auth::tests::uses_default_password_is_true_only_for_the_default`, and confirm it FAILS. Revert.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/web src/lib.rs Cargo.toml Cargo.lock
git commit -m "feat(web): store dashboard credentials with Argon2id"
```

---

## Task 3: Session store with expiry

**Files:**
- Modify: `src/web/auth.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_new_session_authenticates() {
    let store = SessionStore::new(Duration::from_secs(3600));
    let id = store.create();
    assert!(store.validate(&id));
}

#[test]
fn an_unknown_session_id_is_rejected() {
    let store = SessionStore::new(Duration::from_secs(3600));
    assert!(!store.validate("nope"));
}

#[test]
fn logout_invalidates_a_session() {
    let store = SessionStore::new(Duration::from_secs(3600));
    let id = store.create();
    store.destroy(&id);
    assert!(!store.validate(&id));
}

#[test]
fn an_expired_session_is_rejected() {
    let store = SessionStore::new(Duration::from_secs(0));
    let id = store.create();
    assert!(!store.validate(&id), "a zero TTL must not authenticate");
}

#[test]
fn session_ids_are_not_guessable_or_repeated() {
    let store = SessionStore::new(Duration::from_secs(3600));
    let a = store.create();
    let b = store.create();
    assert_ne!(a, b);
    assert!(a.len() >= 64, "session ids must carry at least 256 bits of entropy");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::auth::tests::session`
Expected: FAIL — `SessionStore` does not exist.

- [ ] **Step 3: Implement the session store**

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-memory session store.
///
/// Sessions deliberately do not survive a restart: a dashboard session is a
/// live credential, and process restarts are a cheap, reliable way to revoke
/// every one of them.
pub struct SessionStore {
    ttl: Duration,
    sessions: Mutex<HashMap<String, Instant>>,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, sessions: Mutex::new(HashMap::new()) }
    }

    pub fn create(&self) -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        if let Ok(mut map) = self.sessions.lock() {
            map.insert(id.clone(), Instant::now());
        }
        id
    }

    pub fn validate(&self, id: &str) -> bool {
        if id.is_empty() {
            return false;
        }
        let Ok(mut map) = self.sessions.lock() else {
            return false;
        };
        // Drop expired entries as we go, so an abandoned session cannot keep
        // occupying memory forever.
        let now = Instant::now();
        map.retain(|_, created| now.duration_since(*created) < self.ttl);
        map.contains_key(id)
    }

    pub fn destroy(&self, id: &str) {
        if let Ok(mut map) = self.sessions.lock() {
            map.remove(id);
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib web::auth`
Expected: PASS.

- [ ] **Step 5: Prove the expiry test has teeth**

Change `validate` to ignore `self.ttl` (compare against `Duration::MAX`), run `cargo test --lib web::auth::tests::an_expired_session_is_rejected`, confirm FAIL, revert.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/web/auth.rs
git commit -m "feat(web): add expiring session store"
```

---

## Task 4: IP allowlist and login rate limiting

**Files:**
- Modify: `src/web/auth.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn an_empty_allowlist_permits_any_source() {
    let gate = IpGate::new(&[]).unwrap();
    assert!(gate.permits("203.0.113.7".parse().unwrap()));
}

#[test]
fn a_non_empty_allowlist_permits_a_listed_ip() {
    let gate = IpGate::new(&["192.168.1.5".to_string()]).unwrap();
    assert!(gate.permits("192.168.1.5".parse().unwrap()));
    assert!(!gate.permits("192.168.1.6".parse().unwrap()));
}

#[test]
fn a_cidr_entry_covers_its_range() {
    let gate = IpGate::new(&["10.0.0.0/8".to_string()]).unwrap();
    assert!(gate.permits("10.255.1.1".parse().unwrap()));
    assert!(!gate.permits("11.0.0.1".parse().unwrap()));
}

#[test]
fn an_ipv6_cidr_entry_covers_its_range() {
    let gate = IpGate::new(&["fd00::/8".to_string()]).unwrap();
    assert!(gate.permits("fd12:3456::1".parse().unwrap()));
    assert!(!gate.permits("fe80::1".parse().unwrap()));
}

#[test]
fn an_ipv4_mapped_ipv6_address_does_not_smuggle_past_an_ipv4_allowlist() {
    let gate = IpGate::new(&["192.168.1.0/24".to_string()]).unwrap();
    let mapped: std::net::IpAddr = "::ffff:192.168.1.5".parse().unwrap();
    assert!(!gate.permits(mapped), "mapped addresses must not match an IPv4 rule");
}

#[test]
fn a_malformed_entry_is_rejected_at_construction() {
    assert!(IpGate::new(&["999.1.1.1".to_string()]).is_err());
}

#[test]
fn rate_limiter_allows_attempts_below_the_threshold() {
    let mut limiter = LoginLimiter::new();
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..4 {
        assert!(limiter.check(ip).is_ok());
        limiter.record_failure(ip);
    }
}

#[test]
fn rate_limiter_locks_out_after_repeated_failures() {
    let mut limiter = LoginLimiter::new();
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..5 {
        limiter.record_failure(ip);
    }
    assert!(limiter.check(ip).is_err(), "five failures must lock the source out");
}

#[test]
fn rate_limiter_tracks_sources_independently() {
    let mut limiter = LoginLimiter::new();
    let bad: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let good: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    for _ in 0..5 {
        limiter.record_failure(bad);
    }
    assert!(limiter.check(good).is_ok());
}

#[test]
fn a_successful_login_clears_the_failure_counter() {
    let mut limiter = LoginLimiter::new();
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..4 {
        limiter.record_failure(ip);
    }
    limiter.record_success(ip);
    for _ in 0..4 {
        assert!(limiter.check(ip).is_ok());
        limiter.record_failure(ip);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::auth`
Expected: FAIL — `IpGate` and `LoginLimiter` do not exist.

- [ ] **Step 3: Implement both**

```rust
use ipnet::IpNet;
use std::net::IpAddr;

/// Source-IP gate for the dashboard.
///
/// Unlike the A2A listener's allowlist, an empty list here means "any source",
/// because the dashboard has a password and A2A does not. The asymmetry is
/// intentional and is stated in the UI so an operator is never misled into
/// thinking an empty list is a restriction.
pub struct IpGate {
    nets: Vec<IpNet>,
}

impl IpGate {
    pub fn new(entries: &[String]) -> Result<Self> {
        let mut nets = Vec::with_capacity(entries.len());
        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                bail!("web.allow_ips contains an empty entry");
            }
            let net = trimmed
                .parse::<IpNet>()
                .or_else(|_| trimmed.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| anyhow::anyhow!("web.allow_ips entry '{trimmed}' is not an IP or CIDR range"))?;
            nets.push(net);
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        // An IPv4-mapped IPv6 address is a distinct address family to `ipnet`.
        // Matching it against an IPv4 rule would let `::ffff:10.0.0.1` bypass
        // an allowlist written for `10.0.0.0/8`, so mapped addresses are
        // compared only against explicitly IPv6 rules.
        self.nets.iter().any(|net| match (net, ip) {
            (IpNet::V4(_), IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some() => false,
            _ => net.contains(&ip),
        })
    }
}

const MAX_LOGIN_FAILURES: u32 = 5;

/// Per-source login failure tracker with a lockout window.
pub struct LoginLimiter {
    failures: HashMap<IpAddr, (u32, Instant)>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self { failures: HashMap::new() }
    }

    fn lockout_window(&self) -> Duration {
        Duration::from_secs(300)
    }

    pub fn check(&mut self, ip: IpAddr) -> Result<()> {
        let window = self.lockout_window();
        let now = Instant::now();
        if let Some((count, last)) = self.failures.get(&ip).copied() {
            if now.duration_since(last) > window {
                self.failures.remove(&ip);
                return Ok(());
            }
            if count >= MAX_LOGIN_FAILURES {
                let remaining = window.saturating_sub(now.duration_since(last));
                bail!(
                    "too many failed login attempts; try again in {} seconds",
                    remaining.as_secs().max(1)
                );
            }
        }
        Ok(())
    }

    pub fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let window = self.lockout_window();
        let entry = self.failures.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > window {
            *entry = (1, now);
        } else {
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
        }
    }

    pub fn record_success(&mut self, ip: IpAddr) {
        self.failures.remove(&ip);
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib web::auth`
Expected: PASS.

- [ ] **Step 5: Prove the mapped-address test has teeth**

Delete the `(IpNet::V4(_), IpAddr::V6(v6)) if ... => false` arm, run `cargo test --lib web::auth::tests::an_ipv4_mapped_ipv6_address_does_not_smuggle_past_an_ipv4_allowlist`, confirm FAIL, restore.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/web/auth.rs
git commit -m "feat(web): add IP allowlist and login rate limiting"
```

---

## Task 5: Shared state and the middleware layer

**Files:**
- Create: `src/web/state.rs`
- Create: `src/web/middleware.rs`
- Modify: `src/web/mod.rs`

- [ ] **Step 1: Write the failing tests**

In `src/web/middleware.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
        headers.insert(axum::http::header::COOKIE, HeaderValue::from_static("other=x"));
        assert!(session_from_cookies(&headers).is_none());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::middleware`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement state and middleware**

`src/web/state.rs`:

```rust
use crate::agent::Agent;
use crate::config::WebConfig;
use crate::supervisor::Supervisor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::auth::{Credentials, IpGate, LoginLimiter, SessionStore};

#[derive(Clone)]
pub struct WebState {
    pub config: WebConfig,
    pub credentials: Arc<Mutex<Credentials>>,
    pub sessions: Arc<SessionStore>,
    pub limiter: Arc<Mutex<LoginLimiter>>,
    pub ip_gate: Arc<IpGate>,
    pub agent: Arc<Agent>,
    pub supervisor: Arc<Supervisor>,
    pub credentials_path: PathBuf,
    pub logs: Arc<super::logs::LogBuffer>,
}
```

`src/web/middleware.rs`:

```rust
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::SocketAddr;

use super::state::WebState;

pub const SESSION_COOKIE: &str = "haos_session";
pub const CSRF_HEADER: &str = "x-haos-green-csrf";

/// Mutating methods require the CSRF header.
///
/// `SameSite=Strict` already blocks cross-site form posts in current browsers,
/// but it is a browser behaviour, not a server-side guarantee. Requiring the
/// header means the protection holds even if a browser ignores the attribute
/// or the request arrives from a non-browser client replaying a cookie.
pub fn requires_csrf(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH | Method::DELETE)
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

    if !state.ip_gate.permits(ip) {
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

    let bearer_ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| {
            state
                .credentials
                .lock()
                .map(|c| c.verify_bearer(token.trim()))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if session_ok || bearer_ok {
        return next.run(request).await;
    }

    (StatusCode::UNAUTHORIZED, "authentication required").into_response()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib web::middleware`
Expected: PASS (7 tests).

- [ ] **Step 5: Prove the CSRF test has teeth**

Change `csrf_ok` to always return `true`, run `cargo test --lib web::middleware`, confirm the three CSRF rejection tests FAIL, revert.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/web
git commit -m "feat(web): add request guard middleware"
```

---

## Task 6: Router, spawn, and startup wiring

**Files:**
- Modify: `src/web/mod.rs`
- Modify: `src/main.rs`
- Test: `tests/web_endpoint.rs` (create)

- [ ] **Step 1: Write the failing integration tests**

Create `tests/web_endpoint.rs`:

```rust
//! Integration tests for the embedded web dashboard.
//!
//! Every test binds an ephemeral port and speaks real HTTP. No mocks: the
//! value of these tests is that the auth gate, the cookie handling, and the
//! JSON shapes are exercised end to end.

use std::net::SocketAddr;

async fn spawn_test_server() -> (String, tempfile::TempDir) {
    // Implemented in Step 3 alongside `web::spawn_for_test`.
    let dir = tempfile::tempdir().unwrap();
    let (addr, _handle) = haos_green::web::spawn_for_test(dir.path().to_path_buf())
        .await
        .expect("dashboard should start");
    (format!("http://{addr}"), dir)
}

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
async fn login_with_the_default_password_yields_a_working_session() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let login = client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);

    let settings = client
        .get(format!("{base}/api/settings"))
        .send()
        .await
        .unwrap();
    assert_eq!(settings.status(), 200);
    let body: serde_json::Value = settings.json().await.unwrap();
    assert_eq!(body["uses_default_password"], true);
}

#[tokio::test]
async fn the_login_page_is_reachable_without_authentication() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new().get(&base).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("HaosGreen"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test web_endpoint`
Expected: FAIL — `haos_green::web::spawn_for_test` does not exist.

- [ ] **Step 3: Implement the router and spawn**

`src/web/mod.rs`:

```rust
pub mod auth;
pub mod logs;
pub mod middleware;
pub mod routes;
pub mod state;

use anyhow::{Context, Result};
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_http::trace::TraceLayer;

use crate::agent::Agent;
use crate::config::WebConfig;
use crate::supervisor::Supervisor;
use auth::{Credentials, IpGate, LoginLimiter, SessionStore};
use state::WebState;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_JS: &str = include_str!("assets/app.js");
const STYLE_CSS: &str = include_str!("assets/style.css");

/// Build the dashboard router. Separated from `spawn` so tests can drive the
/// router without binding a socket.
pub fn router(state: WebState) -> Router {
    let protected = Router::new()
        .merge(routes::auth_routes::router())
        .merge(routes::settings::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::guard,
        ));

    Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/style.css", get(serve_style_css))
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn serve_index() -> axum::response::Html<&'static str> {
    axum::response::Html(INDEX_HTML)
}

async fn serve_app_js() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        APP_JS,
    )
}

async fn serve_style_css() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css")],
        STYLE_CSS,
    )
}

fn build_state(
    config: WebConfig,
    home: PathBuf,
    agent: Arc<Agent>,
    supervisor: Arc<Supervisor>,
) -> Result<WebState> {
    config.validate()?;
    let credentials_path = home.join("web-auth.toml");
    let credentials = Credentials::load_or_create(&credentials_path)?;

    if credentials.uses_default_password {
        tracing::warn!(
            "web: the dashboard is using the default password 'admin'. Change it in \
             Settings before exposing the port to any network you do not fully trust."
        );
    }

    Ok(WebState {
        ip_gate: Arc::new(IpGate::new(&config.allow_ips)?),
        sessions: Arc::new(SessionStore::new(Duration::from_secs(
            config.session_ttl_hours.saturating_mul(3600),
        ))),
        limiter: Arc::new(Mutex::new(LoginLimiter::new())),
        credentials: Arc::new(Mutex::new(credentials)),
        credentials_path,
        logs: Arc::new(logs::LogBuffer::new(2000)),
        config,
        agent,
        supervisor,
    })
}

/// Start the dashboard listener.
///
/// A failure here is logged by the caller and must never take the Telegram bot
/// down, mirroring how the A2A listener is treated.
pub async fn spawn(
    config: WebConfig,
    home: PathBuf,
    agent: Arc<Agent>,
    supervisor: Arc<Supervisor>,
) -> Result<SocketAddr> {
    let bind = config.bind.clone();
    let state = build_state(config, home, agent, supervisor)?;
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind web dashboard to {bind}"))?;
    let addr = listener.local_addr()?;

    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "web: the dashboard is bound to a non-loopback address; anyone who can reach it \
             and guess the password gets shell execution"
        );
    }

    tracing::info!("  Web dashboard: http://{addr}");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = %e, "web dashboard listener stopped");
        }
    });

    Ok(addr)
}
```

Add to `src/web/mod.rs` a test-only constructor used by the integration tests:

```rust
/// Build and bind a dashboard for tests, with a throwaway home directory.
#[doc(hidden)]
pub async fn spawn_for_test(home: PathBuf) -> Result<(SocketAddr, ())> {
    let config = WebConfig {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        ..Default::default()
    };
    let state = build_state_for_test(config, home)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok((addr, ()))
}
```

`build_state_for_test` constructs the same state but requires no `Agent` or
`Supervisor`. Because both are needed only by phases 2-3, phase 1 makes them
optional in `WebState`:

```rust
pub agent: Option<Arc<Agent>>,
pub supervisor: Option<Arc<Supervisor>>,
```

Routes that need them return 503 with a clear message when they are absent, so
a partially wired dashboard degrades instead of panicking. Update `guard` and
the state constructor accordingly.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test web_endpoint`
Expected: PASS (5 tests).

- [ ] **Step 5: Wire it into `main.rs`**

After the A2A listener block in `src/main.rs`, add:

```rust
if config.web.enabled {
    if let Err(e) = config.web.validate() {
        tracing::error!(error = %e, "web configuration is invalid; the dashboard was NOT started");
    } else {
        let home = config
            .resolved_home
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        match haos_green::web::spawn(
            config.web.clone(),
            home,
            Arc::clone(&agent),
            Arc::clone(&_supervisor),
        )
        .await
        {
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "web dashboard failed to start"),
        }
    }
} else {
    tracing::debug!("web dashboard disabled");
}
```

- [ ] **Step 6: Run the full gates and commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web src/main.rs tests/web_endpoint.rs
git commit -m "feat(web): serve the dashboard on its own listener"
```

---

## Task 7: Login, logout, and session routes

**Files:**
- Create: `src/web/routes/mod.rs`
- Create: `src/web/routes/auth_routes.rs`
- Modify: `src/web/middleware.rs` (exempt login from the session requirement)

- [ ] **Step 1: Write the failing tests**

Add to `tests/web_endpoint.rs`:

```rust
#[tokio::test]
async fn logout_invalidates_the_session() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
    client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();

    let logout = client
        .post(format!("{base}/api/auth/logout"))
        .header("x-haos-green-csrf", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 200);

    let after = client.get(format!("{base}/api/settings")).send().await.unwrap();
    assert_eq!(after.status(), 401, "a destroyed session must not authenticate");
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
    assert_eq!(last, 429, "the source must be rate limited after repeated failures");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test web_endpoint`
Expected: FAIL — routes do not exist (404).

- [ ] **Step 3: Implement the auth routes**

The login route must be reachable **without** a session but **with** the CSRF
header. Split the router so `guard` is not applied to login:

```rust
// src/web/routes/auth_routes.rs
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::web::auth::{verify_password, DEFAULT_PASSWORD};
use crate::web::middleware::{csrf_ok, SESSION_COOKIE};
use crate::web::state::WebState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub ok: bool,
    pub uses_default_password: bool,
}

pub fn public_router() -> Router<WebState> {
    Router::new().route("/api/auth/login", post(login))
}

pub fn router() -> Router<WebState> {
    Router::new().route("/api/auth/logout", post(logout))
}

async fn login(
    State(state): State<WebState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    // The public login route is outside `guard`, so it re-applies the CSRF
    // check itself. Forgetting it here would silently reopen CSRF on the one
    // route that mints sessions.
    if !csrf_ok(&headers) {
        return (StatusCode::FORBIDDEN, "missing CSRF header").into_response();
    }

    let ip = addr.ip();
    {
        let Ok(mut limiter) = state.limiter.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "limiter unavailable").into_response();
        };
        if limiter.check(ip).is_err() {
            tracing::warn!(%ip, "web: login blocked by rate limit");
            return (StatusCode::TOO_MANY_REQUESTS, "too many attempts").into_response();
        }
    }

    let (ok, uses_default) = {
        let Ok(creds) = state.credentials.lock() else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "credentials unavailable").into_response();
        };
        let user_ok = creds.username == body.username;
        let pass_ok = verify_password(&body.password, &creds.password_hash);
        // Both comparisons run regardless of the first result so a wrong
        // username and a wrong password take the same time.
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
        .map(|u| u.trim().to_ascii_lowercase().starts_with("https://"))
        .unwrap_or(false);
    let cookie = format!(
        "{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/{}{}",
        if secure { "; Secure" } else { "" },
        // 12h default, expressed in seconds for the browser.
        format!("; Max-Age={}", state.config.session_ttl_hours.saturating_mul(3600))
    );

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse { ok: true, uses_default_password: uses_default }),
    )
        .into_response()
}

async fn logout(State(state): State<WebState>, headers: HeaderMap) -> Response {
    if let Some(id) = crate::web::middleware::session_from_cookies(&headers) {
        state.sessions.destroy(&id);
    }
    (
        StatusCode::OK,
        [(header::SET_COOKIE, format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"))],
    )
        .into_response()
}
```

Update `router()` in `src/web/mod.rs` to merge `auth_routes::public_router()`
**outside** the guarded layer.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test web_endpoint`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web tests/web_endpoint.rs
git commit -m "feat(web): add login and logout routes"
```

---

## Task 8: Settings routes

**Files:**
- Create: `src/web/routes/settings.rs`

- [ ] **Step 1: Write the failing tests**

Add to `tests/web_endpoint.rs`:

```rust
#[tokio::test]
async fn changing_the_password_invalidates_the_old_one() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
    client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();

    let changed = client
        .post(format!("{base}/api/settings/password"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"current": "admin", "new": "a-better-secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), 200);

    let fresh = reqwest::Client::new();
    let old = fresh
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), 401, "the default password must stop working");
}

#[tokio::test]
async fn changing_the_password_requires_the_current_one() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
    client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/api/settings/password"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"current": "wrong", "new": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn enabling_bearer_returns_the_token_exactly_once() {
    let (base, _dir) = spawn_test_server().await;
    let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
    client
        .post(format!("{base}/api/auth/login"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"username": "admin", "password": "admin"}))
        .send()
        .await
        .unwrap();

    let enable = client
        .post(format!("{base}/api/settings/bearer"))
        .header("x-haos-green-csrf", "1")
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(enable.status(), 200);
    let body: serde_json::Value = enable.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    assert!(!token.is_empty());

    // The token authenticates without a cookie...
    let api = reqwest::Client::new();
    let ok = api
        .get(format!("{base}/api/settings"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    // ...and reading settings back never returns it again.
    let again: serde_json::Value = client
        .get(format!("{base}/api/settings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(again["token"].is_null(), "the bearer token must not be readable");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test web_endpoint`
Expected: FAIL — 404.

- [ ] **Step 3: Implement the settings routes**

Implement `GET /api/settings`, `POST /api/settings/password`,
`POST /api/settings/bearer`, and `PUT /api/settings/allow-ips`.

Requirements the implementation must satisfy:
- `GET` returns `{ username, uses_default_password, bearer_enabled, allow_ips, session_ttl_hours }` and **never** a token or hash.
- Password change verifies `current` before applying, returns 403 on mismatch, persists via `Credentials::save`, and leaves existing sessions alone.
- Bearer enable returns the token in the response body once and persists only the hash.
- Allow-IP update replaces the list in memory and reports whether the list is empty (so the UI can explain the semantics).
- Every handler that mutates state calls `Credentials::save` or updates `WebState` under the existing mutex, and logs the change without any secret material.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test web_endpoint`
Expected: PASS (10 tests).

- [ ] **Step 5: Prove the bearer test has teeth**

Make `GET /api/settings` include `"token": creds.bearer_token_hash`, run
`cargo test --test web_endpoint::enabling_bearer_returns_the_token_exactly_once`,
confirm FAIL, revert.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web tests/web_endpoint.rs
git commit -m "feat(web): add settings routes"
```

---

## Task 9: Frontend shell and the neuromorphic design system

**Files:**
- Create: `src/web/assets/index.html`
- Create: `src/web/assets/style.css`
- Create: `src/web/assets/app.js`

- [ ] **Step 1: Write `style.css` — the design system**

Define the palette as CSS custom properties so no colour is hard-coded twice:

```css
:root {
  --bg:            #eef3ee;
  --surface:       #f7faf7;
  --surface-sunken:#e6ece6;
  --text:          #243027;
  --text-muted:    #6b7a6d;
  --accent:        #7cc47f;
  --accent-bright: #b8e6bb;
  --danger:        #c96a6a;

  --shadow-out: -6px -6px 14px #ffffff, 6px 6px 14px #c9d6c9;
  --shadow-in:  inset -3px -3px 8px #ffffff, inset 3px 3px 8px #c9d6c9;
  --radius: 18px;
}
```

Requirements:
- Body background `--bg`, text `--text`, font stack `-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`.
- Raised cards use `--shadow-out`; pressed buttons and inputs use `--shadow-in`.
- No 1px grey divider lines; separation comes from shadow and spacing.
- Sidebar navigation with an accent-filled pill for the active view.
- Accent buttons use a subtle gradient from `--accent` to `--accent-bright`.
- A `.banner-warning` style for the default-password banner: soft, persistent, not alarming red.
- Responsive: below 720px the sidebar becomes a horizontal scrolling row; usable to 380px.
- Respect `prefers-reduced-motion`.

- [ ] **Step 2: Write `index.html`**

Single-page shell: sidebar with five nav items (Chat, Supervisor, Logs, A2A, Settings), a main panel, a login overlay, and the default-password banner container. Include inline SVG icons for each nav item — a leaf for Chat, a shield for Supervisor, a stacked-bars mark for Logs, a network node mark for A2A, and a gear for Settings. Thin stroke, `stroke="currentColor"`, no external requests.

No CDN links, no external fonts, no analytics. The page must render correctly with networking disabled.

- [ ] **Step 3: Write `app.js`**

Requirements:
- `api(path, options)` helper that always sets `X-HaosGreen-CSRF: 1` on mutating methods and throws on non-2xx with the server's message.
- Hash-based routing (`#/chat`, `#/supervisor`, `#/logs`, `#/a2a`, `#/settings`) with no page reloads.
- On load: `GET /api/settings`; on 401 show the login overlay, on 200 render the shell and, when `uses_default_password` is true, show the persistent banner.
- Settings view: change password form, bearer enable/disable with one-time token display, IP allowlist editor with an explicit note that an empty list permits any source.
- Views for the other four surfaces are stubs in this phase that render an empty-state message; phases 2-5 fill them in.
- All user-supplied and server-supplied strings are inserted with `textContent`, never `innerHTML`, so a task title or log line cannot inject markup.

- [ ] **Step 4: Verify the assets are embedded and served**

Run:
```bash
cargo test --test web_endpoint
cargo build --release
```

Then confirm the assets are in the binary and no external URL is referenced:

```bash
grep -nE 'https?://(?!127\.0\.0\.1|localhost)' src/web/assets/*.html src/web/assets/*.js src/web/assets/*.css
```

Expected: no matches (the only permitted URLs are localhost, if any).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/web/assets
git commit -m "feat(web): add the dashboard shell and design system"
```

---

## Task 10: Phase 1 review and gate

- [ ] **Step 1: Run every gate**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- [ ] **Step 2: Verify the security mutation tests were actually performed**

Confirm the five mutation checks from Tasks 2, 3, 4, 5, and 8 were each
observed to fail before being reverted. If any was skipped, perform it now.

- [ ] **Step 3: Spec compliance review**

Dispatch a review subagent against
`docs/superpowers/specs/2026-09-16-haos-green-web-dashboard-design.md`
sections 3, 4, 6, and 7, checking: config validation coverage, Argon2id usage,
session TTL enforcement, CSRF on every mutating route including login, rate
limiting, IP allowlist semantics matching the documented asymmetry, bearer
stored hashed only, default-password banner and startup warning present, and the
palette matching the spec values.

- [ ] **Step 4: Code quality review**

Dispatch a second review subagent for: secret leakage into logs or error
strings, unwrap/expect in request paths, lock poisoning handled without
panicking, unbounded memory growth, missing `Content-Type` headers, and
`innerHTML` usage in the frontend.

- [ ] **Step 5: Fix findings, re-run gates, commit**

---

# Phase 2 — Chat with SSE streaming

## Task 11: Chat session store

**Files:**
- Create: `src/web/chat.rs`
- Modify: `src/web/state.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_new_session_starts_empty() {
    let store = ChatSessionStore::new();
    let id = store.create();
    assert!(store.history(&id).unwrap().is_empty());
}

#[test]
fn appended_turns_are_returned_in_order() {
    let store = ChatSessionStore::new();
    let id = store.create();
    store.append_user(&id, "hello").unwrap();
    store.append_assistant(&id, "hi").unwrap();
    let history = store.history(&id).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].role, "user");
    assert_eq!(history[1].role, "assistant");
}

#[test]
fn history_is_capped_so_a_long_session_cannot_grow_without_bound() {
    let store = ChatSessionStore::new();
    let id = store.create();
    for i in 0..500 {
        store.append_user(&id, &format!("turn {i}")).unwrap();
    }
    assert!(store.history(&id).unwrap().len() <= MAX_HISTORY_TURNS);
}

#[test]
fn sessions_are_isolated_from_each_other() {
    let store = ChatSessionStore::new();
    let a = store.create();
    let b = store.create();
    store.append_user(&a, "only in a").unwrap();
    assert!(store.history(&b).unwrap().is_empty());
}

#[test]
fn an_unknown_session_id_is_an_error_not_an_empty_history() {
    let store = ChatSessionStore::new();
    assert!(store.history("missing").is_err());
}

#[test]
fn deleting_a_session_removes_its_history() {
    let store = ChatSessionStore::new();
    let id = store.create();
    store.append_user(&id, "x").unwrap();
    store.delete(&id);
    assert!(store.history(&id).is_err());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::chat`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement the store**

Requirements:
- `MAX_HISTORY_TURNS` bounded (256), dropping the oldest turns first.
- Cancel tokens namespaced `web:{session_id}` so they cannot collide with
  Telegram `/stop` or A2A task cancellation.
- History entries are plain `{role, content}` pairs, stored as `ChatMessage`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib web::chat`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/web
git commit -m "feat(web): add chat session store"
```

---

## Task 12: Chat routes with SSE streaming and the tool policy

**Files:**
- Create: `src/web/routes/chat.rs`
- Modify: `src/web/routes/mod.rs`

- [ ] **Step 1: Write the failing tests**

Unit test for the policy, in `src/web/routes/chat.rs`:

```rust
/// Build the tool policy for the web chat from the live sources.
///
/// The registry is the single source of truth: a hand-written list would drift
/// the moment someone registers a new tool, and would either silently withhold
/// it or silently grant a tool that was meant to be withheld.
///
/// MCP tools are included because the loop offers them too
/// (`src/loop_runner.rs:111`). Omitting them would silently withhold every MCP
/// tool from the dashboard while the Telegram bot kept them.
///
/// Do NOT return `vec!["*".to_string()]`. The wildcard is expanded only by
/// `a2a::policy::resolve_allowed_tools`; the loop itself filters with a literal
/// `whitelist.contains(&d.function.name)` (`src/loop_runner.rs:113`), so a
/// wildcard here would match nothing and hand the operator a chat with no tools
/// and no error.
pub fn web_tool_policy(
    registry: &crate::tool_registry::ToolRegistry,
    mcp: &crate::mcp::McpManager,
) -> Vec<String> {
    registry
        .all_definitions()
        .iter()
        .chain(mcp.tool_definitions().iter())
        .map(|d| d.function.name.clone())
        .collect()
}

#[test]
fn the_web_tool_policy_matches_the_registry_exactly() {
    let mut registry = crate::tool_registry::ToolRegistry::new();
    registry.register(Box::new(crate::builtin_tools::BuiltinTools::new_for_test()));
    let policy = web_tool_policy(&registry);
    let names: Vec<String> = registry
        .all_definitions()
        .iter()
        .map(|d| d.function.name.clone())
        .collect();
    assert_eq!(policy, names);
}

#[test]
fn the_web_tool_policy_is_never_empty_when_the_registry_has_tools() {
    // An empty policy means "no tools" in `run_with_policy_streaming_history`,
    // which is the fail-closed default. Silently passing it would look like a
    // working chat that mysteriously cannot use any tool.
    let mut registry = crate::tool_registry::ToolRegistry::new();
    registry.register(Box::new(crate::builtin_tools::BuiltinTools::new_for_test()));
    assert!(!web_tool_policy(&registry).is_empty());
}

#[test]
fn the_web_tool_policy_does_not_grant_special_subagent_handlers() {
    // `invoke_agent` and `spawn_agents` are not registry tools; they dispatch
    // through a special closure (see CLAUDE.md). Asserting their absence keeps
    // a future refactor from quietly handing the dashboard subagent dispatch.
    let mut registry = crate::tool_registry::ToolRegistry::new();
    registry.register(Box::new(crate::builtin_tools::BuiltinTools::new_for_test()));
    let policy = web_tool_policy(&registry);
    assert!(!policy.iter().any(|t| t == "invoke_agent" || t == "spawn_agents"));
}
```

If `BuiltinTools::new_for_test` does not exist, construct whichever handler the
existing `src/tool_registry.rs` tests already use — do not invent a constructor.

Integration tests in `tests/web_endpoint.rs`:

```rust
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
```

A live SSE test gated behind `HAOS_GREEN_WEB_LIVE=1`, following the existing
`HAOS_GREEN_A2A_LIVE` pattern, asserting the stream contains at least one `token`
event and exactly one terminal `done` event.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::routes::chat`
Expected: FAIL.

- [ ] **Step 3: Implement the routes**

```
POST /api/chat/sessions               → create, returns { id }
GET  /api/chat/sessions               → list
GET  /api/chat/sessions/{id}/messages → history
POST /api/chat/sessions/{id}/messages → SSE stream
```

The send handler:
1. Validates the session exists; 404 otherwise.
2. Builds `allowed_tools` from the **live sources** via `web_tool_policy()`
   (registry `all_definitions()` **plus** `McpManager::tool_definitions()`).
   Never `vec!["*".to_string()]` — see the doc comment on `web_tool_policy`.
   Do not call `a2a::policy::resolve_allowed_tools` either: it takes an
   `A2aPeerConfig` and would couple the dashboard to A2A policy types.
3. Creates a `tokio::sync::mpsc` channel, passes the sender as
   `stream_token_tx`, and forwards each received chunk as an SSE `token` event.
4. Passes prior history as `run_with_policy_streaming_history(history, prompt, allowed_tools, cancel_token, Some(tx))`.
5. Emits `tool_call` / `tool_result` events if the loop surfaces them, then a
   terminal `done` (or `error`) event, and closes the stream.
6. Persists the user turn and the assistant reply into the session store.

**Verify explicitly:** confirm that `invoke_agent` and `spawn_agents` are not
granted by the registry-derived policy. Per `CLAUDE.md` these are not registry
tools and dispatch through a special closure; the test must assert they are
absent from the policy list so the dashboard cannot trigger subagent dispatch.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib web::routes::chat && cargo test --test web_endpoint`
Expected: PASS.

- [ ] **Step 5: Prove the policy test has teeth**

Change `web_tool_policy` to return `Vec::new()`, run
`cargo test --lib web::routes::chat`, confirm the non-empty assertion FAILS,
revert.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web tests/web_endpoint.rs
git commit -m "feat(web): stream chat over SSE"
```

---

## Task 13: Chat UI

**Files:**
- Modify: `src/web/assets/app.js`
- Modify: `src/web/assets/style.css`

- [ ] **Step 1: Implement the chat view**

Requirements:
- Session list in the sidebar area with a "New chat" control.
- Message list with user/agent bubbles; agent bubbles stream tokens as they
  arrive.
- `EventSource` is not usable because the request is a POST; use `fetch` with a
  `ReadableStream` reader and parse SSE frames manually.
- A stop button that aborts the fetch and posts to a cancel endpoint.
- Errors render inline in the conversation, not as an alert.
- All text inserted with `textContent`.

- [ ] **Step 2: Verify manually and with the live test**

Run: `HAOS_GREEN_WEB_LIVE=1 cargo test --test web_endpoint -- --ignored --nocapture`
Expected: PASS, with the streamed text visible in the captured output.

- [ ] **Step 3: Commit**

```bash
git add src/web/assets
git commit -m "feat(web): add the chat interface"
```

---

# Phase 3 — Supervisor

## Task 14: Add `list_recent` to the supervisor store

**Files:**
- Modify: `src/supervisor/store.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn list_recent_returns_tasks_newest_first() {
    let (store, _dir) = test_store().await;
    let a = Task::new("first", "req a");
    let b = Task::new("second", "req b");
    store.create(&a).await.unwrap();
    store.create(&b).await.unwrap();
    let rows = store.list_recent(20).await.unwrap();
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn list_recent_clamps_an_oversized_limit_to_twenty() {
    let (store, _dir) = test_store().await;
    for i in 0..25 {
        store.create(&Task::new(&format!("t{i}"), "req")).await.unwrap();
    }
    let rows = store.list_recent(1000).await.unwrap();
    assert_eq!(rows.len(), 20, "the dashboard must never ask for more than 20");
}

#[tokio::test]
async fn list_recent_on_an_empty_store_is_empty_not_an_error() {
    let (store, _dir) = test_store().await;
    assert!(store.list_recent(20).await.unwrap().is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib supervisor::store`
Expected: FAIL — `list_recent` does not exist.

- [ ] **Step 3: Implement it**

```rust
/// Newest-first task listing for the dashboard.
///
/// The limit is clamped to [`MAX_RECENT_TASKS`] rather than trusted, so no
/// caller can turn the dashboard into a way to page the entire task history
/// into memory.
///
/// `created_at` is `TEXT NOT NULL DEFAULT (datetime('now'))` with one-second
/// resolution, so several tasks created in the same second would tie and make
/// the order non-deterministic. `rowid` breaks the tie and keeps paging stable.
pub async fn list_recent(&self, limit: usize) -> Result<Vec<Task>> {
    let limit = limit.clamp(1, MAX_RECENT_TASKS);
    let conn = self.conn.lock().await;
    let mut stmt = conn.prepare(
        "SELECT id,title,user_request,task_type,priority,risk_level,execution_mode,state,
                required_capabilities,inputs,constraints,expected_outputs,approval_policy,
                platform,user_id,chat_id,created_at,updated_at
         FROM sup_tasks ORDER BY created_at DESC, rowid DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit as i64], row_to_task)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}
```

Match the existing column list and row-mapping helper used by `get` in the same
file rather than inventing a new mapping; `get` at `src/supervisor/store.rs:69`
is the reference.

with `pub const MAX_RECENT_TASKS: usize = 20;`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib supervisor::store`
Expected: PASS.

- [ ] **Step 5: Prove the clamp test has teeth**

Remove the `.clamp(...)`, run
`cargo test --lib supervisor::store::tests::list_recent_clamps_an_oversized_limit_to_twenty`,
confirm FAIL, restore.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/supervisor/store.rs
git commit -m "feat(supervisor): add a bounded recent-task listing"
```

---

## Task 15: Supervisor routes

**Files:**
- Create: `src/web/routes/supervisor.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn supervisor_listing_requires_authentication() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/supervisor/tasks"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn supervisor_listing_is_capped_at_twenty() {
    // Seed 25 tasks through the store, then assert the API returns 20.
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test web_endpoint supervisor`
Expected: FAIL — 404.

- [ ] **Step 3: Implement the routes**

**Prerequisites — verified gaps in the current `Supervisor` API.** Before the
routes below can exist, three things must be added; none of them exist today:

| Missing | Evidence | Needed for |
|---|---|---|
| `Supervisor::store()` accessor | `store` is a private field (`src/supervisor/mod.rs:54`); no public getter | `list_recent`, task detail (jobs, transitions) |
| `Supervisor::cancel(task_id)` | No `cancel` anywhere in `src/supervisor/mod.rs` | `POST .../cancel` |
| `Supervisor::approve(task_id)` | No `approve` anywhere in `src/supervisor/mod.rs` | `POST .../approve` |

`cancel` and `approve` must go through `state.rs::transition_allowed()` rather
than writing the state directly — that function is the documented single source
of truth for the state machine, and a route that bypasses it would let the
dashboard drive the supervisor into a state the rest of the code treats as a
bug. Add a unit test per new method proving an illegal transition is refused.

Note that the Telegram dispatcher does not call any supervisor method today
(CLAUDE.md marks that integration as pending), so these routes are the first
real caller of `pause`/`resume`/`cancel`/`approve`. Treat that as a signal to
test the transitions carefully rather than assuming the methods are exercised.

```
GET  /api/supervisor/tasks
GET  /api/supervisor/tasks/{id}
POST /api/supervisor/tasks
POST /api/supervisor/tasks/{id}/pause
POST /api/supervisor/tasks/{id}/resume
POST /api/supervisor/tasks/{id}/cancel
POST /api/supervisor/tasks/{id}/approve
```

The detail route returns task, jobs, transitions, and artifacts. Unknown ids
return 404, not an empty object. When `WebState.supervisor` is `None`, routes
return 503 with a message naming the missing wiring rather than panicking.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test web_endpoint supervisor`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web tests/web_endpoint.rs
git commit -m "feat(web): add supervisor task routes"
```

---

## Task 16: Supervisor UI

**Files:**
- Modify: `src/web/assets/app.js`
- Modify: `src/web/assets/style.css`

- [ ] **Step 1: Implement the view**

Requirements: task cards with state chips coloured by status, a detail drawer
showing jobs, transitions timeline, and artifacts, and action buttons that
enable or disable based on the task's current state. Submit form for new tasks.
Poll the listing every 5 seconds while the view is visible, and stop polling
when it is not.

- [ ] **Step 2: Verify**

Run: `cargo test --test web_endpoint` and a manual smoke check of the rendered
HTML for the presence of the view container.

- [ ] **Step 3: Commit**

```bash
git add src/web/assets
git commit -m "feat(web): add the supervisor view"
```

---

# Phase 4 — Live logs

## Task 17: Tracing layer and bounded ring buffer

**Files:**
- Create: `src/web/logs.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn the_buffer_is_bounded_and_drops_the_oldest_first() {
    let buffer = LogBuffer::new(3);
    for i in 0..5 {
        buffer.push(LogEntry::new("info", "test", &format!("line {i}")));
    }
    let entries = buffer.recent(10);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].message, "line 2");
    assert_eq!(entries[2].message, "line 4");
}

#[test]
fn recent_returns_newest_last() {
    let buffer = LogBuffer::new(10);
    buffer.push(LogEntry::new("info", "t", "first"));
    buffer.push(LogEntry::new("warn", "t", "second"));
    let entries = buffer.recent(10);
    assert_eq!(entries[0].message, "first");
}

#[test]
fn secrets_are_redacted_in_buffered_entries() {
    let buffer = LogBuffer::new(10);
    buffer.push(LogEntry::new("info", "t", "token=abc123 secret=xyz"));
    let entries = buffer.recent(1);
    assert!(!entries[0].message.contains("abc123"));
}

#[test]
fn a_concurrent_flood_does_not_exceed_the_capacity() {
    // Spawn several threads pushing in parallel and assert the bound holds.
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib web::logs`
Expected: FAIL.

- [ ] **Step 3: Implement the buffer and the layer**

`LogBuffer` wraps `Mutex<VecDeque<LogEntry>>` with a fixed capacity, dropping
the oldest entry on overflow. `LogEntry` carries `timestamp`, `level`,
`target`, and `message`. Redaction runs at push time via
`crate::supervisor::redact::redact` so a secret never sits in the buffer at all
— cheaper and safer than redacting on every read.

The `tracing_subscriber::Layer` implementation writes into the buffer and must
never panic: a poisoned lock drops the event rather than propagating.

- [ ] **Step 4: Install the layer in `main.rs`**

Add the buffer layer to the existing subscriber setup so the dashboard sees the
same events as the terminal, then pass the `Arc<LogBuffer>` into `web::spawn`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib web::logs`
Expected: PASS.

- [ ] **Step 6: Prove the redaction test has teeth**

Remove the redaction call, run
`cargo test --lib web::logs::tests::secrets_are_redacted_in_buffered_entries`,
confirm FAIL, restore.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web src/main.rs
git commit -m "feat(web): capture tracing events in a bounded buffer"
```

---

## Task 18: Log routes and view

**Files:**
- Create: `src/web/routes/logs.rs`
- Modify: `src/web/assets/app.js`
- Modify: `src/web/assets/style.css`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn the_log_endpoint_requires_authentication() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/logs"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn the_log_endpoint_respects_the_requested_limit() {
    // Authenticate, request ?limit=5, assert at most 5 entries.
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test web_endpoint logs`
Expected: FAIL — 404.

- [ ] **Step 3: Implement the routes and the view**

`GET /api/logs?limit=N` returns recent entries with `limit` clamped to the
buffer capacity. `GET /api/logs/stream` is an SSE stream of new entries. The
view renders a monospace list with level chips, auto-scrolls while pinned to
the bottom, and pauses auto-scroll when the operator scrolls up.

- [ ] **Step 4: Run the tests to verify they pass and commit**

```bash
cargo test --test web_endpoint logs
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web tests/web_endpoint.rs
git commit -m "feat(web): add the live log view"
```

---

# Phase 5 — A2A manager

## Task 19: A2A routes

**Files:**
- Create: `src/web/routes/a2a.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn a2a_status_requires_authentication() {
    let (base, _dir) = spawn_test_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/a2a/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn peer_listings_never_return_a_token() {
    // Seed config with a peer token, authenticate, and assert the response
    // body does not contain the token anywhere.
}

#[tokio::test]
async fn testing_an_unreachable_peer_reports_an_error_without_leaking_the_token() {
    // Point a peer at a closed port and assert the error message is present
    // and the token is absent.
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test web_endpoint a2a`
Expected: FAIL — 404.

- [ ] **Step 3: Implement the routes**

```
GET  /api/a2a/status
GET  /api/a2a/peers
GET  /api/a2a/outbound
PUT  /api/a2a/outbound
POST /api/a2a/test
```

Requirements:
- Inbound and outbound peer views expose name, URL, IP/CIDR list, and tool
  policy, with tokens replaced by a short fingerprint (first 6 hex characters of
  a SHA-256 digest). The raw token is never returned.
- `PUT /api/a2a/outbound` accepts replacement tokens; an omitted token keeps the
  existing one rather than clearing it.
- `PUT /api/a2a/outbound` **persists and is live** (operator decision; design
  spec §5.4.1, which withdrew the "editing `config.toml` from the UI" non-goal
  for this one route). It rewrites only the `[a2a.outbound.peers]` table of the
  `config.toml` the process was started from — the path
  `home::resolve_config_path` resolved, never a re-derivation — through
  `toml_edit`, so every comment, blank line and key order *outside* that table is
  preserved. The write is atomic (a temporary file in the same directory,
  fsynced, renamed over the target) and the replacement keeps the original file's
  permissions. Only after the file is written are the peers applied to the shared
  handle `main.rs` creates — the same handle `call_a2a_agent` reads — so the
  running agent uses them on its next invocation. A failed write is a 500 that
  leaves both the file and the running configuration unchanged; a missing
  `config.toml` is refused rather than created. Concurrent `PUT`s are serialised
  by a mutex around the read-modify-write. The response reports
  `persistent: true`, `restart_reverts: false`, `affects_running_agent: true`,
  with prose that says the same.
- `POST /api/a2a/test` calls `A2aClient::discover` against the named peer and
  returns the card name, protocol binding, and skill count, or a redacted error.
- When the A2A listener is disabled, status reports that plainly rather than
  erroring.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test web_endpoint a2a`
Expected: PASS.

- [ ] **Step 4b: Prove the persistence tests have teeth**

The persistence properties are only worth testing if the tests fail when the
implementation stops providing them. Mutate each one, confirm the named test
fails, revert:

- Write the whole document back through serde instead of `toml_edit` →
  `an_outbound_update_rewrites_only_the_outbound_table_of_a_real_config_file`
  must fail on the comment/byte-identity assertions.
- Drop the rename and write in place → the atomicity and leftover-temporary-file
  assertions must fail.
- Skip `set_permissions` → `an_outbound_update_keeps_the_configuration_files_permissions`
  must fail.
- Give `CallA2aAgent` its own copy of the configuration instead of the shared
  handle → `an_outbound_update_reaches_the_running_call_a2a_agent_tool` must fail.
- Apply the peers in memory before writing the file, or ignore the write error →
  `a_failed_write_leaves_the_file_and_the_running_agent_unchanged` must fail.

- [ ] **Step 5: Prove the no-token test has teeth**

Add the token to the peers response, run
`cargo test --test web_endpoint::peer_listings_never_return_a_token`, confirm
FAIL, revert.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
git add src/web tests/web_endpoint.rs
git commit -m "feat(web): add the A2A peer manager"
```

---

## Task 20: A2A UI

**Files:**
- Modify: `src/web/assets/app.js`
- Modify: `src/web/assets/style.css`

- [ ] **Step 1: Implement the view**

Requirements: listener status card, inbound peer list with tool-policy chips and
a clear note that tokens are never displayed, outbound peer editor, and a "Test
connection" button per peer that renders the discovered card summary inline.

- [ ] **Step 2: Verify and commit**

```bash
cargo test --test web_endpoint
git add src/web/assets
git commit -m "feat(web): add the A2A manager view"
```

---

## Task 21: Documentation and final verification

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `config.example.toml` (already updated in Task 1)

- [ ] **Step 1: Update `CLAUDE.md`**

Add `src/web/` to the architecture tree, a "Web Dashboard" section covering the
auth model, the credential file location, the accepted risk of default
credentials without forced change, and the security invariants that must not be
weakened:
- Empty `allow_ips` permits any source; non-empty is strict — the opposite of A2A.
- The bearer token is stored only as a hash and is never readable.
- Every mutating route requires the CSRF header, including login.
- The chat tool policy is derived from the live registry, never hand-written.
- `invoke_agent` and `spawn_agents` are not granted to the web chat.

- [ ] **Step 2: Run every gate**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

- [ ] **Step 3: Final spec compliance review**

Dispatch a review subagent against the full spec and report any unmet
requirement, plus every open risk from section 11 that remains unmitigated.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs(web): document the dashboard"
```

---

## Self-review notes

- Every task lists exact file paths and a runnable verification command.
- Security tests in Tasks 2, 3, 4, 5, 8, 12, 14, 17, and 19 each have an
  explicit mutation step, because a security test that has never been observed
  to fail is not evidence.
- Phase 1 is a hard prerequisite; phases 2-5 are independent after it.
- `WebState.agent` and `WebState.supervisor` are `Option` so phase 1 can ship
  and be tested before the chat and supervisor surfaces exist; routes that need
  them return 503 instead of panicking.
