//! Dashboard credentials: password hashing, the on-disk credential file, and
//! bearer-token verification.
//!
//! Secrets live in `<home>/web-auth.toml` (mode 0600), never in `config.toml`,
//! because `config.toml` is the file users copy, share, and paste into issues.

use anyhow::{bail, Context, Result};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// The only dashboard identity. There are no roles and no second user.
pub const DEFAULT_USERNAME: &str = "admin";

/// The password a fresh install starts with.
///
/// Forced change is deliberately disabled (design spec §2), so the compensating
/// controls are: loopback-only default bind, a startup warning, a persistent UI
/// banner, and login rate limiting.
pub const DEFAULT_PASSWORD: &str = "admin";

/// Persisted dashboard credentials.
///
/// The bearer token is stored as a SHA-256 hex digest, not as the token
/// itself: the operator sees the token exactly once, at generation time, and
/// afterwards the process can only verify it. A leaked credential file
/// therefore does not yield a usable bearer token.
#[derive(Clone, Serialize, Deserialize)]
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

/// Hand-written so a stray `tracing::debug!(?credentials)` cannot print the
/// password hash or the bearer hash. `#[derive(Debug)]` would make that mistake
/// one keystroke away, and this repository already redacts secrets in `Debug`
/// for `A2aOutboundPeerConfig`.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .field("bearer_enabled", &self.bearer_enabled)
            .field(
                "bearer_token_hash",
                &if self.bearer_token_hash.is_empty() {
                    "[unset]"
                } else {
                    "[REDACTED]"
                },
            )
            .field("uses_default_password", &self.uses_default_password)
            .finish()
    }
}

/// Hash a password with Argon2id and a fresh random salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))
}

/// Verify a password against a stored PHC hash.
///
/// A malformed stored hash is a denial, never a panic and never an accidental
/// accept: an unreadable credential file must lock the dashboard out, not open
/// it.
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
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

    /// Replace the password. Does not touch the file: callers `save()` when
    /// they want the change to survive a restart.
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

    /// Constant-time bearer check.
    ///
    /// Disabled means disabled: with the toggle off, or with no stored hash,
    /// every token is refused rather than compared against an empty digest.
    pub fn verify_bearer(&self, presented: &str) -> bool {
        if !self.bearer_enabled || self.bearer_token_hash.is_empty() {
            return false;
        }
        let expected = self.bearer_token_hash.as_bytes();
        let actual = hash_bearer(presented);
        expected.ct_eq(actual.as_bytes()).into()
    }

    /// A short, non-reversible label for the active bearer token, or `None`
    /// when bearer is off or unset.
    ///
    /// The stored value is already a SHA-256 digest of a 256-bit random token,
    /// so exposing six of its hex characters identifies a token the operator
    /// already holds without narrowing an attacker's search space in any
    /// useful way. The full digest is never exposed.
    pub fn bearer_fingerprint(&self) -> Option<String> {
        if !self.bearer_enabled || self.bearer_token_hash.is_empty() {
            return None;
        }
        Some(self.bearer_token_hash.chars().take(6).collect())
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
        Self {
            ttl,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a new session id: 256 bits from the OS CSPRNG, hex encoded.
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

    /// True when `id` names a live session.
    ///
    /// A poisoned mutex, an empty id, and an expired session are all denials.
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

/// Source-IP gate for the dashboard.
///
/// Unlike the A2A listener's allowlist, an empty list here means "any source",
/// because the dashboard has a password and A2A does not. The asymmetry is
/// intentional and is stated in the UI so an operator is never misled into
/// thinking an empty list is a restriction.
pub struct IpGate {
    nets: Vec<IpNet>,
    /// The trimmed entries exactly as they were configured. Kept so the
    /// dashboard can show the operator the **live** allowlist after
    /// `PUT /api/settings/allow-ips` replaces it — reporting the startup value
    /// from `WebConfig` would show a list the gate is no longer enforcing.
    entries: Vec<String>,
}

impl IpGate {
    /// Parse the configured entries. A malformed entry is an error rather than
    /// a silently ignored rule, because ignoring it would turn a typo into a
    /// gate that denies everything (or, worse, into one that allows more than
    /// the operator wrote).
    pub fn new(entries: &[String]) -> Result<Self> {
        let mut nets = Vec::with_capacity(entries.len());
        let mut trimmed_entries = Vec::with_capacity(entries.len());
        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                bail!("web.allow_ips contains an empty entry");
            }
            let net = trimmed
                .parse::<IpNet>()
                .or_else(|_| trimmed.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    anyhow::anyhow!("web.allow_ips entry '{trimmed}' is not an IP or CIDR range")
                })?;
            nets.push(net);
            trimmed_entries.push(trimmed.to_string());
        }
        Ok(Self {
            nets,
            entries: trimmed_entries,
        })
    }

    /// The configured entries, trimmed.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// True when the list is empty, i.e. the gate restricts nothing.
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// True when `ip` may proceed.
    pub fn permits(&self, ip: IpAddr) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        // An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) is a distinct address
        // family to `ipnet`, which already refuses to match it against an IPv4
        // rule. The guard below makes that explicit and independent of the
        // library's behaviour, so a future `ipnet` that normalised mapped
        // addresses could not silently let `::ffff:10.0.0.1` through an
        // allowlist written for `10.0.0.0/8`. A mapped address is compared only
        // against explicitly IPv6 rules.
        self.nets.iter().any(|net| match (net, ip) {
            (IpNet::V4(_), IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some() => false,
            _ => net.contains(&ip),
        })
    }
}

/// Failed logins from one source before it is locked out.
const MAX_LOGIN_FAILURES: u32 = 5;

/// How long a lockout lasts, and the window over which failures accumulate.
const LOGIN_LOCKOUT: Duration = Duration::from_secs(300);

/// Per-source login failure tracker with a lockout window.
///
/// In-memory on purpose: a restart clears every lockout, which is acceptable
/// because a restart also clears every session and resets the process the
/// attacker was probing.
pub struct LoginLimiter {
    failures: HashMap<IpAddr, (u32, Instant)>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self {
            failures: HashMap::new(),
        }
    }

    fn lockout_window(&self) -> Duration {
        LOGIN_LOCKOUT
    }

    /// Refuse when this source has already failed too many times inside the
    /// window.
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

    /// A successful login clears the counter, so a legitimate operator who
    /// mistyped a few times is not locked out afterwards.
    pub fn record_success(&mut self, ip: IpAddr) {
        self.failures.remove(&ip);
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new()
    }
}

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
    fn debug_never_prints_the_password_or_bearer_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        let token = creds.enable_bearer().unwrap();

        let rendered = format!("{creds:?}");
        assert!(
            !rendered.contains(&creds.password_hash),
            "the password hash must never appear in Debug output"
        );
        assert!(
            !rendered.contains(&creds.bearer_token_hash),
            "the bearer hash must never appear in Debug output"
        );
        assert!(
            !rendered.contains(&token),
            "the bearer token must never appear in Debug output"
        );
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn bearer_token_is_stored_only_as_a_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        let token = creds.enable_bearer().unwrap();
        assert_eq!(token.len(), 64, "the token must be 256 bits, hex encoded");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "the token must be hex, not base64 or arbitrary bytes"
        );
        // Persist first: the point of this test is what a written credential
        // file holds, so the file has to actually hold the current state.
        creds.save(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains(&token),
            "the raw bearer token must never hit disk"
        );
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
        creds.disable_bearer();
        assert!(!creds.bearer_enabled);
        assert!(!creds.verify_bearer("anything"));
    }

    // ── Sessions ────────────────────────────────────────────────────────────

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
        assert!(
            a.len() >= 64,
            "session ids must carry at least 256 bits of entropy"
        );
    }

    // ── Source-IP allowlist ─────────────────────────────────────────────────

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
        assert!(
            !gate.permits(mapped),
            "mapped addresses must not match an IPv4 rule"
        );
    }

    #[test]
    fn a_malformed_entry_is_rejected_at_construction() {
        assert!(IpGate::new(&["999.1.1.1".to_string()]).is_err());
    }

    #[test]
    fn the_gate_reports_the_entries_it_was_built_with() {
        let gate = IpGate::new(&[" 10.0.0.0/8 ".to_string(), "192.168.1.5".to_string()]).unwrap();
        assert_eq!(
            gate.entries().to_vec(),
            vec!["10.0.0.0/8", "192.168.1.5"],
            "entries must be trimmed and preserved in order"
        );
        assert!(!gate.is_empty());
        assert!(IpGate::new(&[]).unwrap().entries().is_empty());
        assert!(IpGate::new(&[]).unwrap().is_empty());
    }

    #[test]
    fn ipnet_still_refuses_cross_family_matches() {
        // Canary for the mapped-address guard in `permits()`. With ipnet
        // 2.12.1 that guard is redundant: `IpNet::contains` already returns
        // false when the families differ, which is why deleting the guard does
        // not fail the test above. This test pins the assumption so that a
        // future ipnet which *did* normalise mapped addresses turns the guard
        // from belt-and-braces into the only thing standing between
        // `::ffff:10.0.0.1` and an allowlist written for `10.0.0.0/8`.
        let net: IpNet = "192.168.1.0/24".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.168.1.5".parse().unwrap();
        assert!(
            !net.contains(&mapped),
            "ipnet changed: re-derive the allowlist semantics before relaxing the guard"
        );
    }

    // ── Login rate limiting ─────────────────────────────────────────────────

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
        assert!(
            limiter.check(ip).is_err(),
            "five failures must lock the source out"
        );
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
}
