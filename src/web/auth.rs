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
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

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

/// Lowercase hex SHA-256 of `value`.
///
/// Used for the two comparisons in this module that must not use `==`: the
/// stored bearer digest, and the username. Hashing both sides of a comparison
/// also equalises their length, which `ConstantTimeEq` requires.
fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// How many Argon2 operations may run at the same time.
///
/// Argon2id with this crate's default parameters costs ~50 ms of CPU and
/// allocates ~19 MiB per operation (measured on this machine — see the ignored
/// `tests::argon2_cost_is_measured`). The dashboard shares its tokio runtime
/// *and its process* with the Telegram bot, so a burst of login attempts is a
/// memory- and CPU-exhaustion vector against the bot even once the work has
/// been moved off the async executor. Four permits bound the transient
/// allocation at roughly 4 × 19 MiB while still letting a handful of
/// legitimate logins proceed in parallel; a lower number would serialise the
/// settings page behind a single slow login, and a higher one buys nothing —
/// the operator is one person.
const MAX_CONCURRENT_KDF_OPERATIONS: usize = 4;

/// Process-wide gate for the constant above. Lazily created so the module has
/// no initialisation order to get wrong.
static KDF_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

/// The process-wide Argon2 concurrency gate.
fn kdf_semaphore() -> &'static Semaphore {
    KDF_SEMAPHORE.get_or_init(|| Semaphore::new(MAX_CONCURRENT_KDF_OPERATIONS))
}

/// [`hash_password`] for async callers.
///
/// Argon2id is deliberately expensive, purely CPU-bound work. Awaiting it
/// inside an axum handler parks a tokio worker thread for ~50 ms, and this
/// process also drives the Telegram bot, so a login burst would stall the bot
/// for as long as the attacker keeps posting. The permit is taken *before* the
/// work is spawned, so the blocking pool never holds more than
/// [`MAX_CONCURRENT_KDF_OPERATIONS`] Argon2 operations at once.
///
/// The sync [`hash_password`] stays public for tests and sync callers.
pub async fn hash_password_async(password: &str) -> Result<String> {
    // Held for the whole operation, including the `?` returns below.
    let _permit = kdf_semaphore()
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("the password hashing gate is closed"))?;

    let password = password.to_string();
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .context("the password hashing task failed to join")?
}

/// [`verify_password`] for async callers, with the same fail-closed contract:
/// a gate that cannot be acquired, a panicking blocking task, and a runtime
/// that is shutting down all answer `false` rather than propagating a
/// surprise. A caller cannot tell "wrong password" from "internal failure",
/// and that is intentional — both are a 401 at the login route.
pub async fn verify_password_async(password: &str, hash: &str) -> bool {
    let Ok(_permit) = kdf_semaphore().acquire().await else {
        tracing::error!("web: the password verification gate is closed; denying");
        return false;
    };

    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .unwrap_or_else(|e| {
            // A panic in the blocking task, or a runtime that is shutting
            // down. Both are a denial, never an accidental accept.
            tracing::error!(error = %e, "web: the password verification task failed");
            false
        })
}

impl Credentials {
    /// Load credentials, creating the default `admin`/`admin` pair on first
    /// run. The file is written mode 0600 before any content lands in it.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            tighten_to_owner_only(path);
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
    ///
    /// Synchronous, and it calls Argon2 inline. An async caller — the settings
    /// route — must use [`hash_password_async`] followed by
    /// [`Credentials::set_password_hash`] instead, or it parks a runtime worker
    /// for the duration of the hash.
    pub fn set_password(&mut self, password: &str) -> Result<()> {
        self.password_hash = hash_password(password)?;
        self.uses_default_password = password == DEFAULT_PASSWORD;
        Ok(())
    }

    /// Install a password hash that was computed elsewhere, typically by
    /// [`hash_password_async`].
    ///
    /// This is the async counterpart of [`Credentials::set_password`], split so
    /// that the expensive half happens off the runtime and **outside** the
    /// credentials lock, and the cheap half happens while holding it. It takes
    /// `&mut self` and contains no `.await`, so it is safe to call from an axum
    /// handler that is holding the `std::sync::MutexGuard`.
    ///
    /// `password` is the plaintext, needed only to keep
    /// [`Credentials::uses_default_password`] — and therefore the mandatory UI
    /// banner — honest. Setting `password_hash` directly would silently
    /// desynchronise it.
    pub fn set_password_hash(&mut self, password: &str, password_hash: String) {
        self.password_hash = password_hash;
        self.uses_default_password = password == DEFAULT_PASSWORD;
    }

    /// Generate and store a new bearer token, returning it so the caller can
    /// display it once. It is never readable again.
    pub fn enable_bearer(&mut self) -> Result<String> {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.bearer_token_hash = sha256_hex(&token);
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
        let actual = sha256_hex(presented);
        expected.ct_eq(actual.as_bytes()).into()
    }

    /// Constant-time username comparison, for the login handler.
    ///
    /// `creds.username == body.username` compares byte by byte and stops at the
    /// first difference. The password half is already constant-time (Argon2),
    /// so this is not a practical oracle *today* — but it becomes one the
    /// moment the KDF cost is lowered, or a code path reaches the comparison
    /// without paying for a KDF at all. Making the comparison unconditionally
    /// constant-time removes the dependency on Argon2's cost for a property
    /// that should not depend on it.
    ///
    /// Both sides are hashed first: `ConstantTimeEq` is defined for
    /// equal-length slices, and digesting also keeps the comparison from
    /// revealing the length of the stored username.
    pub fn verify_username(&self, presented: &str) -> bool {
        let expected = sha256_hex(&self.username);
        let actual = sha256_hex(presented);
        expected.as_bytes().ct_eq(actual.as_bytes()).into()
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

/// Bring an existing credential file down to mode 0600, warning when it was
/// wider.
///
/// `write_owner_only` applies its mode at **creation** only, so a file that is
/// already on disk keeps whatever mode it has: restored from an archive that
/// dropped it, copied by an operator, or written by an older build. That file
/// holds the Argon2 password hash, so "it was 0600 when we made it" is not a
/// guarantee about the file we are about to read.
///
/// Failing to tighten is logged but is **not** fatal. The file is already
/// exposed either way, and refusing to load it would lock the operator out of
/// the only UI that can change the password — the warning is the actionable
/// part, and the caller's own read still reports a genuinely unreadable file.
fn tighten_to_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        // Let the caller's `read_to_string` produce the real error.
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode == 0o600 {
        return;
    }

    tracing::warn!(
        path = %path.display(),
        mode = %format!("{mode:04o}"),
        "web: credential file is readable beyond its owner; tightening it to 0600"
    );
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::error!(
            path = %path.display(),
            error = %e,
            "web: could not tighten the credential file to 0600; it stays readable by \
             group/other and it holds the password hash"
        );
    }
}

/// Write a file that only its owner can read, creating it with that mode
/// rather than chmod-ing after the fact so the content is never briefly
/// world-readable.
pub fn write_owner_only(path: &Path, body: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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

    // `mode()` above is honoured only when the file is *created*; an existing
    // file keeps the mode it already had, which would silently leave a secret
    // world-readable. Tighten before the body lands, so a failure here cannot
    // leave the new hash on disk with a wide mode.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set 0600 on {}", path.display()))?;

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
    ///
    /// Returns `Err` rather than an id it could not store. Silently returning
    /// the id on a poisoned mutex handed the client HTTP 200 plus a cookie that
    /// could never authenticate — an unexplained login loop — while every other
    /// lock site in this module (`validate`, `destroy`, `ip_permitted`, the
    /// login limiter) fails closed.
    ///
    /// **Caller contract:** on `Err`, respond `500 Internal Server Error` and
    /// send **no** `Set-Cookie` header. Never fall back to a session that was
    /// not recorded.
    pub fn create(&self) -> Result<String> {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

        let mut map = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session store mutex poisoned"))?;
        map.insert(id.clone(), Instant::now());
        Ok(id)
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

/// Failed logins from one source before a lockout starts.
const MAX_LOGIN_FAILURES: u32 = 5;

/// The first lockout applied once the threshold above is crossed. Each further
/// failure doubles it.
const LOGIN_BACKOFF_BASE: Duration = Duration::from_secs(5);

/// The duration backoff saturates at, and the window over which failures
/// accumulate before the counter starts over.
const LOGIN_LOCKOUT: Duration = Duration::from_secs(300);

/// How many distinct sources are remembered at once.
///
/// The limiter is per source address, so an attacker varying the source —
/// trivial over IPv6, where one /64 hands out 2^64 addresses — would otherwise
/// grow the map without limit. 1024 entries of `(IpAddr, (u32, Instant))` is a
/// few tens of KiB, and the eviction order is documented on `evict_oldest`.
const MAX_TRACKED_SOURCES: usize = 1024;

/// Lockout duration for a source that has accumulated `failures` failures.
///
/// Zero below [`MAX_LOGIN_FAILURES`], then [`LOGIN_BACKOFF_BASE`] doubling once
/// per further failure, saturating at [`LOGIN_LOCKOUT`]. Design spec §2.1 and
/// §4.5 require *exponential backoff after repeated failures, with a lockout
/// window*; a flat 300 s lockout is a single step, so an attacker gets five
/// fresh guesses every five minutes for as long as they care to keep going.
///
/// The counter is deliberately **not** reset when a lockout is served — only on
/// a successful login, or after [`LOGIN_LOCKOUT`] with no failures at all.
/// Resetting it on expiry would flatten the backoff again: five guesses every
/// five seconds, which is weaker than the flat lockout this replaces.
fn backoff_for(failures: u32) -> Duration {
    if failures < MAX_LOGIN_FAILURES {
        return Duration::ZERO;
    }
    // `checked_shl` yields `None` past 63 doublings, where the shift would be
    // undefined; `saturating_mul` then pins the result to the cap below.
    let doublings = failures - MAX_LOGIN_FAILURES;
    let seconds = LOGIN_BACKOFF_BASE
        .as_secs()
        .saturating_mul(1u64.checked_shl(doublings).unwrap_or(u64::MAX));
    Duration::from_secs(seconds).min(LOGIN_LOCKOUT)
}

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

    /// Refuse when this source has already failed too many times inside the
    /// window.
    pub fn check(&mut self, ip: IpAddr) -> Result<()> {
        let Some(&(count, last)) = self.failures.get(&ip) else {
            return Ok(());
        };
        let backoff = backoff_for(count);
        if backoff.is_zero() {
            return Ok(());
        }

        let elapsed = Instant::now().duration_since(last);
        if elapsed >= backoff {
            return Ok(());
        }

        let remaining = backoff - elapsed;
        // Rounded up: reporting "4 seconds" when 4.99 remain invites a retry
        // that fails again, and "0 seconds" is worse than useless.
        let seconds = remaining
            .as_secs()
            .saturating_add(u64::from(remaining.subsec_nanos() > 0));
        bail!("too many failed login attempts; try again in {seconds} seconds");
    }

    pub fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();

        // Drop sources whose last failure is older than the window: they carry
        // no information, and they are what an attacker would use to grow the
        // map. The scan is bounded by `MAX_TRACKED_SOURCES` and runs at most
        // once per failed login — i.e. after an Argon2 verification costing
        // ~20 ms, so it is not on any hot path.
        self.failures
            .retain(|_, (_, last)| now.duration_since(*last) <= LOGIN_LOCKOUT);

        // Everything stale is gone, so an entry that is still here is fresh and
        // only needs its count bumped.
        if let Some(entry) = self.failures.get_mut(&ip) {
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
            return;
        }

        // A source we are not already tracking. Keep the map bounded.
        while self.failures.len() >= MAX_TRACKED_SOURCES && self.evict_oldest() {}
        self.failures.insert(ip, (1, now));
    }

    /// Drop the entry whose last failure is furthest in the past, returning
    /// `false` when the map is empty so the caller's loop always terminates.
    ///
    /// Evicting the *oldest* entry means a source that is currently locked out
    /// can be forgotten once enough other sources fail. That is accepted: the
    /// limiter is per source address, so an attacker who can vary the source at
    /// will — trivial over IPv6 — is not constrained by it in the first place,
    /// and the alternative is to trade a limitation that does not exist for a
    /// memory-exhaustion vector that does.
    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .failures
            .iter()
            .min_by_key(|(_, (_, last))| *last)
            .map(|(ip, _)| *ip);
        let Some(oldest) = oldest else {
            return false;
        };
        self.failures.remove(&oldest);
        true
    }

    /// A successful login clears the counter, so a legitimate operator who
    /// mistyped a few times is not locked out afterwards.
    pub fn record_success(&mut self, ip: IpAddr) {
        self.failures.remove(&ip);
    }

    /// Number of sources currently remembered.
    ///
    /// Test-only: the map is an implementation detail and no caller should
    /// depend on its size.
    #[cfg(test)]
    fn tracked_sources(&self) -> usize {
        self.failures.len()
    }

    /// Move a source's last-failure instant into the past, so a test can
    /// observe a *served* lockout without sleeping through it.
    #[cfg(test)]
    fn backdate(&mut self, ip: IpAddr, by: Duration) {
        if let Some(entry) = self.failures.get_mut(&ip) {
            entry.1 = entry.1.checked_sub(by).unwrap_or(entry.1);
        }
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

    /// The permission bits of `path`, masked to `0o777`.
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn set_file_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn loading_tightens_a_world_readable_credential_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        Credentials::load_or_create(&path).unwrap();

        // Reproduce a credential file that is already on disk world-readable:
        // written by an older build, restored from an archive that dropped the
        // mode, or chmod-ed by an operator. `OpenOptions::mode` is applied only
        // at creation, so nothing else in this module would ever repair it, and
        // the file holds the password hash.
        set_file_mode(&path, 0o644);
        assert_eq!(file_mode(&path), 0o644, "the setup must widen the file");

        let reloaded = Credentials::load_or_create(&path).unwrap();
        assert_eq!(
            reloaded.username, DEFAULT_USERNAME,
            "tightening must not stop the file from loading"
        );
        assert_eq!(
            file_mode(&path),
            0o600,
            "loading a group/world-readable credential file must tighten it"
        );
    }

    #[test]
    fn saving_over_a_world_readable_credential_file_tightens_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let creds = Credentials::load_or_create(&path).unwrap();

        // `OpenOptions::mode` is creation-only, so `save()` alone would rewrite
        // the secret into a file that is still world-readable.
        set_file_mode(&path, 0o644);
        creds.save(&path).unwrap();

        assert_eq!(
            file_mode(&path),
            0o600,
            "a save must not preserve a wide mode on an existing file"
        );
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

    /// The default-password flag is not persisted (`#[serde(skip)]`), so a
    /// second run has to recompute it from the stored hash. If that computation
    /// regresses, the mandatory UI banner (design spec §2.1) and the startup
    /// warning silently disappear for *every existing installation* — the one
    /// case they exist for.
    #[test]
    fn an_async_caller_can_install_a_precomputed_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();

        // What the settings route does: hash off the runtime, then install the
        // result under the lock.
        creds.set_password_hash("a-new-secret", hash_password("a-new-secret").unwrap());
        assert!(verify_password("a-new-secret", &creds.password_hash));
        assert!(!verify_password(DEFAULT_PASSWORD, &creds.password_hash));
        assert!(
            !creds.uses_default_password,
            "installing a non-default password must clear the banner flag"
        );

        // ...and installing the default must raise it again, or the mandatory
        // banner would stay hidden for an operator who reset the password back.
        creds.set_password_hash(DEFAULT_PASSWORD, hash_password(DEFAULT_PASSWORD).unwrap());
        assert!(
            creds.uses_default_password,
            "installing the default password must raise the banner flag"
        );
    }

    #[test]
    fn reloading_a_default_password_file_still_flags_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");

        let created = Credentials::load_or_create(&path).unwrap();
        assert!(created.uses_default_password);
        created.save(&path).unwrap();

        let reloaded = Credentials::load_or_create(&path).unwrap();
        assert!(
            reloaded.uses_default_password,
            "a reloaded credential file holding the default password must still be \
             flagged, or the banner and the startup warning never appear"
        );
        assert!(
            verify_password(DEFAULT_PASSWORD, &reloaded.password_hash),
            "the reload must not have changed the stored hash"
        );
    }

    /// The other half of the same computation: a changed password must clear
    /// the flag on reload, or the banner would never go away.
    #[test]
    fn reloading_a_changed_password_clears_the_default_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        creds.set_password("a-new-secret").unwrap();
        creds.save(&path).unwrap();

        let reloaded = Credentials::load_or_create(&path).unwrap();
        assert!(
            !reloaded.uses_default_password,
            "a reloaded file with a changed password must not be flagged as default"
        );
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
    fn verify_username_accepts_only_the_configured_username() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let creds = Credentials::load_or_create(&path).unwrap();

        assert!(
            creds.verify_username(DEFAULT_USERNAME),
            "the configured username must be accepted"
        );

        for wrong in [
            "", "admi", "adminx", "Admin",
            // Same length as "admin" and differing only in the last byte, so a
            // comparison that stopped early would still be exercised.
            "admiN", " admin", "admin ",
        ] {
            assert!(
                !creds.verify_username(wrong),
                "{wrong:?} must not be accepted as the username"
            );
        }
    }

    #[test]
    fn verify_username_uses_the_stored_name_not_a_constant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web-auth.toml");
        let mut creds = Credentials::load_or_create(&path).unwrap();
        creds.username = "someone-else".to_string();

        assert!(creds.verify_username("someone-else"));
        assert!(
            !creds.verify_username(DEFAULT_USERNAME),
            "the comparison must follow the stored username"
        );
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
        let id = store.create().unwrap();
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
        let id = store.create().unwrap();
        store.destroy(&id);
        assert!(!store.validate(&id));
    }

    #[test]
    fn an_expired_session_is_rejected() {
        let store = SessionStore::new(Duration::from_secs(0));
        let id = store.create().unwrap();
        assert!(!store.validate(&id), "a zero TTL must not authenticate");
    }

    #[test]
    fn session_ids_are_not_guessable_or_repeated() {
        let store = SessionStore::new(Duration::from_secs(3600));
        let a = store.create().unwrap();
        let b = store.create().unwrap();
        assert_ne!(a, b);
        assert!(
            a.len() >= 64,
            "session ids must carry at least 256 bits of entropy"
        );
    }

    /// A poisoned store must report the failure instead of handing out an id it
    /// never recorded. The old signature returned the id anyway, so the caller
    /// answered HTTP 200 with a cookie that could never authenticate and the
    /// browser looped back to the login page forever with no explanation.
    #[test]
    fn create_fails_closed_when_the_store_is_poisoned() {
        let store = SessionStore::new(Duration::from_secs(3600));

        // Poison the mutex exactly as a panicking request handler would.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = store.sessions.lock().unwrap();
            panic!("simulated panic while holding the session lock");
        }));
        assert!(
            poisoned.is_err(),
            "the helper must actually poison the mutex"
        );

        let created = store.create();
        assert!(
            created.is_err(),
            "a poisoned store must fail, not return {:?}",
            created.ok()
        );
        assert!(
            !store.validate("anything"),
            "a poisoned store must deny every session"
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

    /// A distinct source address for each `n`, in a documentation range.
    fn source(n: usize) -> IpAddr {
        format!("2001:db8::{n:x}").parse().unwrap()
    }

    #[test]
    fn the_lockout_backs_off_exponentially() {
        for failures in 0..MAX_LOGIN_FAILURES {
            assert_eq!(
                backoff_for(failures),
                Duration::ZERO,
                "{failures} failures must not lock a source out"
            );
        }

        assert_eq!(
            backoff_for(MAX_LOGIN_FAILURES),
            LOGIN_BACKOFF_BASE,
            "the first lockout must be the base delay, not the cap"
        );

        let mut previous = LOGIN_BACKOFF_BASE;
        for failures in (MAX_LOGIN_FAILURES + 1)..(MAX_LOGIN_FAILURES + 6) {
            let backoff = backoff_for(failures);
            assert!(
                backoff > previous,
                "the lockout must grow with the failure count: {failures} failures gave \
                 {backoff:?}, which is no more than the {previous:?} before it"
            );
            previous = backoff;
        }
    }

    #[test]
    fn the_lockout_backoff_is_capped_at_the_window() {
        for failures in [MAX_LOGIN_FAILURES + 6, 50, 1_000, u32::MAX] {
            assert_eq!(
                backoff_for(failures),
                LOGIN_LOCKOUT,
                "{failures} failures must saturate at the lockout window instead of \
                 overflowing or growing without bound"
            );
        }
    }

    #[test]
    fn a_locked_out_source_is_told_how_long_to_wait() {
        let mut limiter = LoginLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure(ip);
        }

        let message = limiter
            .check(ip)
            .expect_err("the source must be locked out")
            .to_string();
        assert!(
            message.contains(&LOGIN_BACKOFF_BASE.as_secs().to_string()),
            "the first lockout is {LOGIN_BACKOFF_BASE:?}, so the message must report {} \
             seconds: {message}",
            LOGIN_BACKOFF_BASE.as_secs()
        );
    }

    #[test]
    fn a_served_lockout_doubles_the_next_one() {
        let mut limiter = LoginLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure(ip);
        }

        // The first lockout has now been served. Serving it must **not** reset
        // the counter, or the backoff would be flat again — five guesses every
        // five seconds, weaker than the flat 300 s lockout it replaced.
        limiter.backdate(ip, LOGIN_BACKOFF_BASE);
        assert!(
            limiter.check(ip).is_ok(),
            "a lockout of {LOGIN_BACKOFF_BASE:?} that has been served must not deny"
        );

        limiter.record_failure(ip);
        let message = limiter
            .check(ip)
            .expect_err("the source must be locked out again")
            .to_string();
        assert!(
            message.contains(&(LOGIN_BACKOFF_BASE.as_secs() * 2).to_string()),
            "the second lockout must be twice the first ({} seconds): {message}",
            LOGIN_BACKOFF_BASE.as_secs() * 2
        );
    }

    #[test]
    fn a_long_idle_period_clears_the_failure_count() {
        let mut limiter = LoginLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure(ip);
        }

        limiter.backdate(ip, LOGIN_LOCKOUT + Duration::from_secs(1));
        assert!(
            limiter.check(ip).is_ok(),
            "a lockout whose window has long passed must not deny"
        );

        limiter.record_failure(ip);
        assert!(
            limiter.check(ip).is_ok(),
            "after the lockout window with no failures at all the count must start over \
             rather than resume at {MAX_LOGIN_FAILURES}"
        );
    }

    #[test]
    fn the_failure_map_stays_bounded_under_many_distinct_sources() {
        let mut limiter = LoginLimiter::new();
        let sources = MAX_TRACKED_SOURCES * 2;
        for n in 0..sources {
            limiter.record_failure(source(n));
        }

        assert!(
            limiter.tracked_sources() <= MAX_TRACKED_SOURCES,
            "{sources} distinct sources grew the failure map to {} entries; the cap is \
             {MAX_TRACKED_SOURCES}",
            limiter.tracked_sources()
        );
    }

    #[test]
    fn the_limiter_still_functions_after_the_map_is_pruned() {
        let mut limiter = LoginLimiter::new();
        for n in 0..(MAX_TRACKED_SOURCES * 2) {
            limiter.record_failure(source(n));
        }

        let attacker: IpAddr = "203.0.113.9".parse().unwrap();
        let innocent: IpAddr = "203.0.113.10".parse().unwrap();
        for _ in 0..MAX_LOGIN_FAILURES {
            limiter.record_failure(attacker);
        }

        assert!(
            limiter.check(attacker).is_err(),
            "a source that fails after pruning must still be locked out"
        );
        assert!(
            limiter.check(innocent).is_ok(),
            "an unrelated source must still be allowed after pruning"
        );
        assert!(limiter.tracked_sources() <= MAX_TRACKED_SOURCES);
    }

    #[test]
    fn expired_entries_are_pruned() {
        let mut limiter = LoginLimiter::new();
        let stale: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.record_failure(stale);
        limiter.backdate(stale, LOGIN_LOCKOUT + Duration::from_secs(1));
        assert_eq!(limiter.tracked_sources(), 1);

        limiter.record_failure("10.0.0.2".parse().unwrap());
        assert_eq!(
            limiter.tracked_sources(),
            1,
            "the stale entry must be dropped when the next failure is recorded"
        );
    }

    // ── Argon2 off the async executor ───────────────────────────────────────

    #[tokio::test]
    async fn the_async_hash_round_trips_through_the_async_verifier() {
        let hash = hash_password_async("correct horse").await.unwrap();
        assert!(verify_password_async("correct horse", &hash).await);
        assert!(!verify_password_async("wrong horse", &hash).await);
    }

    #[tokio::test]
    async fn the_async_verifier_fails_closed_on_a_malformed_hash() {
        assert!(!verify_password_async("anything", "not-a-phc-string").await);
    }

    /// Every queued verification must finish, even when more of them are in
    /// flight than the gate has permits: the point of the gate is to *queue*
    /// Argon2, not to drop logins on the floor.
    #[tokio::test]
    async fn more_concurrent_verifications_than_permits_all_complete() {
        let hash = hash_password("correct horse").unwrap();
        let mut handles = Vec::new();
        for _ in 0..(MAX_CONCURRENT_KDF_OPERATIONS * 3) {
            let hash = hash.clone();
            handles.push(tokio::spawn(async move {
                verify_password_async("correct horse", &hash).await
            }));
        }
        for handle in handles {
            assert!(
                handle.await.unwrap(),
                "a queued verification was dropped instead of run"
            );
        }
    }

    /// The gate must really bound how many Argon2 operations run at once.
    ///
    /// This is a memory bound as much as a CPU one: each operation allocates
    /// ~19 MiB, so an ungated burst is an out-of-memory vector against the
    /// process that also runs the Telegram bot.
    #[tokio::test]
    async fn the_kdf_gate_bounds_concurrency() {
        let hash = hash_password("correct horse").unwrap();

        // How long one verification actually takes here. This has to be
        // measured, not guessed: a fixed window (say 100 ms) is *longer* than a
        // real verification in a release build but *shorter* than one in a
        // debug build, so an ungated implementation would sail through it and
        // the test would pass for the wrong reason.
        let started = Instant::now();
        assert!(verify_password("correct horse", &hash));
        let cost = started.elapsed();

        // Wait until *all* permits are free, then hold them. Unlike
        // `try_acquire` in a loop this cannot be raced by a test running in
        // parallel in the same process.
        let all = kdf_semaphore()
            .acquire_many(MAX_CONCURRENT_KDF_OPERATIONS as u32)
            .await
            .expect("the gate is never closed");

        let mut pending =
            tokio::spawn(async move { verify_password_async("correct horse", &hash).await });

        assert!(
            tokio::time::timeout(cost * 3, &mut pending).await.is_err(),
            "a verification completed in under {:?} while every permit was held, so it \
             was not gated: the ~19 MiB per operation is unbounded",
            cost * 3
        );

        drop(all);
        assert!(
            tokio::time::timeout(Duration::from_secs(60), pending)
                .await
                .expect("the verification must resume once a permit is free")
                .unwrap(),
            "the released verification must still succeed"
        );
    }

    /// A verification must not occupy the runtime thread.
    ///
    /// Argon2id is ~50 ms of uninterruptible CPU. The dashboard shares its
    /// tokio runtime with the Telegram bot, so a handler that awaited it inline
    /// would stall the bot for the duration of every login attempt — the
    /// denial of service this test exists to prevent.
    ///
    /// The heartbeat task runs on the *same* single-threaded runtime as the
    /// await below. If the KDF runs inline the heartbeat is never scheduled and
    /// the tick count stays at zero.
    #[tokio::test(flavor = "current_thread")]
    async fn the_async_verifier_does_not_block_the_executor() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let hash = hash_password("correct horse").unwrap();

        // What one inline verification costs, measured here so the thresholds
        // below are relative to this machine instead of hard-coded.
        let started = Instant::now();
        assert!(verify_password("correct horse", &hash));
        let inline_cost = started.elapsed();

        let beats: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = {
            let beats = Arc::clone(&beats);
            let stop = Arc::clone(&stop);
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    beats.lock().unwrap().push(Instant::now());
                }
            })
        };

        assert!(verify_password_async("correct horse", &hash).await);

        stop.store(true, Ordering::Relaxed);
        heartbeat.await.unwrap();

        // Behavioural half: no heartbeat may be starved for as long as an
        // inline verification starves it. Measuring the *longest gap* rather
        // than a tick count means a wait on the concurrency gate — which is
        // supposed to yield — cannot mask an inline KDF.
        let beats = beats.lock().unwrap();
        assert!(
            beats.len() >= 2,
            "the heartbeat never ran: the runtime thread was not free while the KDF ran"
        );
        let worst_gap = beats
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]))
            .max()
            .unwrap_or_default();
        assert!(
            worst_gap * 2 < inline_cost,
            "the runtime thread stalled for {worst_gap:?} against an inline verification \
             cost of {inline_cost:?}: the KDF is blocking the async executor"
        );
    }

    /// A verification must go to tokio's blocking pool, not run on the runtime
    /// thread.
    ///
    /// The runtime is built with a single blocking thread, that thread is
    /// occupied by a task that parks until released, and the verification is
    /// then required **not** to finish even once a concurrency permit is free.
    /// An inline Argon2 would run on the worker thread and finish, so it cannot
    /// pass this test.
    ///
    /// The permits are taken and handed back by this test rather than left
    /// alone, because the gate is process-wide: a test running in parallel
    /// could otherwise hold it and make the assertion below pass for the wrong
    /// reason.
    #[test]
    fn the_kdf_runs_on_the_blocking_pool_not_the_runtime_thread() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let hash = hash_password("correct horse").unwrap();

            // Measured, not guessed: a debug build spends ~500 ms in Argon2,
            // where a fixed 100 ms window would be meaningless.
            let started = Instant::now();
            assert!(verify_password("correct horse", &hash));
            let cost = started.elapsed();

            // Hold every permit individually so exactly one can be handed back
            // later.
            let mut permits = Vec::new();
            for _ in 0..MAX_CONCURRENT_KDF_OPERATIONS {
                permits.push(
                    kdf_semaphore()
                        .acquire()
                        .await
                        .expect("the gate is never closed"),
                );
            }

            // Occupy the one and only blocking thread.
            let (release, parked) = std::sync::mpsc::channel::<()>();
            let hog = tokio::task::spawn_blocking(move || {
                let _ = parked.recv();
            });
            // Let the hog actually take the thread before anything else asks
            // the pool for one.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut pending =
                tokio::spawn(async move { verify_password_async("correct horse", &hash).await });
            // Let it queue on the gate before a permit is handed back.
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Hand back exactly one permit. Tokio's semaphore is fair, so the
            // queued verification is the next to be served, and from here the
            // only thing that can still be holding it up is the saturated
            // blocking pool.
            drop(permits.pop());
            assert!(
                tokio::time::timeout(cost * 3, &mut pending).await.is_err(),
                "the verification finished within {:?} of a permit being free, while \
                 tokio's only blocking thread was still occupied: the KDF is not running \
                 on the blocking pool",
                cost * 3
            );

            drop(permits);
            drop(release);
            assert!(tokio::time::timeout(Duration::from_secs(60), pending)
                .await
                .expect("the verification must run once the blocking pool is free")
                .unwrap());
            hog.await.unwrap();
        });
    }

    /// Peak resident set size in KiB, from `/proc/self/status` (Linux only).
    fn peak_rss_kib() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    /// Not an assertion — a measurement, so it is `#[ignore]`d and never
    /// gates CI on a timing. Run it to re-derive the numbers the permit count
    /// in this module is chosen from:
    ///
    /// ```text
    /// cargo test --lib web::auth::tests::argon2_cost -- --ignored --nocapture
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "measurement, not an assertion"]
    async fn argon2_cost_is_measured() {
        let started = Instant::now();
        let hash = hash_password("correct horse").unwrap();
        let hash_cost = started.elapsed();

        let started = Instant::now();
        assert!(verify_password("correct horse", &hash));
        let verify_cost = started.elapsed();

        let before = peak_rss_kib();
        let started = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..(MAX_CONCURRENT_KDF_OPERATIONS * 2) {
            let hash = hash.clone();
            handles.push(tokio::spawn(async move {
                verify_password_async("correct horse", &hash).await
            }));
        }
        for handle in handles {
            assert!(handle.await.unwrap());
        }
        let batch_cost = started.elapsed();
        let after = peak_rss_kib();

        let batch = MAX_CONCURRENT_KDF_OPERATIONS * 2;
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        println!("profile                    : {profile}");
        println!("one Argon2 derivation      : {hash_cost:?}");
        println!("one Argon2 check (sync)    : {verify_cost:?}");
        println!("{batch} async checks, bounded : {batch_cost:?}");
        println!("permits                    : {MAX_CONCURRENT_KDF_OPERATIONS}");
        println!("peak RSS before -> after   : {before:?} -> {after:?} KiB");
    }
}
