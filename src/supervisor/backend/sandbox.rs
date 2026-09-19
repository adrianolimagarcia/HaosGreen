//! Bubblewrap sandbox for the supervisor's shell backend.
//!
//! One module owns the version floor, the argv and the job-directory
//! invariants, so the sandbox is described in exactly one place and the tests
//! exercise the same builder production uses.

use serde::{Deserialize, Serialize};
use std::ffi::{CString, OsStr};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;

/// Minimum safe bubblewrap version.
///
/// Below this, bubblewrap is affected by CVE-2026-87766 / GHSA-pxhw-h44j-8pfx:
/// during setup, before any sandboxed process starts, a symlink traversal
/// through `/oldroot` lets it create files and directories outside the sandbox,
/// on the host, with the launcher's privileges. 0.12.0 resolves paths with
/// `openat2()` and `RESOLVE_IN_ROOT`.
///
/// This is directly reachable for us: the one attacker-writable path in the
/// argv is the job's own sandbox directory, which a shell job can write to, so
/// a job can plant a symlink that the **next** job's setup walks.
pub const MIN_BWRAP: (u32, u32, u32) = (0, 12, 0);

/// Parse the version out of `bwrap --version` output.
///
/// Accepts `bubblewrap 0.12.0` and a bare `0.12.0`. Anything unparseable is an
/// error, never a pass: every path out of here that is not a complete
/// `major.minor.patch` returns `None`, so a caller cannot mistake "we could not
/// tell" for "new enough".
pub fn parse_version(output: &str) -> Option<(u32, u32, u32)> {
    let token = output
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // Tolerate a suffix such as `0.12.0-1` or `0.12.0.git`.
    let patch = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

pub fn version_is_supported(v: (u32, u32, u32)) -> bool {
    v >= MIN_BWRAP
}

/// How long `bwrap --version` may take before the probe gives up.
///
/// It answers a question about a version string, not work: a probe still silent
/// after this is a hung binary, and the supervisor's startup must not wait on it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the probe checks whether the child has exited.
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Longest capture kept, and longest text quoted back in an error message.
const MAX_PROBE_TEXT: usize = 512;

/// How many times a spawn the kernel refused with `ETXTBSY` is retried, and how
/// long the first wait is. The wait doubles, so the whole retry budget stays
/// well inside [`PROBE_TIMEOUT`].
const SPAWN_RETRIES: u32 = 8;
const SPAWN_RETRY_DELAY: Duration = Duration::from_millis(5);
const SPAWN_RETRY_MAX_DELAY: Duration = Duration::from_millis(50);

/// Spawn `<bin> --version`, waiting out a refusal the kernel reports as
/// `ETXTBSY`.
///
/// `ExecutableFileBusy` is not a real failure: it means the binary is open for
/// writing somewhere, which happens when a package manager replaces `bwrap` in
/// place, and when one test thread's fork inherits another's still-open write
/// descriptor. Both clear on their own within milliseconds, so the probe waits
/// them out rather than reporting an isolation failure the operator cannot act
/// on. A refusal that outlasts the retries is returned as an ordinary io error,
/// which the caller turns into [`IsolationUnavailable::VersionUnreadable`] —
/// never a pass. That error says how long was spent waiting, so a persistent
/// writer can be told apart from a one-off refusal.
fn spawn_bwrap(bin: &Path) -> std::io::Result<std::process::Child> {
    let mut delay = SPAWN_RETRY_DELAY;
    let mut waits = 0;
    let mut waited = Duration::ZERO;
    loop {
        let mut cmd = std::process::Command::new(bin);
        cmd.arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e)
                if e.kind() == std::io::ErrorKind::ExecutableFileBusy && waits < SPAWN_RETRIES =>
            {
                waits += 1;
                waited += delay;
                std::thread::sleep(delay);
                delay = (delay * 2).min(SPAWN_RETRY_MAX_DELAY);
            }
            Err(e) => {
                // An exhausted retry must be separable from a refusal that was
                // never retried, or a writer that never goes away reads exactly
                // like the transient failure this retry exists to remove.
                if waits == 0 {
                    return Err(e);
                }
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("{e} (after {waits} retries over ~{waited:?})"),
                ));
            }
        }
    }
}

/// Read a pipe to EOF, keeping only the first [`MAX_PROBE_TEXT`] bytes.
///
/// The pipe is drained to the end even after the cap is reached: a child that
/// blocks on a full pipe never exits, so a merely noisy binary would otherwise
/// be reported as a hang.
fn drain_capped(mut pipe: impl Read) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < MAX_PROBE_TEXT {
                    let take = n.min(MAX_PROBE_TEXT - kept.len());
                    kept.extend_from_slice(&buf[..take]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    kept
}

/// The async twin of [`drain_capped`], for the probe's own invocations.
///
/// Bounded for the same reason, and it matters more here: the version probe
/// reads a binary we chose, while this one runs an arbitrary command string
/// inside the sandbox. `wait_with_output` collects the whole stream into memory,
/// so it cannot be used — a sandboxed process that prints without end would grow
/// this process until it died, at startup, before the supervisor serves
/// anything.
///
/// Still drained to EOF after the cap is reached: stopping the read would block
/// the child on a full pipe and turn a merely noisy job into a reported hang.
/// [`MAX_PROBE_TEXT`] is comfortably above the largest transcript the probe asks
/// for — ten short fields, two of them the job path.
async fn drain_capped_async(pipe: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < MAX_PROBE_TEXT {
                    let take = n.min(MAX_PROBE_TEXT - kept.len());
                    kept.extend_from_slice(&buf[..take]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    kept
}

/// Collect a reader thread's capture, but never wait past `deadline`.
///
/// The child can exit while a grandchild it left behind still holds the write
/// end of the pipe, and a plain `join` would then block for as long as that
/// grandchild lives — the very hang the deadline exists to survive. An
/// abandoned capture comes back empty, which reads as `(no output)` and so
/// fails closed.
///
/// Abandoning it leaks that reader thread and its two pipe descriptors until
/// the grandchild exits and the pipe finally closes. That is deliberate: the
/// probe runs once at startup, the caller is never pinned, and no zombie is
/// left behind because the child itself is reaped before this is reached.
fn join_within(handle: std::thread::JoinHandle<Vec<u8>>, deadline: Instant) -> Vec<u8> {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Vec::new();
        }
        std::thread::sleep(PROBE_POLL_INTERVAL);
    }
    handle.join().unwrap_or_default()
}

/// Turn a probe's captured output into text that is safe to put in an error.
///
/// Capped, so an unparseable flood cannot become a 20 MB error string, and never
/// empty, so the message never degrades to a bare `cannot read ... version:`.
fn describe_output(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "(no output)".to_string();
    }
    if trimmed.len() <= MAX_PROBE_TEXT {
        return trimmed.to_string();
    }
    // Cut on a character boundary: the cap is a byte count, and splitting a
    // multi-byte character would be both invalid and useless to the operator.
    let mut end = MAX_PROBE_TEXT;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… (truncated)", &trimmed[..end])
}

/// How the child ended, for an error message: `3` for an exit code, or the
/// signal that killed it. `ExitStatus`'s own `Display` doubles the words up
/// ("exit status: 3"), which would read as `exited with exit status: 3`.
fn describe_status(status: std::process::ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| status.to_string(), |code| code.to_string())
}

/// Why isolation is unavailable. One variant per distinct cause, so the
/// operator sees *why* rather than "unavailable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationUnavailable {
    /// `bwrap` is not on `PATH`.
    NotInstalled,
    /// `bwrap --version` failed, or its output could not be parsed.
    VersionUnreadable(String),
    /// Installed, but older than [`MIN_BWRAP`]. Carries the version found.
    VersionTooOld((u32, u32, u32)),
    /// The smoke test failed. Carries the step that failed.
    SmokeTestFailed(String),
}

impl std::fmt::Display for IsolationUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "bubblewrap is not installed"),
            Self::VersionUnreadable(e) => write!(f, "cannot read the bubblewrap version: {e}"),
            Self::VersionTooOld((major, minor, patch)) => write!(
                f,
                "bubblewrap {major}.{minor}.{patch} is older than {}.{}.{}, which fixes \
                 CVE-2026-87766 (a symlink-traversal write outside the sandbox during setup)",
                MIN_BWRAP.0, MIN_BWRAP.1, MIN_BWRAP.2
            ),
            Self::SmokeTestFailed(step) => write!(f, "the sandbox smoke test failed: {step}"),
        }
    }
}

impl std::error::Error for IsolationUnavailable {}

/// What the shell backend may do, resolved **once** at startup.
///
/// This is the only reader of `[supervisor.shell].sandbox`. It is an enum and
/// not a `Result`, because "the boundary was proven" and "the operator chose to
/// have none" are different facts and only one of them is a failure. Collapsing
/// them into `Ok(())` is what would make `sandbox = "none"` still spawn `bwrap`
/// — and fail on a host without it, which is the host the mode exists for.
///
/// `PartialEq` is here for the tests that pin the precedence table; there is no
/// production comparison of two `Isolation` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Isolation {
    /// `sandbox = "bwrap"` and both the version floor and the smoke probe
    /// passed. Jobs run inside the argv `build_argv` produces.
    Sandboxed,
    /// `sandbox = "none"`: the operator's standing consent (spec §4). Nothing
    /// is gated — Layer 1 does not park the task and Layer 2 does not refuse it
    /// — and no `bwrap` is spawned.
    Unconfined,
    /// `sandbox = "bwrap"` and the boundary could not be proven. Refuse; never
    /// fall back to `sh -c`.
    Unavailable(IsolationUnavailable),
}

impl Default for Isolation {
    /// Fail closed. A backend built without an explicit decision must not spawn
    /// anything.
    fn default() -> Self {
        Isolation::Unavailable(IsolationUnavailable::NotInstalled)
    }
}

impl Isolation {
    /// Resolve the configured mode into the decision.
    ///
    /// `is_unconfined()` is an equality against the literal `"none"` (Task 4),
    /// so a value that is neither mode takes the **proving** branch here, never
    /// the consenting one. `ShellSandboxConfig::validate` has already refused
    /// such a value at load; this is the second, independent guarantee.
    ///
    /// The consenting branch is taken **before** the probe, and that order is
    /// load-bearing rather than an optimisation: the mode exists for a host
    /// with no usable bubblewrap, so probing first would spawn `bwrap` on
    /// exactly the host the mode is for and report a failure the operator has
    /// already consented to.
    pub async fn resolve(shell: &crate::config::ShellSandboxConfig, grants: &Grants) -> Self {
        if shell.is_unconfined() {
            return Isolation::Unconfined;
        }
        Self::from_boundary(prove_boundary(grants).await)
    }

    /// The probe outcome, as the mode. A function of its own so that every cell
    /// of the precedence table can be pinned on a host that passes — a host
    /// without a working bubblewrap cannot exercise the `Ok` arm through
    /// [`Self::resolve`], and a host with one cannot exercise the `Err` arm.
    ///
    /// The reason travels into the variant rather than being flattened: the
    /// operator acts on the difference between "not installed" and "older than
    /// the version that fixes the CVE".
    fn from_boundary(boundary: Result<(), IsolationUnavailable>) -> Self {
        match boundary {
            Ok(()) => Isolation::Sandboxed,
            Err(reason) => Isolation::Unavailable(reason),
        }
    }

    /// Does Layer 1 have to park a shell task for approval?
    ///
    /// Only when the boundary is **absent**. `Unconfined` is the operator's
    /// consent, so nothing is gated (spec §4) — and this is the whole of what
    /// Task 7 needs from this type, which is why it is a method here rather
    /// than a second read of the config key there.
    ///
    /// **Task 8 deletes this.** Once the gate carries a second term it `match`es
    /// on the mode directly, so this predicate would have no production caller
    /// left and would be a second representation of a decision that must have
    /// exactly one.
    pub fn needs_approval(&self) -> bool {
        matches!(self, Isolation::Unavailable(_))
    }
}

/// The version floor and the smoke probe, as **one** result.
///
/// This is `check_bwrap_version`'s only production caller: the floor is a
/// precondition and the probe is what asserts the boundary the argv claims, so
/// a binary that is installed but older than [`MIN_BWRAP`] refuses jobs here
/// rather than at the first spawn. Both failures are
/// [`IsolationUnavailable`], which is the same *kind* of outcome as "not
/// installed" — there is no "present but insecure, carry on" state.
async fn prove_boundary(grants: &Grants) -> Result<(), IsolationUnavailable> {
    check_bwrap_version()?;
    probe(grants).await
}

/// Locate `bwrap` on `PATH` and confirm it is a version we may rely on.
///
/// An older version is reported as [`IsolationUnavailable::VersionTooOld`] —
/// the same *kind* of outcome as "not installed", so there is no "present but
/// insecure, carry on" state anywhere in the code.
pub fn check_bwrap_version() -> Result<(), IsolationUnavailable> {
    check_bwrap_version_at(Path::new("bwrap"))
}

/// [`check_bwrap_version`] against an explicit binary, so callers and tests can
/// pin the path instead of relying on `PATH` lookup.
pub fn check_bwrap_version_at(bin: &Path) -> Result<(), IsolationUnavailable> {
    check_bwrap_version_at_within(bin, PROBE_TIMEOUT)
}

/// [`check_bwrap_version_at`] with the wait made explicit, so the deadline is
/// testable without a test that itself waits [`PROBE_TIMEOUT`].
fn check_bwrap_version_at_within(
    bin: &Path,
    timeout: Duration,
) -> Result<(), IsolationUnavailable> {
    let mut child = spawn_bwrap(bin).map_err(|e| match e.kind() {
        // Genuinely not there to be found, on `PATH` or at the given path.
        std::io::ErrorKind::NotFound => IsolationUnavailable::NotInstalled,
        // Present but unrunnable (EACCES, ENOEXEC, ...). Saying "not
        // installed" would send the operator after the wrong problem.
        _ => IsolationUnavailable::VersionUnreadable(format!("{}: {e}", bin.display())),
    })?;

    // Drain both pipes on their own threads. Reading them only once the child
    // has exited would deadlock the probe against any child that fills a pipe
    // buffer, because that child blocks on write and never exits.
    let out_reader = child
        .stdout
        .take()
        .map(|pipe| std::thread::spawn(move || drain_capped(pipe)));
    let err_reader = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || drain_capped(pipe)));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Fail closed, and do not leave the hung child behind.
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(PROBE_POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(IsolationUnavailable::VersionUnreadable(format!(
                    "{}: {e}",
                    bin.display()
                )));
            }
        }
    };

    let Some(status) = status else {
        return Err(IsolationUnavailable::VersionUnreadable(format!(
            "{} --version did not finish within {timeout:?}",
            bin.display()
        )));
    };

    // Bounded: a grandchild left holding a pipe open must not pin the probe.
    let stdout = out_reader
        .map(|h| join_within(h, deadline))
        .unwrap_or_default();
    let stderr = err_reader
        .map(|h| join_within(h, deadline))
        .unwrap_or_default();

    // A binary that reports a good version and *then* fails is not one we may
    // rely on, so the exit status is settled before the output is believed.
    if !status.success() {
        // Prefer stderr, but fall back to stdout: a binary that explains itself
        // on stdout and exits non-zero would otherwise read "(no output)".
        let detail = if stderr.iter().all(u8::is_ascii_whitespace) {
            describe_output(&stdout)
        } else {
            describe_output(&stderr)
        };
        return Err(IsolationUnavailable::VersionUnreadable(format!(
            "{} --version exited with {}: {detail}",
            bin.display(),
            describe_status(status)
        )));
    }

    let version = parse_version(&String::from_utf8_lossy(&stdout)).ok_or_else(|| {
        IsolationUnavailable::VersionUnreadable(format!(
            "unrecognised output: {}",
            describe_output(&stdout)
        ))
    })?;
    if !version_is_supported(version) {
        return Err(IsolationUnavailable::VersionTooOld(version));
    }
    Ok(())
}

/// What the sandbox is built from: the host paths a job may write, and whether
/// it may see the host's network namespace.
///
/// **Authorization is declared before the run, not discovered during it.**
/// bubblewrap builds its argv before the process starts, so a bind cannot be
/// added to a running sandbox: a job whose declaration is not covered is
/// refused, it is never run in a wider sandbox. One instance is shared behind
/// `Arc<RwLock<_>>` — the supervisor mutates it when the operator types
/// `/allow`, and every `ShellBackend` reads it when it builds an argv. The
/// mutating operations, the canonicalised matching and the audit rows are added
/// in Task 8; the fields are what the argv is built from, and the shipped
/// default is the empty set (spec §4).
///
/// `Serialize`/`Deserialize` are here because the declaration is carried by
/// `Task` and `Job`, which are serde types (`src/supervisor/task.rs`,
/// `src/supervisor/job.rs`). Neither carries one yet — Task 8 adds them, and
/// they are `#[serde(default)]` there so a stored task written before that reads
/// back as "declares nothing" rather than failing to load.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants {
    /// Host paths the job may mount read-write. Absolute, canonicalised.
    pub write: std::collections::BTreeSet<std::path::PathBuf>,
    /// Share the host network namespace.
    pub network: bool,
}

/// Append `--ro-bind <path> <path>` for `path`, if it exists under `root`.
///
/// `root` is `/` in production and a scratch tree in the tests, which is what
/// makes the "absent" branch testable: Debian/Ubuntu have no
/// `/etc/ca-certificates`, and an argv tuned to either layout must not break on
/// the other.
fn push_ro_bind_if_present(a: &mut Vec<String>, root: &Path, path: &str) {
    let src = root.join(path.trim_start_matches('/'));
    if src.exists() {
        a.extend([
            "--ro-bind".into(),
            src.to_string_lossy().into_owned(),
            path.into(),
        ]);
    }
}

/// A job's sandbox directory: where it is, and a descriptor for it.
///
/// The path is for naming the directory — logs, the workspace record, the
/// `--chdir` inside the sandbox. The descriptor is what the argv binds, because
/// bubblewrap re-resolves a path and cannot re-resolve a descriptor. Only
/// [`resolve_job_dir`] constructs one, so a path that has not been through the
/// checks cannot reach [`build_argv`].
///
/// Measured on bubblewrap 0.12.0, with `<root>/<task-id>` renamed away and a
/// symlink to a second directory left in its place **after** this value was
/// built:
///
/// ```text
/// path-based bind (symlink swapped in):  out='WRONG-TARGET'
/// fd-based bind  (descriptor held):      out='bound-by-inode'
/// ```
///
/// The path is re-resolved by a different process at a different time; the
/// descriptor names the inode this function checked.
///
/// `Debug` is derived because `unwrap_err()` on a `Result<JobDir, _>` needs it
/// — and because the path and the descriptor number are exactly what a reader
/// of a failing test wants to see.
#[derive(Debug)]
pub struct JobDir {
    path: PathBuf,
    fd: OwnedFd,
}

impl JobDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A duplicate of the descriptor with `FD_CLOEXEC` **cleared**, so the child
    /// inherits exactly this one. `try_clone` dups with `F_DUPFD_CLOEXEC`, so the
    /// duplicate is close-on-exec until this clears it; the original keeps the
    /// flag and is closed when `JobDir` drops. Bind the result to a name that
    /// outlives the `spawn` call — a dropped descriptor is a closed one.
    ///
    /// Clearing the flag on the duplicate and never on the original is the whole
    /// of this method. Cleared on the original, the descriptor would be inherited
    /// by **every** later `exec` in this process, including the probe's own
    /// `bwrap` invocations and every other job's child.
    pub fn inheritable_fd(&self) -> anyhow::Result<OwnedFd> {
        let dup = self.fd.try_clone()?;
        // SAFETY: `dup` is an open descriptor owned by `dup` for the call.
        if unsafe { libc::fcntl(dup.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
            anyhow::bail!(
                "cannot make the job directory inheritable: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(dup)
    }
}

/// The argv for a sandboxed run, **together with the descriptor it names**.
///
/// The two cannot be separated. `bwrap --bind-fd N` opens the descriptor when
/// it starts, so a caller that dropped the duplicate before `spawn` would hand
/// `bwrap` a number that is no longer open — and a bare `Vec<String>` is
/// exactly the shape that lets that happen. Holding the descriptor here means
/// the argv cannot exist without it, and dropping this value is the only way to
/// close it.
#[derive(Debug)]
pub struct SandboxArgv {
    argv: Vec<String>,
    /// Held for its `Drop`, never read: the descriptor must still be open when
    /// the child is spawned, and this value outlives that spawn.
    _job_fd: OwnedFd,
}

impl SandboxArgv {
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
}

/// Build the full bubblewrap argv. **Order is normative** — see the tests.
///
/// `job_dir` must already have passed [`resolve_job_dir`].
///
/// `grants` is what the operator holds **now**: each write grant adds a
/// read-write `--bind`, and the network grant adds `--share-net`. This is where
/// authorization becomes a bind — there is nowhere else it can happen.
///
/// The job directory itself is bound by **descriptor** (`--bind-fd`), not by
/// path, and the difference is measured rather than theoretical — see
/// [`JobDir`]. The path-based form re-resolves `<root>/<task-id>` when bubblewrap
/// runs, so a symlink swapped in after [`resolve_job_dir`] returned makes
/// bubblewrap mount a directory of the writer's choosing read-write as the job's
/// sandbox. `--bind-fd` mounts the inode the descriptor names.
///
/// The **grants** keep their `--bind`: a grant is a host path the operator
/// named, it is not what the job's own sandbox is built from, and it is already
/// refused when it covers the root (Task 8 Step 3b).
pub fn build_argv(job_dir: &JobDir, grants: &Grants, command: &str) -> anyhow::Result<SandboxArgv> {
    let dir = job_dir.path().to_string_lossy().to_string();
    // The duplicate the child inherits. Taken here, moved into the returned
    // value, and therefore open for as long as the argv it belongs to.
    let job_fd = job_dir.inheritable_fd()?;
    let mut a: Vec<String> = vec![
        "--unshare-all".into(),
        // Explicit: --unshare-all only does --unshare-user-try, which is
        // silently skipped when the user namespace cannot be created.
        "--unshare-user".into(),
        // Requires --unshare-user. Stops the sandbox creating further user
        // namespaces (sets user.max_user_namespaces=1).
        "--disable-userns".into(),
        // --disable-userns *asks*; this *verifies*, and fails the run if the
        // restriction did not take effect on this kernel.
        //
        // The probe cannot detect this flag's removal while `--disable-userns`
        // remains: with that flag present the observable behaviour is identical,
        // because this one verifies rather than acts. A mutation deleting this
        // line therefore survives the **probe** — the runtime check — though not
        // the static argv test, which does catch it. It is here for the failure
        // mode the probe cannot see: `--disable-userns` silently *not* taking
        // effect. Do not delete it on the strength of a green probe.
        "--assert-userns-disabled".into(),
        // Detach the controlling terminal, or TIOCSTI lets the job inject
        // input into the operator's terminal.
        "--new-session".into(),
        // Kill the whole tree, not just the direct child, when we die.
        "--die-with-parent".into(),
        // We already have a UTS namespace; leaking the host's hostname is a
        // free identity signal for no benefit.
        "--hostname".into(),
        "haos-sandbox".into(),
        // MUST precede every --setenv: reversed, it wipes them and HOME comes
        // back empty.
        "--clearenv".into(),
        "--setenv".into(),
        "HOME".into(),
        dir.clone(),
        "--setenv".into(),
        "PATH".into(),
        "/usr/bin:/bin".into(),
        "--ro-bind".into(),
        "/usr".into(),
        "/usr".into(),
        // On Arch, /bin and /lib are symlinks into /usr; without these the
        // loader is unreachable and execvp fails with ENOENT.
        "--symlink".into(),
        "usr/bin".into(),
        "/bin".into(),
        "--symlink".into(),
        "usr/lib".into(),
        "/lib".into(),
        "--symlink".into(),
        "usr/lib64".into(),
        "/lib64".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
    ];
    // The `/etc` files a job needs to resolve a name, and the two certificate
    // paths that keep HTTPS working. All read-only, all bound whenever they
    // exist: these are reads, and reads are never gated (spec §3).
    for f in [
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/hosts",
        // Load-bearing, measured: without these two, `curl https://example.com`
        // inside the sandbox fails with `curl: (77) error adding trust anchors
        // from file: /etc/ssl/certs/ca-certificates.crt`. Binding
        // `/etc/ssl/certs` ALONE still fails — on Arch/CachyOS the bundle is a
        // symlink to `../../ca-certificates/extracted/tls-ca-bundle.pem`, so
        // the directory holding the symlink is useless without its target. Both
        // together give HTTP 200 and `openssl s_client` → `Verify return code:
        // 0 (ok)`. Public CA certificates: read-only, no secrets.
        "/etc/ssl/certs",
        "/etc/ca-certificates",
    ] {
        push_ro_bind_if_present(&mut a, Path::new("/"), f);
    }
    // A write grant is the operator naming one host path. These come after the
    // read-only base because a later bind wins: granting a path inside the base
    // set is an explicit, separate decision (spec §3), never a side effect.
    for p in &grants.write {
        let p = p.to_string_lossy().to_string();
        a.extend(["--bind".into(), p.clone(), p]);
    }
    // The HOST network namespace, and only under a grant. Measured, `--share-net`
    // gives the sandbox `lo enp2s0 wlan0 tailscale0 virbr0 dnsstub`, with the
    // operator's own LLM gateway on 127.0.0.1:8790 reachable from inside — which
    // is why it is not a default and not a config key.
    if grants.network {
        a.push("--share-net".into());
    }
    a.extend([
        // The job directory, by descriptor. The **destination** stays a path,
        // and that is fine: it is created inside the sandbox namespace, by
        // bubblewrap, and is never resolved on the host.
        "--bind-fd".into(),
        job_fd.as_raw_fd().to_string(),
        dir.clone(),
        "--chdir".into(),
        dir,
        "/bin/sh".into(),
        "-c".into(),
        command.to_string(),
    ]);
    Ok(SandboxArgv {
        argv: a,
        _job_fd: job_fd,
    })
}

/// Bound on one probe invocation, in seconds.
///
/// A hang detector, not a performance assertion — the same reasoning as
/// `supervisor::bounded`. The probe runs at startup, so one wedged step would
/// hold the process before it ever serves a message. Both curl steps carry their
/// own `--connect-timeout 2 --max-time 3` (see [`HTTPS_SCRIPT`] and
/// [`loopback_script`]), so this bound is only ever reached by a wedge, never by
/// a slow network — a blackholed connection must be reported as a network
/// condition, not as a sandbox failure.
pub const PROBE_STEP_TIMEOUT_SECS: u64 = 10;

/// The canary the probe sets in its **own** environment. The sandbox must not
/// see it.
///
/// `--clearenv` is what removes it, and `$HOME`/`$PATH` cannot prove that.
/// Measured: removing `--clearenv` leaves a probe asserting only `$HOME`/`$PATH`
/// passing 7/7, because `--setenv` sets exactly those two variables. With the
/// canary present in the probe's environment, removing `--clearenv` leaks it
/// (`canary=[SEGREDO]`) and the probe fails.
pub const SMOKE_CANARY: &str = "HAOS_GREEN_SMOKE_CANARY";

/// The CA bundle `curl` reads, and the reason the two certificate binds exist.
///
/// Checked from inside the sandbox because `-r` follows symlinks: measured on
/// this host, binding `/etc/ssl/certs` **alone** leaves this path dangling
/// (`/etc/ssl/certs/ca-certificates.crt` → `../../ca-certificates/extracted/
/// tls-ca-bundle.pem`) and `[ -r ]` is false, which is exactly the state that
/// makes `curl https://example.com` fail with `(77) error adding trust anchors`.
pub const SMOKE_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

fn smoke(step: &str, detail: impl std::fmt::Display) -> IsolationUnavailable {
    IsolationUnavailable::SmokeTestFailed(format!("{step}: {detail}"))
}

/// Run the production argv against a scratch job directory and assert the
/// properties the boundary claims (spec §6). A failed assertion, a spawn failure
/// or a timeout is [`IsolationUnavailable::SmokeTestFailed`], carrying the step
/// that failed; a `bwrap` that cannot be executed at all is
/// [`IsolationUnavailable::NotInstalled`], the same variant the version probe
/// reports, so a missing package is never described as a broken sandbox.
///
/// Called once at startup; the result is cached by being stored in the
/// `ShellBackend` and the `Supervisor`.
pub async fn probe(grants: &Grants) -> Result<(), IsolationUnavailable> {
    // Not `tempfile`: it is a **dev**-dependency (`Cargo.toml:128`), so it is
    // not available here. A private directory under the system temp root is
    // enough, and it is removed on the way out.
    let scratch = std::env::temp_dir().join(format!(
        "haos-green-sandbox-probe-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = probe_at(Path::new("bwrap"), grants, &scratch).await;
    // Best effort: a leftover scratch directory is a nuisance, not a fault.
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

/// The probe against an explicit binary and scratch root, so its own plumbing
/// is testable without a real sandbox — the same seam as
/// [`check_bwrap_version_at`].
pub async fn probe_at(
    bwrap: &Path,
    grants: &Grants,
    scratch: &Path,
) -> Result<(), IsolationUnavailable> {
    // The probe's job directory goes through the **same** resolution a real job
    // does, descriptor included: the argv binds it by descriptor, so a probe
    // that built its own path would not be exercising the code production runs.
    let job_dir = resolve_job_dir(scratch, "probe-task", "probe-job")
        .map_err(|e| smoke("the scratch job directory", e))?;
    // The probe's own cwd, deliberately OUTSIDE the job directory — and pinned
    // to `/`, which is **present** inside the sandbox.
    //
    // This is not the plan's version, and the difference is measured. The plan
    // pinned an unbound scratch directory, on the reasoning that "bwrap inherits
    // the invoking process's cwd when `--chdir` is absent". That is only half the
    // rule, and it is the half that removes the check's teeth: bwrap(1) says HOME
    // "is used as the cwd in the sandbox if `--chdir` has not been explicitly
    // specified and the current cwd is **not present inside the sandbox**". The
    // argv sets HOME to the job directory and binds it, so pinning a directory
    // the sandbox cannot see makes bwrap fall back to the job directory — and the
    // `pwd` assertion below then passes with `--chdir` deleted. Verified by
    // mutation on bubblewrap 0.12.0: with the unbound scratch directory,
    // removing `--chdir` left the probe green.
    //
    // `/` is present inside the sandbox and is not the job directory, so bwrap
    // preserves it when `--chdir` is absent and the assertion fails.
    let probe_cwd = Path::new("/");

    // One invocation, one tagged line per property, so a failure names the
    // property rather than "the smoke test".
    let script = format!(
        "echo shell=ok; \
         echo home=$HOME; \
         echo path=$PATH; \
         echo pwd=$(pwd -P); \
         echo hostname=$(hostname); \
         echo canary=${{{SMOKE_CANARY}-unset}}; \
         if [ -r /etc/passwd ]; then echo passwd=readable; else echo passwd=unreadable; fi; \
         if [ -e /etc/shadow ]; then echo shadow=present; else echo shadow=absent; fi; \
         if [ -r {SMOKE_CA_BUNDLE} ]; then echo cabundle=readable; else echo cabundle=unreadable; fi; \
         if touch .smoke-write 2>/dev/null; then echo writable=yes; else echo writable=no; fi"
    );
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        &script,
        probe_cwd,
        "the base properties",
    )
    .await?;
    verdict_base(
        &out,
        &job_dir.path().to_string_lossy(),
        Path::new(SMOKE_CA_BUNDLE).exists(),
    )?;

    // `--disable-userns` asks; with `--assert-userns-disabled` this is what
    // proves the restriction took effect on this kernel.
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        NESTED_SCRIPT,
        probe_cwd,
        STEP_NESTED,
    )
    .await?;
    verdict_nested(&out)?;

    // This is the check the two certificate binds exist for. curl is in `/usr`,
    // which the base set binds; if it is not there the probe **fails**, naming
    // that, rather than skipping the check — a silently skipped check is the
    // failure mode this plan exists to avoid.
    //
    // It runs **only under a network grant**, and that is not a convenience.
    // `--share-net` is what puts the sandbox in the host's network namespace;
    // without it the sandbox has `lo` and nothing else, so DNS cannot leave and
    // curl fails with `(6) Could not resolve host` before TLS is ever reached.
    // Measured on this host: with the shipped default (empty) grant set, an
    // unconditional HTTPS check fails with exactly that, which would make
    // `probe()` refuse isolation for every operator who has not typed
    // `/allow-net` — while the sandbox itself is fine. The certificate binds are
    // therefore checked network-free by the `cabundle` field above, and
    // end-to-end here only when there is a network to reach.
    if grants.network {
        let out =
            run_in_sandbox(bwrap, &job_dir, grants, HTTPS_SCRIPT, probe_cwd, STEP_HTTPS).await?;
        verdict_https(&out)?;
    }

    // The network, asserted against the grant set **actually in force**, so both
    // states are covered rather than the default assumed. The probe holds a
    // listener in its own namespace and never accepts from it: the kernel
    // completes the handshake from the backlog, so "reachable" shows up as curl
    // waiting for a response rather than as a refused connection (exit 7).
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| smoke("the loopback check", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| smoke("the loopback check", e))?
        .port();
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        &loopback_script(port),
        probe_cwd,
        STEP_LOOPBACK,
    )
    .await?;
    let verdict = verdict_loopback(&out, grants);
    // The listener is still open here on purpose — dropping it would close the
    // port and make the "reachable" case fail. The `drop` is explicit so the
    // intent survives a later reordering of this function.
    drop(listener);
    verdict
}

/// The step names, shared by the invocation and the verdict, so the two cannot
/// drift: a spawn failure, a timeout and a failed assertion must name the same
/// property.
const STEP_NESTED: &str = "nested user namespaces are blocked";
const STEP_HTTPS: &str = "HTTPS works";
const STEP_LOOPBACK: &str = "the host network is reachable only under a grant";

/// The nested-user-namespace check, as one command.
const NESTED_SCRIPT: &str =
    "unshare --user true 2>/dev/null && echo nested=allowed || echo nested=blocked";

/// The HTTPS check, as one command.
///
/// `--connect-timeout` and `--max-time` are load-bearing: without them a
/// blackholed connection to `example.com` runs until the probe's own step
/// timeout, and is then reported as a sandbox failure rather than as the network
/// condition it is.
const HTTPS_SCRIPT: &str =
    "curl -fsS --connect-timeout 2 --max-time 3 -o /dev/null -w 'http=%{http_code}' \
     https://example.com";

/// The loopback check, as one command.
///
/// `command -v curl` is not decoration. The `echo exit=$?` runs whatever `curl`
/// does, so on a host without `/usr/bin/curl` the transcript reads `exit=127` —
/// a code the verdict must not read as "reachable" (see [`loopback_reachable`]).
/// Proving curl is there lets the verdict name a missing binary instead of
/// guessing from a number.
fn loopback_script(port: u16) -> String {
    format!(
        "if command -v curl >/dev/null 2>&1; then \
         curl -sS --connect-timeout 2 --max-time 3 -o /dev/null http://127.0.0.1:{port}/ ; \
         echo exit=$?; else echo curl=missing; fi"
    )
}

/// What bubblewrap said, when it said it somewhere other than stdout.
///
/// bubblewrap reports a failed setup on **stderr** and exits non-zero with
/// nothing on stdout — `bwrap: Can't find source path ...`, and the single most
/// common failure on a fresh host, `bwrap: No permissions to creating new
/// namespace`. An assertion that reads only stdout reports `expected shell=ok,
/// got None` and throws away the one line that names the cause. Empty when the
/// invocation succeeded and said nothing, so a genuine assertion mismatch is not
/// padded with noise.
fn bwrap_cause(out: &std::process::Output) -> String {
    if out.status.success() && out.stderr.iter().all(u8::is_ascii_whitespace) {
        return String::new();
    }
    format!(
        "; bubblewrap {} and said {}",
        describe_status(out.status),
        describe_output(&out.stderr)
    )
}

/// The verdict on the base-properties transcript.
///
/// Split out of [`probe_at`] so every branch is reachable from a unit test. A
/// check that can only be reached by a successful sandbox invocation is a check
/// that cannot be tested without one — which is how a fail-open default survives
/// review.
fn verdict_base(
    out: &std::process::Output,
    home: &str,
    cabundle_required: bool,
) -> Result<(), IsolationUnavailable> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let field = |k: &str| -> Option<String> {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .map(str::to_string)
    };
    let cause = bwrap_cause(out);
    // A capture that reached the cap may have been cut before the field being
    // looked for, which would otherwise read as "the shell never printed it".
    // The transcript is ~300 bytes against a 512-byte cap, so this should never
    // fire — but a surprise here has to be diagnosable rather than confusing.
    let capped = if out.stdout.len() >= MAX_PROBE_TEXT {
        "; the capture hit the {MAX_PROBE_TEXT}-byte cap, so the transcript may be incomplete"
    } else {
        ""
    };
    let expect = |k: &str, want: &str, what: &str| -> Result<(), IsolationUnavailable> {
        match field(k).as_deref() {
            Some(v) if v == want => Ok(()),
            other => Err(smoke(
                what,
                format!("expected {k}={want}, got {other:?}{cause}{capped}"),
            )),
        }
    };

    expect("shell", "ok", "the shell starts")?;
    expect("home", home, "$HOME is the job directory")?;
    expect("path", "/usr/bin:/bin", "$PATH is the set value")?;
    // NOT `$HOME`/`$PATH`: `--setenv` sets exactly those two, so measured, a
    // probe asserting them passes with `--clearenv` removed. The canary is what
    // has teeth.
    expect(
        "canary",
        "unset",
        "the inherited canary is absent (--clearenv ran)",
    )?;
    expect(
        "pwd",
        home,
        "the cwd is the job directory (--chdir took effect)",
    )?;
    expect("hostname", "haos-sandbox", "the hostname is haos-sandbox")?;
    expect("passwd", "unreadable", "/etc/passwd is unreadable")?;
    expect("shadow", "absent", "/etc/shadow is absent")?;
    // `cabundle_required` is the caller's `Path::new(SMOKE_CA_BUNDLE).exists()`
    // — the same rule the argv binds with (`push_ro_bind_if_present`), so a
    // certificate path the host does not have is skipped, never demanded. It is
    // a parameter rather than a lookup in here so that **both** branches are
    // testable on a host that does have the bundle.
    if cabundle_required {
        expect(
            "cabundle",
            "readable",
            "the CA bundle is readable inside the sandbox",
        )?;
    }
    expect("writable", "yes", "the job directory is writable")?;
    Ok(())
}

/// The verdict on the nested-user-namespace transcript.
fn verdict_nested(out: &std::process::Output) -> Result<(), IsolationUnavailable> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.contains("nested=blocked") {
        return Ok(());
    }
    if stdout.contains("nested=allowed") {
        return Err(smoke(
            STEP_NESTED,
            "`unshare --user` succeeded inside the sandbox",
        ));
    }
    // Neither line: the check did not run. Saying "`unshare --user` succeeded"
    // here would name the wrong cause — bwrap failing to start looks the same.
    Err(smoke(
        STEP_NESTED,
        format!("the check did not run{}", bwrap_cause(out)),
    ))
}

/// The verdict on the HTTPS transcript.
fn verdict_https(out: &std::process::Output) -> Result<(), IsolationUnavailable> {
    let body = String::from_utf8_lossy(&out.stdout);
    if body.contains("http=2") {
        return Ok(());
    }
    if !body.contains("http=") {
        // No marker at all: curl never ran, so nothing here is about the
        // certificate binds.
        return Err(smoke(
            STEP_HTTPS,
            format!("curl did not run{}", bwrap_cause(out)),
        ));
    }
    Err(smoke(
        STEP_HTTPS,
        format!(
            "curl exited {:?} with {body:?} / {}; a `(77) error adding trust anchors` \
             means the /etc/ssl/certs and /etc/ca-certificates binds are missing or \
             unresolvable",
            out.status.code(),
            describe_output(&out.stderr)
        ),
    ))
}

/// Whether the host's loopback was reachable from inside the sandbox.
///
/// The marker is required **before** it is interpreted. Reading "not 7" as
/// reachable makes every other outcome reachable too, and the outcomes are not
/// hypothetical:
///
/// - an **empty capture** (bwrap failed to set up) read as reachable, so under a
///   network grant a broken sandbox passed the one check whose job is to notice
///   reachability — a latent fail-open;
/// - `exit=127` read as reachable, because `sh` runs the `echo exit=$?` after a
///   missing `curl`. Under the shipped empty grant set that produced
///   `the host network is unreachable without a grant`, refusing shell jobs on a
///   **correct** sandbox and sending the operator to `/allow-net` for what is a
///   missing binary.
///
/// So only curl's own outcomes are interpreted, and anything else fails closed
/// with the code it saw.
fn loopback_reachable(stdout: &str) -> Result<bool, String> {
    if stdout.contains("curl=missing") {
        return Err("curl is not available inside the sandbox".to_string());
    }
    let Some(code) = stdout.lines().find_map(|l| l.strip_prefix("exit=")) else {
        return Err("curl did not run".to_string());
    };
    match code.trim() {
        // Could not connect: the sandbox has no route to the host's loopback.
        "7" => Ok(false),
        // Connected, then waited for a response that never comes (28), or got
        // one (0). Either way the host's listener was reachable.
        //
        // 28 is ambiguous — curl returns it for "connected, then the response
        // timed out" and for "the connect itself timed out" — so a loopback that
        // is DROPped rather than refused also reads here as reachable. Kept
        // deliberately. Measured on this host: refused → `exit=7`; a
        // bound-but-never-accepting listener → `exit=28`; a blackholed address →
        // `exit=28`. The two 28s are separable by curl's `%{num_connects}`
        // (1 vs 0), and that is the discriminator to reach for if this ever
        // matters. It does not, because without `--share-net` the sandbox is in
        // its own netns with `lo` and nothing listening — a DROP rule on the
        // host cannot reach into that netns — so it always gets 7. The ambiguous
        // 28 therefore only arises when `--share-net` *is* in effect, which is
        // exactly what the "reachable under a grant" check exists to confirm.
        // The tighter rule would trade that benign miss for a risk of reading a
        // real connection as unreachable, which is the I1 failure mode: refusing
        // shell jobs on a working sandbox.
        "0" | "28" => Ok(true),
        other => Err(format!(
            "cannot tell whether the host network is reachable: curl exited {other}"
        )),
    }
}

/// The verdict on the loopback transcript, against the grant set in force.
fn verdict_loopback(
    out: &std::process::Output,
    grants: &Grants,
) -> Result<(), IsolationUnavailable> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let reachable = match loopback_reachable(&stdout) {
        Ok(reachable) => reachable,
        Err(detail) => {
            return Err(smoke(
                STEP_LOOPBACK,
                format!("{detail}{}", bwrap_cause(out)),
            ))
        }
    };
    match (grants.network, reachable) {
        (true, false) => Err(smoke(
            "the host network is reachable under a grant",
            "the network grant is held but 127.0.0.1 is unreachable: --share-net did not \
             take effect",
        )),
        (false, true) => Err(smoke(
            "the host network is unreachable without a grant",
            "no network grant is held but 127.0.0.1 is reachable",
        )),
        _ => Ok(()),
    }
}

/// Run the production argv in the sandbox, bounded. `step` names what the
/// invocation was for, so a spawn failure or a timeout is reported the same way
/// an assertion failure is.
async fn run_in_sandbox(
    bwrap: &Path,
    job_dir: &JobDir,
    grants: &Grants,
    command: &str,
    cwd: &Path,
    step: &str,
) -> Result<std::process::Output, IsolationUnavailable> {
    // `built` owns the descriptor the argv names, and it is alive here past the
    // `spawn` below — which is the whole reason it is one value rather than a
    // list of strings.
    let built = build_argv(job_dir, grants, command).map_err(|e| smoke(step, e))?;
    let mut cmd = tokio::process::Command::new(bwrap);
    cmd.args(built.argv())
        // The probe's own cwd: `--chdir` is what puts the sandbox in the job
        // directory, and inheriting this one is exactly the silent pass the
        // cwd check exists to catch.
        .current_dir(cwd)
        // The canary goes into the probe's own environment, which is what makes
        // the "absent inside" assertion meaningful.
        .env(SMOKE_CANARY, "SEGREDO")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| match e.kind() {
        // The same outcome the version probe reports, so `probe()` called on its
        // own does not describe a missing binary as a smoke-test failure.
        std::io::ErrorKind::NotFound => IsolationUnavailable::NotInstalled,
        _ => smoke(step, format!("cannot run {}: {e}", bwrap.display())),
    })?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| smoke(step, "the sandbox has no stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| smoke(step, "the sandbox has no stderr pipe"))?;

    let bound = std::time::Duration::from_secs(PROBE_STEP_TIMEOUT_SECS);
    // `async move` so the child is owned by the future: on a timeout the future
    // is dropped, which drops the child, which is what `kill_on_drop` acts on.
    // Borrowing it here instead would leave a wedged sandbox running.
    let run = async move {
        // Both pipes are read while the child runs, and concurrently: a child
        // that fills the pipe we are not reading blocks forever.
        let (stdout, stderr, status) = tokio::join!(
            drain_capped_async(&mut stdout),
            drain_capped_async(&mut stderr),
            child.wait(),
        );
        (stdout, stderr, status)
    };
    match tokio::time::timeout(bound, run).await {
        Ok((stdout, stderr, Ok(status))) => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        Ok((_, _, Err(e))) => Err(smoke(step, e)),
        Err(_) => Err(smoke(
            step,
            format!("did not finish within {PROBE_STEP_TIMEOUT_SECS}s"),
        )),
    }
}

/// Refuse an id that does not normalise to exactly one ordinary path component,
/// and return that component.
///
/// `task_id` and `job_id` are joined onto the root, and `Path::join` lets an
/// absolute argument replace the whole path while `..` walks out of it. Either
/// would put the job directory outside the root — and a refusal that arrives
/// *after* the directory has been created is not containment, so this runs
/// before the first filesystem call, including the one that creates the root.
///
/// `Path::components()` normalises a trailing `/` and `/.` away, so `"a/"` and
/// `"a/."` are the aliases of `"a"` that they are. What the caller joins is the
/// **normalised** component, never the raw string: that keeps
/// `<root>/<task-id>/<job-id>` literally true with no separator left in either
/// id, and it matters beyond tidiness — the path form `"<root>/task-1/job-1/."`
/// is not the same path to `create_dir_all`, which fails on it with `No such
/// file or directory` when `task-1` does not exist yet.
///
/// A control character is refused outright. An id is a UUID in practice, and a
/// newline in one is only ever an attempt to forge a line in a log or an error
/// message; refusing it here closes that at the source, and the escaping in the
/// messages below is the second line of defence rather than the only one.
fn one_component<'a>(id: &'a str, what: &str) -> anyhow::Result<&'a OsStr> {
    if id.chars().any(char::is_control) {
        anyhow::bail!("the {what} {id:?} contains a control character");
    }
    let mut parts = Path::new(id).components();
    match (parts.next(), parts.next()) {
        (Some(std::path::Component::Normal(name)), None) => Ok(name),
        _ => anyhow::bail!("the {what} {id:?} is not a single path component"),
    }
}

/// Which containment clause refused a resolved path.
///
/// A value, not only prose, because the three clauses are not interchangeable:
/// a test that matches on the message cannot tell "this is outside the root"
/// from "this is not what the path names", and a future relaxation of one clause
/// would then look like containment still working. `containment_is_decided_by_
/// path_components_not_by_text` asserts the clause.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// The path resolved to the root itself, which is not below the root.
    IsTheRoot,
    /// The path resolved outside the root.
    OutsideRoot,
    /// The path resolved to something other than what it names — a symlink.
    NotItself,
}

impl Refusal {
    /// The operator-facing wording. Every path in it is `{:?}`: `dir` is built
    /// from caller-supplied ids and `root` from operator config, and
    /// `Path::display()` does not escape control characters.
    fn message(&self, root: &Path, dir: &Path, real: &Path) -> anyhow::Error {
        match self {
            Self::IsTheRoot => anyhow::anyhow!(
                "the sandbox path {real:?} is the sandbox root itself, not below it"
            ),
            Self::OutsideRoot => anyhow::anyhow!(
                "the sandbox path {real:?} resolved outside the sandbox root {root:?}"
            ),
            Self::NotItself => anyhow::anyhow!(
                "the sandbox path {dir:?} resolves to {real:?} rather than to itself; \
                 a symlink here would let two jobs share one sandbox"
            ),
        }
    }
}

/// The refusal for a level that resolved to `real`, or `None` when `real` is an
/// acceptable resolution of `dir`: strictly below `root`, and `dir` itself.
///
/// One function rather than a check at each site, so that a mutation removing a
/// clause is not masked by the same clause surviving in a second copy. Three
/// distinct refusals, because one message for all of them reads wrong: a path
/// that *is* the root, reported as "outside" it, sends a reader looking for a
/// traversal that never happened.
///
/// Containment is `Path::starts_with`, which compares **components**. Comparing
/// the two paths as strings passes every test here except the sibling one:
/// `/…/ws-evil` starts with `/…/ws` as text and is outside it as a path.
fn containment_refusal(root: &Path, dir: &Path, real: &Path) -> Option<Refusal> {
    if real == root {
        return Some(Refusal::IsTheRoot);
    }
    if !real.starts_with(root) {
        return Some(Refusal::OutsideRoot);
    }
    // An in-root symlink passes both checks above — it resolves to a directory
    // inside the root — and still breaks the layout the spec makes normative:
    // two ids symlinked to one directory would share a sandbox, which is what
    // per-job directories exist to prevent. The ids arrive here normalised to
    // one component each, so `dir` is exactly `<root>/<task-id>` or
    // `<task-id>/<job-id>` lexically, and a path that does not canonicalise to
    // itself has a symlink at its last level.
    if real != dir {
        return Some(Refusal::NotItself);
    }
    None
}

/// Why `dir` is not a directory that can be used, given that opening it as one
/// without following a symlink failed.
fn not_a_directory(root: &Path, dir: &Path, err: std::io::Error) -> anyhow::Error {
    // A symlink is the interesting case, so name where it points, and give the
    // containment wording when containment is the reason it is refused.
    if let Ok(real) = std::fs::canonicalize(dir) {
        if let Some(refusal) = containment_refusal(root, dir, &real) {
            return refusal.message(root, dir, &real);
        }
        // Only claim "not a directory" when that is what the kernel said. `EMFILE`
        // or a umask that leaves the level created but unopenable says nothing
        // about the entry's type — and the level exists by then, because
        // `mkdirat` already succeeded, so "is not a directory" would send a
        // reader looking for the wrong thing entirely.
        if err.raw_os_error() == Some(libc::ENOTDIR) {
            return anyhow::anyhow!("the sandbox path {dir:?} is not a directory");
        }
    }
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            anyhow::anyhow!("the sandbox path {dir:?} is a symlink to a target that does not exist")
        }
        _ => anyhow::anyhow!("cannot open {dir:?} as a directory: {err}"),
    }
}

/// Why the configured root cannot be used, given that creating or opening it
/// failed. `File exists (os error 17)` is what the raw error says for a root
/// that is a regular file, a root that is a dangling symlink, and a symlink at
/// either level — none of which is what "file exists" leads a reader to.
/// `verb` is "create" or "open", so the fallback names the call that failed
/// rather than guessing.
fn root_not_usable(root: &Path, verb: &str, err: std::io::Error) -> anyhow::Error {
    match std::fs::symlink_metadata(root) {
        Ok(m) if m.file_type().is_symlink() => anyhow::anyhow!(
            "the sandbox root {root:?} is a symlink to a target that does not exist"
        ),
        Ok(m) if !m.is_dir() => {
            anyhow::anyhow!("the sandbox root {root:?} is not a directory")
        }
        _ => anyhow::anyhow!("cannot {verb} the sandbox root {root:?}: {err}"),
    }
}

/// Open `path` as a directory, without following a symlink at the last
/// component.
///
/// `O_PATH`, not `O_RDONLY`: nothing here reads the directory's contents, only
/// `mkdirat` and `openat` relative to it, and `O_PATH` needs no permission on
/// the directory itself — only traversal of its parents. A root that is writable
/// and traversable but not readable (mode 0333) is therefore usable, where a
/// read-only open refused it with `Permission denied`. Verified: an `O_PATH`
/// descriptor is a valid `dirfd` for both calls, and `O_DIRECTORY` still refuses
/// a FIFO instead of blocking on it.
fn open_dir(path: &Path) -> anyhow::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("the path {path:?} contains a NUL byte"))?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call, and
    // the descriptor is immediately owned by `OwnedFd`, which closes it on drop.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(root_not_usable(
            path,
            "open",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor from `open`, checked non-negative.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `mkdirat(parent, name)`, treating an existing entry as success.
fn mkdir_in(parent: &OwnedFd, name: &OsStr, dir: &Path) -> anyhow::Result<()> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| anyhow::anyhow!("the name {name:?} contains a NUL byte"))?;
    // SAFETY: `parent` is an open directory descriptor and `c` is a valid
    // NUL-terminated string; `mkdirat` neither retains nor frees either.
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o777) };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(anyhow::anyhow!("cannot create {dir:?}: {e}"))
}

/// `openat(parent, name)` as a directory, refusing a symlink at this level.
///
/// `O_PATH` for the same reason as [`open_dir`], and it matters just as much
/// here: `mkdirat` creates the level with `0o777 & !umask`, so a umask that
/// strips the read bit produces a level this process may not read and may still
/// write — and the next `mkdirat` needs write and traversal, not read.
fn open_dir_in(parent: &OwnedFd, name: &OsStr) -> std::io::Result<OwnedFd> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: as in `open_dir`.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor from `openat`, checked non-negative.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Create `name` inside `parent` — a directory already verified — and return the
/// canonical path together with a descriptor for the new level.
///
/// Creation is relative to the descriptor rather than to a path, and that is
/// the whole point: a symlink swapped in at this level *after* the level above
/// was verified cannot redirect the creation, because `mkdirat` creates inside
/// the directory the descriptor names or fails. A path-based `create_dir_all`
/// re-traverses from the root and does follow the swap, which is how a writer
/// looping on that swap got a directory created outside the root. The descriptor
/// is opened with `O_NOFOLLOW`, so a symlink already in place is refused with
/// nothing written through it — and that flag is load-bearing for the race as
/// well, not just for a symlink that is already there: without it, a symlink
/// swapped in just before the open becomes the parent descriptor for the level
/// below, and the level below is then created on the other side of it.
///
/// Every message uses `{:?}` rather than `display()`: the path is built from
/// caller-supplied ids and an operator-supplied root, and `Path::display()` does
/// not escape control characters.
fn create_within(
    parent: &OwnedFd,
    root: &Path,
    dir: &Path,
    name: &OsStr,
) -> anyhow::Result<(PathBuf, OwnedFd)> {
    mkdir_in(parent, name, dir)?;
    let child = match open_dir_in(parent, name) {
        Ok(fd) => fd,
        Err(e) => return Err(not_a_directory(root, dir, e)),
    };
    let real = std::fs::canonicalize(dir)
        .map_err(|e| anyhow::anyhow!("cannot canonicalise {dir:?}: {e}"))?;
    match containment_refusal(root, dir, &real) {
        Some(refusal) => Err(refusal.message(root, dir, &real)),
        None => Ok((real, child)),
    }
}

/// The files this application creates in its own home directory. A root that
/// directly holds one of them is the home directory, one level too high.
///
/// Deliberately not `config.toml`: a project workspace holding a `config.toml`
/// is ordinary — a Rust or Python project has one — and refusing every shell job
/// in such a workspace, as a *security* refusal, is a control that can only
/// break the feature. These two names are created by this application and are
/// not names project content uses.
const HOME_MARKERS: [&str; 2] = ["haos-green.db", "web-auth.toml"];

/// Resolve and validate the per-job sandbox directory.
///
/// This directory is the **only** read-write bind in the argv that is derived
/// from the sandbox root — write grants add binds of their own, but they are
/// operator-named and independent of it — which makes this the critical part of
/// the boundary. Every check below is a hard error.
///
/// The returned path is canonical, is a strict descendant of `root` — never
/// equal to it — and is exactly `<root>/<task-id>/<job-id>`, so a job can never
/// write at the root itself and two ids can never share one directory. The
/// descriptor that travels with it names that same directory, and it is what
/// the argv binds: see [`JobDir`].
///
/// Order matters as much as the checks do. The ids are validated before any
/// filesystem call; each level is created relative to the descriptor of the
/// level above it, opened without following a symlink, and canonicalised and
/// checked before the level below it is attempted. So against a filesystem that
/// is not being modified underneath the call, a path that is going to be refused
/// is refused before anything is created — outside the root, or through a
/// symlink. A refusal that arrives after the directory exists is an apology, not
/// containment.
///
/// **Residual, measured.** A concurrent writer that can replace
/// `<root>/<task-id>` after this function has verified it can still make the
/// *returned* path resolve elsewhere, and this function will refuse it; what it
/// can no longer do is make this function create a directory at a path of its
/// choosing outside the root, because the creation is `mkdirat` on a descriptor
/// rather than a path (measured before that change: 1472 of 8246 refusals over
/// 15 s of swapping had created `elsewhere/job-1`, first hit after 4 refusals).
/// The two cases left are both harmless:
///
/// - the writer *moves* the verified directory outside the root, and the level
///   below is then created inside it. That directory is one the writer could
///   already write to — moving it requires write access to both ends — so no
///   privilege is gained, and the containment check still refuses the result;
/// - the writer swaps a level after this returns. The path it returns then
///   resolves elsewhere, but the path is not what gets mounted: [`build_argv`]
///   binds the descriptor this value carries, so the sandbox is still the
///   directory this function checked. (Measured on bubblewrap 0.12.0: with the
///   swap in place, `--bind <path>` mounted the symlink's target while
///   `--bind-fd <fd>` mounted the original inode.)
///
/// Both need a local writer with write access to the sandbox root. That is not
/// free: `/allow <root>` is grantable, and the default root is the same
/// directory the chat agent's shell tool uses as its working directory, so the
/// precondition is recorded in the spec — **no write grant may cover the sandbox
/// root** — rather than assumed here.
pub fn resolve_job_dir(root: &Path, task_id: &str, job_id: &str) -> anyhow::Result<JobDir> {
    let task_id = one_component(task_id, "task id")?;
    let job_id = one_component(job_id, "job id")?;

    if !root.is_absolute() {
        anyhow::bail!("sandbox root {root:?} is not absolute");
    }
    std::fs::create_dir_all(root).map_err(|e| root_not_usable(root, "create", e))?;
    let root = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!("cannot canonicalise {root:?}: {e}"))?;
    if root == Path::new("/") {
        anyhow::bail!("the sandbox root must not be /");
    }
    // A root that directly holds one of the home markers is the "one level too
    // high" misconfiguration: the home layout puts the workspace beside them, so
    // pointing the root at `<home>` itself is a realistic mistake. It is not by
    // itself an exposure — the only read-write bind derived from the sandbox
    // root is the job directory, and a write grant would have to name the file
    // explicitly — so this is defence in depth against a root that is one level
    // too high, refused rather than tolerated.
    if let Some(marker) = HOME_MARKERS.iter().find(|m| root.join(m).exists()) {
        anyhow::bail!(
            "the sandbox root {root:?} holds {marker}; that looks like the HaosGreen home \
             directory, not a sandbox root. Point it at a dedicated directory such as \
             <home>/workspace"
        );
    }
    let root_fd = open_dir(&root)?;
    let (task_dir, task_fd) = create_within(&root_fd, &root, &root.join(task_id), task_id)?;
    let (job_dir, job_fd) = create_within(&task_fd, &root, &task_dir.join(job_id), job_id)?;
    // The job level's descriptor is the one that matters and the one this value
    // carries: it is what `--bind-fd` binds. The root and task descriptors are
    // dropped here, and they are `O_CLOEXEC` besides, so neither can reach a
    // child.
    Ok(JobDir {
        path: job_dir,
        fd: job_fd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A fake `bwrap` in a fresh temporary directory that reports a version we
    /// choose. This is what makes the version floor testable without a
    /// vulnerable bubblewrap installed.
    ///
    /// The [`tempfile::TempDir`] is returned alongside the path because it owns
    /// the directory: dropping it deletes the stub. The caller must bind it for
    /// as long as the path is used.
    fn stub_bwrap_reporting(version_line: &str) -> (tempfile::TempDir, PathBuf) {
        stub_bwrap_running(&format!("echo '{version_line}'\nexit 0"))
    }

    /// A fake `bwrap` whose whole body we choose, for probes that must fail in a
    /// particular way: a bad exit status, a hang, a flood of output.
    fn stub_bwrap_running(body: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bwrap");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    /// Serializes the tests that install a stub `bwrap` on `PATH`.
    ///
    /// `PATH` is process-global and libtest runs these tests on many threads, so
    /// without this one test's stub could answer another test's `bwrap` lookup.
    /// Only [`PathOnly`] takes it, and the rule it enforces is worth stating:
    /// **no test may assert a *successful* probe through `PATH`**. Every other
    /// test in this module either names its binary explicitly
    /// (`check_bwrap_version_at`, `probe_at`) or asserts only that the mode is
    /// not `Unconfined`, which holds whichever binary answers.
    static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `PATH` with one directory **prepended**, with [`PATH_LOCK`] held, restored
    /// on drop — including when the test panics, or one failing test would leave
    /// every later `bwrap` lookup in this binary pointing at a stub.
    struct PathOnly {
        saved: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl PathOnly {
        fn new(dir: &Path) -> Self {
            // A poisoned lock means another test panicked while holding it; the
            // guard is still what serializes this, so take it back rather than
            // cascading the failure.
            let lock = PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let saved = std::env::var_os("PATH");
            // Prepended, **not** substituted, and the difference is measured:
            // every other stub in this module is a shell script that calls the
            // real `sleep`, `head` and `tr`, and a `PATH` of just the stub
            // directory hides all three from them. A mutation round that
            // replaced `PATH` wholesale failed eight of eleven mutants on tests
            // that had nothing to do with the mutation —
            // `a_hung_probe_is_refused_instead_of_waited_on` with
            // `exec: sleep: não encontrado`. Prepending still wins the `bwrap`
            // lookup, because `PATH` is searched left to right.
            let mut path = std::ffi::OsString::from(dir);
            if let Some(existing) = &saved {
                path.push(":");
                path.push(existing);
            }
            std::env::set_var("PATH", path);
            Self { saved, _lock: lock }
        }
    }

    impl Drop for PathOnly {
        fn drop(&mut self) {
            match self.saved.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    #[test]
    fn parses_the_shipped_version_string() {
        assert_eq!(parse_version("bubblewrap 0.12.0"), Some((0, 12, 0)));
    }

    #[test]
    fn parses_a_bare_version() {
        assert_eq!(parse_version("0.12.0"), Some((0, 12, 0)));
    }

    #[test]
    fn parses_a_distro_suffix() {
        assert_eq!(parse_version("bubblewrap 0.12.0-1"), Some((0, 12, 0)));
    }

    #[test]
    fn rejects_unparseable_output() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("command not found"), None);
        // A truncated version is not a version: if `0.12` were padded to
        // `0.12.0`, an incomplete string would satisfy the floor.
        assert_eq!(parse_version("bubblewrap 0.12"), None);
        // A non-numeric component must not be silently read as 0.
        assert_eq!(parse_version("bubblewrap 0.12.xyz"), None);
    }

    #[test]
    fn the_floor_is_exactly_0_12_0() {
        assert!(version_is_supported((0, 12, 0)));
        assert!(version_is_supported((0, 13, 0)));
        assert!(version_is_supported((1, 0, 0)));
        assert!(!version_is_supported((0, 11, 9)));
        assert!(!version_is_supported((0, 9, 0)));
    }

    #[test]
    fn a_vulnerable_version_is_refused_as_unavailable() {
        // Two different versions, so the variant has to carry the version it
        // actually found: no single constant at the construction site can
        // satisfy both.
        for (line, expected) in [
            ("bubblewrap 0.11.9", (0, 11, 9)),
            ("bubblewrap 0.7.3", (0, 7, 3)),
        ] {
            let (_dir, bin) = stub_bwrap_reporting(line);
            match check_bwrap_version_at(&bin) {
                Err(IsolationUnavailable::VersionTooOld(v)) => {
                    assert_eq!(v, expected, "wrong version carried for {line:?}");
                }
                other => panic!("{line} must be refused as VersionTooOld, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_supported_version_passes_the_check() {
        let (_dir, bin) = stub_bwrap_reporting("bubblewrap 0.12.0");
        let r = check_bwrap_version_at(&bin);
        assert!(r.is_ok(), "0.12.0 must pass, got {r:?}");
    }

    // --- the startup decision (`[supervisor.shell].sandbox`) ----------------
    //
    // The precedence table, cell by cell. `Isolation::resolve` is the one
    // reader of the config key; `from_boundary` is the probe half of it, split
    // out so that the failing-probe cells are reachable on a host whose
    // bubblewrap works (and the passing cell on one whose bubblewrap does not).

    /// The probe outcome, both ways, with the reason carried through. A
    /// flattened "unavailable" would send an operator after the wrong problem:
    /// "not installed" is a package to install, "older than 0.12.0" is a
    /// package to upgrade, and a failed smoke step is a host to investigate.
    #[test]
    fn the_probe_result_decides_between_sandboxed_and_unavailable() {
        assert_eq!(Isolation::from_boundary(Ok(())), Isolation::Sandboxed);
        for reason in [
            IsolationUnavailable::NotInstalled,
            IsolationUnavailable::VersionUnreadable("no output".into()),
            IsolationUnavailable::VersionTooOld((0, 11, 9)),
            IsolationUnavailable::SmokeTestFailed("HTTPS works: curl did not run".into()),
        ] {
            assert_eq!(
                Isolation::from_boundary(Err(reason.clone())),
                Isolation::Unavailable(reason.clone()),
                "the reason must survive into the mode: {reason:?}"
            );
        }
    }

    /// The consenting half of the table, and the fail-closed half for a value
    /// `Config::load` would already have refused.
    ///
    /// `is_unconfined()` is an equality against the literal `"none"`, so a
    /// value that is neither mode takes the **proving** branch. This asserts
    /// that from the outside, because the two branches are not interchangeable:
    /// reading `"chroot"` as consent would run a shell job with no boundary
    /// because of a typo.
    #[tokio::test]
    async fn only_the_literal_none_is_consent_and_an_unknown_value_is_proved() {
        let grants = Grants::default();
        for value in ["chroot", "None", "none ", "", "bwrap "] {
            let cfg = crate::config::ShellSandboxConfig {
                sandbox: value.into(),
            };
            let got = Isolation::resolve(&cfg, &grants).await;
            assert!(
                !matches!(got, Isolation::Unconfined),
                "{value:?} must never resolve to the unconfined mode, got {got:?}"
            );
        }
        assert_eq!(
            Isolation::resolve(
                &crate::config::ShellSandboxConfig {
                    sandbox: "none".into()
                },
                &grants
            )
            .await,
            Isolation::Unconfined,
            "the literal is consent"
        );
    }

    /// `resolve` must reach **both** production steps, not route around them.
    /// These two tests are that, and they are the only ones that can be: the
    /// floor and the probe both resolve `bwrap` from `PATH`, and a host with a
    /// working bubblewrap cannot make either fail on its own.
    ///
    /// They install a stub `bwrap` on `PATH`, so they are also the only tests in
    /// this module that mutate process-global state — see [`PATH_LOCK`].
    ///
    /// A floor that is not enforced here is the CVE the floor exists for:
    /// `bwrap` 0.11.9 answers the version question with its own version, so a
    /// `resolve` that skipped the check would go on to probe it, fail on the
    /// transcript, and report a **smoke-test** failure — which the assertion
    /// below separates from the `VersionTooOld` this must be. It is the
    /// difference between "install bubblewrap" and "upgrade bubblewrap", which
    /// is the whole reason the variant carries the version.
    #[tokio::test]
    async fn the_version_floor_is_enforced_by_resolve_and_not_only_by_its_own_test() {
        let (_dir, stub) = stub_bwrap_reporting("bubblewrap 0.11.9");
        let _path = PathOnly::new(stub.parent().unwrap());

        let got = Isolation::resolve(
            &crate::config::ShellSandboxConfig::default(),
            &Grants::default(),
        )
        .await;
        assert_eq!(
            got,
            Isolation::Unavailable(IsolationUnavailable::VersionTooOld((0, 11, 9))),
            "a bwrap older than the floor must be refused as VersionTooOld before the \
             probe runs, not reported as a smoke-test failure"
        );
    }

    /// ... and the probe is reached too. The stub answers `--version` with a
    /// version that satisfies the floor and fails at everything else, so a
    /// `resolve` that stopped after the version check would return `Sandboxed`
    /// here — a boundary asserted by nothing but a version string.
    #[tokio::test]
    async fn a_failing_probe_refuses_the_mode_rather_than_asserting_the_boundary() {
        let (_dir, stub) = stub_bwrap_running(
            "for a in \"$@\"; do\n\
               if [ \"$a\" = \"--version\" ]; then echo 'bubblewrap 0.12.0'; exit 0; fi\n\
             done\n\
             echo 'bwrap: No permissions to creating new namespace' >&2\n\
             exit 1",
        );
        let _path = PathOnly::new(stub.parent().unwrap());

        let got = Isolation::resolve(
            &crate::config::ShellSandboxConfig::default(),
            &Grants::default(),
        )
        .await;
        assert!(
            matches!(
                got,
                Isolation::Unavailable(IsolationUnavailable::SmokeTestFailed(_))
            ),
            "a bwrap that passes the floor and fails the smoke test must refuse the \
             mode, got {got:?}"
        );
    }

    /// Layer 1's only question, pinned for all three modes. `Unconfined` is the
    /// operator's consent, so nothing is gated (spec §4) — parking their shell
    /// tasks anyway would be the same operator loop the refusal message opens,
    /// one layer up.
    #[test]
    fn needs_approval_is_true_only_when_the_boundary_is_absent() {
        assert!(!Isolation::Sandboxed.needs_approval());
        assert!(!Isolation::Unconfined.needs_approval());
        assert!(Isolation::Unavailable(IsolationUnavailable::NotInstalled).needs_approval());
        assert!(
            Isolation::default().needs_approval(),
            "the default fails closed"
        );
    }

    #[test]
    fn a_missing_binary_is_reported_as_not_installed() {
        let r = check_bwrap_version_at(Path::new("/nonexistent/bwrap"));
        assert!(
            matches!(r, Err(IsolationUnavailable::NotInstalled)),
            "a missing binary must be NotInstalled, got {r:?}"
        );
    }

    /// A binary that prints the right version and *then* fails is not a binary
    /// we may rely on. Accepting it would be fail-open in a security gate.
    #[test]
    fn a_failing_exit_status_is_refused_even_with_a_good_version() {
        let (_dir, bin) = stub_bwrap_running("echo 'bubblewrap 0.12.0'\nexit 1");
        let r = check_bwrap_version_at(&bin);
        assert!(
            matches!(r, Err(IsolationUnavailable::VersionUnreadable(_))),
            "a non-zero exit must be refused as VersionUnreadable, got {r:?}"
        );
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("exited with 1:"),
            "the exit code must be reported as a bare number, got {msg:?}"
        );
    }

    /// The operator's only clue is this message, so it must never end in a bare
    /// colon with the real reason thrown away.
    #[test]
    fn an_empty_capture_never_leaves_a_dangling_colon() {
        // Exits 0 and says nothing at all.
        let (_d1, silent) = stub_bwrap_running("exit 0");
        // Says nothing on stdout, explains itself on stderr, and fails.
        let (_d2, stderr_only) = stub_bwrap_running("echo 'permission denied' >&2\nexit 1");
        for (label, bin) in [("silent", &silent), ("stderr-only", &stderr_only)] {
            let msg = check_bwrap_version_at(bin).unwrap_err().to_string();
            assert!(
                !msg.trim_end().ends_with(':'),
                "the {label} probe must not end in a bare colon: {msg:?}"
            );
        }
        let stderr_msg = check_bwrap_version_at(&stderr_only)
            .unwrap_err()
            .to_string();
        assert!(
            stderr_msg.contains("permission denied"),
            "the reason on stderr must survive into the message: {stderr_msg:?}"
        );
    }

    /// The binary is there but we may not run it. Reporting "not installed"
    /// sends the operator looking for a package that is already present.
    #[test]
    fn a_binary_that_cannot_be_executed_is_not_reported_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwrap");
        std::fs::write(&bin, "#!/bin/sh\necho 'bubblewrap 0.12.0'\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = check_bwrap_version_at(&bin);
        assert!(
            matches!(r, Err(IsolationUnavailable::VersionUnreadable(_))),
            "an unrunnable binary must carry the io error, not claim it is missing, got {r:?}"
        );
    }

    /// The refusal is the operator's only explanation for why shell jobs
    /// stopped, so it has to name both the vulnerability and the fix.
    #[test]
    fn the_refusal_names_the_cve_and_the_required_version() {
        let e = IsolationUnavailable::VersionTooOld((0, 11, 9));
        let msg = e.to_string();
        assert!(
            msg.contains("CVE-2026-87766"),
            "the refusal must name the CVE, got {msg:?}"
        );
        let required = format!("{}.{}.{}", MIN_BWRAP.0, MIN_BWRAP.1, MIN_BWRAP.2);
        assert!(
            msg.contains(&required),
            "the refusal must name the required version {required}, got {msg:?}"
        );
        // Compile-time proof that callers can box it and `?`-chain it.
        let _: &dyn std::error::Error = &e;
    }

    /// The variant used to carry the whole stdout while `Display` prefixed
    /// `bubblewrap `, so the operator read
    /// `bubblewrap bubblewrap 0.11.9 is older than ...`.
    #[test]
    fn the_refusal_does_not_repeat_the_program_name() {
        let msg = IsolationUnavailable::VersionTooOld((0, 11, 9)).to_string();
        assert_eq!(
            msg.matches("bubblewrap").count(),
            1,
            "the program name must appear exactly once, got {msg:?}"
        );
        assert!(
            msg.contains("0.11.9"),
            "the version that was found must still appear, got {msg:?}"
        );
    }

    /// A hung `bwrap --version` must not stall startup. The deadline is injected
    /// so this test does not itself wait the production [`PROBE_TIMEOUT`].
    #[test]
    fn a_hung_probe_is_refused_instead_of_waited_on() {
        // `exec` so the shell replaces itself and the kill reaches the sleeper.
        let (_dir, bin) = stub_bwrap_running("exec sleep 30");
        let started = Instant::now();
        let r = check_bwrap_version_at_within(&bin, Duration::from_millis(150));
        let elapsed = started.elapsed();
        assert!(
            matches!(r, Err(IsolationUnavailable::VersionUnreadable(_))),
            "a hung probe must fail closed, got {r:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the probe must give up on its deadline, took {elapsed:?}"
        );
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("150ms"),
            "the deadline must be reported as it was given, not truncated to \
             whole seconds: {msg:?}"
        );
    }

    /// The child exits at once, but the sleeper it backgrounds inherits the
    /// pipe and keeps it open. Waiting for that capture would pin the probe for
    /// as long as the grandchild lives, so the deadline has to cover it too.
    #[test]
    fn a_grandchild_holding_the_pipe_does_not_pin_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwrap");
        let pidfile = dir.path().join("grandchild.pid");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nsleep 30 &\necho $! > {}\nexit 0\n",
                pidfile.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let started = Instant::now();
        let r = check_bwrap_version_at_within(&bin, Duration::from_millis(150));
        let elapsed = started.elapsed();

        // Kill the sleeper this test deliberately left holding the pipe, so the
        // suite does not leave an orphan behind on every run.
        if let Some(pid) = std::fs::read_to_string(&pidfile)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok())
        {
            // SAFETY: the pid was just reported by the shell this test started,
            // and signalling an already-exited pid is a no-op.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }

        assert!(
            matches!(r, Err(IsolationUnavailable::VersionUnreadable(_))),
            "an unreadable capture must fail closed, got {r:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the probe must not wait on a grandchild's pipe, took {elapsed:?}"
        );
    }

    /// A binary held open for writing makes the kernel refuse the exec with
    /// `ETXTBSY`. The condition is transient — a package manager replacing
    /// `bwrap` in place does the same — so the probe waits it out rather than
    /// reporting an isolation failure the operator cannot act on.
    ///
    /// Holding the descriptor across the first spawn makes the refusal certain
    /// rather than a race, so this is the deterministic form of the flake the
    /// module suite saw about one run in ten.
    #[test]
    fn a_binary_open_for_writing_is_waited_out_rather_than_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwrap");
        std::fs::write(&bin, "#!/bin/sh\necho 'bubblewrap 0.12.0'\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let held = std::fs::OpenOptions::new().write(true).open(&bin).unwrap();

        // The refusal is a precondition of this test, not a hope: establish it
        // before relying on it. Without this, a spawn that simply never met
        // ETXTBSY would let the test pass with the retry left untested.
        let refused = std::process::Command::new(&bin).arg("--version").output();
        assert!(
            matches!(&refused, Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy),
            "a held writer must make the exec fail with ETXTBSY, got {refused:?}"
        );

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(held);
        });
        let started = Instant::now();
        let r = check_bwrap_version_at(&bin);
        let elapsed = started.elapsed();
        releaser.join().unwrap();

        assert!(
            r.is_ok(),
            "a transient ETXTBSY must be waited out, not reported as unavailable, got {r:?}"
        );
        // The writer is released only after 30ms, so a probe that had not
        // retried could not have succeeded. The threshold clears both sides:
        // a probe that never met the refusal costs one 20ms poll interval
        // (~20-28ms measured), while the retry path measures ~58-67ms.
        assert!(
            elapsed >= Duration::from_millis(45),
            "the probe must have retried the refused spawn, took {elapsed:?}"
        );
    }

    /// The retry has to be bounded, and it has to cover `ETXTBSY` and nothing
    /// else. A retry that ran for every failure would make a missing binary pay
    /// the whole budget for no reason.
    #[test]
    fn the_retry_is_bounded_and_covers_only_etxtbsy() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bwrap");
        std::fs::write(&bin, "#!/bin/sh\necho 'bubblewrap 0.12.0'\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Never released, so the refusal cannot clear: the probe has to give up
        // on its own budget rather than wait the writer out. Holding it for the
        // whole test is stronger than holding it for a fixed second.
        let _held = std::fs::OpenOptions::new().write(true).open(&bin).unwrap();

        let started = Instant::now();
        let r = check_bwrap_version_at(&bin);
        let elapsed = started.elapsed();
        assert!(
            matches!(r, Err(IsolationUnavailable::VersionUnreadable(_))),
            "an exhausted retry must fail closed, got {r:?}"
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "the retry must be bounded, not wait for the writer, took {elapsed:?}"
        );
        // An exhausted retry must be distinguishable from a refusal that was
        // never retried, or a persistent writer reads like the transient
        // failure the retry exists to remove.
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("after 8 retries"),
            "the message must say the retry was exhausted, got {msg:?}"
        );

        // A missing binary is not a condition to wait on: it must fail at once
        // instead of spending the ~275ms budget.
        let started = Instant::now();
        let missing = check_bwrap_version_at(Path::new("/nonexistent/bwrap"));
        let elapsed = started.elapsed();
        assert!(
            matches!(missing, Err(IsolationUnavailable::NotInstalled)),
            "a missing binary must be NotInstalled, got {missing:?}"
        );
        assert!(
            elapsed < Duration::from_millis(150),
            "a missing binary must not pay the retry budget, took {elapsed:?}"
        );
    }

    /// A child killed by a signal has no exit code, and the whole reason
    /// `describe_status` exists is to report that case rather than printing
    /// `exit status: None`.
    #[test]
    fn a_binary_killed_by_a_signal_is_reported_as_a_signal() {
        let (_dir, bin) = stub_bwrap_running("kill -9 $$");
        let msg = check_bwrap_version_at(&bin).unwrap_err().to_string();
        assert!(
            msg.contains("signal: 9 (SIGKILL)"),
            "a signalled child must be reported as such, got {msg:?}"
        );
        assert!(
            !msg.contains("None"),
            "the missing exit code must not leak into the message, got {msg:?}"
        );
    }

    /// An unparseable flood must not become the error message.
    #[test]
    fn a_flood_of_output_is_capped_in_the_error() {
        let huge = "x".repeat(20 * 1024 * 1024);
        let described = describe_output(huge.as_bytes());
        assert!(
            described.len() <= MAX_PROBE_TEXT + 32,
            "the description must stay bounded, got {} bytes",
            described.len()
        );

        // A multi-byte character straddling the cap must not split or panic.
        let multibyte = "€".repeat(200);
        let described = describe_output(multibyte.as_bytes());
        assert!(described.starts_with('€'), "got {described:?}");
        assert!(
            described.len() <= MAX_PROBE_TEXT + 32,
            "the description must stay bounded, got {} bytes",
            described.len()
        );

        // ... and the same bound holds at the boundary, through a real probe.
        // 1 MiB, far past the 64 KiB pipe buffer: the child cannot exit unless
        // the reader keeps draining after the cap is reached, so a reader that
        // stops at the cap shows up here as a child that never finished.
        let (_dir, bin) = stub_bwrap_running("head -c 1048576 /dev/zero | tr '\\000' x");
        let msg = check_bwrap_version_at(&bin).unwrap_err().to_string();
        assert!(
            msg.contains("unrecognised output"),
            "the child must run to completion with its output read, got {msg:?}"
        );
        assert!(
            msg.len() <= MAX_PROBE_TEXT + 128,
            "the probe's message must stay bounded, got {} bytes: {msg:?}",
            msg.len()
        );
    }

    /// A real, resolved job directory in a fresh temporary root.
    ///
    /// [`build_argv`] takes a [`JobDir`] rather than a path because the argv
    /// binds the job directory by **descriptor**, and only [`resolve_job_dir`]
    /// may build one — so the argv tests go through the same door production
    /// does. The `TempDir` is returned because it owns the root the descriptor
    /// names.
    fn test_job_dir() -> (tempfile::TempDir, JobDir) {
        let dir = tempfile::tempdir().unwrap();
        let jd = resolve_job_dir(dir.path(), "task-1", "job-1").unwrap();
        (dir, jd)
    }

    /// The production argv for a job in a fresh root. The `TempDir` is returned
    /// with it so the root outlives the descriptor the argv names.
    fn argv_of(grants: &Grants, command: &str) -> (tempfile::TempDir, SandboxArgv) {
        let (dir, jd) = test_job_dir();
        let built = build_argv(&jd, grants, command).unwrap();
        (dir, built)
    }

    #[test]
    fn argv_unshares_and_hardens_namespaces() {
        let (_dir, built) = argv_of(&Grants::default(), "echo hi");
        let a = built.argv();
        assert!(a.contains(&"--unshare-all".to_string()));
        // --unshare-all is only --unshare-user-try: it is silently skipped when
        // the user namespace cannot be created, so it must be named explicitly.
        assert!(a.contains(&"--unshare-user".to_string()));
        assert!(a.contains(&"--disable-userns".to_string()));
        // Asserted here because nothing else can: the probe cannot detect this
        // flag's removal while `--disable-userns` remains — with that flag
        // present the behaviour is identical, because this one verifies rather
        // than acts. This assertion is therefore the only thing standing between
        // the flag and a silent deletion; deleting the flag line makes *this
        // test* fail, and nothing else in the suite would. See the flag's own
        // comment in `build_argv`.
        assert!(a.contains(&"--assert-userns-disabled".to_string()));
    }

    #[test]
    fn argv_detaches_the_terminal_and_dies_with_the_parent() {
        let (_dir, built) = argv_of(&Grants::default(), "echo hi");
        let a = built.argv();
        assert!(a.contains(&"--new-session".to_string()), "TIOCSTI");
        assert!(a.contains(&"--die-with-parent".to_string()));
    }

    #[test]
    fn clearenv_comes_before_every_setenv() {
        let (_dir, built) = argv_of(&Grants::default(), "echo hi");
        let a = built.argv();
        let clear = a.iter().position(|x| x == "--clearenv").unwrap();
        let setenvs: Vec<usize> = a
            .iter()
            .enumerate()
            .filter(|(_, x)| *x == "--setenv")
            .map(|(i, _)| i)
            .collect();
        assert!(!setenvs.is_empty(), "HOME and PATH must be set");
        for s in setenvs {
            assert!(
                s > clear,
                "--setenv at {s} precedes --clearenv at {clear}, which would wipe it"
            );
        }
    }

    #[test]
    fn argv_links_the_dynamic_loader_paths() {
        let (_dir, built) = argv_of(&Grants::default(), "echo hi");
        let a = built.argv();
        // Omitting /lib64 makes execvp fail with "No such file or directory".
        for link in ["/bin", "/lib", "/lib64"] {
            assert!(
                a.windows(2).any(|w| w[0] == link),
                "missing --symlink target {link}"
            );
        }
        // ... and the *pairing* is what the loader actually needs. A link whose
        // target is wrong is as broken as one that is absent, and the window
        // check above cannot tell the two apart: `--symlink usr/lib64 /lib`
        // satisfies it while leaving /lib64 with no loader.
        for (target, link) in [
            ("usr/bin", "/bin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
        ] {
            assert!(
                a.windows(3)
                    .any(|w| w[0] == "--symlink" && w[1] == target && w[2] == link),
                "expected --symlink {target} {link}, got {a:?}"
            );
        }
    }

    #[test]
    fn argv_isolates_the_hostname() {
        let (_dir, built) = argv_of(&Grants::default(), "echo hi");
        let a = built.argv();
        let i = a.iter().position(|x| x == "--hostname").unwrap();
        assert_eq!(a[i + 1], "haos-sandbox");
    }

    /// `--chdir` is asserted statically as well as through the probe, because
    /// the probe's runtime check rests on bwrap's documented cwd rule: without
    /// `--chdir`, bwrap falls back to `$HOME` — which this same argv sets to the
    /// job directory — whenever the invoking cwd is not present in the sandbox.
    /// A future bubblewrap that changed that fallback would silently re-arm the
    /// hole the probe's pinned cwd exists to close; the argv itself cannot drift
    /// unnoticed.
    #[test]
    fn argv_pins_the_job_directory_as_the_working_directory() {
        let (_dir, jd) = test_job_dir();
        let built = build_argv(&jd, &Grants::default(), "echo hi").unwrap();
        let a = built.argv();
        let dir = jd.path().to_string_lossy().to_string();
        let i = a.iter().position(|x| x == "--chdir").unwrap();
        assert_eq!(a[i + 1], dir);
        // Immediately before the command, so a later flag cannot re-point it.
        assert_eq!(a[i + 2], "/bin/sh");
        // And HOME is the same directory, which is what makes bwrap's fallback
        // for a missing `--chdir` land in the job directory (see the probe's
        // cwd check).
        let h = a.iter().position(|x| x == "--setenv").unwrap();
        assert_eq!(a[h + 1], "HOME");
        assert_eq!(a[h + 2], dir);
    }

    /// The job directory is bound by **descriptor**, not by path.
    ///
    /// Measured on bubblewrap 0.12.0, with `<root>/<task-id>` renamed away and a
    /// symlink to a second directory left in its place *after* the descriptor
    /// was taken:
    ///
    /// ```text
    /// path-based bind (symlink swapped in):  out='WRONG-TARGET'
    /// fd-based bind  (descriptor held):      out='bound-by-inode'
    /// ```
    ///
    /// `--bind` re-resolves the path when bubblewrap runs, so the writer wins;
    /// `--bind-fd` mounts the inode the descriptor names. The path is still in
    /// the argv for `HOME` and `--chdir` — those are names *inside* the
    /// sandbox, not host resolutions — so this test pins both: the bind is by
    /// descriptor, and no `--bind` of the job directory survives beside it.
    #[test]
    fn the_job_directory_is_bound_by_descriptor_not_by_path() {
        let (_dir, jd) = test_job_dir();
        let built = build_argv(&jd, &Grants::default(), "x").unwrap();
        let a = built.argv();
        let dir = jd.path().to_string_lossy().to_string();

        let at = a
            .iter()
            .position(|x| x == "--bind-fd")
            .unwrap_or_else(|| panic!("the job directory must be bound by descriptor: {a:?}"));
        // The number is a *live* descriptor, and it is the duplicate the argv
        // value is holding open — not a constant, and not the original, which
        // is close-on-exec and therefore closed by the time bubblewrap runs.
        let named: i32 = a[at + 1].parse().expect("--bind-fd takes a number");
        // SAFETY: `named` is only ever a descriptor this process holds; a wrong
        // number reports `EBADF` rather than doing anything.
        let flags = unsafe { libc::fcntl(named, libc::F_GETFD) };
        assert!(
            flags >= 0,
            "the descriptor the argv names is not open: F_GETFD = {flags}, errno {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "the descriptor the argv names is close-on-exec, so bubblewrap would \
             not inherit it"
        );
        assert_eq!(a[at + 2], dir, "the bind destination is the job directory");
        assert!(
            !a.windows(3).any(|w| w[0] == "--bind" && w[1] == dir),
            "a path-based bind of the job directory re-resolves the path, which is \
             the race the descriptor closes: {a:?}"
        );
    }

    /// The end-to-end version of the test above, on the argv **and** the spawn:
    /// the descriptor the argv names must be open in the child, naming the job
    /// directory, or `--bind-fd` binds nothing.
    ///
    /// A stub `bwrap` is enough — it reads `--bind-fd N` out of its own argv and
    /// `readlink`s that descriptor — and it is the same `run_in_sandbox` the
    /// probe uses, so the argv, the duplicate and the spawn are all the
    /// production ones. No real sandbox is needed, and none is assumed: this
    /// runs on a host without bubblewrap.
    ///
    /// It is what catches the obvious mistake this design invites — naming
    /// `JobDir`'s **original** descriptor, which is close-on-exec, instead of
    /// the duplicate. That mutant passes the string-level test above and fails
    /// here with an empty `readlink`.
    #[tokio::test]
    async fn the_argv_hands_the_child_a_live_descriptor_for_the_job_directory() {
        let scratch = tempfile::tempdir().unwrap();
        let (_dir, bin) = stub_bwrap_running(
            "fd=\"\"\n\
             prev=\"\"\n\
             for a in \"$@\"; do\n\
               if [ \"$prev\" = \"--bind-fd\" ]; then fd=\"$a\"; fi\n\
               prev=\"$a\"\n\
             done\n\
             if [ -z \"$fd\" ]; then echo 'no --bind-fd in the argv' >&2; exit 1; fi\n\
             if ! readlink /proc/self/fd/\"$fd\"; then\n\
               echo \"the argv named descriptor $fd, which the child does not have\" >&2\n\
               exit 1\n\
             fi",
        );
        let job_dir = resolve_job_dir(scratch.path(), "task-1", "job-1").unwrap();

        let out = crate::supervisor::bounded(
            "the descriptor check",
            run_in_sandbox(
                &bin,
                &job_dir,
                &Grants::default(),
                "x",
                scratch.path(),
                "the descriptor check",
            ),
        )
        .await
        .expect("the stub cannot fail the step for any reason but the descriptor");

        assert!(
            out.status.success(),
            "the child could not read the descriptor the argv named: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            job_dir.path().to_string_lossy(),
            "the descriptor the argv names must be the job directory, open in the child"
        );
    }

    #[test]
    fn share_net_appears_only_when_the_network_grant_is_held() {
        let none = Grants::default();
        let net = Grants {
            write: Default::default(),
            network: true,
        };
        assert!(!argv_of(&none, "x")
            .1
            .argv()
            .contains(&"--share-net".to_string()));
        let (_dir, built) = argv_of(&net, "x");
        let a = built.argv();
        assert!(a.contains(&"--share-net".to_string()));
        // Presence is not enough: order is load-bearing. `--share-net` before
        // `--unshare-all` is re-unshared by it, so the grant becomes a silent
        // no-op — measured against the real binary, the inverted order leaves the
        // sandbox with `lo` alone (1 interface against 16), which the probe
        // reports as "the host network is reachable under a grant". Presence
        // alone passes either way.
        //
        // Exactly one of each, asserted before the ordering. A second
        // `--unshare-all` *after* `--share-net` would re-unshare the network
        // while a first-occurrence comparison still read as correctly ordered —
        // so the count is pinned and the comparison is then unambiguous, rather
        // than picking an occurrence and hoping it is the one that matters.
        assert_eq!(
            a.iter().filter(|x| *x == "--unshare-all").count(),
            1,
            "the builder must unshare the namespaces exactly once: {a:?}"
        );
        assert_eq!(
            a.iter().filter(|x| *x == "--share-net").count(),
            1,
            "the builder must share the network exactly once: {a:?}"
        );
        let unshare = a.iter().position(|x| x == "--unshare-all").unwrap();
        let share = a.iter().position(|x| x == "--share-net").unwrap();
        assert!(
            share > unshare,
            "--share-net at {share} precedes --unshare-all at {unshare}, which re-unshares \
             the network and makes the grant a silent no-op"
        );
    }

    #[test]
    fn a_write_grant_becomes_a_read_write_bind() {
        // A grant is the only way a host path becomes writable, and `--bind` is
        // the only bubblewrap flag that makes one. Read-only would silently
        // grant nothing.
        //
        // Two paths on purpose, one under `/usr` and one under `/etc`: the `/etc`
        // binds are emitted by a later loop than the `/usr` ones, so a grant loop
        // moved above it would shadow an `/etc` grant while a check against
        // `/usr` alone still passed.
        let g = Grants {
            write: [PathBuf::from("/var/lib"), PathBuf::from("/etc/ssl/certs")].into(),
            network: false,
        };
        let (_dir, built) = argv_of(&g, "x");
        let a = built.argv();
        for granted in ["/var/lib", "/etc/ssl/certs"] {
            assert!(
                a.windows(3)
                    .any(|w| w[0] == "--bind" && w[1] == granted && w[2] == granted),
                "{granted} must be bound read-write, got {a:?}"
            );
        }
        // Presence is not enough here either: a later mount wins, so a grant
        // mounted *before* a read-only bind is covered by it and grants nothing.
        // Every grant must follow **every** read-only bind, not just the `/usr`
        // one. Measured: `--bind /usr/share /usr/share` then
        // `--ro-bind /usr /usr` leaves `/usr/share` read-only where the
        // production order leaves it writable, and the same rule holds for
        // `/etc/ssl/certs`.
        let last_ro = a
            .iter()
            .rposition(|x| x == "--ro-bind")
            .expect("the read-only base must be bound");
        for granted in ["/var/lib", "/etc/ssl/certs"] {
            let at = a
                .windows(3)
                .position(|w| w[0] == "--bind" && w[1] == granted)
                .expect("asserted present above");
            assert!(
                at > last_ro,
                "the grant for {granted} at {at} precedes the last read-only bind at \
                 {last_ro}, which mounts over it and silently grants nothing"
            );
        }
        // And nothing is bound read-write without a grant.
        let (_dir, built) = argv_of(&Grants::default(), "x");
        let none = built.argv();
        assert!(
            !none
                .windows(3)
                .any(|w| w[0] == "--bind" && w[1] == "/var/lib"),
            "no grant, no writable host path: {none:?}"
        );
    }

    #[test]
    fn both_certificate_paths_are_bound_read_only_when_they_exist() {
        // Load-bearing, not garnish: measured, without them `curl
        // https://example.com` inside the sandbox fails with `curl: (77) error
        // adding trust anchors from file: /etc/ssl/certs/ca-certificates.crt`.
        let root = tempfile::tempdir().unwrap();
        for p in ["etc/ssl/certs", "etc/ca-certificates"] {
            std::fs::create_dir_all(root.path().join(p)).unwrap();
        }
        let mut a = Vec::new();
        for p in ["/etc/ssl/certs", "/etc/ca-certificates"] {
            push_ro_bind_if_present(&mut a, root.path(), p);
        }
        for p in ["/etc/ssl/certs", "/etc/ca-certificates"] {
            assert!(
                a.windows(3).any(|w| w[0] == "--ro-bind" && w[2] == p),
                "{p} must be bound read-only, got {a:?}"
            );
        }
        // And the production argv carries them on this host, where both exist.
        let (_dir, built) = argv_of(&Grants::default(), "x");
        let full = built.argv();
        for p in ["/etc/ssl/certs", "/etc/ca-certificates"] {
            if Path::new(p).exists() {
                assert!(
                    full.windows(3).any(|w| w[0] == "--ro-bind" && w[2] == p),
                    "{p} exists on this host and must be bound: {full:?}"
                );
            }
        }
    }

    #[test]
    fn a_missing_certificate_path_is_skipped_rather_than_aborting_the_argv() {
        // On Debian/Ubuntu `/etc/ca-certificates` does not exist. Pointed at a
        // scratch root holding only one of the two, the other must simply not
        // appear — the branch this host's own layout cannot exercise.
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/ssl/certs")).unwrap();
        let mut a = Vec::new();
        for p in ["/etc/ssl/certs", "/etc/ca-certificates"] {
            push_ro_bind_if_present(&mut a, root.path(), p);
        }
        assert!(a
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[2] == "/etc/ssl/certs"));
        assert!(
            !a.iter().any(|x| x == "/etc/ca-certificates"),
            "a path that does not exist is skipped, never bound: {a:?}"
        );
        // And the argv it feeds is still complete.
        let (_dir, built) = argv_of(&Grants::default(), "x");
        let full = built.argv();
        assert_eq!(full[full.len() - 3..], ["/bin/sh", "-c", "x"]);
    }

    #[test]
    fn the_command_is_last_and_passed_verbatim() {
        let (_dir, built) = argv_of(&Grants::default(), "run x; cat /etc/hostname");
        let a = built.argv();
        assert_eq!(
            a[a.len() - 3..],
            ["/bin/sh", "-c", "run x; cat /etc/hostname"]
        );
    }

    /// A fake `bwrap` that ignores its argv, records the physical cwd it
    /// inherited, and exits 0. Used to drive the probe's own plumbing without a
    /// real sandbox.
    ///
    /// `pwd -P`, not `pwd`: the child inherits `PWD` from this process, and the
    /// shell builtin will echo that stale value if it looks valid.
    fn stub_bwrap_recording_cwd(record: &Path) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bwrap");
        std::fs::write(
            &path,
            format!("#!/bin/sh\npwd -P > '{}'\nexit 0\n", record.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[tokio::test]
    async fn a_probe_that_cannot_start_a_shell_reports_smoke_test_failed() {
        // The stub satisfies nothing the probe asks for, so the failure must
        // come back as SmokeTestFailed — named, and through the variant spec §6
        // requires rather than a panic.
        let scratch = tempfile::tempdir().unwrap();
        let (_dir, bin) = stub_bwrap_recording_cwd(&scratch.path().join("cwd.txt"));
        match probe_at(&bin, &Grants::default(), scratch.path()).await {
            Err(IsolationUnavailable::SmokeTestFailed(step)) => {
                assert!(!step.is_empty(), "the failing step must be named");
            }
            other => panic!("expected SmokeTestFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_probe_spawns_bwrap_from_a_cwd_of_its_own() {
        // Measured, and documented in bwrap(1): HOME "is used as the cwd in the
        // sandbox if `--chdir` has not been explicitly specified and the current
        // cwd is not present inside the sandbox". The argv sets HOME to the job
        // directory and binds it, so a probe spawned from a directory the
        // sandbox cannot see would find the job directory as its cwd whether
        // `--chdir` were present or not — and the probe's `pwd` assertion would
        // then pass with `--chdir` deleted.
        //
        // The probe therefore pins `/`: present inside the sandbox, and not the
        // job directory, so a missing `--chdir` leaves the cwd at `/` and is
        // caught. This is the check that it does — the stub records the cwd it
        // was spawned with.
        //
        // Asserting equality with the pinned directory (not merely "not the job
        // directory") is what gives this teeth: the *test process's* cwd is
        // already outside the job directory, so a probe that pinned nothing
        // would satisfy the weaker assertion.
        let scratch = tempfile::tempdir().unwrap();
        let record = scratch.path().join("cwd.txt");
        let (_dir, bin) = stub_bwrap_recording_cwd(&record);
        let _ = probe_at(&bin, &Grants::default(), scratch.path()).await;
        let seen = std::fs::read_to_string(&record).unwrap();
        // The probe's job directory is the one `probe_at` resolves — the same
        // two-level layout a real job gets, because it goes through
        // `resolve_job_dir` like a real job does.
        let job_dir = std::fs::canonicalize(scratch.path().join("probe-task/probe-job")).unwrap();
        assert!(
            job_dir.is_dir(),
            "the probe's job directory was not created"
        );
        assert_eq!(
            Path::new(seen.trim()),
            Path::new("/"),
            "the probe must pin its own cwd to a directory that exists inside the sandbox, \
             or bwrap's HOME fallback masks a missing --chdir"
        );
        assert!(
            !Path::new(seen.trim()).starts_with(&job_dir),
            "the probe spawned bwrap from inside the job directory: {seen}"
        );
    }

    #[tokio::test]
    async fn a_failing_bwrap_explains_itself_in_the_error() {
        // Measured with real bwrap: a failed setup exits non-zero, prints
        // **nothing** on stdout, and explains itself on stderr — `bwrap: Can't
        // find source path ...`, or the single most common failure on a fresh
        // host, `bwrap: No permissions to creating new namespace`. Reading only
        // stdout reported `expected shell=ok, got None` and threw away the one
        // line that names the cause.
        let scratch = tempfile::tempdir().unwrap();
        let (_dir, bin) = stub_bwrap_running(
            "echo 'bwrap: No permissions to creating new namespace' >&2\nexit 42",
        );
        let e = probe_at(&bin, &Grants::default(), scratch.path())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("the shell starts"),
            "the failing step must still be named, got {e:?}"
        );
        assert!(
            e.contains("No permissions to creating new namespace"),
            "the cause bwrap printed on stderr must survive into the error, got {e:?}"
        );
        assert!(
            e.contains("42"),
            "the exit status must be reported, got {e:?}"
        );
    }

    /// A fake `bwrap` that reads the argv it was given and answers with the
    /// transcript a **working** sandbox would produce.
    ///
    /// The probe's positive path — the one that returns `Ok(())` — had no test:
    /// both other probe tests accept an `Err`, so a mutation making `probe_at`
    /// fail unconditionally passed the whole module suite. This gives `Ok(())`
    /// teeth without real bubblewrap, so plain `cargo test` stays green on a host
    /// that has none.
    ///
    /// It derives `home` and `pwd` from `--setenv HOME` and `--chdir` in `"$@"`,
    /// and reachability from `--share-net`, so it answers as the argv asks rather
    /// than echoing constants: a missing `--chdir` yields `pwd=` and a missing
    /// `--share-net` under a grant yields `exit=7`, and both fail the probe.
    fn stub_bwrap_answering_transcript() -> (tempfile::TempDir, PathBuf) {
        stub_bwrap_running(
            r#"home=""; cwd=""; net=no; cmd=""
prev=""
for a in "$@"; do
  case "$prev" in
    --chdir) cwd="$a" ;;
    HOME) home="$a" ;;
  esac
  [ "$a" = "--share-net" ] && net=yes
  prev="$a"
  cmd="$a"
done
case "$cmd" in
  *unshare*) echo nested=blocked ;;
  *https://*) if [ "$net" = yes ]; then echo http=200; else echo http=000; fi ;;
  *127.0.0.1*) if [ "$net" = yes ]; then echo exit=28; else echo exit=7; fi ;;
  *)
    echo shell=ok
    echo "home=$home"
    echo path=/usr/bin:/bin
    echo "pwd=$cwd"
    echo hostname=haos-sandbox
    echo canary=unset
    echo passwd=unreadable
    echo shadow=absent
    echo cabundle=readable
    echo writable=yes ;;
esac
exit 0"#,
        )
    }

    #[tokio::test]
    async fn the_probe_passes_a_working_sandbox() {
        let scratch = tempfile::tempdir().unwrap();
        let (_dir, bin) = stub_bwrap_answering_transcript();
        let r = probe_at(&bin, &Grants::default(), scratch.path()).await;
        assert!(
            r.is_ok(),
            "a working sandbox must pass the probe, got {r:?}"
        );
    }

    #[tokio::test]
    async fn the_probe_passes_a_working_sandbox_under_a_network_grant() {
        // The other half of the `(grants.network, reachable)` matrix, answered
        // from the argv: the stub reports reachability only if `--share-net` is
        // there, so this also fails if the grant stops reaching the argv.
        let scratch = tempfile::tempdir().unwrap();
        let (_dir, bin) = stub_bwrap_answering_transcript();
        let grants = Grants {
            write: Default::default(),
            network: true,
        };
        let r = probe_at(&bin, &grants, scratch.path()).await;
        assert!(
            r.is_ok(),
            "a granted sandbox must pass the probe, got {r:?}"
        );
    }

    /// An [`std::process::Output`] for a verdict test, so a verdict can be
    /// reached without running bubblewrap. `code` is the exit code; the raw form
    /// a normal exit takes is `code << 8`.
    fn output_of(stdout: &str, stderr: &str, code: i32) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    /// Every base property, one at a time. A check that only fails when several
    /// fields are wrong is a check that hides which one broke, and a check that
    /// is never exercised at all is the reason the fail-open loopback rule
    /// survived review.
    #[test]
    fn every_base_property_is_checked() {
        let home = "/jobs/t/j";
        let fields = [
            ("shell", "ok"),
            ("home", home),
            ("path", "/usr/bin:/bin"),
            ("pwd", home),
            ("hostname", "haos-sandbox"),
            ("canary", "unset"),
            ("passwd", "unreadable"),
            ("shadow", "absent"),
            ("cabundle", "readable"),
            ("writable", "yes"),
        ];
        let transcript = |wrong: Option<usize>| {
            fields
                .iter()
                .enumerate()
                .map(|(i, (k, v))| {
                    if Some(i) == wrong {
                        format!("{k}=WRONG")
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        assert!(
            verdict_base(&output_of(&transcript(None), "", 0), home, true).is_ok(),
            "a well-formed transcript must pass"
        );
        for (i, (name, _)) in fields.iter().enumerate() {
            assert!(
                verdict_base(&output_of(&transcript(Some(i)), "", 0), home, true).is_err(),
                "{name} must be checked, but a wrong value passed"
            );
        }

        // The bundle is demanded only when the host has it — the same rule the
        // argv binds with — and both branches are reachable from here because
        // the guard is a parameter, not a host lookup inside the verdict.
        let without_bundle = output_of(
            &fields
                .iter()
                .filter(|(k, _)| *k != "cabundle")
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n"),
            "",
            0,
        );
        assert!(
            verdict_base(&without_bundle, home, false).is_ok(),
            "a host without the bundle must not be asked for it"
        );
        assert!(
            verdict_base(&without_bundle, home, true).is_err(),
            "a host with the bundle must be"
        );
    }

    /// A clean invocation must not pad the message, or the bwrap cause added for
    /// a failed setup would make every ordinary assertion failure unreadable.
    #[test]
    fn a_clean_invocation_does_not_pad_the_message() {
        match verdict_base(&output_of("shell=WRONG\n", "", 0), "/jobs/t/j", false) {
            Err(IsolationUnavailable::SmokeTestFailed(msg)) => assert_eq!(
                msg,
                "the shell starts: expected shell=ok, got Some(\"WRONG\")"
            ),
            other => panic!("expected SmokeTestFailed, got {other:?}"),
        }
    }

    /// The loopback verdict must read a **positive** signal, not the absence of
    /// one. Every input here is reachable from a real invocation.
    #[test]
    fn the_loopback_verdict_requires_curl_to_have_run() {
        let none = Grants::default();
        let net = Grants {
            write: Default::default(),
            network: true,
        };
        // Nothing on stdout: bwrap failed to set up. The old
        // `!contains("exit=7")` rule read this as reachable — a fail-open under
        // a grant, and a false failure naming /allow-net under no grant.
        for stdout in ["", "bwrap: setting up uid map: Permission denied\n"] {
            let out = output_of(stdout, "bwrap: Can't find source path /nope\n", 1);
            for grants in [&none, &net] {
                let e = verdict_loopback(&out, grants).unwrap_err().to_string();
                assert!(e.contains("did not run"), "got {e:?}");
                assert!(
                    e.contains("Can't find source path"),
                    "the cause on stderr must survive, got {e:?}"
                );
            }
        }

        // What the script emits when curl is not installed.
        let e = verdict_loopback(&output_of("curl=missing\n", "", 0), &none)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("curl is not available"),
            "a missing curl must be named, not read as reachability: {e:?}"
        );

        // A bare 127 — an older script, or a shell that ignored the guard — must
        // fail closed too, because `sh` runs `echo exit=$?` whatever curl does.
        // The catch-all is the whole safety property, so more than one code has
        // to exercise it: 6 is DNS failure and 52 is "empty reply from server",
        // neither producible by this command on a working sandbox, both
        // reachable if the sandbox substitutes its own curl. Every unexpected
        // code must fail closed and name itself, under either grant.
        for code in ["127", "6", "52"] {
            for grants in [&none, &net] {
                let e = verdict_loopback(&output_of(&format!("exit={code}\n"), "", 0), grants)
                    .unwrap_err()
                    .to_string();
                assert!(
                    e.contains("cannot tell"),
                    "exit {code} must fail closed, got {e:?}"
                );
                assert!(
                    e.contains(&format!("curl exited {code}")),
                    "exit {code} must be named, got {e:?}"
                );
            }
        }
    }

    /// Both states of the grant, so neither is assumed.
    #[test]
    fn the_loopback_verdict_follows_the_grant_in_force() {
        let none = Grants::default();
        let net = Grants {
            write: Default::default(),
            network: true,
        };
        // 7 is curl's "could not connect"; 28 is "connected, then waited for a
        // response that never came"; 0 is "connected and got one".
        assert!(verdict_loopback(&output_of("exit=7\n", "", 0), &none).is_ok());
        assert!(verdict_loopback(&output_of("exit=28\n", "", 0), &net).is_ok());
        assert!(verdict_loopback(&output_of("exit=0\n", "", 0), &net).is_ok());

        let e = verdict_loopback(&output_of("exit=28\n", "", 0), &none)
            .unwrap_err()
            .to_string();
        assert!(e.contains("unreachable without a grant"), "got {e:?}");
        let e = verdict_loopback(&output_of("exit=7\n", "", 0), &net)
            .unwrap_err()
            .to_string();
        assert!(e.contains("reachable under a grant"), "got {e:?}");
    }

    #[tokio::test]
    async fn a_probe_with_no_bwrap_reports_not_installed() {
        // The same outcome the version probe reports, so `probe()` called on its
        // own does not describe a missing binary as a smoke-test failure — which
        // would send the operator looking at namespaces and kernels for a
        // package that is not installed.
        let scratch = tempfile::tempdir().unwrap();
        let missing = scratch.path().join("no-such-bwrap");
        match probe_at(&missing, &Grants::default(), scratch.path()).await {
            Err(IsolationUnavailable::NotInstalled) => {}
            other => panic!("expected NotInstalled, got {other:?}"),
        }
    }

    /// The guard is what makes `curl=missing` reachable at all, so the verdict's
    /// branch for it is dead code without this. Measured: with the guard removed,
    /// a curl-less host emits `exit=127` and the operator is told "cannot tell
    /// whether the host network is reachable: curl exited 127" instead of being
    /// told curl is not installed. Still fail-closed, so this is message quality
    /// rather than safety — but the script's doc claims it proves curl ran, and
    /// nothing else asserts that.
    #[test]
    fn the_loopback_script_proves_curl_is_there() {
        let script = loopback_script(4321);
        assert!(
            script.contains("command -v curl"),
            "the loopback step must prove curl is installed, got {script:?}"
        );
        assert!(
            script.contains("curl=missing"),
            "and must say so when it is not, got {script:?}"
        );
        assert!(
            script.contains("http://127.0.0.1:4321/"),
            "and must probe the port it was given, got {script:?}"
        );
        // The verdict reads this exact token, so the two cannot drift.
        assert!(
            script.contains("exit=$?"),
            "and must report curl's own exit code, got {script:?}"
        );
    }

    /// A sandboxed process is untrusted, so its output must not be able to grow
    /// this process's memory. `wait_with_output` collects all of it; the probe
    /// must cap what it keeps **while still draining** the pipe — a reader that
    /// stopped at the cap would block the child on a full pipe and turn a merely
    /// noisy job into the 10s step timeout, which is what this asserts against.
    #[tokio::test]
    async fn a_chatty_sandbox_is_captured_without_growing() {
        let scratch = tempfile::tempdir().unwrap();
        let job_dir = resolve_job_dir(scratch.path(), "task-1", "job-1").unwrap();
        // ~1 MB per stream: past `MAX_PROBE_TEXT` by three orders of magnitude,
        // and past a 64 KiB pipe buffer, so both halves of the discipline are
        // exercised by one invocation.
        let (_dir, bin) = stub_bwrap_running(
            "i=0\n\
             while [ $i -lt 10000 ]; do\n\
               echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n\
               echo 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' >&2\n\
               i=$((i+1))\n\
             done\n\
             exit 0",
        );
        let out = run_in_sandbox(
            &bin,
            &job_dir,
            &Grants::default(),
            "x",
            scratch.path(),
            "the chatty step",
        )
        .await
        .expect("a chatty child must complete, not deadlock on a full pipe");
        assert!(out.status.success());
        assert!(
            out.stdout.len() <= MAX_PROBE_TEXT,
            "stdout must be capped at {MAX_PROBE_TEXT}, kept {}",
            out.stdout.len()
        );
        assert!(
            out.stderr.len() <= MAX_PROBE_TEXT,
            "stderr must be capped at {MAX_PROBE_TEXT}, kept {}",
            out.stderr.len()
        );
        assert!(
            !out.stdout.is_empty() && !out.stderr.is_empty(),
            "and the cap keeps the head, not nothing"
        );
    }

    /// A curl step with no timeout of its own turns a blackholed network into a
    /// sandbox failure at the probe's own 10s bound — the wrong diagnosis, and
    /// the one the HTTPS step shipped with. Both curl invocations must bound
    /// themselves.
    #[test]
    fn every_curl_step_bounds_itself() {
        let steps = [
            ("HTTPS", HTTPS_SCRIPT.to_string()),
            ("loopback", loopback_script(1)),
        ];
        for (name, script) in steps {
            assert!(
                script.contains("--connect-timeout 2") && script.contains("--max-time 3"),
                "the {name} step must bound its own connection, got {script:?}"
            );
        }
    }

    /// A sandbox that never ran the check is not the same failure as a sandbox
    /// that allowed a nested namespace, and the operator acts differently on
    /// each.
    #[test]
    fn the_nested_verdict_names_the_right_cause() {
        assert!(verdict_nested(&output_of("nested=blocked\n", "", 0)).is_ok());

        let e = verdict_nested(&output_of("nested=allowed\n", "", 0))
            .unwrap_err()
            .to_string();
        assert!(e.contains("succeeded inside the sandbox"), "got {e:?}");

        let e = verdict_nested(&output_of(
            "",
            "bwrap: No permissions to creating new namespace\n",
            1,
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("did not run"), "got {e:?}");
        assert!(
            e.contains("No permissions"),
            "the cause on stderr must survive, got {e:?}"
        );
    }

    /// A missing curl and a missing CA bundle are different problems with
    /// different fixes, so the HTTPS verdict must not conflate them.
    #[test]
    fn the_https_verdict_separates_a_missing_curl_from_a_missing_bundle() {
        assert!(verdict_https(&output_of("http=200", "", 0)).is_ok());

        let e = verdict_https(&output_of(
            "http=000",
            "curl: (77) error adding trust anchors from file: \
             /etc/ssl/certs/ca-certificates.crt\n",
            77,
        ))
        .unwrap_err()
        .to_string();
        assert!(e.contains("trust anchors"), "got {e:?}");

        let e = verdict_https(&output_of("", "sh: curl: not found\n", 127))
            .unwrap_err()
            .to_string();
        assert!(e.contains("curl did not run"), "got {e:?}");
        assert!(e.contains("curl: not found"), "got {e:?}");
    }

    // --- the per-job sandbox directory (spec §1.3) --------------------------
    //
    // The job directory is the **only** writable host path in the argv, so every
    // refusal here is a hard error. Each test below names the *reason* for the
    // refusal, not merely that one happened: `unwrap_err()` is satisfied by any
    // failure at all, including one that comes from a later step, and a guard
    // that is never reached still passes it.

    #[test]
    fn refuses_the_filesystem_root_as_the_root() {
        let e = resolve_job_dir(Path::new("/"), "t", "j").unwrap_err();
        // The plan's assertion here was `e.to_string().contains("/")`, which has
        // no teeth: every message this function can produce quotes a path, so
        // deleting the `/` guard and letting the failure come from
        // `create_dir_all("/t/j")` satisfied it — which is what a non-root runner
        // observed (`cannot create /t: Permission denied`). It was **removed**
        // rather than kept beside this one, because a toothless assertion inside
        // a security test is a trap for the next reader, who may take the pair
        // for one check and delete the wrong half.
        assert!(e.to_string().contains("must not be /"), "{e}");
    }

    /// A project workspace that happens to hold a `config.toml` is **not** the
    /// HaosGreen home directory. Keying the guard on `config.toml` alone refused
    /// every shell job in any project that has one — a Rust or Python project,
    /// for instance — and reported the denial as a security refusal. A control
    /// that can only break the feature is worse than the narrow one it replaces,
    /// so the guard keys on the home layout instead.
    #[test]
    fn a_project_workspace_that_holds_config_toml_is_accepted() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("config.toml"), "[package]\nname = \"thing\"\n").unwrap();
        let got = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        assert!(got.path().is_dir());
        assert_eq!(
            got.path(),
            std::fs::canonicalize(&ws)
                .unwrap()
                .join("task-1")
                .join("job-1"),
        );
    }

    /// `haos-green.db` is created by this application in its home directory and
    /// is not a name ordinary project content uses, so it identifies the "root
    /// is the home directory" mistake without the false positives `config.toml`
    /// brings.
    #[test]
    fn refuses_a_root_that_holds_the_haos_green_database() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("haos-green.db"), "").unwrap();
        let e = resolve_job_dir(home.path(), "t", "j")
            .unwrap_err()
            .to_string();
        assert!(e.contains("haos-green.db"), "{e}");
        assert!(e.contains("home directory"), "{e}");
        assert!(
            !home.path().join("t").exists(),
            "the job directory was created"
        );
    }

    #[test]
    fn refuses_a_root_that_holds_the_dashboard_credentials() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("web-auth.toml"), "").unwrap();
        let e = resolve_job_dir(home.path(), "t", "j")
            .unwrap_err()
            .to_string();
        assert!(e.contains("web-auth.toml"), "{e}");
        assert!(
            !home.path().join("t").exists(),
            "the job directory was created"
        );
    }

    #[test]
    fn a_workspace_root_is_accepted_and_the_job_dir_is_created() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let got = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        assert!(got.path().is_dir());
        assert!(got.path().starts_with(std::fs::canonicalize(&ws).unwrap()));
        assert_ne!(
            got.path(),
            std::fs::canonicalize(&ws).unwrap(),
            "never the root itself"
        );
        // The layout is normative (`<root>/<task-id>/<job-id>`, spec §1.3).
        // Containment and "is a directory" both still hold for a path that
        // dropped the job id — and then two jobs of one task would share a
        // directory, which is the thing per-job directories exist to prevent.
        assert_eq!(
            got.path(),
            std::fs::canonicalize(&ws)
                .unwrap()
                .join("task-1")
                .join("job-1"),
        );
    }

    /// The job level, symlinked out of the root. This one asserts the message
    /// and not the side effect, because there is no side effect to assert: the
    /// task level already exists as a real directory, so the job level is
    /// `mkdirat` on the symlink, which returns `EEXIST` without following it —
    /// a dangling symlink is refused by the same call, which is the case
    /// `a_dangling_symlink_at_a_level_is_refused_by_name` pins.
    #[test]
    fn a_symlinked_job_dir_pointing_out_of_the_root_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(ws.join("task-1")).unwrap();
        std::fs::create_dir_all(home.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(home.path().join("elsewhere"), ws.join("task-1/job-1")).unwrap();
        let e = resolve_job_dir(&ws, "task-1", "job-1").unwrap_err();
        assert!(e.to_string().contains("outside"), "{e}");
        assert_eq!(
            std::fs::read_dir(home.path().join("elsewhere"))
                .unwrap()
                .count(),
            0,
            "the symlink target was written through"
        );
    }

    /// A relative root is resolved against whatever the process's cwd happens to
    /// be, which is not a decision the operator made. Refused, not guessed at.
    #[test]
    fn a_relative_root_is_refused() {
        let e = resolve_job_dir(Path::new("workspace"), "t", "j").unwrap_err();
        assert!(e.to_string().contains("not absolute"), "{e}");
    }

    /// The invariant is *strictly* below the root, never equal to it (spec
    /// §1.3). Component validation closes the empty-id route to that clause, but
    /// it is still reachable through a symlink: a task-level link pointing back
    /// at the root resolves to the root itself, and a job directory that *is*
    /// the root is the whole root bound read-write.
    #[test]
    fn a_task_dir_symlinked_to_the_root_itself_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink(&ws, ws.join("task-1")).unwrap();
        let e = resolve_job_dir(&ws, "task-1", "job-1").unwrap_err();
        assert!(
            e.to_string().contains("is the sandbox root itself"),
            "the refusal must name the root, not an escape: {e}"
        );
    }

    /// Ids are joined onto the root, so an id that is not one ordinary path
    /// component can move the job directory out of it: `..` walks out and an
    /// absolute id replaces the whole path. `create_dir_all` would then create
    /// that directory *before* the containment check refused it, so the ids are
    /// validated before the first filesystem call — and the assertion is that
    /// nothing appeared, not merely that an error came back.
    ///
    /// "Nothing appeared" is asserted where it is observable and nowhere else:
    /// the root's listing, the parent's listing, and the symlink target. This is
    /// not a claim that no directory anywhere was created — the id never reaches
    /// a filesystem call at all, which is what the ordering guarantees, and the
    /// three listings are what this test can see of it.
    ///
    /// Both positions are exercised, and in separate tests, because the two
    /// validations are separate guards: a mutation dropping either one has to
    /// fail a test of its own.
    fn assert_refused_without_creating_anything(
        home: &Path,
        ws: &Path,
        elsewhere: &Path,
        task: &str,
        job: &str,
    ) {
        let e = resolve_job_dir(ws, task, job).unwrap_err();
        assert!(
            e.to_string().contains("not a single path component"),
            "{task:?}/{job:?}: {e}"
        );
        assert_eq!(
            std::fs::read_dir(ws).unwrap().count(),
            0,
            "{task:?}/{job:?} created something inside the root"
        );
        let mut left: Vec<String> = std::fs::read_dir(home)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec!["elsewhere".to_string(), "workspace".to_string()],
            "{task:?}/{job:?}: a refusal created something outside the root"
        );
        assert!(!elsewhere.join("job-1").exists() && !elsewhere.join("task-1").exists());
    }

    /// A `(home, workspace, elsewhere)` triple with both directories created,
    /// plus the traversal shapes to try. The absolute shape is a real path
    /// inside the tempdir, so the old create-then-check order would write there
    /// rather than at the filesystem root.
    fn traversal_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Vec<String>) {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        let elsewhere = home.path().join("elsewhere");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        // `to_string_lossy` rather than `to_str().unwrap()`: a non-UTF-8
        // `TMPDIR` is not a reason to panic a test. The shape only has to be
        // an absolute path, and the assertions are that nothing was created.
        let abs = elsewhere.to_string_lossy().into_owned();
        (
            home,
            ws,
            elsewhere,
            vec!["".into(), ".".into(), "..".into(), "a/b".into(), abs],
        )
    }

    #[test]
    fn traversal_shaped_task_ids_are_refused_before_anything_is_created() {
        let (home, ws, elsewhere, shapes) = traversal_fixture();
        for bad in &shapes {
            assert_refused_without_creating_anything(home.path(), &ws, &elsewhere, bad, "job-1");
        }
    }

    #[test]
    fn traversal_shaped_job_ids_are_refused_before_anything_is_created() {
        let (home, ws, elsewhere, shapes) = traversal_fixture();
        for bad in &shapes {
            assert_refused_without_creating_anything(home.path(), &ws, &elsewhere, "task-1", bad);
        }
    }

    /// The ids are checked before the root itself is created, so the configured
    /// root must not exist afterwards. That is the one place this test can
    /// observe the ordering: the id never reaches a filesystem call, so there is
    /// no other directory it could have left behind.
    #[test]
    fn a_traversal_id_does_not_create_the_root_either() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        let e = resolve_job_dir(&ws, "..", "job-1").unwrap_err();
        assert!(e.to_string().contains("not a single path component"), "{e}");
        assert!(
            !ws.exists(),
            "the root was created before the ids were validated"
        );
    }

    /// A pre-existing symlink at the *task* level survives component validation
    /// — `task-1` is a legitimate single component — so it is caught by
    /// checking each level before descending into the next. `create_dir_all` on
    /// a symlink to an existing directory creates nothing, which is what makes
    /// this the level to check: the job directory is refused without anything
    /// having been written through the link.
    #[test]
    fn a_symlinked_task_dir_is_refused_without_writing_through_it() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        let elsewhere = home.path().join("elsewhere");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, ws.join("task-1")).unwrap();

        let e = resolve_job_dir(&ws, "task-1", "job-1").unwrap_err();
        assert!(e.to_string().contains("outside the sandbox root"), "{e}");
        assert!(
            !elsewhere.join("job-1").exists(),
            "the job directory was created through the symlink before the refusal"
        );
    }

    /// An in-root symlink passes containment — it resolves to a directory inside
    /// the root — but it breaks the layout the spec makes normative: two ids
    /// symlinked to one directory would share a sandbox, which is what per-job
    /// directories exist to prevent.
    #[test]
    fn an_in_root_task_symlink_is_refused_rather_than_aliasing_the_layout() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(ws.join("other")).unwrap();
        std::os::unix::fs::symlink(ws.join("other"), ws.join("task-1")).unwrap();

        let e = resolve_job_dir(&ws, "task-1", "job-1").unwrap_err();
        assert!(e.to_string().contains("rather than to itself"), "{e}");
        assert_eq!(
            std::fs::read_dir(ws.join("other")).unwrap().count(),
            0,
            "the alias was written through before the refusal"
        );
    }

    /// The same rule one level down: `job-1` symlinked to a sibling directory
    /// inside the task directory.
    #[test]
    fn an_in_root_job_symlink_is_refused_rather_than_aliasing_the_layout() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(ws.join("task-1/other")).unwrap();
        std::os::unix::fs::symlink(ws.join("task-1/other"), ws.join("task-1/job-1")).unwrap();

        let e = resolve_job_dir(&ws, "task-1", "job-1").unwrap_err();
        assert!(e.to_string().contains("rather than to itself"), "{e}");
        assert_eq!(
            std::fs::read_dir(ws.join("task-1/other")).unwrap().count(),
            0,
            "the alias was written through before the refusal"
        );
    }

    /// `Path::components()` normalises a trailing `/` and `/.` away, so `a/` and
    /// `a/.` are the aliases of `a` that they are. What is joined is the
    /// normalised component, never the raw string: that is what makes the layout
    /// `<root>/<task-id>/<job-id>` literally true, and what keeps the
    /// "resolves to itself" refusal from rejecting `job-1/.` for a reason that
    /// has nothing to do with symlinks.
    ///
    /// The assertion is on the **entries that were created**, not on `Path`
    /// equality: `Path` equality ignores a trailing separator and `.`, so
    /// comparing paths here would pass for an implementation that joined the raw
    /// string and happened to canonicalise afterwards. The names are what the
    /// layout promises.
    #[test]
    fn an_id_is_joined_as_its_normalised_component() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let got = resolve_job_dir(&ws, "task-1/", "job-1/.").unwrap();

        let tasks: Vec<_> = std::fs::read_dir(&ws)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(tasks, vec![OsStr::new("task-1")], "the task level");
        let jobs: Vec<_> = std::fs::read_dir(got.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(jobs.is_empty(), "the job directory starts empty: {jobs:?}");
        assert_eq!(
            got.path().file_name().unwrap(),
            OsStr::new("job-1"),
            "the job level must be named exactly the id: {got:?}"
        );
        assert_eq!(
            got.path().parent().unwrap().file_name().unwrap(),
            OsStr::new("task-1"),
            "the task level must be named exactly the id: {got:?}"
        );
    }

    /// The root is created when it does not exist yet — the operator names it,
    /// and the first job is what makes it.
    #[test]
    fn the_sandbox_root_is_created_when_it_does_not_exist_yet() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("nested/workspace");
        let got = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        assert_eq!(
            got.path(),
            std::fs::canonicalize(&ws)
                .unwrap()
                .join("task-1")
                .join("job-1"),
        );
    }

    /// Resolving the same job twice finds the levels the first call created
    /// rather than failing on them.
    #[test]
    fn resolving_the_same_job_twice_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        let first = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        let second = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        assert_eq!(first.path(), second.path());
        assert!(second.path().is_dir());
    }

    /// A root that exists but is not a directory, and one that is a symlink to
    /// nothing. Both were reported as `cannot create …: File exists (os error
    /// 17)`, which names a cause that is not the cause.
    #[test]
    fn a_root_that_is_not_a_directory_is_refused_by_name() {
        let home = tempfile::tempdir().unwrap();
        let file = home.path().join("workspace");
        std::fs::write(&file, "not a directory").unwrap();
        let e = resolve_job_dir(&file, "t", "j").unwrap_err().to_string();
        assert!(e.contains("is not a directory"), "{e}");
    }

    #[test]
    fn a_root_that_is_a_dangling_symlink_is_refused_by_name() {
        let home = tempfile::tempdir().unwrap();
        let link = home.path().join("workspace");
        std::os::unix::fs::symlink(home.path().join("gone"), &link).unwrap();
        let e = resolve_job_dir(&link, "t", "j").unwrap_err().to_string();
        assert!(e.contains("symlink to a target that does not exist"), "{e}");
    }

    #[test]
    fn a_dangling_symlink_at_a_level_is_refused_by_name() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        std::os::unix::fs::symlink(home.path().join("gone"), ws.join("task-1")).unwrap();
        let e = resolve_job_dir(&ws, "task-1", "job-1")
            .unwrap_err()
            .to_string();
        assert!(e.contains("symlink to a target that does not exist"), "{e}");
    }

    /// Containment is a path-component test, not a string-prefix test. A sibling
    /// whose *name* extends the root's name — `/…/ws-evil` beside `/…/ws` —
    /// starts with the root as a string and is outside it. Comparing the two as
    /// strings passes every other test in this module.
    #[test]
    fn a_symlink_to_a_sibling_whose_name_extends_the_root_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("ws");
        let sibling = home.path().join("ws-evil");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        std::os::unix::fs::symlink(&sibling, ws.join("task-1")).unwrap();

        let e = resolve_job_dir(&ws, "task-1", "job-1")
            .unwrap_err()
            .to_string();
        assert!(e.contains("outside the sandbox root"), "{e}");
        assert_eq!(
            std::fs::read_dir(&sibling).unwrap().count(),
            0,
            "a directory was created outside the root"
        );
    }

    /// An id with a control character is refused at validation, before it can
    /// become a path or reach a message — and the refusal still escapes it, so
    /// the rule does not rest on the rejection alone.
    #[test]
    fn a_control_character_in_an_id_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let evil = "a\nFORGED LOG LINE: sandbox disabled\nb";
        let e = resolve_job_dir(&ws, evil, "job-1").unwrap_err().to_string();
        assert!(e.contains("control character"), "{e}");
        assert!(
            e.contains("FORGED LOG LINE"),
            "the id must still be quoted back: {e}"
        );
        assert!(
            !e.contains('\n'),
            "a raw newline reached the message: {e:?}"
        );
        assert!(e.contains("\\n"), "the newline must be escaped: {e}");
        assert_eq!(
            std::fs::read_dir(&ws).unwrap().count(),
            0,
            "the id reached the filesystem"
        );
    }

    /// The root is operator-supplied too, and reaches these messages by a route
    /// `one_component` cannot cover: a directory whose *name* contains a newline
    /// is legal, and `Path::display()` would put it into the message raw.
    #[test]
    fn a_newline_in_the_root_path_is_escaped_in_every_message() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("work\nspace");
        let other = ws.join("other");
        std::fs::create_dir_all(&other).unwrap();

        // A symlink to another directory *inside* the root: the refusal quotes
        // `dir`, which is built from the root and so carries the newline.
        std::os::unix::fs::symlink(&other, ws.join("task-1")).unwrap();
        let e = resolve_job_dir(&ws, "task-1", "job-1")
            .unwrap_err()
            .to_string();
        assert!(e.contains("rather than to itself"), "{e}");
        assert!(
            !e.contains('\n'),
            "a raw newline reached the message: {e:?}"
        );
        assert!(
            e.contains("work\\nspace"),
            "the root must still be quoted: {e}"
        );

        // A relative root with a newline reaches the "not absolute" message.
        let e = resolve_job_dir(Path::new("work\nspace"), "t", "j")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not absolute"), "{e}");
        assert!(
            !e.contains('\n'),
            "a raw newline reached the message: {e:?}"
        );
        assert!(
            e.contains("work\\nspace"),
            "the root must still be quoted: {e}"
        );
    }

    /// The one thing a *concurrent* writer can still do, and the reason each
    /// level is created relative to the descriptor of the level above it: a
    /// symlink swapped in after that level was verified cannot redirect the
    /// creation, because `mkdirat` creates inside the directory the descriptor
    /// names or fails. Creating by path instead lets a writer looping on the
    /// swap get a directory created outside the root — measured at 1472 of 8246
    /// refusals over 15 s of swapping before this.
    ///
    /// This is the end-to-end detector, and it is one-sided: it fails only when
    /// the swap wins a race, so on a machine where the window is never hit it
    /// cannot go red. Two things keep it honest. `refused > 0` asserts the loop
    /// actually met the swapped-in state it claims to be testing — under
    /// contention refusals are the common case, so a run with none means the
    /// swapper never interfered and the loop proved nothing. And
    /// `a_level_swapped_for_a_symlink_cannot_redirect_the_level_below` drives the
    /// same window with no race at all, so the property does not rest on this
    /// test's timing.
    #[test]
    fn a_concurrent_swap_cannot_create_a_directory_outside_the_root() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        /// Stops and joins the swapper on **both** paths. The assertion below
        /// unwinds, and a spinning thread leaked on the failing path is how a red
        /// test becomes a flaky one.
        struct Swapper {
            stop: Arc<AtomicBool>,
            handle: Option<std::thread::JoinHandle<()>>,
        }
        impl Drop for Swapper {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
        }

        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        let elsewhere = home.path().join("elsewhere");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let link = ws.join("task-1");
        let target = elsewhere.clone();
        let _swapper = Swapper {
            stop: Arc::clone(&stop),
            handle: Some({
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut real = true;
                    while !stop.load(Ordering::Relaxed) {
                        let _ = std::fs::remove_file(&link);
                        let _ = std::fs::remove_dir_all(&link);
                        if real {
                            let _ = std::fs::create_dir(&link);
                        } else {
                            let _ = std::os::unix::fs::symlink(&target, &link);
                        }
                        real = !real;
                    }
                })
            }),
        };

        let mut refused = 0usize;
        for _ in 0..2000 {
            if resolve_job_dir(&ws, "task-1", "job-1").is_err() {
                refused += 1;
            }
            assert!(
                !elsewhere.join("job-1").exists(),
                "a directory was created outside the root while the level was swapped \
                 ({refused} refusals so far)"
            );
        }
        assert!(
            refused > 0,
            "the loop never met the swapped-in state: the swapper did not interfere, so \
             this run asserted nothing about the property it is named for"
        );
    }

    /// The window the concurrent test hunts for, with no race in it: the swap is
    /// done *between* the two levels, by the test, which is the interleaving the
    /// thread only sometimes wins.
    ///
    /// The level above has been created, verified and opened; its path is then
    /// replaced by a symlink. The creation below is `mkdirat` on the descriptor,
    /// so it lands inside the directory the descriptor names or fails — it cannot
    /// be redirected to the swap target, which is exactly what a path-based
    /// `create_dir_all` did.
    #[test]
    fn a_level_swapped_for_a_symlink_cannot_redirect_the_level_below() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        let elsewhere = home.path().join("elsewhere");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();

        let root = std::fs::canonicalize(&ws).unwrap();
        let root_fd = open_dir(&root).unwrap();
        let (task_dir, task_fd) =
            create_within(&root_fd, &root, &root.join("task-1"), OsStr::new("task-1")).unwrap();

        std::fs::remove_dir_all(&task_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("task-1")).unwrap();

        let outcome = create_within(
            &task_fd,
            &root,
            &task_dir.join("job-1"),
            OsStr::new("job-1"),
        );
        assert!(
            !elsewhere.join("job-1").exists(),
            "the swap redirected the creation: {:?}",
            outcome.map(|(path, _fd)| path)
        );
    }

    /// The residual this design accepts, pinned so the documentation and the
    /// behaviour cannot drift apart. A writer that **moves** the verified
    /// directory out of the root still gets the level below created inside it,
    /// because a descriptor follows the inode, not the name — and an empty
    /// directory is therefore created outside the root. The call still fails
    /// closed: it never *returns* a path outside the root, and the containment
    /// check refuses the result.
    ///
    /// That is the price of closing the symlink variant, and the writer has to
    /// hold write access to both ends to do it, so it gains no privilege it did
    /// not already have. If someone closes this too, this test fails — which is
    /// the point of pinning a residual rather than describing it.
    #[test]
    fn the_move_residual_creates_a_directory_outside_the_root_and_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let root = std::fs::canonicalize(&ws).unwrap();
        let root_fd = open_dir(&root).unwrap();
        let (task_dir, task_fd) =
            create_within(&root_fd, &root, &root.join("task-1"), OsStr::new("task-1")).unwrap();

        let moved = home.path().join("moved");
        std::fs::rename(&task_dir, &moved).unwrap();

        let outcome = create_within(
            &task_fd,
            &root,
            &task_dir.join("job-1"),
            OsStr::new("job-1"),
        );
        assert!(
            outcome.is_err(),
            "a moved level must still be refused, never returned: {:?}",
            outcome.map(|(path, _fd)| path)
        );
        assert!(
            moved.join("job-1").exists(),
            "the move residual has been closed — update spec §1.3 and this test"
        );
    }

    /// Containment asserted as a **property**, not as prose: which clause fired,
    /// as a value. Matching on the message instead would let a future relaxation
    /// of one clause pass for containment still working, because another clause
    /// produces a similar message — and the sibling case below is exactly that
    /// shape: `/ws-evil` is outside `/ws`, but it starts with `/ws` as a string.
    #[test]
    fn containment_is_decided_by_path_components_not_by_text() {
        let root = Path::new("/home/u/ws");
        let dir = Path::new("/home/u/ws/task-1/job-1");
        assert_eq!(
            containment_refusal(root, dir, Path::new("/home/u/ws/task-1/job-1")),
            None,
            "a path below the root that resolves to itself is the only accepted shape"
        );
        for outside in [
            "/home/u/ws-evil/job-1",
            "/home/u/ws-evil",
            "/home/u",
            "/home",
            "/",
        ] {
            assert_eq!(
                containment_refusal(root, dir, Path::new(outside)),
                Some(Refusal::OutsideRoot),
                "{outside} is outside {root:?} and must be refused as such"
            );
        }
        assert_eq!(
            containment_refusal(root, dir, root),
            Some(Refusal::IsTheRoot),
            "the root itself is not below the root"
        );
        assert_eq!(
            containment_refusal(root, dir, Path::new("/home/u/ws/other/job-1")),
            Some(Refusal::NotItself),
            "in-root but not what the path names: a symlink"
        );
    }

    /// `O_PATH` is what lets the root be a directory this process cannot read:
    /// nothing here reads the directory's contents, only `mkdirat`/`openat`
    /// relative to it. Mode 0333 is writable and traversable but not readable,
    /// and the read-only open this replaced refused it with `Permission denied`.
    ///
    /// As root the kernel bypasses the permission bits, so the behavioural half
    /// is masked there and proven by running the suite as uid 1000; the flag
    /// assertion in the next test is what holds for every uid.
    #[test]
    fn a_root_that_cannot_be_read_is_still_usable() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let mut perms = std::fs::metadata(&ws).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o333);
        std::fs::set_permissions(&ws, perms).unwrap();

        let got = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        assert!(
            got.path().ends_with("task-1/job-1"),
            "a writable-but-unreadable root is usable: {got:?}"
        );
    }

    /// Read the descriptor's own flags back and check all four. None of them is
    /// visible in a return value, so this is where they can be pinned at all:
    ///
    /// - `O_PATH` — the root need not be readable (above);
    /// - `O_DIRECTORY` — a non-directory at a level must be refused *there*.
    ///   Measured: without it, a FIFO is opened as a descriptor and the refusal
    ///   arrives one level down as `cannot create …/job-1: Not a directory`, and
    ///   a symlink is opened as a descriptor **for the symlink** — `O_PATH` with
    ///   `O_NOFOLLOW` and no `O_DIRECTORY` is the documented "open the link
    ///   itself" form, not a refusal. `O_PATH` also means an open can no longer
    ///   block on a FIFO at all, which is why this is correctness here rather
    ///   than the liveness guard it was for a read-only open;
    /// - `O_NOFOLLOW` — a symlink swapped in becomes the parent of the next level;
    /// - `FD_CLOEXEC` — neither descriptor may leak into the sandboxed child.
    #[test]
    fn the_descriptors_carry_the_flags_the_race_and_the_permissions_need() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let root = std::fs::canonicalize(&ws).unwrap();
        let root_fd = open_dir(&root).unwrap();
        assert_descriptor_flags(&root_fd, "the root descriptor");

        std::fs::create_dir(root.join("task-1")).unwrap();
        let level_fd = open_dir_in(&root_fd, OsStr::new("task-1")).unwrap();
        assert_descriptor_flags(&level_fd, "a level descriptor");
    }

    /// `F_GETFL` on an `O_PATH` descriptor reports `O_PATH`, `O_DIRECTORY` and
    /// `O_NOFOLLOW`, and `F_GETFD` reports `FD_CLOEXEC`.
    fn assert_descriptor_flags(fd: &OwnedFd, what: &str) {
        // SAFETY: `fd` is open for the duration of the call.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "{what}: F_GETFL failed");
        for (name, want) in [
            ("O_PATH", libc::O_PATH),
            ("O_DIRECTORY", libc::O_DIRECTORY),
            ("O_NOFOLLOW", libc::O_NOFOLLOW),
        ] {
            assert!(
                flags & want != 0,
                "{what} is missing {name}: F_GETFL = 0o{flags:o}"
            );
        }
        // SAFETY: as above.
        let fd_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(
            fd_flags & libc::FD_CLOEXEC != 0,
            "{what} would be inherited by the sandboxed child: F_GETFD = {fd_flags}"
        );
    }

    /// The descriptor [`JobDir`] carries names the directory its path names.
    ///
    /// Without this the two could drift — a descriptor for the task level, or
    /// for a level opened before the last `mkdirat` — and `--bind-fd` would
    /// mount the wrong directory while every string in the argv still looked
    /// right.
    #[test]
    fn the_job_directory_descriptor_names_the_directory_the_path_names() {
        let (_root, jd) = test_job_dir();
        assert!(jd.path().is_dir(), "the path is the directory");
        // `readlink` on the `/proc` entry names the inode the descriptor holds,
        // which is the property `--bind-fd` acts on.
        let via_fd = std::fs::read_link(format!("/proc/self/fd/{}", jd.fd.as_raw_fd()))
            .expect("the descriptor must be readable through /proc/self/fd");
        assert_eq!(
            via_fd,
            jd.path(),
            "the descriptor and the path must name one directory"
        );
    }

    /// `inheritable_fd` clears `FD_CLOEXEC` on the **duplicate only**, and the
    /// child really does inherit it.
    ///
    /// Both halves are load-bearing and they pull in opposite directions:
    ///
    /// - cleared on the **original**, the descriptor is inherited by every later
    ///   `exec` in this process — the probe's `bwrap` invocations, every other
    ///   job's child — which is a handle into the sandbox root held by processes
    ///   that have no business holding one;
    /// - left set on the **duplicate**, the child never sees it and
    ///   `bwrap --bind-fd` fails with a descriptor that is not open.
    ///
    /// The `readlink` is what makes the second half real rather than a flag
    /// check: it is a child process, spawned the way production spawns one,
    /// naming the directory through the descriptor it was handed.
    #[tokio::test]
    async fn the_inheritable_duplicate_reaches_the_child_and_the_original_stays_cloexec() {
        let (_root, jd) = test_job_dir();
        let dup = jd.inheritable_fd().unwrap();
        // SAFETY: both descriptors are open for the duration of the call.
        let fd_flags = |fd: i32| unsafe { libc::fcntl(fd, libc::F_GETFD) };

        let original = fd_flags(jd.fd.as_raw_fd());
        assert!(original >= 0, "the original descriptor is not open");
        assert_ne!(
            dup.as_raw_fd(),
            jd.fd.as_raw_fd(),
            "the duplicate must be a second descriptor, not the original"
        );
        assert_eq!(
            original & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
            "the original must stay close-on-exec, or every later exec in this \
             process inherits a handle into the sandbox root"
        );
        let duplicated = fd_flags(dup.as_raw_fd());
        assert!(duplicated >= 0, "the duplicate is not open");
        assert_eq!(
            duplicated & libc::FD_CLOEXEC,
            0,
            "the duplicate must be inheritable, or the child cannot see it at all"
        );

        let out = crate::supervisor::bounded(
            "the descriptor-inheritance check",
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(format!("readlink /proc/self/fd/{}", dup.as_raw_fd()))
                .output(),
        )
        .await
        .expect("the child must run");
        assert!(
            out.status.success(),
            "readlink failed in the child: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            jd.path().to_string_lossy(),
            "the child must inherit exactly this descriptor, naming the job directory"
        );
    }

    /// A FIFO at a level is refused **at that level**, not accepted as a
    /// directory and then failed one level down. `O_DIRECTORY` is what makes the
    /// open refuse it; without the flag the open succeeds, the resolve carries on
    /// with a descriptor for something that is not a directory, and the error
    /// names `…/task-1/job-1` instead — measured. The assertion that the refusal
    /// does not mention the job level is what pins that.
    ///
    /// The resolve also runs on a helper thread with a deadline, as a safety net:
    /// this suite has no way to report a hang, so a future change that made the
    /// open wait — a read-only open on a FIFO does — would fail here instead of
    /// wedging the binary with no test named.
    #[test]
    fn a_fifo_at_a_level_is_refused_instead_of_blocking() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let fifo = ws.join("task-1");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path in a directory that exists.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let (tx, rx) = std::sync::mpsc::channel();
        let root = ws.clone();
        std::thread::spawn(move || {
            let _ = tx.send(resolve_job_dir(&root, "task-1", "job-1").map_err(|e| e.to_string()));
        });
        let outcome = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(outcome) => outcome,
            Err(_) => panic!(
                "resolve_job_dir did not return within 10s: the open blocked on a FIFO, \
                 which is what O_DIRECTORY is there to prevent"
            ),
        };
        let e = outcome.unwrap_err();
        assert!(e.contains("not a directory"), "{e}");
        assert!(
            !e.contains("job-1"),
            "the FIFO must be refused when it is opened, not one level below: {e}"
        );
    }

    /// `O_NOFOLLOW`, deterministically: a level that is a symlink is not
    /// followed by the `openat` that produces the descriptor for the level
    /// below. The symlink points *inside* the root, so containment is not what
    /// refuses it — the flag is, and the refusal has to come from the open
    /// itself. Without `O_NOFOLLOW` this open succeeds, which is the whole
    /// difference between a descriptor for the level and a descriptor for
    /// whatever the level was swapped to point at.
    ///
    /// The errno is `ENOTDIR`, not `ELOOP`: with `O_DIRECTORY` as well, Linux
    /// reports the type mismatch rather than the symlink. Either way the symlink
    /// is not followed, which is what this asserts.
    #[test]
    fn a_symlinked_level_is_not_followed_by_the_open() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(ws.join("real")).unwrap();
        std::os::unix::fs::symlink(ws.join("real"), ws.join("task-1")).unwrap();

        let root = std::fs::canonicalize(&ws).unwrap();
        let root_fd = open_dir(&root).unwrap();
        let err = open_dir_in(&root_fd, OsStr::new("task-1")).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "a symlinked level must be refused by the open itself, not followed: {err}"
        );
    }
}
