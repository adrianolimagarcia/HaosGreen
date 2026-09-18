//! Bubblewrap sandbox for the supervisor's shell backend.
//!
//! One module owns the version floor, the argv and the job-directory
//! invariants, so the sandbox is described in exactly one place and the tests
//! exercise the same builder production uses.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

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
/// `Serialize`/`Deserialize` are here because `Task` and `Job` both carry a
/// declaration and both are serde types (`src/supervisor/task.rs:56`,
/// `src/supervisor/job.rs:52`); the field is `#[serde(default)]` so a stored
/// task without one reads back as "declares nothing".
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

/// Build the full bubblewrap argv. **Order is normative** — see the tests.
///
/// `job_dir` must already have passed [`resolve_job_dir`].
///
/// `grants` is what the operator holds **now**: each write grant adds a
/// read-write `--bind`, and the network grant adds `--share-net`. This is where
/// authorization becomes a bind — there is nowhere else it can happen.
pub fn build_argv(job_dir: &Path, grants: &Grants, command: &str) -> Vec<String> {
    let dir = job_dir.to_string_lossy().to_string();
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
        "--bind".into(),
        dir.clone(),
        dir.clone(),
        "--chdir".into(),
        dir,
        "/bin/sh".into(),
        "-c".into(),
        command.to_string(),
    ]);
    a
}

/// Bound on one probe invocation, in seconds.
///
/// A hang detector, not a performance assertion — the same reasoning as
/// `supervisor::bounded`. The probe runs at startup, so one wedged step would
/// hold the process before it ever serves a message; the longest legitimate
/// step is the network check, which carries curl's own `--max-time 3`.
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
/// properties the boundary claims (spec §6). Any failure is
/// [`IsolationUnavailable::SmokeTestFailed`], carrying the step that failed.
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
    let job_dir = scratch.join("job");
    std::fs::create_dir_all(&job_dir).map_err(|e| smoke("the scratch job directory", e))?;
    let job_dir =
        std::fs::canonicalize(&job_dir).map_err(|e| smoke("the scratch job directory", e))?;
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    let field = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .map(str::to_string)
    };
    let expect = |k: &str, want: &str, what: &str| -> Result<(), IsolationUnavailable> {
        match field(k).as_deref() {
            Some(v) if v == want => Ok(()),
            other => Err(smoke(what, format!("expected {k}={want}, got {other:?}"))),
        }
    };

    let home = job_dir.to_string_lossy().to_string();
    expect("shell", "ok", "the shell starts")?;
    expect("home", &home, "$HOME is the job directory")?;
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
        &home,
        "the cwd is the job directory (--chdir took effect)",
    )?;
    expect("hostname", "haos-sandbox", "the hostname is haos-sandbox")?;
    expect("passwd", "unreadable", "/etc/passwd is unreadable")?;
    expect("shadow", "absent", "/etc/shadow is absent")?;
    // Guarded by the same rule the argv uses to decide what to bind
    // (`push_ro_bind_if_present`): a certificate path the host does not have is
    // skipped, never demanded. On Debian/Ubuntu the second path is absent; on
    // Fedora both are, and the base set as specified has no CA store at all.
    if Path::new(SMOKE_CA_BUNDLE).exists() {
        expect(
            "cabundle",
            "readable",
            "the CA bundle is readable inside the sandbox",
        )?;
    }
    expect("writable", "yes", "the job directory is writable")?;

    // `--disable-userns` asks; with `--assert-userns-disabled` this is what
    // proves the restriction took effect on this kernel.
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        "unshare --user true 2>/dev/null && echo nested=allowed || echo nested=blocked",
        probe_cwd,
        "nested user namespaces are blocked",
    )
    .await?;
    if !String::from_utf8_lossy(&out.stdout).contains("nested=blocked") {
        return Err(smoke(
            "nested user namespaces are blocked",
            "`unshare --user` succeeded inside the sandbox",
        ));
    }

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
        let out = run_in_sandbox(
            bwrap,
            &job_dir,
            grants,
            "curl -fsS -o /dev/null -w 'http=%{http_code}' https://example.com",
            probe_cwd,
            "HTTPS works",
        )
        .await?;
        let body = String::from_utf8_lossy(&out.stdout);
        if !body.contains("http=2") {
            return Err(smoke(
                "HTTPS works",
                format!(
                    "curl exited {:?} with {body:?} / {:?}; a `(77) error adding trust anchors` \
                     means the /etc/ssl/certs and /etc/ca-certificates binds are missing or \
                     unresolvable",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            ));
        }
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
        &format!(
            "curl -sS --connect-timeout 2 --max-time 3 -o /dev/null \
             http://127.0.0.1:{port}/ ; echo exit=$?"
        ),
        probe_cwd,
        "the host network is reachable only under a grant",
    )
    .await?;
    let reachable = !String::from_utf8_lossy(&out.stdout).contains("exit=7");
    match (grants.network, reachable) {
        (true, false) => {
            return Err(smoke(
                "the host network is reachable under a grant",
                "the network grant is held but 127.0.0.1 is unreachable: --share-net did not \
                 take effect",
            ))
        }
        (false, true) => {
            return Err(smoke(
                "the host network is unreachable without a grant",
                "no network grant is held but 127.0.0.1 is reachable",
            ))
        }
        _ => {}
    }
    // The listener is still open here on purpose — dropping it would close the
    // port and make the "reachable" case fail. The `drop` is explicit so the
    // intent survives a later reordering of this function.
    drop(listener);
    Ok(())
}

/// Run the production argv in the sandbox, bounded. `step` names what the
/// invocation was for, so a spawn failure or a timeout is reported the same way
/// an assertion failure is.
async fn run_in_sandbox(
    bwrap: &Path,
    job_dir: &Path,
    grants: &Grants,
    command: &str,
    cwd: &Path,
    step: &str,
) -> Result<std::process::Output, IsolationUnavailable> {
    let argv = build_argv(job_dir, grants, command);
    let mut cmd = tokio::process::Command::new(bwrap);
    cmd.args(&argv)
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
    let child = cmd
        .spawn()
        .map_err(|e| smoke(step, format!("cannot run {}: {e}", bwrap.display())))?;
    let bound = std::time::Duration::from_secs(PROBE_STEP_TIMEOUT_SECS);
    match tokio::time::timeout(bound, child.wait_with_output()).await {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(smoke(step, e)),
        Err(_) => Err(smoke(
            step,
            format!("did not finish within {PROBE_STEP_TIMEOUT_SECS}s"),
        )),
    }
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

    #[test]
    fn argv_unshares_and_hardens_namespaces() {
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
        assert!(a.contains(&"--unshare-all".to_string()));
        // --unshare-all is only --unshare-user-try: it is silently skipped when
        // the user namespace cannot be created, so it must be named explicitly.
        assert!(a.contains(&"--unshare-user".to_string()));
        assert!(a.contains(&"--disable-userns".to_string()));
        assert!(a.contains(&"--assert-userns-disabled".to_string()));
    }

    #[test]
    fn argv_detaches_the_terminal_and_dies_with_the_parent() {
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
        assert!(a.contains(&"--new-session".to_string()), "TIOCSTI");
        assert!(a.contains(&"--die-with-parent".to_string()));
    }

    #[test]
    fn clearenv_comes_before_every_setenv() {
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
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
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
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
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
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
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
        let i = a.iter().position(|x| x == "--chdir").unwrap();
        assert_eq!(a[i + 1], "/jobs/t/j");
        // Immediately before the command, so a later flag cannot re-point it.
        assert_eq!(a[i + 2], "/bin/sh");
    }

    #[test]
    fn share_net_appears_only_when_the_network_grant_is_held() {
        let none = Grants::default();
        let net = Grants {
            write: Default::default(),
            network: true,
        };
        assert!(!build_argv(Path::new("/j"), &none, "x").contains(&"--share-net".to_string()));
        assert!(build_argv(Path::new("/j"), &net, "x").contains(&"--share-net".to_string()));
    }

    #[test]
    fn a_write_grant_becomes_a_read_write_bind() {
        // A grant is the only way a host path becomes writable, and `--bind` is
        // the only bubblewrap flag that makes one. Read-only would silently
        // grant nothing.
        let g = Grants {
            write: [PathBuf::from("/var/lib")].into(),
            network: false,
        };
        let a = build_argv(Path::new("/jobs/t/j"), &g, "x");
        assert!(
            a.windows(3)
                .any(|w| w[0] == "--bind" && w[1] == "/var/lib" && w[2] == "/var/lib"),
            "a granted path must be bound read-write, got {a:?}"
        );
        // And nothing is bound read-write without a grant.
        let none = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "x");
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
        let full = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "x");
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
        let full = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "x");
        assert_eq!(full[full.len() - 3..], ["/bin/sh", "-c", "x"]);
    }

    #[test]
    fn the_command_is_last_and_passed_verbatim() {
        let a = build_argv(
            Path::new("/jobs/t/j"),
            &Grants::default(),
            "run x; cat /etc/hostname",
        );
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
        let job_dir = std::fs::canonicalize(scratch.path().join("job")).unwrap();
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
}
