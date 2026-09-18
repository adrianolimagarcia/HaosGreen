//! Bubblewrap sandbox for the supervisor's shell backend.
//!
//! One module owns the version floor, the argv and the job-directory
//! invariants, so the sandbox is described in exactly one place and the tests
//! exercise the same builder production uses.

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
    let mut child = std::process::Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
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
            status
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
        let (_dir, bin) = stub_bwrap_reporting("bubblewrap 0.11.9");
        let r = check_bwrap_version_at(&bin);
        assert!(
            matches!(r, Err(IsolationUnavailable::VersionTooOld(_))),
            "0.11.9 must be refused as VersionTooOld, got {r:?}"
        );
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
        let (_dir, bin) = stub_bwrap_running("sleep 30 &\nexit 0");
        let started = Instant::now();
        let r = check_bwrap_version_at_within(&bin, Duration::from_millis(150));
        let elapsed = started.elapsed();
        assert!(
            matches!(r, Err(IsolationUnavailable::VersionUnreadable(_))),
            "an unreadable capture must fail closed, got {r:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the probe must not wait on a grandchild's pipe, took {elapsed:?}"
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
        let (_dir, bin) = stub_bwrap_running("printf '%5000s' '' | tr ' ' x");
        let msg = check_bwrap_version_at(&bin).unwrap_err().to_string();
        assert!(
            msg.len() <= MAX_PROBE_TEXT + 128,
            "the probe's message must stay bounded, got {} bytes: {msg:?}",
            msg.len()
        );
    }
}
