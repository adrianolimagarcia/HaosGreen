# Shell Backend Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the supervisor's `ShellBackend` inside a bubblewrap sandbox that cannot see the host's home directory, `/etc`, or the supervisor's environment, and fail closed — asking the operator — when that sandbox is unavailable.

**Architecture:** One new module, `src/supervisor/backend/sandbox.rs`, owns the version probe, the argv builder, the startup smoke probe and the job-directory invariants, so the sandbox is described in exactly one place and the tests assert against the same builder production uses. `ShellBackend` becomes a thin caller of it. A route-time gate (Layer 1) parks a task in `Route` via `RequireApproval`; a job-time check (Layer 2) refuses to spawn at all. Layer 2 is the boundary, because a task can move between the two. The boundary is drawn at **capability**: reads of the read-only base set are free, and a write to a host path or the host network namespace needs a named, revocable grant, declared before the job runs because bubblewrap cannot be widened after it starts.

**Tech Stack:** Rust 2021, Tokio, `std::process::Command` / `tokio::process::Command`, bubblewrap >= 0.12.0, `anyhow`, `serde` + `toml` for config, `tracing`.

**Spec:** `docs/superpowers/specs/2026-09-18-shell-backend-isolation-design.md` (revision 3). Read it before starting. Every "why" below is in it.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/supervisor/backend/sandbox.rs` | **New.** Version probe, argv builder, job-directory resolution and invariants, the startup smoke probe, and the `Grants` set the argv is built from. The only place that knows what the sandbox is. |
| `src/supervisor/backend/mod.rs` | Modify: `pub mod sandbox;` |
| `src/supervisor/backend/shell.rs` | Modify: `run` delegates to `sandbox`; Layer-2 refusal; output caps |
| `src/config.rs` | Modify: `ShellSandboxConfig` under `[supervisor.shell]`, with validation |
| `src/supervisor/mod.rs` | Modify: Layer-1 gate in `submit`; hold the probe result and the grant set |
| `src/main.rs` | Modify: build the sandbox at startup, run the version check and the smoke probe, pass the grants into `ShellBackend` and `Supervisor` |
| `src/platform/telegram.rs` | Modify: the grant commands `/allow <path>`, `/deny <path>`, `/allow-net`, `/deny-net` |
| `src/web/routes/supervisor.rs` | Modify: the dashboard equivalent of the grant commands |
| `tests/shell_sandbox_live.rs` | **New.** Real-bwrap tests, `#[ignore]`d + env-gated |

---

## Task 1: Version probe — bubblewrap >= 0.12.0

**Files:**
- Create: `src/supervisor/backend/sandbox.rs`
- Modify: `src/supervisor/backend/mod.rs` (add `pub mod sandbox;`)

- [ ] **Step 1: Write the failing test**

Append to `src/supervisor/backend/sandbox.rs`:

```rust
//! Bubblewrap sandbox for the supervisor's shell backend.
//!
//! One module owns the version floor, the argv and the job-directory
//! invariants, so the sandbox is described in exactly one place and the tests
//! exercise the same builder production uses.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

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
/// error, never a pass.
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(parse_version("command not found"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn the_floor_is_exactly_0_12_0() {
        assert!(version_is_supported((0, 12, 0)));
        assert!(version_is_supported((0, 13, 0)));
        assert!(version_is_supported((1, 0, 0)));
        assert!(!version_is_supported((0, 11, 9)));
        assert!(!version_is_supported((0, 9, 0)));
    }
}
```

- [ ] **Step 2: Register the module and run the test**

Add to `src/supervisor/backend/mod.rs`, next to the other `pub mod` lines:

```rust
pub mod sandbox;
```

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: PASS, 5 tests.

- [ ] **Step 3: Add the probe**

Append to `src/supervisor/backend/sandbox.rs`, above `#[cfg(test)]`:

```rust
/// Why isolation is unavailable. One variant per distinct cause, so the
/// operator sees *why* rather than "unavailable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationUnavailable {
    /// `bwrap` is not on `PATH`.
    NotInstalled,
    /// `bwrap --version` failed, or its output could not be parsed.
    VersionUnreadable(String),
    /// Installed, but older than [`MIN_BWRAP`]. Carries the version found.
    VersionTooOld(String),
    /// The smoke test failed. Carries the step that failed.
    SmokeTestFailed(String),
}

impl std::fmt::Display for IsolationUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "bubblewrap is not installed"),
            Self::VersionUnreadable(e) => write!(f, "cannot read the bubblewrap version: {e}"),
            Self::VersionTooOld(v) => write!(
                f,
                "bubblewrap {v} is older than {}.{}.{}, which fixes CVE-2026-87766 \
                 (a symlink-traversal write outside the sandbox during setup)",
                MIN_BWRAP.0, MIN_BWRAP.1, MIN_BWRAP.2
            ),
            Self::SmokeTestFailed(step) => write!(f, "the sandbox smoke test failed: {step}"),
        }
    }
}

impl std::error::Error for IsolationUnavailable {}

/// Locate `bwrap` on `PATH` and confirm it is a version we may rely on.
pub fn check_bwrap_version() -> Result<(), IsolationUnavailable> {
    check_bwrap_version_at(Path::new("bwrap"))
}

/// The real check, against an explicit binary.
///
/// Taking the path as a parameter rather than reading `PATH` is what makes the
/// version floor testable without mutating the environment. **No test in this
/// repo uses `std::env::set_var`**, and `tests/a2a_e2e_live.rs` records why: it
/// is process-global and races with every other test in the same binary. A stub
/// binary on a private path is injected instead.
///
/// (There is exactly one `set_var` in `src/` — `src/setup/mod.rs:56`, in
/// production CLI argument parsing. It is not in a test and not a precedent for
/// one. An earlier draft of this comment claimed the repo had none at all,
/// which was false; corrected after the Task 1 reviewer checked it.)
///
/// An older version is reported as [`IsolationUnavailable::VersionTooOld`] —
/// the same *kind* of outcome as "not installed", so there is no "present but
/// insecure, carry on" state anywhere in the code.
pub fn check_bwrap_version_at(bin: &Path) -> Result<(), IsolationUnavailable> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|_| IsolationUnavailable::NotInstalled)?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let version = parse_version(&text)
        .ok_or_else(|| IsolationUnavailable::VersionUnreadable(text.clone()))?;
    if !version_is_supported(version) {
        return Err(IsolationUnavailable::VersionTooOld(text));
    }
    Ok(())
}
```

- [ ] **Step 4: Test the version check against a stubbed binary**

Add to the `tests` module in `src/supervisor/backend/sandbox.rs`:

```rust
    /// A fake `bwrap` that reports a version we choose, on its own private
    /// path. No `PATH` mutation, so these tests are safe to run in parallel.
    fn stub_bwrap_reporting(version_line: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bwrap");
        std::fs::write(&path, format!("#!/bin/sh\necho '{version_line}'\nexit 0\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        (dir, path)
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
        assert!(matches!(r, Err(IsolationUnavailable::NotInstalled)), "got {r:?}");
    }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: PASS, 19 tests — the eight this task specifies (five in Step 1, three in
Step 4) plus eleven added while implementing it: the ETXTBSY retry, the output cap,
the grandchild holding the pipe, the hung probe, the killed-by-signal status, the
empty capture and the refusal wording. Task 2's Step 4 counts from that 19.

- [ ] **Step 6: Commit**

```bash
git add src/supervisor/backend/sandbox.rs src/supervisor/backend/mod.rs
git commit -m "feat(supervisor): require bubblewrap >= 0.12.0 for shell isolation"
```

---

## Task 2: The argv builder

**Files:**
- Modify: `src/supervisor/backend/sandbox.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module:

```rust
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
    }

    #[test]
    fn argv_isolates_the_hostname() {
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "echo hi");
        let i = a.iter().position(|x| x == "--hostname").unwrap();
        assert_eq!(a[i + 1], "haos-sandbox");
    }

    #[test]
    fn share_net_appears_only_when_the_network_grant_is_held() {
        let none = Grants::default();
        let net = Grants { write: Default::default(), network: true };
        assert!(!build_argv(Path::new("/j"), &none, "x").contains(&"--share-net".to_string()));
        let a = build_argv(Path::new("/j"), &net, "x");
        assert!(a.contains(&"--share-net".to_string()));
        // Presence is not enough: order is load-bearing. `--share-net` before
        // `--unshare-all` is re-unshared by it, so the grant becomes a silent
        // no-op — measured against the real binary, the inverted order leaves the
        // sandbox with `lo` alone (1 interface against 16), which the probe
        // reports as "the host network is reachable under a grant".
        //
        // Exactly one of each, asserted before the ordering: a second
        // `--unshare-all` *after* `--share-net` would re-unshare the network
        // while a first-occurrence comparison still read as correctly ordered.
        assert_eq!(a.iter().filter(|x| *x == "--unshare-all").count(), 1);
        assert_eq!(a.iter().filter(|x| *x == "--share-net").count(), 1);
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
        // binds come from a later loop than the `/usr` ones, so a grant loop
        // moved above it would shadow an `/etc` grant while a check against
        // `/usr` alone still passed.
        let g = Grants {
            write: [PathBuf::from("/var/lib"), PathBuf::from("/etc/ssl/certs")].into(),
            network: false,
        };
        let a = build_argv(Path::new("/jobs/t/j"), &g, "x");
        for granted in ["/var/lib", "/etc/ssl/certs"] {
            assert!(
                a.windows(3).any(|w| w[0] == "--bind" && w[1] == granted && w[2] == granted),
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
        let last_ro = a.iter().rposition(|x| x == "--ro-bind").unwrap();
        for granted in ["/var/lib", "/etc/ssl/certs"] {
            let at = a.windows(3).position(|w| w[0] == "--bind" && w[1] == granted).unwrap();
            assert!(
                at > last_ro,
                "the grant for {granted} at {at} precedes the last read-only bind at \
                 {last_ro}, which mounts over it and silently grants nothing"
            );
        }
        // And nothing is bound read-write without a grant.
        let none = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "x");
        assert!(
            !none.windows(3).any(|w| w[0] == "--bind" && w[1] == "/var/lib"),
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
        assert!(a.windows(3).any(|w| w[0] == "--ro-bind" && w[2] == "/etc/ssl/certs"));
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
        let a = build_argv(Path::new("/jobs/t/j"), &Grants::default(), "run x; cat /etc/hostname");
        assert_eq!(a[a.len() - 3..], ["/bin/sh", "-c", "run x; cat /etc/hostname"]);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: FAIL — `cannot find function build_argv`, `cannot find type Grants` and `cannot find function push_ro_bind_if_present`.

- [ ] **Step 3: Implement the builder**

Add `use serde::{Deserialize, Serialize};` to the imports at the top of
`src/supervisor/backend/sandbox.rs`, then add above `#[cfg(test)]`:

```rust
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
    pub write: std::collections::BTreeSet<PathBuf>,
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
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: PASS, 30 tests (Task 1's 19 plus the 11 argv tests added here — the ten
above plus `argv_pins_the_job_directory_as_the_working_directory`).

- [ ] **Step 5: Write the smoke probe's failing test**

Spec §6 requires `probe()` to run the **production argv** against a scratch job
directory and assert the properties the boundary claims. This is where it lands:
`build_argv` now exists, so the probe can assert against the real thing, and
`IsolationUnavailable::SmokeTestFailed` gets its producer instead of staying a
declared-but-unreachable variant.

Add to the `tests` module:

```rust
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
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
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: FAIL — `cannot find function probe_at`.

- [ ] **Step 7: Implement the startup smoke probe**

Add above `#[cfg(test)]` — except `drain_capped_async`, which belongs beside
the synchronous `drain_capped` near the top of the module, because it is that
function's async twin and not probe-specific:

```rust
/// Bound on one probe invocation, in seconds.
///
/// A hang detector, not a performance assertion — the same reasoning as
/// `supervisor::bounded`. The probe runs at startup, so one wedged step would
/// hold the process before it ever serves a message. Both curl steps carry their
/// own `--connect-timeout 2 --max-time 3` (see `HTTPS_SCRIPT` and
/// `loopback_script`), so this bound is only ever reached by a wedge, never by a
/// slow network — a blackholed connection must be reported as a network
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
    verdict_base(
        &out,
        &job_dir.to_string_lossy(),
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
```

Two of these checks are the ones this repo's testing section calls out — a test
that passes for the wrong reason. Both were measured, not reasoned about:

| Probe check | Mutation applied | Result |
|---|---|---|
| `$HOME`/`$PATH` are set | remove `--clearenv` | **passes** — `--setenv` sets those same two variables |
| `pwd` is the job directory | remove `--chdir` | **passes** when the parent's cwd is already the job dir |
| the inherited canary is absent | remove `--clearenv` | caught (`canary=[SEGREDO]`) |
| `pwd` is the job directory, probe cwd pinned outside | remove `--chdir` | caught |

That is why the canary and the pinned cwd are in the implementation above and
not left to the implementer to rediscover.

- [ ] **Step 8: Run the tests**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: PASS, 45 tests — the 30 above plus 15 probe tests. Steps 5–7 add the
first two (`a_probe_that_cannot_start_a_shell_reports_smoke_test_failed` and
`the_probe_spawns_bwrap_from_a_cwd_of_its_own`); the other thirteen came from the
two review rounds that followed this task, and cover the positive path, each
verdict branch in isolation, the curl guard, the curl bounds and the capture cap.
The probe's own tests use a stub `bwrap`, so they need no real bubblewrap; the
real-sandbox assertions are Task 9's live tests.

- [ ] **Step 9: Commit**

```bash
git add src/supervisor/backend/sandbox.rs
git commit -m "feat(supervisor): build the hardened bubblewrap argv and smoke-probe it"
```

---

## Task 3: Job-directory invariants

**Files:**
- Modify: `src/supervisor/backend/sandbox.rs`

- [ ] **Step 1: Write the failing test**

> **As shipped** (Task 3, `src/supervisor/backend/sandbox.rs`; the source is
> authoritative). The four tests below are the first version and are kept for
> the record. The shipped section is **31 tests** (76 in the module), because
> these four leave the guards unpinned and one assertion with no teeth:
>
> - `refuses_the_filesystem_root_as_the_root` — the plan's `contains("/")` is
>   satisfied by *every* message the function can produce, including the
>   `cannot create /t: Permission denied` a **non-root** runner gets when the `/`
>   guard is deleted. That assertion was **removed**, not kept beside the real
>   one: a toothless assertion inside a security test is a trap for the next
>   reader, who may take the pair for one check and delete the wrong half. The
>   shipped test requires `must not be /`;
> - **`refuses_a_root_that_holds_config_toml` is inverted**, because keying the
>   guard on `config.toml` refuses every shell job in any project workspace that
>   has one — a Rust or Python project has one — and reports the denial as a
>   security refusal. The guard now keys on the files this application creates in
>   its own home (`haos-green.db`, `web-auth.toml`), and
>   `a_project_workspace_that_holds_config_toml_is_accepted` pins the false
>   positive as fixed;
> - ids: `traversal_shaped_task_ids_…`, `traversal_shaped_job_ids_…`,
>   `a_traversal_id_does_not_create_the_root_either`,
>   `a_control_character_in_an_id_is_refused`,
>   `an_id_is_joined_as_its_normalised_component`;
> - ordering: `a_symlinked_task_dir_is_refused_without_writing_through_it`,
>   `a_concurrent_swap_cannot_create_a_directory_outside_the_root`;
> - layout and containment: `a_task_dir_symlinked_to_the_root_itself_is_refused`,
>   `an_in_root_task_symlink_is_refused_rather_than_aliasing_the_layout`,
>   `an_in_root_job_symlink_is_refused_rather_than_aliasing_the_layout`,
>   `a_symlink_to_a_sibling_whose_name_extends_the_root_is_refused`;
> - roots and levels that are not usable directories:
>   `a_relative_root_is_refused`,
>   `a_root_that_is_not_a_directory_is_refused_by_name`,
>   `a_root_that_is_a_dangling_symlink_is_refused_by_name`,
>   `a_dangling_symlink_at_a_level_is_refused_by_name`;
> - `the_sandbox_root_is_created_when_it_does_not_exist_yet`,
>   `resolving_the_same_job_twice_is_idempotent`,
>   `a_newline_in_the_root_path_is_escaped_in_every_message`;
> - descriptors: `the_descriptors_carry_the_flags_the_race_and_the_permissions_need`
>   (all four flags, read back with `F_GETFL`/`F_GETFD`),
>   `a_symlinked_level_is_not_followed_by_the_open`,
>   `a_fifo_at_a_level_is_refused_instead_of_blocking` (a missing `O_DIRECTORY`
>   *hangs* on a FIFO, so the resolve runs on a thread with a deadline — a hang
>   fails the test instead of wedging the binary),
>   `a_root_that_cannot_be_read_is_still_usable`;
> - containment as a clause, not as a message:
>   `containment_is_decided_by_path_components_not_by_text`;
> - the race, deterministically, with no thread in it:
>   `a_level_swapped_for_a_symlink_cannot_redirect_the_level_below`, plus
>   `the_move_residual_creates_a_directory_outside_the_root_and_is_refused`,
>   which pins the accepted residual so the spec and the behaviour cannot drift
>   apart.
>
> Each was shown to fail under a mutation that removes the guard it covers, run
> as uid 1000 — as root the `/`-guard mutant is masked, because root can really
> create `/t`. The one exception is
> `a_concurrent_swap_cannot_create_a_directory_outside_the_root`, which is
> one-sided by construction: it fails only when the swap wins, which is what
> keeps it from going red on a loaded machine. It does fail against path-based
> creation, which is the point of it.

Add to the `tests` module:

```rust
    #[test]
    fn refuses_the_filesystem_root_as_the_root() {
        let e = resolve_job_dir(Path::new("/"), "t", "j").unwrap_err();
        assert!(e.to_string().contains("/"), "{e}");
    }

    #[test]
    fn refuses_a_root_that_holds_config_toml() {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("config.toml"), "x").unwrap();
        let e = resolve_job_dir(home.path(), "t", "j").unwrap_err();
        assert!(e.to_string().contains("config.toml"), "{e}");
    }

    #[test]
    fn a_workspace_root_is_accepted_and_the_job_dir_is_created() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let got = resolve_job_dir(&ws, "task-1", "job-1").unwrap();
        assert!(got.is_dir());
        assert!(got.starts_with(std::fs::canonicalize(&ws).unwrap()));
        assert_ne!(got, std::fs::canonicalize(&ws).unwrap(), "never the root itself");
    }

    #[test]
    fn a_symlinked_job_dir_pointing_out_of_the_root_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let ws = home.path().join("workspace");
        std::fs::create_dir_all(ws.join("task-1")).unwrap();
        std::fs::create_dir_all(home.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(home.path().join("elsewhere"), ws.join("task-1/job-1")).unwrap();
        let e = resolve_job_dir(&ws, "task-1", "job-1").unwrap_err();
        assert!(e.to_string().contains("outside"), "{e}");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: FAIL — `cannot find function resolve_job_dir`.

- [ ] **Step 3: Implement it**

Add above `#[cfg(test)]` — **as shipped**; the ordering and the id checks
below are corrections made after the first implementation, which checked
containment *after* `create_dir_all` and so created directories outside the
root (or through a symlink) before refusing. A refusal that arrives after the
directory exists is not containment. The plan's original block is in the
commit that first shipped Task 3; this is the version that stands:

```rust
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
/// write at the root itself and two ids can never share one directory.
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
/// - the writer swaps a level after this returns but before bubblewrap opens the
///   path in the argv. That window is not this function's to close: the returned
///   `PathBuf` is not what gets mounted, bubblewrap resolves it again when it
///   runs. Closing it belongs to the argv and grant layer, not here.
///
/// Both need a local writer with write access to the sandbox root. That is not
/// free: `/allow <root>` is grantable, and the default root is the same
/// directory the chat agent's shell tool uses as its working directory, so the
/// precondition is recorded in the spec — **no write grant may cover the sandbox
/// root** — rather than assumed here.
pub fn resolve_job_dir(root: &Path, task_id: &str, job_id: &str) -> anyhow::Result<PathBuf> {
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
    let (job_dir, _job_fd) = create_within(&task_fd, &root, &task_dir.join(job_id), job_id)?;
    Ok(job_dir)
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: PASS, 76 tests.

- [ ] **Step 5: Commit**

```bash
git add src/supervisor/backend/sandbox.rs
git commit -m "feat(supervisor): validate the per-job sandbox directory"
```

---

## Task 4: Configuration keys

**Files:**
- Modify: `src/config.rs`
- Modify: `config.example.toml`

- [ ] **Step 1: Write the failing test**

> **Refreshed to match what shipped (review finding F4).** This block used to
> carry three of the eleven tests Task 4 actually added, and
> `an_unknown_sandbox_mode_is_refused` asserted only `is_err()` where the
> shipped test asserts the message names the key **and** quotes the offending
> value. The two `Config::load` tests are the ones that pin the *wiring*, and
> neither was in the draft — so a re-run of this task from the old block
> reproduced the defect the task exists to fix: a `validate()` nothing calls.

Add to the `tests` module in `src/config.rs`:

```rust
    // ── [supervisor.shell] ──────────────────────────────────────────────────
    //
    // One key, and it decides whether a supervisor shell job runs inside a
    // sandbox at all. It has exactly two ways to be taken wrongly: silently
    // accepted when misspelled, and read as the operator's consent to run
    // unconfined when misspelled. The tests below pin both.

    #[test]
    fn shell_sandbox_defaults_to_bwrap_with_an_empty_grant_set() {
        let c = ShellSandboxConfig::default();
        assert_eq!(c.sandbox, "bwrap");
        // The shipped default is the **empty** grant set: no writable host path
        // and no host network. Nothing here decides otherwise — the network is
        // a runtime grant (`/allow-net`), not a setting (spec §4), so there is
        // no key to read and nothing to default.
        let g = crate::supervisor::backend::sandbox::Grants::default();
        assert!(g.write.is_empty(), "no host path is writable by default");
        assert!(!g.network, "the host network is not shared by default");
    }

    #[test]
    fn shell_sandbox_defaults_when_the_section_is_missing() {
        // The overwhelming majority of installs have no `[supervisor.shell]`
        // block. They must get the sandbox, not an unconfined default.
        let cfg: Config = toml::from_str(base_toml()).unwrap();
        assert_eq!(cfg.supervisor.shell.sandbox, "bwrap");
        assert!(!cfg.supervisor.shell.is_unconfined());
    }

    #[test]
    fn an_unknown_sandbox_mode_is_refused() {
        let c = ShellSandboxConfig {
            sandbox: "chroot".into(),
        };
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("sandbox"), "unexpected error: {err}");
        assert!(
            err.contains("chroot"),
            "the error must quote the offending value, got: {err}"
        );
    }

    #[test]
    fn both_documented_modes_are_accepted() {
        for m in ["bwrap", "none"] {
            let c = ShellSandboxConfig { sandbox: m.into() };
            assert!(c.validate().is_ok(), "{m} must be accepted");
        }
    }

    /// The failure mode this key must never have: a typo read as the operator's
    /// standing consent to run shell jobs unconfined.
    ///
    /// `"none"` is consent to *nothing being gated* (spec §4), so the predicate
    /// that answers "is this the consent?" has to be an equality against the
    /// literal — never a `_` arm, and never `!= "bwrap"`, which is the same
    /// mistake with the branches swapped.
    #[test]
    fn an_unknown_sandbox_mode_is_not_consent_to_run_unconfined() {
        for m in [
            "chroot", "None", "NONE", "none ", " none", "bwrap2", "no", "", "off", "false",
        ] {
            let c = ShellSandboxConfig { sandbox: m.into() };
            assert!(
                !c.is_unconfined(),
                "{m:?} must not select the unconfined mode"
            );
        }
        // And the literal does select it, or the key would be inert and the
        // assertion above would hold for a predicate that is always false.
        let c = ShellSandboxConfig {
            sandbox: "none".into(),
        };
        assert!(c.is_unconfined());
    }

    #[test]
    fn supervisor_validate_refuses_an_unknown_sandbox_mode() {
        let cfg = SupervisorConfig {
            shell: ShellSandboxConfig {
                sandbox: "chroot".into(),
            },
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("[supervisor.shell].sandbox"),
            "unexpected error: {err}"
        );
    }

    /// A **companion** to `supervisor_validate_refuses_an_unknown_sandbox_mode`
    /// above, not a check of its own.
    ///
    /// `validate()` returning `Ok(())` is exactly what a `validate()` that had
    /// stopped delegating to the shell block — or that never called it at all —
    /// also returns, so this test passes under that mutant and pins nothing
    /// about the delegation. The property it looks like it guards is only
    /// observable from the **refusing** side, which is the test above.
    ///
    /// It is kept, and strengthened to the whole documented domain, because it
    /// is the only place both accepted modes are shown to pass through
    /// `SupervisorConfig::validate` rather than `ShellSandboxConfig::validate`
    /// directly — i.e. that the delegating entry point does not reject a value
    /// the shell block accepts.
    #[test]
    fn supervisor_validate_accepts_the_shipped_default() {
        assert!(SupervisorConfig::default().validate().is_ok());
        for m in ["bwrap", "none"] {
            let cfg = SupervisorConfig {
                shell: ShellSandboxConfig { sandbox: m.into() },
                ..Default::default()
            };
            assert!(
                cfg.validate().is_ok(),
                "{m} is a documented mode and must pass SupervisorConfig::validate"
            );
        }
    }

    /// The wiring test — the point of this task.
    ///
    /// `ShellSandboxConfig::validate()` existing is not the property; being
    /// *called* is. A misspelled mode in `config.toml` must stop the process at
    /// load, before any shell job can be routed, and it must never be resolved
    /// to one of the two modes.
    #[test]
    fn config_load_refuses_an_unknown_shell_sandbox_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let cfg_path = tmp.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
                [telegram]
                bot_token = "tok"
                allowed_user_ids = [1]
                [openrouter]
                api_key = "key"
                [general]
                home = "{}"
                [supervisor.shell]
                sandbox = "chroot"
                "#,
                home.display()
            ),
        )
        .unwrap();

        // `{:#}` is anyhow's whole-chain rendering, which is what `main` prints
        // when the `?` above it reaches `fn main()`. The plain `Display` shows
        // only the outermost context ("Invalid config in …") and would let the
        // operator's typo go unnamed.
        let err = format!("{:#}", Config::load(&cfg_path).unwrap_err());
        assert!(
            err.contains("[supervisor.shell].sandbox"),
            "loading must fail, naming the key, got: {err}"
        );
        assert!(
            err.contains("chroot"),
            "the error must quote the offending value, got: {err}"
        );
        // The **ordering** is the property, not the message. `Config::load`
        // validates before `resolve()`, and `resolve()` is what creates the home
        // tree — so a refusal that happens after it leaves a half-built home
        // behind on a config this build cannot honour. Moving the
        // `config.supervisor.validate()?` call below `config.resolve()?` keeps
        // every other assertion in this file green and every message identical,
        // which is why the ordering needs an assertion of its own: nothing else
        // here observes it. `home` is the `[general].home` written above and is
        // not created by the test.
        assert!(
            !home.exists(),
            "load must refuse before resolve() creates anything"
        );
    }

    #[test]
    fn config_load_accepts_both_documented_shell_sandbox_modes() {
        for m in ["bwrap", "none"] {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path().join("home");
            let cfg_path = tmp.path().join("config.toml");
            std::fs::write(
                &cfg_path,
                format!(
                    r#"
                    [telegram]
                    bot_token = "tok"
                    allowed_user_ids = [1]
                    [openrouter]
                    api_key = "key"
                    [general]
                    home = "{}"
                    [supervisor.shell]
                    sandbox = "{m}"
                    "#,
                    home.display()
                ),
            )
            .unwrap();

            let cfg = Config::load(&cfg_path).unwrap_or_else(|e| panic!("{m} must load: {e}"));
            assert_eq!(cfg.supervisor.shell.sandbox, m);
        }
    }

    #[test]
    fn the_example_config_ships_the_shell_sandbox_on() {
        // `config.example.toml` is what users copy. If it ever ships
        // `sandbox = "none"` — or drops the block so a reader never sees the
        // key — an operator gets unconfined shell jobs without having decided
        // anything. Same reasoning as `web_disabled_by_default`.
        let cfg: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        assert_eq!(cfg.supervisor.shell.sandbox, "bwrap");
        assert!(!cfg.supervisor.shell.is_unconfined());
        assert!(cfg.supervisor.validate().is_ok());
    }

    #[test]
    fn an_empty_shell_sandbox_table_still_defaults_to_bwrap() {
        // An operator who writes the table and comments the key out — the most
        // likely way to "leave it alone" — must get the sandbox, not `""`.
        // `""` is not consent (`is_unconfined` is an equality), but it would
        // still be refused at load, so the default is what keeps a harmless
        // edit harmless.
        let cfg: Config =
            toml::from_str(&format!("{}\n[supervisor.shell]\n", base_toml())).unwrap();
        assert_eq!(cfg.supervisor.shell.sandbox, "bwrap");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib config::tests::shell_sandbox`
Expected: FAIL — `cannot find type ShellSandboxConfig`.

- [ ] **Step 3: Implement**

Add near `RiskThresholdsConfig` in `src/config.rs`:

```rust
fn default_shell_sandbox() -> String {
    "bwrap".to_string()
}

/// `[supervisor.shell]`.
///
/// One key, deliberately. The host network namespace is a **runtime grant**
/// (`/allow-net`), not a startup setting: a config key is decided once, at rest,
/// by whoever edits `config.toml`, while the escape path it opens is exercised
/// per job. A writable host path is a grant for the same reason (`/allow
/// <path>`). So neither is configured here (spec §4).
#[derive(Debug, Clone, Deserialize)]
pub struct ShellSandboxConfig {
    /// `"bwrap"` (sandboxed) or `"none"` (unsandboxed, the operator's explicit
    /// consent, and nothing else is gated). An unknown value is refused rather
    /// than defaulted — see [`Self::validate`] and [`Self::is_unconfined`].
    #[serde(default = "default_shell_sandbox")]
    pub sandbox: String,
}

impl Default for ShellSandboxConfig {
    fn default() -> Self {
        Self {
            sandbox: default_shell_sandbox(),
        }
    }
}

impl ShellSandboxConfig {
    /// Refuse any mode this build cannot honour.
    ///
    /// There is no safe default for an unrecognised value. Reading it as
    /// `"bwrap"` refuses shell jobs an operator may have meant to allow; reading
    /// it as `"none"` removes the sandbox because of a typo, which is the worst
    /// outcome this key can have. So the value is neither guessed at nor
    /// silently accepted: it stops the load (see [`Config::load`]).
    pub fn validate(&self) -> Result<()> {
        match self.sandbox.as_str() {
            "bwrap" | "none" => Ok(()),
            other => {
                bail!("[supervisor.shell].sandbox must be \"bwrap\" or \"none\", got {other:?}")
            }
        }
    }

    /// Is this the operator's standing consent to run shell jobs unconfined?
    ///
    /// **Equality against the literal `"none"`, never a `_` arm and never
    /// `!= "bwrap"`.** This predicate is the one place the unconfined mode is
    /// selected, so any other shape is a fail-open: a typo — `"None"`,
    /// `"none "`, `"chroot"` — would read as consent and run a shell job with
    /// no boundary at all (spec §4). `validate()` refuses those values at load;
    /// this returns `false` for them anyway, so the decision is fail-closed even
    /// if a caller never validated.
    pub fn is_unconfined(&self) -> bool {
        self.sandbox == "none"
    }
}
```

Add the field to `SupervisorConfig` and give it a `validate()` that **delegates**
— `ShellSandboxConfig::validate()` existing is not the property; being *called*
is:

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub telegram: TelegramConfig,
    pub openrouter: OpenRouterConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    #[serde(default = "default_memory_config")]
    pub memory: MemoryConfig,
    #[serde(default = "default_skills_config")]
    pub skills: SkillsConfig,
    #[serde(default = "default_agents_config")]
    pub agents: AgentsConfig,
    #[serde(default)]
    pub general: Option<GeneralConfig>,
    #[serde(default = "default_agent_config")]
    pub agent: AgentConfig,
    pub embedding: Option<EmbeddingApiConfig>,
    #[serde(default)]
    pub langsmith: Option<LangSmithConfig>,
    #[serde(default = "default_learning_config")]
    pub learning: LearningConfig,
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    #[serde(default)]
    pub subagents: SubagentsConfig,
    #[serde(default)]
    pub a2a: A2aConfig,
    #[serde(default)]
    pub web: WebConfig,
    /// Explicit provider sections (multi-provider mode). Optional —
    /// when empty, `build_providers()` synthesizes a single OpenRouter
    /// provider from the legacy `[openrouter]` section.
    #[serde(default)]
    pub provider: Vec<ProviderSection>,
    /// Fallback chain — additional provider/model names tried when
    /// the primary call fails.
    #[serde(default)]
    pub fallback: FallbackConfig,
    /// Absolute home root resolved at load time (not read from TOML).
    #[serde(skip)]
    pub resolved_home: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SupervisorConfig {
    #[serde(default = "default_autonomy_mode")]
    pub default_autonomy_mode: String,
    #[serde(default)]
    pub artifacts_dir: std::path::PathBuf,
    #[serde(default)]
    pub risk: RiskThresholdsConfig,
    #[serde(default)]
    pub shell: ShellSandboxConfig,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            default_autonomy_mode: default_autonomy_mode(),
            artifacts_dir: default_artifacts_dir(),
            risk: RiskThresholdsConfig::default(),
            shell: ShellSandboxConfig::default(),
        }
    }
}

impl SupervisorConfig {
    /// Validate the `[supervisor]` block.
    ///
    /// Every field here also fails closed at use time; the point of checking up
    /// front is that the failure is *loud* and happens once at load instead of
    /// silently per job. Unlike the `[web]` and `[a2a]` blocks there is no
    /// listener to skip: the supervisor's shell backend is always registered, so
    /// a value this build cannot interpret is not something to carry on with.
    pub fn validate(&self) -> Result<()> {
        self.shell.validate()
    }
}
```

Then call it from `Config::load`, **before** `resolve()`:

```rust
    /// Read and validate `config.toml`.
    ///
    /// Validation happens here, before [`Self::resolve`] creates any directory,
    /// because this is the single choke point every entry point goes through: a
    /// validator that each caller has to remember to invoke is one that will
    /// eventually not be invoked.
    ///
    /// [`SupervisorConfig::validate`] is the one check that is *fatal*. The
    /// `[web]` and `[a2a]` blocks are validated where their listeners start,
    /// because a misconfiguration there costs a listener and not the bot — but
    /// `[supervisor.shell].sandbox` selects whether a shell job runs inside a
    /// sandbox, and an unrecognised value has no safe reading. Refusing to start
    /// is the only answer that cannot be wrong.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&content).with_context(|| "Failed to parse config file")?;

        config
            .supervisor
            .validate()
            .with_context(|| format!("Invalid config in {}", path.display()))?;

        let warnings = config
            .resolve()
            .with_context(|| "Failed to resolve home directory paths")?;
        for w in &warnings {
            tracing::warn!("{}", w.render());
        }

        Ok(config)
    }
```

The ordering is the property, not the message. `resolve()` is what creates the
home tree, so a refusal that happens after it leaves a half-built home behind on
a config this build cannot honour — and the property is otherwise invisible:
moving the call below `resolve()` keeps every message identical and every other
test in this file green.
`config_load_refuses_an_unknown_shell_sandbox_mode` therefore ends with
`assert!(!home.exists(), "load must refuse before resolve() creates anything")`,
which is the only assertion in the suite that observes the order.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib config::tests`
Expected: PASS.

- [ ] **Step 5: Document it**

> **Corrected.** This step used to say "under the `[supervisor]` section", which
> does not exist in `config.example.toml` — the file's only mention of
> "supervisor" is inside a comment. The section has to be **created**, and the
> `[supervisor]` banner goes after the `[learning]` block and before the A2A
> banner, which is where the file's optional sections already run in the same
> order as `CLAUDE.md`. Add:

```toml
# ── Supervisor (optional; defaults apply if section omitted) ────────────────
#
# The autonomous task runner. Its other keys — `artifacts_dir` and the
# `[supervisor.risk]` gates (CLAUDE.md) — are left out here; only the shell
# sandbox is written out.
#
# `default_autonomy_mode` is also left out, and not only for brevity: it is
# parsed and defaulted but no code reads it yet, so writing it here would
# document a key that changes nothing.
#
# It is written out, rather than commented like the sections below, on purpose:
# this is the one key that decides whether a shell job has a boundary at all,
# and an operator should have to see it to change it. `"bwrap"` is the same
# value a config with no `[supervisor.shell]` table gets.

[supervisor.shell]
# "bwrap" runs shell jobs inside a bubblewrap sandbox (requires bwrap >= 0.12.0).
# "none" runs them unconfined, and IS your consent — nothing else is gated.
#
# Any other value is refused when the config is loaded: the process will not
# start. A misspelled mode must never be read as consent to run unconfined.
sandbox = "bwrap"

# Nothing else is configured here on purpose. A writable host path and the host
# network namespace are not settings but runtime grants the operator names at the
# moment they are used — /allow <path> and /allow-net, standing until /deny or
# /deny-net, and revoked by a restart. Neither substitutes for a missing sandbox.
#
# PLANNED, NOT IMPLEMENTED IN THIS BUILD: /allow, /deny, /allow-net and
# /deny-net are specified but not wired up yet — no code reads a grant, so there
# is currently no command that releases one. Until they land a shell job runs
# with the empty grant set: its own job directory, no host path, no network.
# The commands are named here so the intent is visible, not as a claim that they
# work today.
```

- [ ] **Step 6: Commit**

```bash
git add src/config.rs config.example.toml
git commit -m "feat(config): add [supervisor.shell] sandbox"
```

> **Where the invariant actually lives, and what it does not cover (review
> finding M10).** "An unrecognised `sandbox` value cannot reach the consenting
> branch" is enforced in two places, and neither of them is the **type**:
> `Config::load` refuses it, and `is_unconfined()` is an equality against the
> literal `"none"` so an unvalidated value still fails closed. `Config` is `pub`
> and derives `Deserialize`, so
> `toml::from_str::<Config>(…).unwrap().resolve()` — or any future caller that
> builds a `Config` without `load` — skips the validation entirely. That path
> cannot reach the consenting branch (the second guarantee holds), but it does
> skip the *loud* refusal, and a `"chroot"` that arrives that way is carried
> silently until a shell job is attempted.
>
> No production path does this today: every entry point goes through
> `Config::load`. The invariant is a property of the **loader**, not of the type,
> and this note exists so a future caller adding a second construction path knows
> it is bypassing a check rather than reusing a safe constructor. Closing it
> properly would mean a validated newtype or a `#[serde(try_from)]` on
> `ShellSandboxConfig`; that is a change to the config surface, not to this task,
> and it is deliberately not made here.

> **Added during execution, beyond this task's draft.** Two things the draft left
> as "defined, never called", which is the defect this plan has now hit four
> times. Both are **in the Step 3 code blocks above**, not only in this note: a
> note is not a snippet, and the first version of this note was the only place
> either one existed, which is exactly how the defect reproduced.
>
> 1. **`ShellSandboxConfig::validate()` had no caller.** A typo
>    (`sandbox = "chroot"`) was silently accepted. Fixed with
>    `SupervisorConfig::validate()` delegating to it and `Config::load` calling
>    that, **fatally**, before `resolve()` creates anything. `Config::load` is
>    the single choke point every entry point goes through; a check each caller
>    must remember to invoke is one that will eventually not be invoked. The
>    `[web]`/`[a2a]` pattern — validate where the listener starts and skip only
>    the listener — does not transfer: there is no listener to skip here, and an
>    unrecognised value has no safe reading (defaulting to `"bwrap"` refuses
>    jobs the operator may have meant to allow; defaulting to `"none"` removes
>    the sandbox on a typo).
> 2. **`is_unconfined()` is the only place the unconfined mode is selected**,
>    and it is `self.sandbox == "none"` — an equality against the literal, never
>    a `_` arm and never `!= "bwrap"`. That predicate is what Task 5 calls, so
>    the fail-open direction is a single line with a test on it
>    (`an_unknown_sandbox_mode_is_not_consent_to_run_unconfined`) rather than a
>    branch inside `main.rs` that no test can reach.
>
> **Tests added — all eleven, matching the Step 1 block above:**
> `shell_sandbox_defaults_to_bwrap_with_an_empty_grant_set`,
> `shell_sandbox_defaults_when_the_section_is_missing`,
> `an_unknown_sandbox_mode_is_refused`,
> `both_documented_modes_are_accepted`,
> `an_unknown_sandbox_mode_is_not_consent_to_run_unconfined`,
> `supervisor_validate_refuses_an_unknown_sandbox_mode`,
> `supervisor_validate_accepts_the_shipped_default`,
> `config_load_refuses_an_unknown_shell_sandbox_mode`,
> `config_load_accepts_both_documented_shell_sandbox_modes`,
> `the_example_config_ships_the_shell_sandbox_on`,
> `an_empty_shell_sandbox_table_still_defaults_to_bwrap`.
>
> The draft's list named seven and omitted
> `an_empty_shell_sandbox_table_still_defaults_to_bwrap` — the one that keeps an
> operator's commented-out key harmless instead of fatal. Two more notes on the
> eleven:
>
> - `supervisor_validate_accepts_the_shipped_default` is a **companion** to the
>   refusal test, not a check: `Ok(())` is what a `validate()` that stopped
>   delegating also returns, so it passes under that mutant and pins nothing.
>   The delegation is only observable from the refusing side, which is where
>   `supervisor_validate_refuses_an_unknown_sandbox_mode` asserts it. It is kept
>   because it is the only place both accepted modes are shown to pass through
>   the delegating entry point.
> - `config_load_refuses_an_unknown_shell_sandbox_mode` carries the ordering
>   assertion. Its mutant is **moving `config.supervisor.validate()?` below
>   `config.resolve()?`**: identical error text, identical exit code, and a fully
>   created home tree — caught by the `!home.exists()` line and by nothing else.

---

## Task 5: Wire the sandbox into `ShellBackend` (Layer 2)

**Files:**
- Modify: `src/supervisor/backend/shell.rs`
- Modify: `src/main.rs:513-517` (`ShellBackend::new`, inside its `register(Arc::new(…))`)

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/supervisor/backend/shell.rs`:

```rust
    #[tokio::test]
    async fn refuses_to_spawn_when_isolation_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into())
            .with_isolation(Isolation::Unavailable(IsolationUnavailable::NotInstalled));
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "echo should-not-run",
        );
        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(matches!(out.status, crate::supervisor::job::JobStatus::Failed));
        assert!(
            out.errors.iter().any(|e| e.contains("bubblewrap")),
            "the error must name the cause, got {:?}",
            out.errors
        );
        // The way out is named, and so is the grant vocabulary — but a grant is
        // never offered as a substitute for a sandbox that is not there.
        assert!(
            out.errors.iter().any(|e| e.contains("sandbox = \"none\"")),
            "must name the standing way out, got {:?}",
            out.errors
        );
        assert!(
            out.errors.iter().any(|e| e.contains("/allow-net")),
            "must name the grant, got {:?}",
            out.errors
        );
    }

    /// The other half of the promise the refusal above makes.
    ///
    /// That message tells an operator whose host has no usable bubblewrap to
    /// set `[supervisor.shell].sandbox = "none"`. Task 4 shipped the key;
    /// **nothing read it**, so setting it changed nothing and the operator got
    /// the identical refusal on the next start — a loop, with the message as
    /// the thing pointing into it. This pins the key to the mode.
    ///
    /// Host-independent on purpose: the `"none"` half never touches `bwrap` at
    /// all, and the default half asserts only that it is **not** `Unconfined`,
    /// which holds whether or not bubblewrap is installed on the test host.
    #[tokio::test]
    async fn only_the_literal_none_resolves_to_the_unconfined_mode() {
        let none = ShellSandboxConfig {
            sandbox: "none".into(),
        };
        assert!(matches!(
            Isolation::resolve(&none, &Grants::default()).await,
            Isolation::Unconfined
        ));

        let shipped = ShellSandboxConfig::default();
        assert!(
            !matches!(
                Isolation::resolve(&shipped, &Grants::default()).await,
                Isolation::Unconfined
            ),
            "the shipped default must never resolve to the unconfined mode"
        );
    }

    /// The `"none"` mode must not merely skip the *refusal* — it must not spawn
    /// `bwrap` either. If it did, the operator the refusal message sent here
    /// would set the key, restart, and watch the job fail on a missing binary:
    /// the same loop, one step further in.
    ///
    /// `$HOME` is the discriminator, and it is the one the probe itself uses
    /// (spec §6): the sandbox's argv sets `HOME` to the job directory, and the
    /// unconfined path inherits the supervisor's. A host with no `bwrap` at all
    /// is caught by the same test, because the spawn fails and the job fails
    /// with it.
    #[tokio::test]
    async fn the_unconfined_mode_runs_the_command_without_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "printf '%s' \"$HOME\"",
        );
        // Built by hand rather than through `resolve_job_dir`, so the assertion
        // does not depend on the function whose path it is checking.
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let job_dir = root.join(&job.task_id).join(&job.id);

        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Succeeded),
            "the unconfined mode must run the job, got {:?}",
            out.errors
        );
        assert_ne!(
            out.summary.trim(),
            job_dir.to_string_lossy(),
            "the job ran with the sandbox's HOME, so the bwrap path ran"
        );
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib shell::tests`
Expected: FAIL — `no method named with_isolation`, and `cannot find type Isolation
in this scope` (it is added to `sandbox.rs` in Step 3).

- [ ] **Step 3: Implement**

**3a. `Isolation` — the startup decision, in `sandbox.rs`.** Add next to
`IsolationUnavailable`. This is the one place `[supervisor.shell].sandbox`
becomes behaviour, and it is a type rather than a `bool` for a reason: a bool
called `unconfined` reads as "no boundary" even when the boundary is simply
*unproven*, and those two must never be reachable from each other.

```rust
/// What the shell backend may do, resolved **once** at startup.
///
/// This is the only reader of `[supervisor.shell].sandbox`. It is an enum and
/// not a `Result`, because "the boundary was proven" and "the operator chose to
/// have none" are different facts and only one of them is a failure. Collapsing
/// them into `Ok(())` is what would make `sandbox = "none"` still spawn `bwrap`
/// — and fail on a host without it, which is the host the mode exists for.
#[derive(Debug, Clone)]
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
    pub async fn resolve(shell: &crate::config::ShellSandboxConfig, grants: &Grants) -> Self {
        if shell.is_unconfined() {
            return Isolation::Unconfined;
        }
        match check_bwrap_version() {
            Err(e) => Isolation::Unavailable(e),
            Ok(()) => match probe(grants).await {
                Ok(()) => Isolation::Sandboxed,
                Err(e) => Isolation::Unavailable(e),
            },
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
```

**3b. The backend.** In `src/supervisor/backend/shell.rs`, add the import and
the field:

```rust
use std::sync::Arc;

use crate::supervisor::backend::sandbox::{self, Grants, Isolation, IsolationUnavailable};
```

The `tests` module also needs the config type the mode is read from —
`use crate::config::ShellSandboxConfig;` — for
`only_the_literal_none_resolves_to_the_unconfined_mode`.

```rust
pub struct ShellBackend {
    sandbox: PathBuf,
    /// The startup decision, shared. `Unavailable` means the boundary is absent
    /// and the backend must refuse rather than fall back to `sh -c`;
    /// `Unconfined` means the operator chose to have none, and it runs the
    /// command with no sandbox and no `bwrap`.
    isolation: Isolation,
    /// What the operator holds **now**, shared with the `Supervisor` so a
    /// `/allow` typed at the Telegram prompt reaches the next argv. Read once
    /// per job: bubblewrap cannot be widened after it starts.
    grants: Arc<std::sync::RwLock<Grants>>,
}
```

Extend `new` and add the builder:

```rust
    pub fn new(sandbox: PathBuf) -> Self {
        Self {
            sandbox,
            // Fail closed by default: a `ShellBackend` built without an explicit
            // probe result must not spawn anything.
            isolation: Isolation::default(),
            // And fail closed on capability too: a backend built without an
            // explicit grant set holds no writable host path and no host
            // network, which is the shipped default (spec §4).
            grants: Arc::new(std::sync::RwLock::new(Grants::default())),
        }
    }

    /// Attach the decision resolved at startup.
    pub fn with_isolation(mut self, r: Isolation) -> Self {
        self.isolation = r;
        self
    }

    /// Attach the live grant set.
    pub fn with_grants(mut self, grants: Arc<std::sync::RwLock<Grants>>) -> Self {
        self.grants = grants;
        self
    }
```

Replace the body of `run` from the `validate` call through `spawn`:

```rust
    async fn run(&self, job: &mut Job, _ctx: &RunContext) -> Result<JobOutput> {
        let cmd = job.prompt.clone().unwrap_or_else(|| job.goal.clone());

        // LAYER 2 — the boundary. Layer 1 (the route-time gate) is a UX
        // affordance; a task can move between the two, so this check is the one
        // that matters. It spawns nothing when isolation is unavailable.
        //
        // `Unconfined` is checked *first* and is not a fallback: it is set from
        // the config key, once, at startup. Under it the job runs with no
        // sandbox at all — see the launch below.
        if let Isolation::Unavailable(reason) = &self.isolation {
            job.status = JobStatus::Failed;
            return Ok(JobOutput {
                status: JobStatus::Failed,
                summary: String::new(),
                evidence: vec![],
                errors: vec![format!(
                    "refusing to run a shell job without isolation: {reason}. \
                     Install bubblewrap >= 0.12.0, or set \
                     [supervisor.shell].sandbox = \"none\" to run shell jobs \
                     unconfined. A writable host path and the host network are \
                     released by name — `/allow <path>` and `/allow-net` — and \
                     neither substitutes for a sandbox that is not there."
                )],
                changed_files: vec![],
                next_step: None,
            });
        }

        let job_dir = match sandbox::resolve_job_dir(&self.sandbox, &job.task_id, &job.id) {
            Ok(d) => d,
            Err(e) => {
                job.status = JobStatus::Failed;
                return Ok(JobOutput {
                    status: JobStatus::Failed,
                    summary: String::new(),
                    evidence: vec![],
                    errors: vec![format!("sandbox-directory-invalid: {e}")],
                    changed_files: vec![],
                    next_step: None,
                });
            }
        };
        let timeout_secs = job.timeout_secs;
        // Two launches, one decision. `Unconfined` runs `sh -c` in the job's
        // directory — exactly what this backend did before the sandbox existed
        // — and never invokes `bwrap`. That is what makes the refusal message's
        // way out real: the operator who reads it has no usable bubblewrap,
        // so a `bwrap` spawn there would fail the job for the same reason it
        // was refused, and the message would send them in a circle.
        let child = match &self.isolation {
            Isolation::Unconfined => Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .current_dir(job_dir.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?,
            _ => {
                // `_` is `Sandboxed` — `Unavailable` returned above — and it is
                // the **safe** default, unlike the `_` this plan warns about
                // elsewhere: a variant added later would be sandboxed, never
                // run unconfined.
                //
                // The guard is dropped at the end of this statement on purpose:
                // holding it across the `spawn` below would make this future
                // non-`Send`.
                let held = self.grants.read().unwrap().clone();
                let argv = sandbox::build_argv(&job_dir, &held, &cmd);
                Command::new("bwrap")
                    .args(&argv)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()?
            }
        };
        // ... the existing timeout/capture block, unchanged, from here on.
```

> **`job_dir` is a `PathBuf` until Step 6**, which changes `resolve_job_dir`
> to return a `JobDir` (path + descriptor). Before that step, read
> `current_dir(&job_dir)` and keep `build_argv(&job_dir, …)`; Step 6 changes
> the first to `job_dir.path()` and the second to `&job_dir`. The
> `Isolation::Unconfined` arm must be updated with them — it is the only arm
> that does not go through `build_argv` at all.

The job's declaration — `job.declared_grants`, and the refusal that names the
missing grant — is added in Task 8, which owns the grant semantics. This task
wires the grant set in; it does not yet compare it against anything.

> **Revision 6: none of that survived.** `Task::declared_grants` was added and
> both layers did read it, exactly as this step describes — but **no production
> code ever wrote it**, so the comparison was always against an empty set, the
> park could not fire, and the Layer-2 refusal was unreachable. The field, the
> planner's copy, `Grants::missing`, `Grants::covers` and
> `supervisor::park_reason` were all **deleted**, and this plan is left as the
> record of what was attempted. What shipped is the half that runs: a task that
> would select the shell backend is parked when there is no usable boundary, and
> refuses at run time for the same reason. See the spec's §3.

`validate()` is now dead — the sandbox is the containment. Delete it and its
`"sandbox-violation"` error string, and replace the TODO at `shell.rs:19-23`
with a comment pointing at this module. Deleting it is required: `src/lib.rs`
carries `#![deny(dead_code)]`, so an unused private method fails the build.

The existing test `shell_backend_rejects_command_escaping_sandbox` asserts the
old heuristic; it must be **replaced**, not deleted, by a test that the command
reaching `bwrap` is verbatim (the containment is the sandbox now, not a string
check).

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib shell::` and `cargo check --all-targets`
Expected: PASS, and no `dead_code` error.

- [ ] **Step 5: Wire startup**

In `src/main.rs:513-517`, build the backend from the configured mode and the
probe result. That is the `ShellBackend::new(…)` argument inside the
`sup_registry.register(std::sync::Arc::new(…))` statement — **not** the
`Supervisor::new` block at `519-524`, which this step does not touch.

> **Corrected.** This step used to derive `isolation` from the probe alone and
> never read `[supervisor.shell].sandbox` — Task 4 shipped the key, the grep for
> `config.shell` found nothing but Task 4's own test, and the refusal message in
> Step 3 tells the operator to set that key. Setting it changed nothing, so the
> message sent them into a loop. `Isolation::resolve` (Step 3a) is the single
> reader of the key.

```rust
// One shared grant set, empty at startup: the operator grants a writable host
// path or the host network by name, and it is revoked by a restart.
let grants: Arc<std::sync::RwLock<crate::supervisor::backend::sandbox::Grants>> =
    Arc::new(std::sync::RwLock::new(Default::default()));

// The ONE reader of `[supervisor.shell].sandbox`. `"none"` is the operator's
// standing consent (spec §4) and resolves to `Unconfined` without touching
// bwrap; every other value resolves through the version floor and the smoke
// probe, which are **one** result — the floor is a precondition and the probe
// is what asserts the boundary the argv claims. An unrecognised value cannot
// reach the consenting branch: `Config::load` refused it, and `is_unconfined`
// is an equality against the literal.
//
// `probe` is async, so this is in an async context (`main` is).
//
// `Isolation::resolve` takes a `&Grants`, and `grants` here is the
// `Arc<RwLock<Grants>>` shared with every `ShellBackend` — so it is handed a
// **snapshot**, taken by name:
//
//   - `&grants` is `&Arc<RwLock<Grants>>` and does not compile
//     (`error[E0308]: mismatched types … expected &Grants, found
//     &Arc<RwLock<Grants>>`). This is not a coercion subtlety: `RwLock<T>`
//     implements no `Deref` at all, so there is no deref step to take, transitive
//     or otherwise — the only way from `&Arc<RwLock<Grants>>` to `&Grants` is a
//     read.
//   - The binding is a separate statement, not `&grants.read().unwrap().clone()`
//     inline: the guard is a temporary that lives to the end of its statement, so
//     inlined it is held **across the await** — which makes this future non-`Send`
//     and, in tail position, does not compile at all
//     (`error[E0597]: grants does not live long enough`). Bound first, the guard
//     is released before the probe runs, so the probe spawns bwrap without the
//     grant set locked.
//   - `resolve` keeps taking `&Grants` rather than the `Arc`. Taking the `Arc`
//     would move the lock inside `resolve`, where the `probe(grants).await` call
//     needs a `&Grants` anyway — so it would still clone, just one frame further
//     down — and it would put a `std::sync` lock in the hands of a function whose
//     job is to describe the sandbox. It would also force the two unit tests in
//     Step 3a (`Isolation::resolve(&none, &Grants::default())`) to build an
//     `Arc<RwLock<_>>` they have no use for.
let held_at_startup = grants.read().unwrap().clone();
let isolation = crate::supervisor::backend::sandbox::Isolation::resolve(
    &config.supervisor.shell,
    &held_at_startup,
)
.await;
match &isolation {
    crate::supervisor::backend::sandbox::Isolation::Unavailable(e) => tracing::warn!(
        reason = %e,
        "shell jobs will be refused: the bubblewrap sandbox is unavailable"
    ),
    // The operator asked for this, and the spec requires they be told what it
    // means — loudly, once, at startup, not only in the file they edited.
    crate::supervisor::backend::sandbox::Isolation::Unconfined => tracing::warn!(
        "[supervisor.shell].sandbox = \"none\": shell jobs run UNCONFINED — no \
         filesystem, process or network boundary, and no grant is required. Set \
         it back to \"bwrap\" to restore the sandbox."
    ),
    crate::supervisor::backend::sandbox::Isolation::Sandboxed => {}
}

// The backend replaces the one registered at `src/main.rs:513-517` — this is
// that statement, kept in place and kept wrapped in the `register(Arc::new(…))`
// that puts it in the registry. Building a `ShellBackend` and not registering it
// is the "defined and never wired" defect this plan has hit four times, and the
// root is `config.sandbox.allowed_directory` (the resolved sandbox root), not a
// free variable.
sup_registry.register(std::sync::Arc::new(
    haos_green::supervisor::backend::shell::ShellBackend::new(
        config.sandbox.allowed_directory.clone(),
    )
    .with_isolation(isolation.clone())
    .with_grants(grants.clone()),
));
```

> **Corrected twice.** The line range this step named, `src/main.rs:519-523`, is
> the `Supervisor::new` block — `ShellBackend::new` is at **`src/main.rs:514-517`**,
> inside `sup_registry.register(std::sync::Arc::new(…))` at `513-517`. And the
> snippet's `sandbox_path` was a variable that appears nowhere in `main.rs`; the
> real argument is `config.sandbox.allowed_directory.clone()`, which is what
> `resolve()` has already made absolute. The snippet is now the statement it
> replaces, rather than a fragment that would not compile in its place.

The same `isolation` value goes into the `Supervisor` in Task 7, so Layer 1 and
Layer 2 can never disagree about the mode. `Isolation::needs_approval()` is the
only thing Layer 1 asks it, and it is `false` for `Unconfined` — which is what
"with `sandbox = "none"` nothing is gated, and Layer 1 does not apply" means in
code (spec §4).

The same `grants` `Arc` goes into the `Supervisor` in Task 8; until then the
backend is its only holder.

- [ ] **Step 6: Hand the job directory to bubblewrap by descriptor**

Between `resolve_job_dir` returning and `bwrap` opening the path in the argv, a
local writer with write access to the root can replace `<root>/<task-id>` with a
symlink. The path then resolves somewhere else and bubblewrap mounts **that**
directory read-write as the job's sandbox. This is not a theoretical window:
verified on this host by putting the swap in place and running the argv, after
which the sandboxed command read the swap target's file through the mount. The
checks inside `resolve_job_dir` cannot close it — they have already returned, and
the path is re-resolved by a different process.

Close it by handing bubblewrap the **descriptor** instead of the path.
`bwrap --bind-fd <fd> <dest>` binds the inode the descriptor names; it is present
in bubblewrap 0.12.0 (Task 1's floor — `bwrap --help` lists it), and verified
here: with the directory renamed away and a symlink left in its place, the
fd-based bind still read the original directory's file while the path-based bind
read the symlink's target. The destination stays a path, which is fine — it is
created inside the sandbox namespace, not resolved on the host.

This is what the job directory has to be, and it settles the "should the path be
a newtype?" question that Task 3's review left open: the descriptor has to travel
with the path, and only `resolve_job_dir` may construct the pair.

```rust
/// A job's sandbox directory: where it is, and a descriptor for it.
///
/// The path is for naming the directory — logs, the workspace record, the
/// `--chdir` inside the sandbox. The descriptor is what the argv binds, because
/// bubblewrap re-resolves a path and cannot re-resolve a descriptor. Only
/// [`resolve_job_dir`] constructs one, so a path that has not been through the
/// checks cannot reach `build_argv`.
pub struct JobDir {
    path: PathBuf,
    fd: OwnedFd,
}

impl JobDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A duplicate of the descriptor that **keeps** `FD_CLOEXEC` in the parent.
    ///
    /// **This is the corrected form. The text here originally cleared the flag
    /// in the parent, and that was the C1 defect** — clearing `FD_CLOEXEC` on
    /// the duplicate publishes it to *every* child this process spawns, from any
    /// thread, for as long as the argv is alive, not merely to the sandboxed
    /// job. The clear therefore belongs in the child, in the `pre_exec` hook
    /// [`SandboxArgv::command`] installs, where it can only affect the process
    /// about to `exec` `bwrap`.
    ///
    /// `try_clone` dups with `F_DUPFD_CLOEXEC`, so the duplicate is
    /// close-on-exec and stays that way; the original keeps its flag and is
    /// closed when `JobDir` drops. Bind the result to a name that outlives the
    /// `spawn` call — a dropped descriptor is a closed one.
    pub fn duplicate_fd(&self) -> Result<OwnedFd> {
        Ok(self.fd.try_clone()?)
    }
}
```

Change `resolve_job_dir` to return `Result<JobDir>` (it already opens the job
level's descriptor and currently discards it as `_job_fd`), and `build_argv` to
take `&JobDir` — superseding the `&Path` signature Task 2 shipped — emitting
`--bind-fd <n> <dest>` in place of `--bind <path> <dest>` for the job directory
only. The `Isolation::Unconfined` arm is the **third** reader of that path —
its `current_dir` — and it changes with them, to `job_dir.path()`. The
**grants** keep their `--bind`: a grant is a host path the operator
named, it is not what the job's own sandbox is built from, and it is already
refused when it covers the root (Task 8 Step 3b).

**Test.** The end-to-end version belongs in Task 9's live file, because it needs a
real `bwrap`: resolve a job directory, replace `<root>/<task-id>` with a symlink
to a second directory holding a marker file, spawn through the production argv,
and assert the sandboxed command reads the *original* directory (empty) rather
than the marker. **Mutation:** emit `--bind <path>` again and the marker is read.

- [ ] **Step 7: Commit**

```bash
git add src/supervisor/backend/shell.rs src/main.rs
git commit -m "feat(supervisor): refuse shell jobs without a real sandbox"
```

---

## Task 6: Output caps and process limit

**Files:**
- Modify: `src/supervisor/backend/shell.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn an_infinite_producer_is_stopped_by_the_byte_cap() {
        let dir = tempfile::tempdir().unwrap();
        // `Unconfined`, deliberately — see the note below the test. The cap lives
        // in the shared capture block *after* the two-launch `match`, so this
        // test does not need a real `bwrap` on the host to have teeth, and under
        // `Sandboxed` it would be a test of the host's tooling rather than of the
        // cap. No grant is held either way: the shipped grant set is empty, and
        // the unconfined launch reads no grants at all.
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t", crate::supervisor::job::JobType::ShellJob, "shell", "yes",
        );
        job.timeout_secs = 60; // far longer than the test may take
        let out = crate::supervisor::bounded("yes", b.run(&mut job, &RunContext::new()))
            .await
            .unwrap()
            .unwrap();
        // The cap must be the *reason* the job ended, not merely a bound its
        // output happened to fit under. `yes` produces without limit, so a run
        // that ended any other way — the child failed to start, the deadline
        // fired, the pipe closed — must not satisfy this test, and a bare
        // `bytes <= cap` assertion would let all three through. `byte cap` is
        // the wording Step 3 mandates for this error.
        assert!(
            out.errors.iter().any(|e| e.contains("byte cap")),
            "the byte cap must be what stopped the job, got {:?}",
            out.errors
        );
        let bytes: usize = out.summary.len() + out.errors.iter().map(|e| e.len()).sum::<usize>();
        assert!(
            bytes >= MAX_OUTPUT_BYTES,
            "the cap must have been reached before the kill, got {bytes}"
        );
        assert!(bytes <= MAX_OUTPUT_BYTES + 4096, "cap not enforced: {bytes}");
    }
```

> **Why `Unconfined` and not `Sandboxed` (review finding M9).** The draft ran this
> under `Sandboxed`, which makes it depend on a real `bwrap >= 0.12.0` on the
> test host: `with_isolation` bypasses the version check, so on a host without
> bubblewrap the `bwrap` spawn fails and the test fails with a spawn error rather
> than skipping. That is a test of the host, not of the cap. The property under
> test — an unbounded producer is stopped by the byte cap rather than by the wall
> clock — is entirely in the capture block that both launches share, so it does
> not need the sandbox to be real, and `Unconfined` runs the same `sh -c` path
> the backend used before the sandbox existed.
>
> The third option the draft did not consider (a stubbed `bwrap` on `PATH`) was
> rejected: a stub is a second implementation of the thing under test, and the
> assertions it would have to satisfy are the argv assertions Task 2 already
> makes against the real builder.
>
> **What this gives up, and where it is recovered.** No Task 6 unit test then
> exercises the *sandboxed* launch's capture path, so a change that moved the cap
> into the `Unconfined` arm alone would not be caught here. Task 9's live file
> recovers it with item 9 below, which is exactly where a real `bwrap` is allowed
> to be required.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib shell::tests::an_infinite_producer`
Expected: FAIL — `cannot find value MAX_OUTPUT_BYTES`, and the job runs to the 60 s deadline.

- [ ] **Step 3: Implement bounded capture**

Add:

```rust
/// Maximum bytes captured from each of stdout and stderr. bubblewrap bounds
/// namespaces, not output: `wait_with_output` buffers without limit, so `yes`
/// would otherwise exhaust memory before the wall clock fires.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
```

Replace `wait_with_output` with a bounded reader that reads each pipe until the
cap and then kills the child:

```rust
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => return (buf, false),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= cap {
                    buf.truncate(cap);
                    return (buf, true); // truncated
                }
            }
        }
    }
}
```

Wrap the two readers and the wait in `tokio::select!` with
`tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait())`, and
`child.start_kill()` as soon as either reader reports truncation. The error
message must say which bound fired: `"output exceeded the 262144-byte cap"` or
`"the job exceeded its {timeout_secs}s deadline"`.

Add the process limit in a `pre_exec` hook:

```rust
        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                // Best-effort: bounds fork bombs. Not a security boundary — the
                // sandbox is — and it can fail under an existing low RLIMIT.
                let lim = libc::rlimit { rlim_cur: 256, rlim_max: 256 };
                libc::setrlimit(libc::RLIMIT_NPROC, &lim);
                Ok(())
            });
        }
```

If `libc` is not already a dependency, add `libc = "0.2"` to `Cargo.toml`.
**It already is** (`Cargo.toml:100`, `libc = { version = "0.2", default-features = false }`),
so no dependency change is needed — `setrlimit` and `RLIMIT_NPROC` are part of
the core `libc` surface and are not feature-gated. Verify with
`grep -n '^libc' Cargo.toml` before editing anything.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib shell::`
Expected: PASS, and the `yes` test finishes in well under a second.

- [ ] **Step 5: Commit**

```bash
git add src/supervisor/backend/shell.rs Cargo.toml
git commit -m "feat(supervisor): bound shell job output and process count"
```

---

## Task 7: Layer-1 route-time gate

**Files:**
- Modify: `src/supervisor/mod.rs` (the `ROUTE → POLICY` section of `submit`, around line 1300)

> **Does Layer 1 need its own read of `[supervisor.shell].sandbox`? No — and it
> must not have one.** Spec §4: *"With `sandbox = "none"` nothing is gated: that
> mode **is** the operator's consent, and Layer 1 does not apply."* The gate is
> `needs_approval()` on the `Isolation` value Task 5 resolved, which is `false`
> for `Unconfined`, so the exemption is carried by the value — a second read of
> the config key here would be a second place the mode is decided, and two reads
> can drift. The gate still has to be *tested* under `"none"` (Step 1 below),
> because "the type makes it impossible" is exactly the kind of claim this plan
> has been wrong about four times.
>
> **Scope of that claim (review finding F3).** "The exemption is carried by the
> value" is exactly true of this step, where the isolation term **is** the whole
> gate. It stops being true in Task 8, which adds a second term — a declared
> capability the grant set does not cover — and that term is not a property of
> the `Isolation` value at all. Under `Unconfined` the second term would park a
> shell task for a grant the unconfined launch never consults, which contradicts
> spec §4 and buys nothing. Task 8 therefore moves the exemption to the **outer**
> decision (`match &self.shell_isolation { Isolation::Unconfined => None, … }`)
> rather than leaving it on the isolation term, and adds a test that declares a
> grant so the exemption has teeth. `needs_approval()` is still the whole gate
> at this step, and this step's test still asserts it; Task 8 then replaces the
> predicate with the `match` and deletes it, because one decision must have one
> representation.

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test]
    async fn a_shell_task_is_parked_for_approval_when_isolation_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        // REQUIRED: the gate asks the registry, so with an empty registry
        // `select_for` returns None, the gate never fires, and the test would
        // pass for the wrong reason. Registering the shell backend is what
        // gives the assertion teeth.
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup = sup.with_shell_isolation(Isolation::Unavailable(
            IsolationUnavailable::NotInstalled,
        ));

        let outcome = sup.submit("test", "u1", None, "run the build").await.unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::NeedsApproval { .. }),
            "got {outcome:?}"
        );
        let id = outcome.task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
    }

    #[tokio::test]
    async fn a_reasoning_task_is_not_gated_by_the_shell_gate() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup = sup.with_shell_isolation(Isolation::Unavailable(
            IsolationUnavailable::NotInstalled,
        ));

        let outcome = sup.submit("test", "u1", None, "summarise this document").await.unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::AutoExecutePlanned { .. }),
            "a task that does not select the shell backend must not be gated, got {outcome:?}"
        );
    }

    /// Spec §4: with `sandbox = "none"` **nothing is gated**. This is the test
    /// that pins it, and it is the one the whole `"none"` mode exists for — the
    /// refusal message tells an operator with no usable bubblewrap to set that
    /// key, so parking their shell tasks anyway would be the same loop one
    /// layer up.
    ///
    /// The registry is registered for the same reason as the test above: with
    /// an empty registry `would_use_shell` returns `false` and the gate never
    /// fires, so the test would pass for the wrong reason.
    #[tokio::test]
    async fn a_shell_task_is_not_gated_when_the_operator_chose_none() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        // What Task 5 Step 5 passes: `Isolation::resolve` on a config whose
        // `sandbox` is the literal `"none"`.
        let sup = sup.with_shell_isolation(Isolation::Unconfined);

        let outcome = sup.submit("test", "u1", None, "run the build").await.unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::AutoExecutePlanned { .. }),
            "`sandbox = \"none\"` is consent: nothing is gated, got {outcome:?}"
        );
    }
```

> `SubmitOutcome` has a public `task_id()` accessor (`src/supervisor/mod.rs:589-598`),
> which is how the existing tests read the id. Destructuring
> `NeedsApproval { task_id }` does not compile — the variant also carries
> `reason`.
>
> **`a_shell_task_is_not_gated_when_the_operator_chose_none` is deliberately
> superseded by Task 8, and it is worth being explicit about why.** It pins spec
> §4 against the gate *as this task writes it*, where the only term is
> `needs_approval()` — so at this point in the plan it has teeth. Task 8 adds a
> second term (a declared capability the grant set does not cover), and this test
> cannot see it: the task it submits through `submit` declares **nothing**, so
> `missing` is empty and the test returns `AutoExecutePlanned` whether or not the
> gate exempts `Unconfined`. It becomes a test that passes for the wrong reason
> at exactly the moment the property it names gets harder to hold. Task 8
> therefore adds
> `an_unconfined_shell_task_declaring_an_ungranted_capability_is_not_gated`, which
> declares a grant, and extracts the gate into `shell_gate_reason` so that test
> can reach it. **Keep this test** — it is the `submit`-level integration check —
> but do not treat it as the coverage for §4 after Task 8.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib supervisor::tests::a_shell_task`
Expected: FAIL — `no method named with_shell_isolation`, and `cannot find type
Isolation in this scope` until Task 5 Step 3a has added it.

- [ ] **Step 3: Implement the gate**

Add to `Supervisor`:

```rust
    /// The same value `ShellBackend` holds (Task 5 Step 5). `Unavailable` means
    /// the sandbox is absent, so a task that would select the shell backend
    /// must be parked for approval instead of auto-executing. `Unconfined` is
    /// the operator's standing consent, so nothing is gated (spec §4).
    shell_isolation: Isolation,
```

Add the builder:

```rust
    pub fn with_shell_isolation(mut self, r: Isolation) -> Self {
        self.shell_isolation = r;
        self
    }
```

Initialise the field **fail closed** in both constructors — `Supervisor::new`
and `Supervisor::new_for_test` — with `Isolation::default()`, which is
`Unavailable(NotDecided)` (not `NotInstalled`: a backend that was merely never
handed a decision has not established that bubblewrap is missing, and telling
the operator to install a package they probably already have is a wrong cause
with a plausible-sounding message). A `Supervisor` built without an explicit value must
park shell tasks, never run them: the default has to be the refusing one, or the
constructor becomes a way to bypass the gate.

```rust
            shell_isolation: Isolation::default(),
```

`src/main.rs` is the one place that overrides it, with the same value the
backend got (Task 5 Step 5), so the two layers cannot disagree:

```rust
    let _supervisor = Arc::new(
        haos_green::supervisor::Supervisor::new(
            config.supervisor.artifacts_dir.clone(),
            memory.connection(),
            sup_registry,
            config.supervisor.risk.clone(),
        )
        .with_shell_isolation(isolation.clone()),
    );
```

`Isolation` needs importing in `src/supervisor/mod.rs` alongside the existing
`sandbox` imports: `use backend::sandbox::Isolation;`.

In `submit`, immediately after `let decision = self.policy.decide(&task);`, insert
the gate. It asks the **registry**, so it cannot disagree with what the executor
would select:

```rust
        // LAYER 1 — route-time gate. This asks the same registry the executor
        // uses, rather than duplicating a routing predicate that could drift.
        //
        // `needs_approval()` is the whole condition, and it is `false` for
        // `Unconfined`: `sandbox = "none"` is the operator's consent, and under
        // it nothing is gated (spec §4). A second read of the config key here
        // would be a second place the mode is decided, and two can drift.
        let decision = match self.would_use_shell(&task) {
            true if self.shell_isolation.needs_approval() => {
                tracing::warn!(
                    task_id = %task.id,
                    "shell isolation unavailable; parking for approval"
                );
                PolicyDecision::RequireApproval
            }
            _ => decision,
        };
```

And the helper:

```rust
    /// Would this task select the shell backend? Derived from the registry, not
    /// from a hand-written predicate.
    fn would_use_shell(&self, task: &Task) -> bool {
        self.registry
            .select_for(&task.required_capabilities)
            .is_some_and(|b| b.name() == "shell")
    }
```

The gate has one term here — isolation unavailable — because that is the only
park reason this task can decide. Task 8 adds the second one (a declaration the
grant set does not cover) and replaces the forced `RequireApproval` reason, which
at this point still comes from the risk-level match below and would tell the
operator "high-risk task requires approval" when the real cause is the sandbox.

Task 8 also **extracts this gate into `fn shell_gate_reason(&self, task: &Task) ->
Option<String>`** and calls it from `submit` as
`let gate_reason = self.shell_gate_reason(&task);`. That is not tidying: with two
terms, `submit` is no longer a way to test the gate, because `submit` cannot give
a task a `declared_grants` declaration — see the note under Step 1's
`a_shell_task_is_not_gated_when_the_operator_chose_none`. The inline form above
stays as the shape this step writes; Task 8 replaces it.

**There is no job-scoped consent object to consult.** `/approve <id>` is the
existing lifecycle command: it moves a task out of `Route` (`Route -> Execute`,
already legal in `state.rs`), which is what "job-scoped, consumed on use" means —
the task leaves `Route`, so the approval cannot be replayed. Nothing is granted
process-wide and, under `sandbox = "bwrap"`, nothing runs unconfined: Layer 2
decides on its own, and refuses when the boundary is absent. The one standing
consent that does exist is the `"none"` mode, and it is not this gate's to give:
it was decided in `config.toml`, by the operator, and `needs_approval()` is
`false` for it.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib supervisor::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/supervisor/mod.rs
git commit -m "feat(supervisor): park shell tasks when isolation is unavailable"
```

---

## Task 8: Grants — named, revocable capability consent

> **What changed from revision 2.** Revision 2 gated consent with one
> process-wide boolean (`/unsafe-shell on|off`) plus a `host_network` config key,
> and this task built `UnsafeShellGrant` to hold both halves of it. Revision 3
> deletes that type and replaces it with the boundary drawn at **capability**:
> reads of the read-only base set are free, and a **write to a host path** and
> **the host network namespace** each need a named, revocable grant. Nothing runs
> unconfined except under `sandbox = "none"`, which is the operator's standing
> consent and gates nothing.

**Files:**
- Modify: `src/supervisor/backend/sandbox.rs` (the `Grants` operations)
- Modify: `src/supervisor/job.rs` and `src/supervisor/task.rs` (the declaration)
- Modify: `src/supervisor/planner.rs` (carry the declaration into each job)
- Modify: `src/supervisor/backend/shell.rs` (Layer 2 refuses an uncovered declaration)
- Modify: `src/supervisor/store.rs` and `src/memory/mod.rs` (the audit row)
- Modify: `src/supervisor/mod.rs`
- Modify: `src/main.rs` (attach the shared grant set to the supervisor)
- Modify: `src/platform/telegram.rs`
- Modify: `src/web/routes/supervisor.rs`

- [ ] **Step 1: Write the failing tests**

**Grants semantics** — add to the `tests` module in
`src/supervisor/backend/sandbox.rs`:

```rust
    fn declaration(paths: &[&str], network: bool) -> Grants {
        Grants { write: paths.iter().map(PathBuf::from).collect(), network }
    }

    #[test]
    fn a_write_grant_covers_exactly_the_path_named_and_not_its_children() {
        let mut g = Grants::default();
        g.grant_write("/var/lib").unwrap();
        assert!(g.covers(&declaration(&["/var/lib"], false)));
        // `/allow /var/lib` must not hand over `/var/lib/docker/x`: a grant is
        // one path, and widening is a separate, explicit decision.
        assert!(!g.covers(&declaration(&["/var/lib/docker/x"], false)));
        let missing = g.missing(&declaration(&["/var/lib/docker/x"], false));
        assert!(
            missing.iter().any(|m| m.contains("/allow /var/lib/docker/x")),
            "the operator is told the path and the command: {missing:?}"
        );
    }

    #[test]
    fn a_grant_is_matched_on_the_canonicalised_path() {
        // `/etc/../etc` and a symlink pointing at the granted directory must
        // resolve to the same entry, or the grant is trivially side-stepped.
        let mut g = Grants::default();
        g.grant_write("/etc").unwrap();
        assert!(g.covers(&declaration(&["/etc/../etc"], false)));
        assert!(!g.covers(&declaration(&["/etc/hosts"], false)), "still not a prefix match");

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut g = Grants::default();
        g.grant_write(&real.to_string_lossy()).unwrap();
        assert!(g.covers(&declaration(&[&link.to_string_lossy()], false)));
    }

    #[test]
    fn a_grant_of_the_root_is_refused_at_issue_time() {
        let mut g = Grants::default();
        let e = g.grant_write("/").unwrap_err();
        assert!(e.to_string().contains("withhold"), "{e}");
        assert!(g.write.is_empty(), "a refused grant is not held");
    }

    #[test]
    fn a_relative_path_is_refused_at_issue_time() {
        let mut g = Grants::default();
        let e = g.grant_write("etc").unwrap_err();
        assert!(e.to_string().contains("absolute"), "{e}");
    }

    #[test]
    fn a_path_that_does_not_exist_is_refused_at_issue_time() {
        let mut g = Grants::default();
        let e = g.grant_write("/nonexistent/definitely-not-here").unwrap_err();
        assert!(e.to_string().contains("cannot grant"), "{e}");
    }

    #[test]
    fn a_double_dash_is_not_read_as_a_flag() {
        // The path is operator input: `/allow -- /etc` must not be read as a
        // flag, and the `--` must not become part of the path either.
        let mut g = Grants::default();
        assert_eq!(g.grant_write("-- /etc").unwrap(), PathBuf::from("/etc"));
        assert!(g.covers(&declaration(&["/etc"], false)));
        // `--` alone is a missing path, not a grant of everything.
        assert!(g.grant_write("--").is_err());
    }

    #[test]
    fn deny_revokes_immediately() {
        let mut g = Grants::default();
        g.grant_write("/etc").unwrap();
        assert!(g.covers(&declaration(&["/etc"], false)));
        g.revoke_write("/etc").unwrap();
        assert!(!g.covers(&declaration(&["/etc"], false)), "revocation is immediate");
    }

    #[test]
    fn a_grant_can_be_revoked_after_the_path_is_gone() {
        // Otherwise a grant outlives the operator's ability to take it back.
        let root = std::fs::canonicalize(tempfile::tempdir().unwrap().path().to_path_buf()).unwrap();
        let p = root.join("gone");
        std::fs::create_dir_all(&p).unwrap();
        let mut g = Grants::default();
        g.grant_write(&p.to_string_lossy()).unwrap();
        std::fs::remove_dir_all(&p).unwrap();
        g.revoke_write(&p.to_string_lossy()).unwrap();
        assert!(g.write.is_empty(), "the grant must be gone: {:?}", g.write);
    }

    #[test]
    fn the_network_grant_is_the_only_thing_that_covers_the_network() {
        let mut g = Grants::default();
        assert!(!g.covers(&declaration(&[], true)));
        g.grant_network();
        assert!(g.covers(&declaration(&[], true)));
        g.revoke_network();
        assert!(!g.covers(&declaration(&[], true)), "revocation is immediate");
    }

    #[test]
    fn nothing_is_held_by_default() {
        let g = Grants::default();
        assert!(g.write.is_empty(), "no writable host path");
        assert!(!g.network, "no host network");
        assert!(g.held().is_empty(), "and nothing to list");
    }
```

**The audit trail and the restart** — add to the `tests` module in
`src/supervisor/mod.rs`:

```rust
    #[tokio::test]
    async fn every_grant_and_revocation_writes_a_sup_transitions_row() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let sup = Supervisor::new_for_test(dir.path().into(), conn.clone());

        sup.grant_write("telegram:42", "/etc").await.unwrap();
        sup.grant_network("telegram:42").await.unwrap();
        sup.deny_write("telegram:42", "/etc").await.unwrap();
        sup.deny_network("telegram:42").await.unwrap();

        // Read the table itself: the row **is** the audit trail, and a row
        // written through something nobody can query would be no trail at all.
        let conn = conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT actor, reason, task_id FROM sup_transitions ORDER BY id")
            .unwrap();
        let rows: Vec<(String, String, Option<String>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(rows.len(), 4, "one row per grant and per revocation: {rows:?}");
        for (actor, _reason, task_id) in &rows {
            assert_eq!(actor, "telegram:42", "the row names the actor");
            assert!(task_id.is_none(), "a grant belongs to no task");
        }
        assert!(rows[0].1.contains("granted") && rows[0].1.contains("/etc"), "{:?}", rows[0]);
        assert!(rows[1].1.contains("network"), "{:?}", rows[1]);
        assert!(rows[2].1.contains("revoked") && rows[2].1.contains("/etc"), "{:?}", rows[2]);
        assert!(rows[3].1.contains("revoked") && rows[3].1.contains("network"), "{:?}", rows[3]);
    }

    #[tokio::test]
    async fn a_restart_holds_no_grants() {
        // In-memory, deliberately: a restart is a cheap, complete revocation,
        // matching the dashboard's session model. The audit rows survive; the
        // grants do not.
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let sup = Supervisor::new_for_test(dir.path().into(), conn.clone());
        sup.grant_write("telegram:42", "/etc").await.unwrap();
        assert!(!sup.grants_held().is_empty());

        // A second supervisor over the same database is a restart.
        let restarted = Supervisor::new_for_test(dir.path().into(), conn.clone());
        assert!(restarted.grants_held().is_empty(), "grants never persist");
    }

    #[test]
    fn the_park_reason_names_each_missing_grant_and_how_to_release_it() {
        let held = Grants::default();
        let declared = Grants {
            write: [std::path::PathBuf::from("/var/lib")].into(),
            network: true,
        };
        let reason = park_reason(&held, &declared, "task-1", "run the migration");
        assert!(reason.contains("/allow /var/lib"), "{reason}");
        assert!(reason.contains("/allow-net"), "{reason}");
        assert!(reason.contains("task-1"), "the task is named: {reason}");
        assert!(
            reason.contains("run the migration"),
            "why the task wants it is named too: {reason}"
        );
    }
```

**The Layer-2 refusal** — add to the `tests` module in
`src/supervisor/backend/shell.rs`:

```rust
    #[tokio::test]
    async fn refuses_a_job_whose_declaration_is_not_covered() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into())
            .with_isolation(Isolation::Sandboxed)
            .with_grants(Arc::new(std::sync::RwLock::new(Grants::default())));
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "echo should-not-run",
        );
        job.declared_grants = Grants {
            write: [std::path::PathBuf::from("/var/lib")].into(),
            network: true,
        };
        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(matches!(out.status, crate::supervisor::job::JobStatus::Failed));
        assert!(
            out.errors.iter().any(|e| e.contains("/allow /var/lib")),
            "must name the grant that releases it, got {:?}",
            out.errors
        );
        assert!(
            out.errors.iter().any(|e| e.contains("/allow-net")),
            "got {:?}",
            out.errors
        );
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib supervisor::` and `cargo test --lib shell::`
Expected: FAIL — `no method named grant_write`, `no field declared_grants`, `no
method named record_grant_audit`, `cannot find function park_reason`.

- [ ] **Step 3: Implement the grant set**

Add to `src/supervisor/backend/sandbox.rs`:

```rust
/// Strip one leading `--` from operator input.
///
/// The path is operator input, so `/allow -- /etc` must not be read as a flag.
/// No absolute path begins with `--`, so this cannot eat a legitimate one.
fn strip_dashes(raw: &str) -> &str {
    let raw = raw.trim();
    raw.strip_prefix("--").map(str::trim_start).unwrap_or(raw)
}

impl Grants {
    /// Canonicalise an operator-supplied grant path, refusing the three that
    /// have no meaning as a grant.
    ///
    /// Refused **at issue time**, not when a job later fails to start:
    ///
    /// - `/` would hand back everything the sandbox exists to withhold;
    /// - a relative path has no meaning once the sandbox has its own root;
    /// - a path that does not exist cannot be bound, and binding it later would
    ///   be a decision nobody made.
    pub fn resolve_path(raw: &str, sandbox_root: &Path) -> Result<PathBuf> {
        let raw = strip_dashes(raw);
        if raw.is_empty() {
            bail!("a grant needs a path");
        }
        let p = Path::new(raw);
        if !p.is_absolute() {
            bail!(
                "{raw:?} is not an absolute path: the sandbox has its own root, so a \
                 relative path has no meaning"
            );
        }
        if p == Path::new("/") {
            bail!("refusing to grant /: it is everything the sandbox withholds");
        }
        let canon = std::fs::canonicalize(p)
            .map_err(|e| anyhow::anyhow!("cannot grant {}: {e}", p.display()))?;
        if canon == Path::new("/") {
            bail!("refusing to grant {}: it resolves to /", p.display());
        }
        Ok(canon)
    }

    /// Grant read-write access to one host path, for every future job until it
    /// is revoked. Returns the canonical path the caller audits.
    pub fn grant_write(&mut self, raw: &str, sandbox_root: &Path) -> Result<PathBuf> {
        let path = Self::resolve_path(raw, sandbox_root)?;
        self.write.insert(path.clone());
        Ok(path)
    }

    /// Revoke a write grant.
    ///
    /// Lenient about existence, unlike [`Self::resolve_path`]: a path deleted
    /// since it was granted must still be revocable, or a grant could outlive
    /// the operator's ability to take it back. Both the literal path and its
    /// canonical form are removed, so the entry that was inserted is found
    /// either way.
    pub fn revoke_write(&mut self, raw: &str) -> Result<PathBuf> {
        let raw = strip_dashes(raw);
        let p = Path::new(raw);
        if raw.is_empty() || !p.is_absolute() {
            bail!("a revocation needs an absolute path, got {raw:?}");
        }
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        self.write.remove(p);
        self.write.remove(&canon);
        Ok(canon)
    }

    pub fn grant_network(&mut self) {
        self.network = true;
    }

    pub fn revoke_network(&mut self) {
        self.network = false;
    }

    /// What `declared` asks for that is not held, named the way the operator
    /// has to name it. Used verbatim in the park reason and in the Layer-2
    /// refusal, so the two cannot say different things.
    pub fn missing(&self, declared: &Grants) -> Vec<String> {
        let mut out = Vec::new();
        for d in &declared.write {
            // Canonicalised on both sides: `/etc/../etc` and a symlink to /etc
            // resolve to the same entry. An **exact** match, never a prefix — a
            // grant covers the path named and not its children.
            let canon = std::fs::canonicalize(d).unwrap_or_else(|_| d.clone());
            if !self.write.contains(&canon) {
                out.push(format!(
                    "a writable host path {} — grant it with `/allow {}`",
                    d.display(),
                    d.display()
                ));
            }
        }
        if declared.network && !self.network {
            out.push("the host network namespace — grant it with `/allow-net`".to_string());
        }
        out
    }

    /// Does the held set cover everything this declaration asks for?
    pub fn covers(&self, declared: &Grants) -> bool {
        self.missing(declared).is_empty()
    }

    /// What is held, for the operator and the dashboard.
    pub fn held(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .write
            .iter()
            .map(|p| format!("write {}", p.display()))
            .collect();
        if self.network {
            out.push("network".to_string());
        }
        out
    }
}
```

The fields stay `pub` because the argv builder and the tests read them; every
**write** goes through `Supervisor`, which is what writes the audit row.

- [ ] **Step 3b: Refuse a grant that covers the sandbox root, or an ancestor of it**

The job directory's own checks (Task 3) assume no *job* can write the levels they
walk, and spec §1.3 says so next to them. Nothing enforces that assumption today:
`resolve_path` above accepts any absolute existing path, and the default root is
the same directory the chat agent's shell tool uses as its working directory, so
`/allow <home>/workspace` — or `/allow <home>`, which covers it just as surely —
is exactly the grant that makes the residual reachable by a job. The resolution
checks cannot enforce it themselves: the writer they would have to exclude *is*
the job.

Thread the root into the resolution. `Supervisor` already holds the backend, so
give it the root as a field in Task 5 Step 5's wiring (`sandbox_root: PathBuf`,
the same value `ShellBackend::new` receives) and change the two signatures:

```rust
pub fn resolve_path(raw: &str, sandbox_root: &Path) -> Result<PathBuf>
pub fn grant_write(&mut self, raw: &str, sandbox_root: &Path) -> Result<PathBuf>
```

and add the rule to `resolve_path`, after the canonicalise and the `/` check:

```rust
    // A grant that covers the sandbox root hands a job write access to the
    // levels `resolve_job_dir` walks, which is the one precondition its
    // containment checks cannot enforce for themselves (spec §1.3). Ancestors
    // count: `<home>` covers `<home>/workspace`, and the root path is
    // re-resolved on every call, so write access to the *parent* is enough to
    // swap the root itself. `starts_with` is a component test — `/ws-evil` is
    // not below `/ws`, however much it looks like it as a string.
    let root = std::fs::canonicalize(sandbox_root).unwrap_or_else(|_| sandbox_root.to_path_buf());
    if root.starts_with(&canon) {
        bail!(
            "refusing to grant {}: it covers the sandbox root {} — a job that can \
             write there can move the directory its own sandbox is built from",
            canon.display(),
            root.display()
        );
    }
```

The direction is the whole rule: refuse when the **granted** path is the root or
an ancestor of it. A grant *inside* the root does not cover the root, and the
exact-path matching above means it cannot reach the root's own levels either, so
it stays allowed.

Add this test beside the other `resolve_path` refusals in Step 1:

```rust
    #[test]
    fn a_grant_covering_the_sandbox_root_or_an_ancestor_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("workspace");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        // The root, and every ancestor of it: each one hands a job write access
        // to the levels `resolve_job_dir` walks.
        for covered in [
            root.clone(),
            home.path().to_path_buf(),
            home.path().parent().unwrap().to_path_buf(),
        ] {
            let e = Grants::resolve_path(&covered.to_string_lossy(), &root)
                .unwrap_err()
                .to_string();
            assert!(e.contains("covers the sandbox root"), "{}: {e}", covered.display());
        }

        // A sibling of the root, and a path inside it, are legitimate grants.
        let sibling = home.path().join("other");
        std::fs::create_dir_all(&sibling).unwrap();
        assert!(Grants::resolve_path(&sibling.to_string_lossy(), &root).is_ok());
        let inside = root.join("sub");
        std::fs::create_dir_all(&inside).unwrap();
        assert!(Grants::resolve_path(&inside.to_string_lossy(), &root).is_ok());
    }
```

**Mutation (required).** Change `root.starts_with(&canon)` to `root == canon` and
run the test: the ancestor cases must fail with the grant accepted, while the two
legitimate grants still pass. A rule with no mutant is a rule nobody has seen
work, and this one is the only thing standing between a job and the sandbox
root.

- [ ] **Step 4: Make the audit row writable, and write it**

`sup_transitions.task_id` is `TEXT NOT NULL` with a foreign key to `sup_tasks`
(`src/memory/mod.rs:295-304`), and the connection sets `PRAGMA
foreign_keys=ON`. A grant belongs to **no task**, so a row for one cannot be
inserted as the schema stands — and `TaskStore::record_transition("", …)` cannot
be used for it: the insert fails the foreign key, and its compare-and-swap on
`sup_tasks` has no row to match. Both failures roll the audit row back.

In `src/memory/mod.rs`, after the existing DDL in `run_migrations`, add the
one-time rebuild — SQLite cannot drop `NOT NULL` in place:

```rust
        // Migration: `sup_transitions.task_id` must be nullable.
        //
        // A grant is process-wide, not task-scoped: `/allow /etc` is not a
        // transition of any task, so its audit row has no `sup_tasks` row to
        // point at. The column was declared NOT NULL with a foreign key, which
        // makes that row impossible to write. NULL is allowed in a foreign key
        // column, so the rebuild is enough — no foreign key is dropped.
        let not_null: bool = conn
            .query_row(
                "SELECT notnull FROM pragma_table_info('sup_transitions') WHERE name = 'task_id'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n == 1)
            .unwrap_or(false);
        if not_null {
            conn.execute_batch(
                "PRAGMA foreign_keys=OFF;
                 BEGIN;
                 CREATE TABLE sup_transitions_new (
                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                     task_id     TEXT,
                     from_state  TEXT NOT NULL,
                     to_state    TEXT NOT NULL,
                     reason      TEXT,
                     actor       TEXT NOT NULL,
                     occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
                     FOREIGN KEY (task_id) REFERENCES sup_tasks(id)
                 );
                 INSERT INTO sup_transitions_new
                     (id, task_id, from_state, to_state, reason, actor, occurred_at)
                     SELECT id, task_id, from_state, to_state, reason, actor, occurred_at
                     FROM sup_transitions;
                 DROP TABLE sup_transitions;
                 ALTER TABLE sup_transitions_new RENAME TO sup_transitions;
                 COMMIT;
                 PRAGMA foreign_keys=ON;",
            )?;
        }
```

Add to `src/supervisor/store.rs`:

```rust
    /// Append an audit row that belongs to no task.
    ///
    /// `record_transition` is the wrong tool twice over: a grant is not a state
    /// transition, and its row has no task to point at, so the foreign key
    /// refuses the insert and the `sup_tasks` compare-and-swap answers
    /// `not_found`. The row is inserted directly, with a NULL `task_id`.
    ///
    /// `from_state`/`to_state` are both `Route`: the columns are NOT NULL and
    /// this is not a transition at all — `reason` carries the meaning, and it
    /// names the actor's action, the path and whether it was granted or revoked.
    pub async fn record_grant_audit(&self, actor: &str, reason: &str) -> Result<()> {
        let state = serde_json::to_string(&TaskStatus::Route)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO sup_transitions (task_id, from_state, to_state, reason, actor)
             VALUES (NULL, ?1, ?2, ?3, ?4)",
            rusqlite::params![state, state, reason, actor],
        )
        .context("insert sup_transitions grant audit row")?;
        Ok(())
    }
```

Add to `Supervisor` in `src/supervisor/mod.rs`:

```rust
    /// The live grant set, shared with every `ShellBackend`.
    grants: Arc<std::sync::RwLock<Grants>>,
```

```rust
    /// Grant read-write access to one host path.
    ///
    /// Mutation and audit are one method on purpose: there is no way to grant
    /// without leaving a row. The row is written **before** the grant takes
    /// effect, so a grant that cannot be recorded does not exist.
    pub async fn grant_write(&self, actor: &str, raw: &str) -> Result<PathBuf> {
        let path = Grants::resolve_path(raw, &self.sandbox_root)?;
        self.store
            .record_grant_audit(actor, &format!("granted write access to {}", path.display()))
            .await?;
        self.grants.write().unwrap().write.insert(path.clone());
        Ok(path)
    }

    pub async fn deny_write(&self, actor: &str, raw: &str) -> Result<PathBuf> {
        // Resolve leniently first — a path deleted since it was granted must
        // still be revocable — then audit, then mutate, the same order and for
        // the same reason as `grant_write`.
        let path = {
            let mut probe = self.grants.read().unwrap().clone();
            probe.revoke_write(raw)?
        };
        self.store
            .record_grant_audit(actor, &format!("revoked write access to {}", path.display()))
            .await?;
        self.grants.write().unwrap().revoke_write(&path.to_string_lossy())?;
        Ok(path)
    }

    pub async fn grant_network(&self, actor: &str) -> Result<()> {
        self.store
            .record_grant_audit(actor, "granted the host network namespace")
            .await?;
        self.grants.write().unwrap().grant_network();
        Ok(())
    }

    pub async fn deny_network(&self, actor: &str) -> Result<()> {
        self.store
            .record_grant_audit(actor, "revoked the host network namespace")
            .await?;
        self.grants.write().unwrap().revoke_network();
        Ok(())
    }

    /// What is held, for the dashboard and the operator.
    pub fn grants_held(&self) -> Vec<String> {
        self.grants.read().unwrap().held()
    }
```

`deny_write` above is deliberately lenient where `grant_write` is strict: a
revocation must work for a path that has been deleted since it was granted, or a
grant could outlive the operator's ability to take it back. Everything else is
identical — resolve, audit, mutate.

`new_for_test` and `new` both build `Self { … }` field by field
(`src/supervisor/mod.rs:614`, `:640`), so both need
`grants: Arc::new(std::sync::RwLock::new(Grants::default()))` — fail closed, the
empty set. The production wiring in `src/main.rs` then attaches the shared set
with the builder below, so the supervisor and every `ShellBackend` hold the
**same** one:

```rust
    pub fn with_grants(mut self, grants: Arc<std::sync::RwLock<Grants>>) -> Self {
        self.grants = grants;
        self
    }
```

In `src/main.rs`, the supervisor takes the same `Arc` the backend did (Task 5),
so a `/allow` typed at the Telegram prompt reaches the next argv:

```rust
let supervisor = Supervisor::new(artifacts_root, conn, registry, thresholds)
    .with_grants(grants.clone());
```

- [ ] **Step 5: Refuse an uncovered declaration, and say who to ask**

Add the declaration to `Task` and `Job` (`src/supervisor/task.rs`,
`src/supervisor/job.rs`), defaulting to the empty set — "this job needs nothing
beyond its own job directory" — and have the planner copy the task's declaration
into every job it creates:

```rust
    /// The capabilities this task declares it needs. Empty means "nothing
    /// beyond its own job directory", which is the shipped default.
    #[serde(default)]
    pub declared_grants: Grants,
```

In `src/supervisor/backend/shell.rs`, `run` gains the coverage refusal, and the
guard read moves above it so one snapshot serves both the check and the argv:

```rust
        // A capability the job declares and the operator has not granted is
        // refused here, before anything is spawned. bubblewrap cannot be widened
        // after it starts, so a missing grant can only mean "do not run".
        let held = self.grants.read().unwrap().clone();
        let missing = held.missing(&job.declared_grants);
        if !missing.is_empty() {
            job.status = JobStatus::Failed;
            return Ok(JobOutput {
                status: JobStatus::Failed,
                summary: String::new(),
                evidence: vec![],
                errors: vec![format!(
                    "refusing to run a shell job that needs what the supervisor does not \
                     hold: {}. Grant it by name, then approve the task again.",
                    missing.join("; ")
                )],
                changed_files: vec![],
                next_step: None,
            });
        }
        let argv = sandbox::build_argv(&job_dir, &held, &cmd);
```

In `src/supervisor/mod.rs`, extend the Layer-1 gate to park on a missing
declaration too, and replace the risk-level reason with the gate's own. The
operator is asked **by name**, per missing grant:

```rust
/// Why a shell task was parked, naming each grant it needs, the command that
/// releases it, and what the task is trying to do. The operator is never told
/// only "approval required" — spec §3 asks for the path **and** the reason.
pub fn park_reason(held: &Grants, declared: &Grants, task_id: &str, request: &str) -> String {
    let missing = held.missing(declared);
    format!(
        "task {task_id} declares {} it does not hold, for: {request}. Grant {} by name, then \
         approve the task again with `/approve {task_id}`.",
        missing.join(", "),
        if missing.len() == 1 { "it" } else { "them" }
    )
}
```

```rust
    /// The Layer-1 park reason for a task, or `None` if it is not gated.
    ///
    /// Extracted from `submit` so the gate is reachable from a test holding a
    /// task that **declares a capability**. `submit` cannot produce one in this
    /// revision — nothing populates `Task::declared_grants` from operator input
    /// yet — so a gate driven only through `submit` can never be shown to fire
    /// on the grant term, and a test that cannot make the gate fire cannot tell
    /// a working exemption from a gate that never runs.
    fn shell_gate_reason(&self, task: &Task) -> Option<String> {
        if !self.would_use_shell(task) {
            return None;
        }
        // **The whole gate is skipped under `Unconfined`, and that is spec §4,
        // not an optimisation.** "With `sandbox = "none"` nothing is gated: that
        // mode *is* the operator's consent, and Layer 1 does not apply." The
        // exemption is therefore the *outer* decision, not the isolation term
        // alone. Both terms exist to stop a job reaching a boundary wider than
        // the operator sanctioned: `Unavailable` because there is no boundary to
        // reach at all, and a missing grant because the sandboxed launch would
        // bind more than was granted. Under `Unconfined` there is no argv and no
        // bind: Layer 2 runs `sh -c` in the job directory and reads neither
        // `Grants` nor `declared_grants`. Parking on the grant term there would
        // therefore cost one approval round-trip and change nothing about what
        // runs — and Layer 2, which is the boundary, would not corroborate the
        // park.
        //
        // A `match` rather than `needs_approval() || !missing.is_empty()`:
        // `needs_approval()` is a pure function of the isolation decision and has
        // no grant set to look at, so it cannot express the second term. Keeping
        // both terms in one `match` on the mode is what makes the exemption
        // structural — there is exactly one place `Unconfined` is answered, and
        // it answers before either term is evaluated, so a third term cannot be
        // added above it by accident. For the same reason this `match` replaces
        // `needs_approval()` entirely — see the deletion below.
        match &self.shell_isolation {
            Isolation::Unconfined => None,
            Isolation::Unavailable(reason) => Some(format!(
                "shell isolation is unavailable, so a task that would select the shell \
                 backend is parked: {reason}. Fix bubblewrap (>= 0.12.0) or set \
                 [supervisor.shell].sandbox = \"none\". A grant cannot replace a missing \
                 sandbox; `/allow <path>` and `/allow-net` release a capability."
            )),
            Isolation::Sandboxed => {
                let held = self.grants.read().unwrap().clone();
                let missing = held.missing(&task.declared_grants);
                if missing.is_empty() {
                    None
                } else {
                    Some(park_reason(
                        &held,
                        &task.declared_grants,
                        &task.id,
                        // `user_request` is already capped by `IntakeRouter`, and
                        // the reply is bounded again before it is sent.
                        &task.user_request,
                    ))
                }
            }
        }
    }
```

and in `submit`, in place of the whole inline gate:

```rust
        let gate_reason = self.shell_gate_reason(&task);
        let decision = if gate_reason.is_some() {
            PolicyDecision::RequireApproval
        } else {
            decision
        };
```

**Delete `Isolation::needs_approval()`.** It was the whole gate in Task 7, and
this step's `match` answers the same question — including spec §4's exemption —
structurally, from the one place the mode is decided. Leaving the predicate
behind would mean **two representations of one decision**, and the plan has been
burned four times by an interface that was defined and then not wired to
anything; the drift risk here is the same defect with the polarity reversed: a
future arm added to `needs_approval()` that the `match` never consults, or the
reverse. Its only caller is the Task 7 gate this step replaces, and no test calls
it directly — Task 7's `a_shell_task_is_not_gated_when_the_operator_chose_none`
asserts through `submit` — so the deletion moves nothing else. `Isolation` is
`pub`, so `#![deny(dead_code)]` would **not** have caught it.

**The test that gives the exemption teeth** — add to the `tests` module in
`src/supervisor/mod.rs`, next to Task 7's
`a_shell_task_is_not_gated_when_the_operator_chose_none`:

```rust
    /// Spec §4, with teeth — which Task 7's
    /// `a_shell_task_is_not_gated_when_the_operator_chose_none` does not have
    /// once this task adds the grant term.
    ///
    /// That test goes through `submit`, and `submit` cannot give a task a
    /// declaration: `declared_grants` is empty for every task this revision can
    /// create. So `missing` is empty, the grant term cannot fire, and the test
    /// returns `AutoExecutePlanned` whether or not the gate exempts
    /// `Unconfined` — it passes for the wrong reason against exactly the
    /// regression this pins. This test declares the capability the grant term
    /// parks on under `"bwrap"`, asserts the same task is **not** gated under
    /// `"none"`, and then asserts it **is** gated under `"bwrap"`, so the
    /// exemption cannot pass by the gate being dead.
    #[tokio::test]
    async fn an_unconfined_shell_task_declaring_an_ungranted_capability_is_not_gated() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));

        // The task `submit` builds for "run the build" — the heuristic
        // classifier gives it the `shell` capability — carrying the declaration
        // the planner copies into every job. The supervisor holds
        // `Grants::default()`, so both halves of the declaration are missing.
        let mut task = crate::supervisor::intake::IntakeRouter::normalize("run the build");
        task.required_capabilities = vec!["shell".into()];
        task.declared_grants = Grants {
            write: [std::path::PathBuf::from("/var/lib")].into(),
            network: true,
        };

        let unconfined = sup.with_shell_isolation(Isolation::Unconfined);
        assert_eq!(
            unconfined.shell_gate_reason(&task),
            None,
            "`sandbox = \"none\"` is the operator's consent: neither term may park"
        );

        // The control. Without it the assertion above holds for a gate that
        // never fires at all, which is the shape of the bug this test exists
        // for — the test would be its own counterexample.
        let sandboxed = unconfined.with_shell_isolation(Isolation::Sandboxed);
        let reason = sandboxed
            .shell_gate_reason(&task)
            .expect("a declared-but-ungranted capability must park under `bwrap`");
        assert!(reason.contains("/var/lib"), "{reason}");
        assert!(reason.contains("/allow-net"), "{reason}");
    }
```

> `use crate::supervisor::backend::sandbox::Grants;` and
> `use crate::supervisor::intake::IntakeRouter;` join the test module's imports
> if they are not already there. The `required_capabilities` line is set
> explicitly rather than left to the classifier: the assertion is about the gate
> reading the registry, and it must not move if the classifier's heuristics are
> retuned.

**Mutation:** make the `Unconfined` arm fall through to the `Sandboxed` arm (or
delete it) and
`an_unconfined_shell_task_declaring_an_ungranted_capability_is_not_gated` fails,
naming `/var/lib`. Task 7's test still passes under that mutant — which is the
whole reason the second test exists.

and in the `RequireApproval` arm of the outcome match, the gate's reason wins:

```rust
            PolicyDecision::RequireApproval => {
                let reason = gate_reason.clone().unwrap_or_else(|| match task.risk_level {
                    // ... the existing risk-level text, unchanged ...
                });
                SubmitOutcome::NeedsApproval { task_id: task.id, reason }
            }
```

**Known bound, stated rather than hidden:** nothing in the current intake or
planner path *fills* a declaration — a task built from operator text declares
nothing, so the missing-grant park fires only for a task something else declared
for. Deriving the declaration from a job's command is the planner's job and is
not part of this task (spec §3 leaves the derivation open). The isolation-
unavailable park is live today, and `/allow` is live today through the argv:
a granted path is bound read-write on the next job.

- [ ] **Step 6: Add the four commands**

In `src/platform/telegram.rs`, add `allow`, `deny`, `allow-net` and `deny-net` to
**both** `supervisor_commands()` (the published menu) and `SUPERVISOR_COMMANDS`
(now `[&str; 10]`), and add the match arms to `dispatch_supervisor_command`.
The two lists are compared by
`the_published_menu_and_the_router_name_the_same_commands`, so they cannot drift:

```rust
        "/allow" => grant_command(arg, actor, supervisor, GrantAction::Allow).await,
        "/deny" => grant_command(arg, actor, supervisor, GrantAction::Deny).await,
        "/allow-net" => grant_command(arg, actor, supervisor, GrantAction::AllowNet).await,
        "/deny-net" => grant_command(arg, actor, supervisor, GrantAction::DenyNet).await,
```

```rust
/// Longest grant path the dispatcher accepts, in characters. `PATH_MAX` is 4096
/// on Linux; a longer argument is refused, never truncated.
pub(crate) const MAX_GRANT_PATH_CHARS: usize = 4096;

/// The four grant commands. `takes_path` is what keeps `/allow-net` from
/// accepting an argument it has no use for.
enum GrantAction {
    Allow,
    Deny,
    AllowNet,
    DenyNet,
}

impl GrantAction {
    fn takes_path(&self) -> bool {
        matches!(self, Self::Allow | Self::Deny)
    }

    fn usage(&self) -> String {
        match self {
            Self::Allow => "Usage: /allow <absolute path>".to_string(),
            Self::Deny => "Usage: /deny <absolute path>".to_string(),
            Self::AllowNet => "Usage: /allow-net".to_string(),
            Self::DenyNet => "Usage: /deny-net".to_string(),
        }
    }
}

/// One path, one command. `/allow /etc /var` is a usage line, not a silent
/// grant of the first path — a path containing a space cannot be expressed here
/// at all, which is a documented bound rather than a truncation.
async fn grant_command(
    arg: &str,
    actor: &SupervisorActor,
    supervisor: &Supervisor,
    action: GrantAction,
) -> String {
    let mut parts = arg.split_whitespace();
    let first = parts.next().unwrap_or("");
    let path = if first == "--" { parts.next().unwrap_or("") } else { first };

    if action.takes_path() {
        if path.is_empty() || path.chars().count() > MAX_GRANT_PATH_CHARS || parts.next().is_some()
        {
            return action.usage();
        }
    } else if !arg.trim().is_empty() {
        // `/allow-net /etc` is a usage line: the command takes no argument.
        return action.usage();
    }

    // The actor is the Telegram user id, so the audit row answers "who allowed
    // writes to /etc, and when?" without a second lookup.
    let who = format!("telegram:{}", actor.user_id);
    match action {
        GrantAction::Allow => match supervisor.grant_write(&who, path).await {
            Ok(p) => format!(
                "Granted write access to {}. Every future shell job may write there until \
                 `/deny {}` or a restart.",
                p.display(),
                p.display()
            ),
            Err(e) => format!("Refused: {e}"),
        },
        GrantAction::Deny => match supervisor.deny_write(&who, path).await {
            Ok(p) => format!("Revoked write access to {}. A job that needs it is refused again.", p.display()),
            Err(e) => format!("Refused: {e}"),
        },
        GrantAction::AllowNet => match supervisor.grant_network(&who).await {
            Ok(()) => "The host network namespace is granted until `/deny-net` or a restart. \
                       This is the HOST namespace: loopback services, the LAN and Tailscale \
                       are reachable from inside the sandbox."
                .to_string(),
            Err(_) => SUPERVISOR_FAULT.to_string(),
        },
        GrantAction::DenyNet => match supervisor.deny_network(&who).await {
            Ok(()) => "The host network namespace is revoked. The sandbox is filesystem-only again.".to_string(),
            Err(_) => SUPERVISOR_FAULT.to_string(),
        },
    }
}
```

A refusal at issue time (`/`, a relative path, a path that does not exist) is the
operator's input, so its reason is answered verbatim; a store fault answers the
fixed `SUPERVISOR_FAULT`. The reply goes through the same `redact` +
`bounded_reply` path as every other supervisor reply, and the allowed-user check
stays where it is — first statement, before the argument is parsed.

- [ ] **Step 7: Add the dashboard equivalents**

In `src/web/routes/supervisor.rs`, add three routes inside the existing guarded
router (so the session/IP/CSRF layers already apply — every one of them is a
`POST` except the listing):

```rust
        .route("/api/supervisor/grants", get(list_grants))
        .route("/api/supervisor/grants/allow", post(allow_grant))
        .route("/api/supervisor/grants/deny", post(deny_grant))
```

```rust
/// A grant request. Exactly one of the two fields is set: a host path, or the
/// host network.
#[derive(serde::Deserialize)]
struct GrantRequest {
    path: Option<String>,
    network: Option<bool>,
}
```

- `GET /api/supervisor/grants` → `{ "held": ["write /etc", "network"] }`.
- `POST …/allow` with `{"path": "/etc"}` or `{"network": true}` → 200 with what
  is now held; **400** with the refusal reason for `/`, a relative path, a path
  that does not exist, or neither field set; **503** when the supervisor is
  unavailable, through `state.supervisor_or_unavailable()` exactly as the other
  routes do.
- `POST …/deny` with the same body → the same, revoking.

The dashboard has one operator identity, so the audit actor is the fixed string
`"dashboard"`. The routes take no task id and change no task state, so there is
no lifecycle pre-check and no 409: a refusal here is about the path, which is
what the 400 body carries.

- [ ] **Step 8: Run the tests**

Run: `cargo test --lib` and `cargo test --test web_endpoint`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/supervisor/backend/sandbox.rs src/supervisor/backend/shell.rs \
        src/supervisor/job.rs src/supervisor/task.rs src/supervisor/planner.rs \
        src/supervisor/mod.rs src/supervisor/store.rs src/memory/mod.rs \
        src/main.rs src/platform/telegram.rs src/web/routes/supervisor.rs
git commit -m "feat(supervisor): gate host writes and the host network behind named grants"
```

---

## Task 9: Real-bwrap tests, documentation, gates

**Files:**
- Create: `tests/shell_sandbox_live.rs`
- Modify: `CLAUDE.md`
- Modify: `docs/GUIDE.md`

- [ ] **Step 1: Write the live test file**

Follow the `tests/a2a_e2e_live.rs` convention exactly: `#[ignore]`d **and**
re-checked at runtime against `HAOS_GREEN_SHELL_LIVE=1`, so plain `cargo test`
stays green on a host without bubblewrap.

```rust
//! Real-bubblewrap tests. Run with:
//! `HAOS_GREEN_SHELL_LIVE=1 cargo test --test shell_sandbox_live -- --ignored`

fn live() -> bool { std::env::var("HAOS_GREEN_SHELL_LIVE").as_deref() == Ok("1") }
```

Assert, each in its own test:

1. the original attack fails — `run x; cat /etc/hostname` cannot read the host
   hostname, because `--hostname` replaced it;
2. `~/.haos-green/config.toml` is unreachable;
3. the environment leak is closed (`env` shows no supervisor variables);
4. nested `unshare --user` fails;
5. with no network grant held, `127.0.0.1:8787` is unreachable; with the grant
   held, it is reachable — the same argv, one flag apart;
6. `/etc/passwd` is unreadable;
7. killing the supervisor leaves no descendant (`pgrep -x sleep` count returns
   to its pre-run value);
8. HTTPS works from inside the sandbox **under a network grant** (`curl -fsS
   https://example.com` returns an HTTP 2xx status). Under the empty grant set
   there is no network to reach and the probe skips this step — the certificate
   binds are checked network-free there by the `cabundle` field. This is the test
   the two certificate binds exist for:
   without them it fails with `curl: (77) error adding trust anchors`, and with
   `/etc/ssl/certs` bound **alone** it still fails, because the bundle is a
   symlink into `/etc/ca-certificates`.
9. **an infinite producer is stopped by the byte cap through the *sandboxed*
   launch** — `ShellBackend` with `Isolation::Sandboxed` and `job.timeout_secs =
   60`, running `yes`, asserting the job ended with the `byte cap` error and that
   the captured bytes reached `MAX_OUTPUT_BYTES` (the same assertions Task 6's
   unit test makes, on the other launch arm). This is the one place a real
   `bwrap` is allowed to be required, and it is what proves the capture block is
   genuinely shared: Task 6's test runs `Unconfined`, so a mutation that applies
   the cap on the `Unconfined` arm only leaves it green and is caught here.

- [ ] **Step 2: Run them**

Run: `HAOS_GREEN_SHELL_LIVE=1 cargo test --test shell_sandbox_live -- --ignored`
Expected: PASS. If the host lacks bwrap >= 0.12.0, they must **skip with a
printed reason**, not fail.

- [ ] **Step 3: Run the mutation round**

For each mutation below, apply it, confirm the named test fails, revert, then
run `cargo clean -p haos-green` before trusting any later result — the
`CLAUDE.md` rule about shared `target/` applies:

| Mutation | Test that must fail |
|---|---|
| stub `--version` at `0.11.9` | `a_vulnerable_version_is_refused_as_unavailable` |
| drop `--new-session` | live test 1 |
| drop `--disable-userns` | live test 4 |
| drop `--unshare-user`, keep `--disable-userns` | the run must error, not downgrade |
| move `--clearenv` after `--setenv` | `clearenv_comes_before_every_setenv` |
| drop `--symlink usr/lib64 /lib64` | live test 1 |
| drop `--hostname` | live test 1 |
| drop `--die-with-parent` | live test 7 |
| drop both certificate binds | live test 8 — HTTPS must fail with `(77)` |
| drop `/etc/ca-certificates` only, keep `/etc/ssl/certs` | live test 8 — it must **still** fail, which is what proves the second bind is load-bearing rather than redundant |
| hold the network grant, then drop `--share-net` | live test 5 — loopback must be unreachable, proving the flag is what carries reachability |
| hold no network grant | live test 5 — loopback must be unreachable |
| `/deny` a path after `/allow` | `deny_revokes_immediately` — the write must be refused again |
| grant `/var/lib`, then declare a write to `/var/lib/docker/x` | `a_write_grant_covers_exactly_the_path_named_and_not_its_children` |
| remove the Layer-2 coverage refusal | `refuses_a_job_whose_declaration_is_not_covered` |
| write the grant without the audit row | `every_grant_and_revocation_writes_a_sup_transitions_row` |
| set the sandbox root to `/` | `refuses_the_filesystem_root_as_the_root` |
| remove the Layer-2 refusal | `refuses_to_spawn_when_isolation_is_unavailable` |
| `Isolation::Unconfined` takes the `bwrap` path anyway | `the_unconfined_mode_runs_the_command_without_the_sandbox` — the job's `$HOME` becomes the job directory, so the sandbox's argv ran |
| `Isolation::resolve` reads anything other than `"bwrap"` as consent (`shell.sandbox != "bwrap"`, or a `_ =>` arm returning `Unconfined`) | `only_the_literal_none_resolves_to_the_unconfined_mode`, plus Task 4's `an_unknown_sandbox_mode_is_not_consent_to_run_unconfined` |
| `Isolation::needs_approval()` returns `true` for `Unconfined` (Task 7 only — Task 8 deletes the predicate) | `a_shell_task_is_not_gated_when_the_operator_chose_none`, at Task 7's gate |
| `SupervisorConfig::validate()` stops delegating to the shell block | `supervisor_validate_refuses_an_unknown_sandbox_mode` |
| delete the `config.supervisor.validate()?` call from `Config::load` | `config_load_refuses_an_unknown_shell_sandbox_mode` — a validator nothing calls is the defect this pins |
| **move** `config.supervisor.validate()?` **below** `config.resolve()?`, keeping the same error and message | `config_load_refuses_an_unknown_shell_sandbox_mode`, and **only** its `assert!(!home.exists(), …)` line. Measured on a scratch copy with its own `CARGO_TARGET_DIR`: 80 of the 81 `config::tests` pass under this mutant and only that one fails, the process still exits 1 with a byte-identical message, and the run leaves `AGENTS.md SOUL.md agents artifacts skills workspace` behind in the home directory |
| `SupervisorConfig::validate()` returns `Ok(())` without delegating | `supervisor_validate_refuses_an_unknown_sandbox_mode`, `config_load_refuses_an_unknown_shell_sandbox_mode`. **Not** `supervisor_validate_accepts_the_shipped_default` — `Ok(())` is what that test asserts, which is why it is marked a companion rather than a check |
| `ShellSandboxConfig::validate()`'s unknown arm returns `Ok(())` | `an_unknown_sandbox_mode_is_refused`, `supervisor_validate_refuses_an_unknown_sandbox_mode`, `config_load_refuses_an_unknown_shell_sandbox_mode` |
| remove the Layer-1 gate | `a_shell_task_is_parked_for_approval_…` |
| remove the byte cap | `an_infinite_producer_is_stopped_by_the_byte_cap` (unconfined arm) **and** live test 9 (sandboxed arm) |
| apply the cap on the `Unconfined` arm only, leaving the sandboxed arm unbounded | live test 9 — Task 6's unit test stays green, which is why the live test exists |
| make the `Unconfined` arm of Layer 1 fall through to the grant term | `an_unconfined_shell_task_declaring_an_ungranted_capability_is_not_gated` (Task 8). Task 7's `a_shell_task_is_not_gated_when_the_operator_chose_none` stays green — it declares nothing |

**Results (run in a scratch copy with its own `CARGO_TARGET_DIR`, per the
`CLAUDE.md` rule).** Every row is caught once the right test is run. Two rows
named the wrong test, two named tests that do not exist, and four are stale:

| Row | Outcome |
|---|---|
| `--version` floor, `--clearenv` order, `--disable-userns`, `--unshare-user`, `/lib64` symlink, both certificate binds, `/etc/ca-certificates` alone, `--die-with-parent`, `--share-net` under a grant, byte cap, Layer-2 refusal, `SupervisorConfig::validate`, `ShellSandboxConfig::validate` | caught, as named |
| `drop --hostname` | caught — `the_host_hostname_is_not_readable` fails, and **only** that one |
| `drop --die-with-parent` | caught — `killing_the_supervisor_leaves_no_descendant` fails, and **only** that one |
| `drop both certificate binds` / `drop /etc/ca-certificates only` | both caught by `https_works_under_a_network_grant`, which is what proves the second bind is load-bearing rather than redundant |
| `drop --new-session` → "live test 1" | **the live suite does not catch this** (0 failures). The static argv test `argv_detaches_the_terminal_and_dies_with_the_parent` does. The row names the wrong test; there is no coverage gap. |
| set the sandbox root to `/` | caught by `refuses_the_filesystem_root_as_the_root`, but the guard is the explicit `root == Path::new("/")` check in `resolve_job_dir` — **not** `Grants::resolve_path`, where this row was first applied. `containment_refusal`'s `IsTheRoot` arm is a second, distinct guard covered by `containment_is_decided_by_path_components_not_by_text`. |
| `/deny` after `/allow` → `deny_revokes_immediately` | **that test does not exist.** The property is covered by `the_grant_commands_refuse_grant_list_and_revoke` (telegram). |
| write the grant without the audit row → `every_grant_and_revocation_writes_a_sup_transitions_row` | **that test does not exist.** Covered by `a_grant_writes_an_audit_row_that_belongs_to_no_task`. |
| `grant /var/lib, then declare a write to /var/lib/docker/x` | **stale** — `declared_grants` was deleted (revision 6). |
| `remove the Layer-2 coverage refusal` | **stale** — the refusal was deleted with it. |
| `Isolation::needs_approval()` | **stale** — the predicate was deleted in Task 8, as the row itself says. |
| `Unconfined` arm falls through to the grant term | **stale** — the grant term is gone. |

- [ ] **Step 4: Correct the documentation**

- `CLAUDE.md`: the security section's claim that file and command operations are
  contained by `validate_sandbox_path()` gains the exception for this backend;
  the `kill_on_drop` bound gains the `--die-with-parent` exception; the new
  `[supervisor.shell].sandbox` key and the four grant commands (`/allow`,
  `/deny`, `/allow-net`, `/deny-net`) are documented, including that the grant
  set is in-memory and a restart revokes it.
- `docs/GUIDE.md`: the config table gains the key, and the grant commands get
  their own row.

- [ ] **Step 5: Run the full gates**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected: all clean. Last known green baseline: 906 lib tests, 17 targets.

- [ ] **Step 6: Commit**

```bash
git add tests/shell_sandbox_live.rs CLAUDE.md docs/GUIDE.md
git commit -m "test(supervisor): prove the shell sandbox boundary against real bubblewrap"
```

---

## Self-Review

**Spec coverage:** version floor → Task 1; argv incl. the two certificate binds,
`--new-session`, `--unshare-user`/`--disable-userns`/`--assert-userns-disabled`,
`--hostname`, the conditional `--share-net` and ordering → Task 2; job-directory
invariants → Task 3; config → Task 4; Layer 2 → Task 5; resource containment →
Task 6; Layer 1 → Task 7; grants, their commands, their audit rows and the
missing-grant park → Task 8; smoke test with the production argv, mutation round,
docs, gates → Task 9.

**Where the smoke probe lands — decided after the Task 1 quality review.**
Spec §6 requires `probe()` to run the production argv against a scratch job
directory and assert the boundary's properties at startup. Task 1 could not
build it (there was no argv builder yet), so `IsolationUnavailable::SmokeTestFailed`
was declared with no producer. The quality reviewer correctly flagged that as
speculative public API whose `Display` arm was also untested.

The variant stays, and **the probe is added in Task 2**, immediately after
`build_argv` exists — not deferred to Task 9. Task 9's live tests assert
properties of a running sandbox; they do not return `IsolationUnavailable`, so
folding the probe there would leave the variant dead and spec §6 unimplemented.
Task 2 therefore also adds `probe()`, its `SmokeTestFailed` producer, and a test
that a deliberately broken smoke step is reported through it.

The startup cost is four bubblewrap invocations — the base properties, the nested
userns check, HTTPS and the loopback check — plus the version check, run once and
cached for the process lifetime. That is the price of the spec's requirement, and
it is paid at startup rather than per job.

**Two of the probe's assertions do not discriminate as originally written —
measured on this host, not reasoned about.** I mutation-tested the probe design
against the real binary before writing it, and two checks passed with the
property deliberately removed:

| Probe check | Mutation applied | Result |
|---|---|---|
| `$HOME`/`$PATH` are set | remove `--clearenv` | **passes** — `--setenv` sets those same two variables |
| `pwd` is the job directory | remove `--chdir` | **passes** when the parent's cwd is already the job dir |
| `hostname` is `haos-sandbox` | remove `--hostname` | caught (`cachyos-x8664`) |
| `/etc/passwd` unreadable | bind `/etc` read-only | caught |
| nested `unshare --user` fails | drop `--disable-userns` | caught |
| loopback unreachable | with the network grant held, drop `--share-net` | caught |

So Task 2's probe must:

1. **Detect `--clearenv` with an inherited canary, not with `$HOME`/`$PATH`.** The
   probe sets a marker variable in its own environment and asserts it is *absent*
   inside. Verified: without `--clearenv` the canary leaks
   (`canario vazou=[SEGREDO]`); with it, the probe passes.
2. **Spawn `bwrap` with an explicit cwd that is not the job directory**, so a
   missing `--chdir` cannot pass by inheritance. Measured: bwrap inherits the
   invoking process's cwd when `--chdir` is absent — with the parent at `/` the
   sandbox sees `/` (caught), with the parent already inside the job directory it
   sees the job directory (silently passes).

Both are the failure mode this repo's testing section calls out: a test that
passes for the wrong reason. Neither was visible from reading the argv.

**The argv as written breaks HTTPS, which is a functional regression — measured.**

`ShellBackend` today runs `sh -c` on the host with a complete `/etc`, so a job
that fetches a URL works. The planned argv binds `/usr`, `/proc`, `/dev` and
three `/etc` files, and nothing else from `/etc`. Measured from inside that
sandbox with the network grant held:

| Bound from `/etc` | `curl https://example.com` |
|---|---|
| `resolv.conf`, `nsswitch.conf`, `hosts` (the plan) | `curl: (77) error adding trust anchors from file: /etc/ssl/certs/ca-certificates.crt` |
| `+ /etc/ssl/certs` | still `(77)` — the symlink dangles |
| `+ /etc/ssl/certs` **and** `/etc/ca-certificates` | **HTTP 200** |
| `/etc/ca-certificates` alone, without `/etc/ssl` | `(77)` — the symlink does not exist at all |

The cause is the host's CA layout, not curl: on Arch/CachyOS
`/etc/ssl/certs/ca-certificates.crt` is a symlink to
`../../ca-certificates/extracted/tls-ca-bundle.pem`, so binding the directory
that holds the *symlink* without binding its *target* leaves it dangling. On
Debian/Ubuntu the bundle is a real file in `/etc/ssl/certs`, where binding that
one directory is enough — so an argv tuned to either layout breaks on the other.

Task 2 therefore binds **both** `/etc/ssl/certs` and `/etc/ca-certificates`, each
only if it exists, following the same bind-if-present pattern the plan already
uses for `resolv.conf` — and all five of those binds sit in the **base** argv, not
behind the network grant, because they are reads and reads are never gated (spec
§3). Read-only is correct and carries no secrets: these are public CA
certificates. `getent hosts example.com` resolves correctly inside the sandbox
with the three name-resolution files, so DNS is not affected — only TLS was.

**Type consistency:** `IsolationUnavailable` (Task 1) is used in Tasks 5, 7 and
8; `build_argv(&Path, &Grants, &str)` (Task 2) is called with exactly that
signature in Task 5 and inside the probe; `Grants` (Task 2) is read by Task 4's
default test, by `ShellBackend` in Task 5 and by every grant operation in Task 8;
`resolve_job_dir(&Path, &str, &str)` (Task 3) returns a `JobDir` (path +
descriptor) as of Task 5 Step 6, which is what `build_argv` takes; `Grants::
resolve_path(raw, sandbox_root)` and `grant_write(raw, sandbox_root)` take the
root as of Task 8 Step 3b, because a grant that covers it (or an ancestor of it)
is refused; `ShellSandboxConfig { sandbox }` (Task 4) is read by
`Isolation::resolve` (Task 5 Step 3a) and by **nothing else** — `Isolation` is
the value Task 5's backend and Task 8's gate both hold, so the config key is read
once and the two layers cannot drift; `Isolation` is used in Tasks 5, 7 and 8,
its `Unconfined` arm is what spec §4's "nothing is gated" means in code, and from
Task 8 on the gate `match`es on it directly, and Task 8 **deletes**
`needs_approval()` — the single-term form of the same decision — so the mode is
answered in exactly one place at every point in the plan;
`Grants::{resolve_path, grant_write, revoke_write, grant_network, revoke_network,
missing, covers, held}` and `Supervisor::{grant_write, deny_write, grant_network,
deny_network, grants_held}` (Task 8) match their uses in Tasks 7, 8 and 9.

**Corrections made during self-review** — four claims in the first draft were
wrong and were checked against the code rather than left to the implementer:

| First draft | Reality | Fixed |
|---|---|---|
| `Supervisor::new_for_test().await` | takes `(artifacts_root, conn)` and is not async — `src/supervisor/mod.rs:614` | Task 7 test now uses the real signature, following `mod.rs:1422` |
| `NeedsApproval { task_id } => task_id` | the variant also carries `reason`; destructuring does not compile — `mod.rs:589` | uses the public `outcome.task_id()` accessor |
| `supervisor::bounded(...)` | it is `pub(crate) async fn bounded` at `mod.rs:1382` | `crate::supervisor::bounded(...)` |
| "add `libc` to `Cargo.toml`" | already a dependency at `Cargo.toml:100` | step now says verify, not add |
| "record the grant with `record_transition(\"\", Route, Route, …)`" | `sup_transitions.task_id` is `TEXT NOT NULL` with a foreign key to `sup_tasks`, and the connection sets `PRAGMA foreign_keys=ON` — the insert fails, the `sup_tasks` compare-and-swap finds no row, and the audit row rolls back. The `.ok()` around it hid both failures | Task 8 adds `TaskStore::record_grant_audit` (NULL `task_id`) and a guarded one-time table rebuild in `src/memory/mod.rs` |
| "the probe's scratch directory comes from `tempfile`" | `tempfile` is a **dev**-dependency (`Cargo.toml:128`), so it is not available in `src/` | the probe builds and removes its own directory under the system temp root |
| "the probe spawns bwrap wherever it happens to be" | bwrap inherits the invoking process's cwd when `--chdir` is absent, so a probe run from inside the job directory would pass a missing `--chdir` — and the *test process's* cwd is outside the job directory anyway, so the weaker assertion had no teeth | the probe pins its own cwd, and the test asserts equality with that pinned directory |

One further hazard was found and written into the plan rather than left
implicit: **the Task 7 gate reads the registry**, so a test with an empty
registry never fires the gate and passes for the wrong reason. Both Task 7
tests now register `ShellBackend` first, and the plan says why.

**Corrections made during execution** — four instances of one defect, all found
after Task 4 was dispatched, all of the same shape: an interface was defined and
never wired to anything. (A fifth, in the other direction, was found by Task 4's
review: the plan's own Task 4 code blocks had **drifted from what shipped** —
no `is_unconfined()`, no `SupervisorConfig::validate()` block, no `Config::load`
call, three of eleven tests and an `is_err()`-only assertion — so re-running the
task from the plan reproduced the very defect it fixed. The blocks are now
extracted from the shipped source. **The plan is an artifact that must compile;
a note is not a snippet.**)

| Draft said | Reality | Fixed |
|---|---|---|
| `ShellSandboxConfig::validate()` runs at startup | **nothing called it.** `SupervisorConfig` had no `validate()` at all, so `sandbox = "chroot"` was silently accepted | Task 4 gains `SupervisorConfig::validate()` and a fatal `Config::load` call, with `config_load_refuses_an_unknown_shell_sandbox_mode` and a mutant that deletes the call — **and that call's position matters**: below `resolve()` it still exits 1 with the same message and leaves a whole home tree behind, so the test also asserts `!home.exists()` |
| the plan's Task 4 Step 5: "add to `config.example.toml`, under the `[supervisor]` section" | that section **does not exist** in the file — its only mention of "supervisor" is inside a comment | Step 5 now creates the section, after `[learning]` and before the A2A banner |
| `[supervisor.shell].sandbox` selects the mode | **no code read the key.** The grep for `config.shell` matched only Task 4's own test | Task 5 Step 3a adds `Isolation::resolve` as the single reader, Step 5 wires it, and Task 7 Step 1 tests the `"none"` exemption |
| Task 5 Step 5 derives `isolation` from the probe alone | under `sandbox = "none"` the backend would still have spawned `bwrap` — and failed on a host without it, which is the host the mode exists for. The refusal message's way out was therefore a **loop**, not a way out | `Isolation::Unconfined` is a distinct arm that runs `sh -c` and never invokes `bwrap`, with `the_unconfined_mode_runs_the_command_without_the_sandbox` and a mutant that sends it back down the `bwrap` path |

The fourth is the one worth remembering: the *message* was correct and the
*code* did not implement it, so the failure mode was not a crash or an error but
an operator following the documented remedy and landing in the same refusal.

**Task 6's real-`bwrap` dependency — decided, not left open (review finding
M9).** The draft used `.with_isolation(Ok(()))`, which after the Task 5
correction is `Isolation::Sandboxed`, on tests that run real commands — so they
need a real `bwrap >= 0.12.0` on the host and fail rather than skip where there
is none. Task 9's live file is the one gated behind `HAOS_GREEN_SHELL_LIVE=1`.

Three options were on the table: (a) gate Task 6 behind the same env var, (b)
stub `bwrap` on `PATH`, (c) run the mode-independent properties under
`Isolation::Unconfined`.

**Decision: (c) for the byte-cap test, plus a live test for the sandboxed arm.**

- (a) was rejected because a skipped test is a test that can stay skipped: the
  cap would be unpinned on every host without bubblewrap, which includes CI
  runners, and the mutation "remove the byte cap" would then have no catcher at
  all. Task 6's subject is resource containment, not the sandbox, so gating it
  behind the sandbox's availability buys nothing and risks everything.
- (b) was rejected because a stub is a second implementation of the thing under
  test: it would have to satisfy the argv assertions Task 2 already makes against
  the real builder, and it would test the stub's behaviour, not bubblewrap's.
- (c) is correct because the cap is enforced by `read_capped` in the capture
  block that sits **after** the two-launch `match` — one block, both arms — so
  the property holds on either. `Unconfined` runs the same `sh -c` path the
  backend used before the sandbox existed.

The residual is real and is recovered rather than ignored: with the byte-cap test
on the unconfined arm, a mutation that applied the cap to the `Unconfined` arm
only would leave Task 6 green. **Task 9 therefore gains item 9** — the same
assertions, run through the sandboxed launch against a real `bwrap`, in the one
file that is already gated behind `HAOS_GREEN_SHELL_LIVE=1`. That is where a real
`bwrap` may be required, and it is what proves the capture block is genuinely
shared rather than merely written once.

**Known separate finding, recorded here so it is not lost (review finding
M10-adjacent).** `[supervisor].default_autonomy_mode` is parsed, defaulted, and
documented in `docs/GUIDE.md:44`, but **no production code reads it** — the only
references in `src/` are the field, its default function, `SupervisorConfig::
Default`, and one assertion in `config.rs`'s own test. `config.example.toml` no
longer cites it as a working key. It is pre-existing, independent of this plan,
and deserves its own issue rather than a fix folded in here.

> **Resolved in revision 6: deleted, not wired.** Wiring was rejected on
> inspection rather than on principle. The mode is derived by the classifier from
> the task type and risk, and the natural slot for a "default" is its fallback
> arm — which catches only Research, Writing, Ops and Unknown, because code
> changes are hardcoded `Rigorous` (`classifier.rs:61`) and general assistant
> tasks hardcoded `Fast`. So `default_autonomy_mode = "fast"` would not have made
> a refactor fast, and `Fast` skips `Clarify` and `Plan` entirely
> (`workflow.rs:16`). Wiring it there would have produced a name that lies in a
> new way — the same defect as `declared_grants`, one level up. A coherent wiring
> exists but is a *new semantic* (a floor: "never below this mode"), which no
> document describes and which needs a product decision. So the field, its
> default function, the wizard's raw shadow field and the `config.rs` assertion
> are removed, the `docs/GUIDE.md:44` row is gone, and `config.example.toml`
> records the reasoning so a real knob is added as a designed feature rather than
> a resurrected dead field.
