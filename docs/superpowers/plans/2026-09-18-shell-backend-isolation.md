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
Expected: PASS, 7 tests.

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
        assert!(build_argv(Path::new("/j"), &net, "x").contains(&"--share-net".to_string()));
    }

    #[test]
    fn a_write_grant_becomes_a_read_write_bind() {
        // A grant is the only way a host path becomes writable, and `--bind` is
        // the only bubblewrap flag that makes one. Read-only would silently
        // grant nothing.
        let g = Grants { write: [PathBuf::from("/var/lib")].into(), network: false };
        let a = build_argv(Path::new("/jobs/t/j"), &g, "x");
        assert!(
            a.windows(3).any(|w| w[0] == "--bind" && w[1] == "/var/lib" && w[2] == "/var/lib"),
            "a granted path must be bound read-write, got {a:?}"
        );
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
Expected: PASS, 17 tests (Task 1's 7 plus the 10 added here).

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
        // Measured: bwrap inherits the invoking process's cwd when `--chdir` is
        // absent, so a probe spawned from inside the job directory would pass a
        // missing `--chdir` silently. The probe therefore pins its own cwd, and
        // this is the check that it does: the stub records what it inherited.
        //
        // Asserting equality with the pinned directory (not merely "not the job
        // directory") is what gives this teeth — the *test process's* cwd is
        // already outside the job directory, so a probe that pinned nothing
        // would satisfy the weaker assertion.
        let scratch = tempfile::tempdir().unwrap();
        let record = scratch.path().join("cwd.txt");
        let (_dir, bin) = stub_bwrap_recording_cwd(&record);
        let _ = probe_at(&bin, &Grants::default(), scratch.path()).await;
        let seen = std::fs::read_to_string(&record).unwrap();
        let pinned = std::fs::canonicalize(scratch.path().join("probe-cwd")).unwrap();
        let job_dir = std::fs::canonicalize(scratch.path().join("job")).unwrap();
        assert_eq!(
            Path::new(seen.trim()),
            pinned,
            "the probe must pin its own cwd, not inherit one"
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

Add above `#[cfg(test)]`:

```rust
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
    let job_dir = std::fs::canonicalize(&job_dir).map_err(|e| smoke("the scratch job directory", e))?;
    // The probe's own cwd, deliberately OUTSIDE the job directory: bwrap
    // inherits the invoking process's cwd when `--chdir` is absent, so a probe
    // spawned from inside the job directory would pass a missing `--chdir`
    // silently (measured).
    let outside = scratch.join("probe-cwd");
    std::fs::create_dir_all(&outside).map_err(|e| smoke("the probe's own cwd", e))?;

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
         if touch .smoke-write 2>/dev/null; then echo writable=yes; else echo writable=no; fi"
    );
    let out = run_in_sandbox(bwrap, &job_dir, grants, &script, &outside, "the base properties").await?;
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
    expect("canary", "unset", "the inherited canary is absent (--clearenv ran)")?;
    expect("pwd", &home, "the cwd is the job directory (--chdir took effect)")?;
    expect("hostname", "haos-sandbox", "the hostname is haos-sandbox")?;
    expect("passwd", "unreadable", "/etc/passwd is unreadable")?;
    expect("shadow", "absent", "/etc/shadow is absent")?;
    expect("writable", "yes", "the job directory is writable")?;

    // `--disable-userns` asks; with `--assert-userns-disabled` this is what
    // proves the restriction took effect on this kernel.
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        "unshare --user true 2>/dev/null && echo nested=allowed || echo nested=blocked",
        &outside,
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
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        "curl -fsS -o /dev/null -w 'http=%{http_code}' https://example.com",
        &outside,
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

    // The network, asserted against the grant set **actually in force**, so both
    // states are covered rather than the default assumed. The probe holds a
    // listener in its own namespace and never accepts from it: the kernel
    // completes the handshake from the backlog, so "reachable" shows up as curl
    // waiting for a response rather than as a refused connection (exit 7).
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| smoke("the loopback check", e))?;
    let port = listener.local_addr().map_err(|e| smoke("the loopback check", e))?.port();
    let out = run_in_sandbox(
        bwrap,
        &job_dir,
        grants,
        &format!(
            "curl -sS --connect-timeout 2 --max-time 3 -o /dev/null \
             http://127.0.0.1:{port}/ ; echo exit=$?"
        ),
        &outside,
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
Expected: PASS, 19 tests. The probe's own two tests use a stub `bwrap`, so they
need no real bubblewrap; the real-sandbox assertions are Task 9's live tests.

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

Add above `#[cfg(test)]`:

```rust
/// Resolve and validate the per-job sandbox directory.
///
/// This directory is the **only** writable host path in the argv, which makes
/// it the critical part of the boundary. Every check below is a hard error.
///
/// The returned path is canonical, and is a strict descendant of `root` — never
/// equal to it — so a job can never write at the root itself.
pub fn resolve_job_dir(root: &Path, task_id: &str, job_id: &str) -> Result<PathBuf> {
    if !root.is_absolute() {
        bail!("sandbox root {} is not absolute", root.display());
    }
    std::fs::create_dir_all(root)
        .map_err(|e| anyhow::anyhow!("cannot create sandbox root {}: {e}", root.display()))?;
    let root = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!("cannot canonicalise {}: {e}", root.display()))?;
    if root == Path::new("/") {
        bail!("the sandbox root must not be /");
    }
    // A root that directly holds config.toml would make the job directory's
    // parent the directory holding the API key and every peer token.
    if root.join("config.toml").exists() {
        bail!(
            "the sandbox root {} holds config.toml; point it at a dedicated \
             directory such as <home>/workspace",
            root.display()
        );
    }
    let dir = root.join(task_id).join(job_id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", dir.display()))?;
    // Re-canonicalise AFTER creation: a pre-existing symlink at this path is
    // caught here, which is also the CVE-2026-87766 precondition.
    let dir = std::fs::canonicalize(&dir)
        .map_err(|e| anyhow::anyhow!("cannot canonicalise {}: {e}", dir.display()))?;
    if !dir.starts_with(&root) || dir == root {
        bail!(
            "the job sandbox {} resolved outside the sandbox root {}",
            dir.display(),
            root.display()
        );
    }
    Ok(dir)
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: PASS, 18 tests.

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

Add to the `tests` module in `src/config.rs`:

```rust
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
    fn an_unknown_sandbox_mode_is_refused() {
        let c = ShellSandboxConfig { sandbox: "chroot".into(), ..Default::default() };
        assert!(c.validate().is_err());
    }

    #[test]
    fn both_documented_modes_are_accepted() {
        for m in ["bwrap", "none"] {
            let c = ShellSandboxConfig { sandbox: m.into(), ..Default::default() };
            assert!(c.validate().is_ok(), "{m} must be accepted");
        }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellSandboxConfig {
    /// `"bwrap"` (sandboxed) or `"none"` (unsandboxed, the operator's explicit
    /// consent, and nothing else is gated). An unknown value is refused rather
    /// than defaulted.
    #[serde(default = "default_shell_sandbox")]
    pub sandbox: String,
}

impl Default for ShellSandboxConfig {
    fn default() -> Self {
        Self { sandbox: default_shell_sandbox() }
    }
}

impl ShellSandboxConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        match self.sandbox.as_str() {
            "bwrap" | "none" => Ok(()),
            other => anyhow::bail!(
                "[supervisor.shell].sandbox must be \"bwrap\" or \"none\", got {other:?}"
            ),
        }
    }
}
```

Add the field to `SupervisorConfig`:

```rust
    #[serde(default)]
    pub shell: ShellSandboxConfig,
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib config::tests`
Expected: PASS.

- [ ] **Step 5: Document it**

Add to `config.example.toml`, under the `[supervisor]` section:

```toml
[supervisor.shell]
# "bwrap" runs shell jobs inside a bubblewrap sandbox (requires bwrap >= 0.12.0).
# "none" runs them unconfined, and IS your consent — nothing else is gated.
sandbox = "bwrap"

# Nothing else is configured here on purpose. A writable host path and the host
# network namespace are not settings but runtime grants the operator names at the
# moment they are used — /allow <path> and /allow-net — standing until /deny or
# /deny-net, and revoked by a restart. Neither substitutes for a missing sandbox.
```

- [ ] **Step 6: Commit**

```bash
git add src/config.rs config.example.toml
git commit -m "feat(config): add [supervisor.shell] sandbox"
```

---

## Task 5: Wire the sandbox into `ShellBackend` (Layer 2)

**Files:**
- Modify: `src/supervisor/backend/shell.rs`
- Modify: `src/main.rs:519-523`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/supervisor/backend/shell.rs`:

```rust
    #[tokio::test]
    async fn refuses_to_spawn_when_isolation_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into())
            .with_isolation(Err(sandbox::IsolationUnavailable::NotInstalled));
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib shell::tests::refuses_to_spawn`
Expected: FAIL — `no method named with_isolation`.

- [ ] **Step 3: Implement**

In `src/supervisor/backend/shell.rs`, add the import and the field:

```rust
use std::sync::Arc;

use crate::supervisor::backend::sandbox::{self, Grants, IsolationUnavailable};
```

```rust
pub struct ShellBackend {
    sandbox: PathBuf,
    /// The startup probe's result, shared. `Err` means the boundary is absent
    /// and the backend must refuse rather than fall back to `sh -c`.
    isolation: Result<(), IsolationUnavailable>,
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
            isolation: Err(IsolationUnavailable::NotInstalled),
            // And fail closed on capability too: a backend built without an
            // explicit grant set holds no writable host path and no host
            // network, which is the shipped default (spec §4).
            grants: Arc::new(std::sync::RwLock::new(Grants::default())),
        }
    }

    /// Attach the probe result from startup.
    pub fn with_isolation(mut self, r: Result<(), IsolationUnavailable>) -> Self {
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
        if let Err(reason) = &self.isolation {
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
        // The guard is dropped at the end of this statement on purpose: holding
        // it across the `spawn` below would make this future non-`Send`.
        let held = self.grants.read().unwrap().clone();
        let argv = sandbox::build_argv(&job_dir, &held, &cmd);
        let timeout_secs = job.timeout_secs;
        let child = Command::new("bwrap")
            .args(&argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        // ... the existing timeout/capture block, unchanged, from here on.
```

The job's declaration — `job.declared_grants`, and the refusal that names the
missing grant — is added in Task 8, which owns the grant semantics. This task
wires the grant set in; it does not yet compare it against anything.

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

In `src/main.rs:519-523`, build the backend with the probe result. The version
check and the smoke probe are **one** result: the floor is a precondition, and
the probe is what asserts the boundary the argv claims.

```rust
// One shared grant set, empty at startup: the operator grants a writable host
// path or the host network by name, and it is revoked by a restart.
let grants: Arc<std::sync::RwLock<crate::supervisor::backend::sandbox::Grants>> =
    Arc::new(std::sync::RwLock::new(Default::default()));

// The version floor first, then the functional smoke test against the same argv
// production uses. The result is cached for the process lifetime by being stored
// in the backend and the supervisor.
let isolation = match crate::supervisor::backend::sandbox::check_bwrap_version() {
    Err(e) => Err(e),
    Ok(()) => crate::supervisor::backend::sandbox::probe(&grants).await,
};
if let Err(ref e) = isolation {
    tracing::warn!(
        reason = %e,
        "shell jobs will be refused: the bubblewrap sandbox is unavailable"
    );
}
let shell = ShellBackend::new(sandbox_path)
    .with_isolation(isolation.clone())
    .with_grants(grants.clone());
```

`probe` is async, so this wiring lives in an async context (`main` is). The same
`grants` `Arc` goes into the `Supervisor` in Task 8; until then the backend is
its only holder.

- [ ] **Step 6: Commit**

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
        let b = ShellBackend::new(dir.path().into())
            .with_isolation(Ok(()))
            // No grant held: the sandbox is filesystem-only, which is the
            // shipped default.
            .with_grants(std::sync::Arc::new(std::sync::RwLock::new(
                crate::supervisor::backend::sandbox::Grants::default(),
            )));
        let mut job = crate::supervisor::job::Job::new(
            "t", crate::supervisor::job::JobType::ShellJob, "shell", "yes",
        );
        job.timeout_secs = 60; // far longer than the test may take
        let out = crate::supervisor::bounded("yes", b.run(&mut job, &RunContext::new()))
            .await
            .unwrap()
            .unwrap();
        let bytes: usize = out.summary.len() + out.errors.iter().map(|e| e.len()).sum::<usize>();
        assert!(bytes <= MAX_OUTPUT_BYTES + 4096, "cap not enforced: {bytes}");
    }
```

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
        let sup = sup.with_shell_isolation(Err(IsolationUnavailable::NotInstalled));

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
        let sup = sup.with_shell_isolation(Err(IsolationUnavailable::NotInstalled));

        let outcome = sup.submit("test", "u1", None, "summarise this document").await.unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::AutoExecutePlanned { .. }),
            "a task that does not select the shell backend must not be gated, got {outcome:?}"
        );
    }
```

> `SubmitOutcome` has a public `task_id()` accessor (`src/supervisor/mod.rs:589-598`),
> which is how the existing tests read the id. Destructuring
> `NeedsApproval { task_id }` does not compile — the variant also carries
> `reason`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib supervisor::tests::a_shell_task_is_parked`
Expected: FAIL — `no method named with_shell_isolation`.

- [ ] **Step 3: Implement the gate**

Add to `Supervisor`:

```rust
    /// `Err` means the sandbox is unavailable, so a task that would select the
    /// shell backend must be parked for approval instead of auto-executing.
    shell_isolation: Result<(), IsolationUnavailable>,
```

Add the builder:

```rust
    pub fn with_shell_isolation(mut self, r: Result<(), IsolationUnavailable>) -> Self {
        self.shell_isolation = r;
        self
    }
```

In `submit`, immediately after `let decision = self.policy.decide(&task);`, insert
the gate. It asks the **registry**, so it cannot disagree with what the executor
would select:

```rust
        // LAYER 1 — route-time gate. This asks the same registry the executor
        // uses, rather than duplicating a routing predicate that could drift.
        let decision = match self.would_use_shell(&task) {
            true if self.shell_isolation.is_err() => {
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

**There is no job-scoped consent object to consult.** `/approve <id>` is the
existing lifecycle command: it moves a task out of `Route` (`Route -> Execute`,
already legal in `state.rs`), which is what "job-scoped, consumed on use" means —
the task leaves `Route`, so the approval cannot be replayed. Nothing is granted
process-wide and nothing runs unconfined: Layer 2 decides on its own, and
refuses when the boundary is absent.

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
            .with_isolation(Ok(()))
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
    pub fn resolve_path(raw: &str) -> Result<PathBuf> {
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
    pub fn grant_write(&mut self, raw: &str) -> Result<PathBuf> {
        let path = Self::resolve_path(raw)?;
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
        let path = Grants::resolve_path(raw)?;
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
        // LAYER 1 — route-time gate. This asks the same registry the executor
        // uses, rather than duplicating a routing predicate that could drift.
        let gate_reason = if self.would_use_shell(&task) {
            let held = self.grants.read().unwrap().clone();
            let missing = held.missing(&task.declared_grants);
            if self.shell_isolation.is_err() {
                Some(format!(
                    "shell isolation is unavailable, so a task that would select the shell \
                     backend is parked: {}. Fix bubblewrap (>= 0.12.0) or set \
                     [supervisor.shell].sandbox = \"none\". A grant cannot replace a missing \
                     sandbox; `/allow <path>` and `/allow-net` release a capability.",
                    self.shell_isolation.as_ref().unwrap_err()
                ))
            } else if !missing.is_empty() {
                Some(park_reason(
                    &held,
                    &task.declared_grants,
                    &task.id,
                    // `user_request` is already capped by `IntakeRouter`, and the
                    // reply is bounded again before it is sent.
                    &task.user_request,
                ))
            } else {
                None
            }
        } else {
            None
        };
        let decision = if gate_reason.is_some() {
            PolicyDecision::RequireApproval
        } else {
            decision
        };
```

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
8. HTTPS works from inside the sandbox (`curl -fsS https://example.com` returns
   an HTTP 2xx status). This is the test the two certificate binds exist for:
   without them it fails with `curl: (77) error adding trust anchors`, and with
   `/etc/ssl/certs` bound **alone** it still fails, because the bundle is a
   symlink into `/etc/ca-certificates`.

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
| remove the Layer-1 gate | `a_shell_task_is_parked_for_approval_…` |
| remove the byte cap | `an_infinite_producer_is_stopped_by_the_byte_cap` |

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
`resolve_job_dir(&Path, &str, &str)` (Task 3) is called with those arguments in
Task 5; `ShellSandboxConfig { sandbox }` (Task 4) is read in Task 5;
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
