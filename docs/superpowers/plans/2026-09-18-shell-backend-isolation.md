# Shell Backend Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the supervisor's `ShellBackend` inside a bubblewrap sandbox that cannot see the host's home directory, `/etc`, or the supervisor's environment, and fail closed — asking the operator — when that sandbox is unavailable.

**Architecture:** One new module, `src/supervisor/backend/sandbox.rs`, owns the version probe, the argv builder and the job-directory invariants, so the sandbox is described in exactly one place and the tests assert against the same builder production uses. `ShellBackend` becomes a thin caller of it. A route-time gate (Layer 1) parks a task in `Route` via `RequireApproval`; a job-time check (Layer 2) refuses to spawn at all. Layer 2 is the boundary, because a task can move between the two.

**Tech Stack:** Rust 2021, Tokio, `std::process::Command` / `tokio::process::Command`, bubblewrap >= 0.12.0, `anyhow`, `serde` + `toml` for config, `tracing`.

**Spec:** `docs/superpowers/specs/2026-09-18-shell-backend-isolation-design.md` (revision 2). Read it before starting. Every "why" below is in it.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/supervisor/backend/sandbox.rs` | **New.** Version probe, argv builder, job-directory resolution and invariants, `UnsafeShellGrant`. The only place that knows what the sandbox is. |
| `src/supervisor/backend/mod.rs` | Modify: `pub mod sandbox;` |
| `src/supervisor/backend/shell.rs` | Modify: `run` delegates to `sandbox`; Layer-2 refusal; output caps |
| `src/config.rs` | Modify: `ShellSandboxConfig` under `[supervisor.shell]`, with validation |
| `src/supervisor/mod.rs` | Modify: Layer-1 gate in `submit`; hold the probe result and the grant |
| `src/main.rs` | Modify: build the sandbox at startup, run the probe, pass into `ShellBackend` and `Supervisor` |
| `src/platform/telegram.rs` | Modify: `/unsafe-shell on\|off` |
| `src/web/routes/supervisor.rs` | Modify: the dashboard equivalent of `/unsafe-shell` |
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
/// version floor testable without mutating the environment: this repo has no
/// `std::env::set_var` anywhere in `src/`, and `tests/a2a_e2e_live.rs` records
/// why — it is process-global and races with every other test in the same
/// binary. A stub binary on a private path is injected instead.
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
        let a = build_argv(Path::new("/jobs/t/j"), false, "echo hi");
        assert!(a.contains(&"--unshare-all".to_string()));
        // --unshare-all is only --unshare-user-try: it is silently skipped when
        // the user namespace cannot be created, so it must be named explicitly.
        assert!(a.contains(&"--unshare-user".to_string()));
        assert!(a.contains(&"--disable-userns".to_string()));
        assert!(a.contains(&"--assert-userns-disabled".to_string()));
    }

    #[test]
    fn argv_detaches_the_terminal_and_dies_with_the_parent() {
        let a = build_argv(Path::new("/jobs/t/j"), false, "echo hi");
        assert!(a.contains(&"--new-session".to_string()), "TIOCSTI");
        assert!(a.contains(&"--die-with-parent".to_string()));
    }

    #[test]
    fn clearenv_comes_before_every_setenv() {
        let a = build_argv(Path::new("/jobs/t/j"), false, "echo hi");
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
        let a = build_argv(Path::new("/jobs/t/j"), false, "echo hi");
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
        let a = build_argv(Path::new("/jobs/t/j"), false, "echo hi");
        let i = a.iter().position(|x| x == "--hostname").unwrap();
        assert_eq!(a[i + 1], "haos-sandbox");
    }

    #[test]
    fn share_net_appears_only_when_host_network_is_on() {
        assert!(!build_argv(Path::new("/j"), false, "x").contains(&"--share-net".to_string()));
        assert!(build_argv(Path::new("/j"), true, "x").contains(&"--share-net".to_string()));
    }

    #[test]
    fn the_command_is_last_and_passed_verbatim() {
        let a = build_argv(Path::new("/jobs/t/j"), false, "run x; cat /etc/hostname");
        assert_eq!(a[a.len() - 3..], ["/bin/sh", "-c", "run x; cat /etc/hostname"]);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: FAIL — `cannot find function build_argv`.

- [ ] **Step 3: Implement the builder**

Add above `#[cfg(test)]` in `src/supervisor/backend/sandbox.rs`:

```rust
/// Build the full bubblewrap argv. **Order is normative** — see the tests.
///
/// `job_dir` must already have passed [`resolve_job_dir`].
pub fn build_argv(job_dir: &Path, host_network: bool, command: &str) -> Vec<String> {
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
    if host_network {
        // --share-net keeps the HOST network namespace. Name resolution needs
        // these, and they are read-only.
        for f in ["/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hosts"] {
            if Path::new(f).exists() {
                a.extend(["--ro-bind".into(), f.into(), f.into()]);
            }
        }
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
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add src/supervisor/backend/sandbox.rs
git commit -m "feat(supervisor): build the hardened bubblewrap argv"
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
    fn shell_sandbox_defaults_to_bwrap_with_host_network() {
        let c = ShellSandboxConfig::default();
        assert_eq!(c.sandbox, "bwrap");
        assert!(c.host_network, "the shipped default is the host namespace");
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

fn default_host_network() -> bool {
    true
}

/// `[supervisor.shell]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellSandboxConfig {
    /// `"bwrap"` (sandboxed) or `"none"` (unsandboxed, the operator's explicit
    /// consent). An unknown value is refused rather than defaulted.
    #[serde(default = "default_shell_sandbox")]
    pub sandbox: String,
    /// Share the **host** network namespace with the sandbox.
    ///
    /// The name is deliberate: `network = true` reads as "allow internet
    /// access", but `--share-net` keeps the host namespace, so the sandbox
    /// reaches loopback services, the LAN and Tailscale. Defaults to `true`
    /// by operator decision; see the spec's §4 for the escape route that opens.
    #[serde(default = "default_host_network")]
    pub host_network: bool,
}

impl Default for ShellSandboxConfig {
    fn default() -> Self {
        Self { sandbox: default_shell_sandbox(), host_network: default_host_network() }
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

# Share the HOST network namespace with the sandbox. This is not merely
# "internet access": the sandbox can then reach loopback services, your LAN and
# Tailscale — including the dashboard on 127.0.0.1:8787. Set to false for a
# filesystem-only boundary with no network.
host_network = true
```

- [ ] **Step 6: Commit**

```bash
git add src/config.rs config.example.toml
git commit -m "feat(config): add [supervisor.shell] sandbox and host_network"
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
        assert!(out.errors.iter().any(|e| e.contains("unsafe-shell")), "must name the way out");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib shell::tests::refuses_to_spawn`
Expected: FAIL — `no method named with_isolation`.

- [ ] **Step 3: Implement**

In `src/supervisor/backend/shell.rs`, add the import and the field:

```rust
use crate::supervisor::backend::sandbox::{self, IsolationUnavailable};
```

```rust
pub struct ShellBackend {
    sandbox: PathBuf,
    /// The startup probe's result, shared. `Err` means the boundary is absent
    /// and the backend must refuse rather than fall back to `sh -c`.
    isolation: Result<(), IsolationUnavailable>,
    host_network: bool,
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
            host_network: true,
        }
    }

    /// Attach the probe result from startup.
    pub fn with_isolation(mut self, r: Result<(), IsolationUnavailable>) -> Self {
        self.isolation = r;
        self
    }

    pub fn with_host_network(mut self, on: bool) -> Self {
        self.host_network = on;
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
                     Install bubblewrap >= 0.12.0, or grant explicit consent with \
                     `/unsafe-shell on` (or set [supervisor.shell].sandbox = \"none\")."
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
        let argv = sandbox::build_argv(&job_dir, self.host_network, &cmd);
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

In `src/main.rs:519-523`, build the backend with the probe result:

```rust
let isolation = crate::supervisor::backend::sandbox::check_bwrap_version();
if let Err(ref e) = isolation {
    tracing::warn!(
        reason = %e,
        "shell jobs will be refused: the bubblewrap sandbox is unavailable"
    );
}
let shell = ShellBackend::new(sandbox_path)
    .with_isolation(isolation)
    .with_host_network(config.supervisor.shell.host_network);
```

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
            .with_host_network(false);
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
            true if self.shell_isolation.is_err() && !self.grant.covers(&task.id) => {
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

`grant` is added in Task 8; until then, replace `!self.grant.covers(&task.id)`
with `true` and note it in the commit.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib supervisor::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/supervisor/mod.rs
git commit -m "feat(supervisor): park shell tasks when isolation is unavailable"
```

---

## Task 8: Consent — `UnsafeShellGrant`

**Files:**
- Modify: `src/supervisor/backend/sandbox.rs` (the type)
- Modify: `src/supervisor/mod.rs`
- Modify: `src/platform/telegram.rs`
- Modify: `src/web/routes/supervisor.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn a_job_grant_covers_only_its_own_task_and_is_consumed() {
        let g = UnsafeShellGrant::default();
        g.grant_job("task-a");
        assert!(g.covers("task-a"));
        assert!(!g.covers("task-b"), "a job grant must not leak to another task");
        g.consume("task-a");
        assert!(!g.covers("task-a"), "a job grant is one-shot");
    }

    #[test]
    fn a_process_grant_covers_everything_until_revoked() {
        let g = UnsafeShellGrant::default();
        assert!(!g.covers("any"));
        g.grant_process();
        assert!(g.covers("any"));
        assert!(g.covers("other"));
        g.revoke();
        assert!(!g.covers("any"), "revocation must be immediate");
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --lib supervisor::backend::sandbox`
Expected: FAIL — `cannot find type UnsafeShellGrant`.

- [ ] **Step 3: Implement**

Add to `src/supervisor/backend/sandbox.rs`:

```rust
/// Who may run shell jobs without isolation.
///
/// The two decisions are kept apart deliberately: an operator typing
/// `/approve <id>` believes they are approving **one job**, and must not be
/// silently granting unconfined shell for the rest of the process.
#[derive(Debug, Default)]
pub struct UnsafeShellGrant {
    process: std::sync::atomic::AtomicBool,
    jobs: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl UnsafeShellGrant {
    pub fn grant_process(&self) {
        self.process.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn revoke(&self) {
        self.process.store(false, std::sync::atomic::Ordering::SeqCst);
        self.jobs.lock().unwrap().clear();
    }

    pub fn grant_job(&self, task_id: &str) {
        self.jobs.lock().unwrap().insert(task_id.to_string());
    }

    pub fn covers(&self, task_id: &str) -> bool {
        self.process.load(std::sync::atomic::Ordering::SeqCst)
            || self.jobs.lock().unwrap().contains(task_id)
    }

    /// A job grant is one-shot: an approval cannot be replayed by a later run
    /// of the same task id.
    pub fn consume(&self, task_id: &str) {
        self.jobs.lock().unwrap().remove(task_id);
    }

    pub fn standing(&self) -> bool {
        self.process.load(std::sync::atomic::Ordering::SeqCst)
    }
}
```

Add `grant: Arc<UnsafeShellGrant>` to `Supervisor`, share the same `Arc` with
`ShellBackend`, and call `grant.consume(&job.task_id)` inside `ShellBackend::run`
when it allows an unisolated run.

- [ ] **Step 4: Add the commands**

In `src/platform/telegram.rs`, extend `dispatch_supervisor_command` with:

```rust
        "/unsafe-shell" => {
            match args.first().map(String::as_str) {
                Some("on") => {
                    self.grant.grant_process();
                    self.store
                        .record_transition(
                            "", TaskStatus::Route, TaskStatus::Route,
                            "operator", Some("unsafe-shell: process-wide grant"),
                        )
                        .await
                        .ok();
                    "Unsafe shell is now ON for every shell job until /unsafe-shell off \
                     or a restart. This bypasses the bubblewrap sandbox."
                }
                Some("off") => {
                    self.grant.revoke();
                    "Unsafe shell is OFF. Shell jobs are sandboxed or refused."
                }
                _ => "Usage: /unsafe-shell on | /unsafe-shell off",
            }
        }
```

`/approve <id>` must call `grant_job(&id)`, **not** `grant_process()`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib` and `cargo test --test web_endpoint`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/supervisor/backend/sandbox.rs src/supervisor/mod.rs src/platform/telegram.rs src/web/routes/supervisor.rs
git commit -m "feat(supervisor): separate per-job approval from process-wide unsafe shell"
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
5. under `host_network = false`, `127.0.0.1:8787` is unreachable;
6. `/etc/passwd` is unreadable;
7. killing the supervisor leaves no descendant (`pgrep -x sleep` count returns
   to its pre-run value).

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
| set the sandbox root to `/` | `refuses_the_filesystem_root_as_the_root` |
| remove the Layer-2 refusal | `refuses_to_spawn_when_isolation_is_unavailable` |
| remove the Layer-1 gate | `a_shell_task_is_parked_for_approval_…` |
| remove the byte cap | `an_infinite_producer_is_stopped_by_the_byte_cap` |

- [ ] **Step 4: Correct the documentation**

- `CLAUDE.md`: the security section's claim that file and command operations are
  contained by `validate_sandbox_path()` gains the exception for this backend;
  the `kill_on_drop` bound gains the `--die-with-parent` exception; the new
  `[supervisor.shell]` keys and `/unsafe-shell` are documented.
- `docs/GUIDE.md`: the config table gains the two keys.

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

**Spec coverage:** version floor → Task 1; argv incl. `--new-session`,
`--unshare-user`/`--disable-userns`/`--assert-userns-disabled`, `--hostname`,
ordering → Task 2; job-directory invariants → Task 3; config →
Task 4; Layer 2 → Task 5; resource containment → Task 6; Layer 1 → Task 7;
consent split → Task 8; smoke test with the production argv, mutation round,
docs, gates → Task 9.

**Known gap, deliberate:** the smoke test described in spec §6 is folded into
Task 9's live tests rather than implemented as a startup probe in Task 1, so
that startup does not pay for seven bubblewrap invocations. If the operator
wants the full probe at startup, add it as a Task 1 step — the code is the same
argv builder.

**Type consistency:** `IsolationUnavailable` (Task 1) is used in Tasks 5 and 7;
`build_argv(&Path, bool, &str)` and `resolve_job_dir(&Path, &str, &str)`
(Tasks 2–3) are called with exactly those signatures in Task 5;
`ShellSandboxConfig { sandbox, host_network }` (Task 4) is read in Task 5;
`UnsafeShellGrant::{grant_process, grant_job, covers, consume, revoke, standing}`
(Task 8) matches its uses in Tasks 7 and 8.

**Corrections made during self-review** — four claims in the first draft were
wrong and were checked against the code rather than left to the implementer:

| First draft | Reality | Fixed |
|---|---|---|
| `Supervisor::new_for_test().await` | takes `(artifacts_root, conn)` and is not async — `src/supervisor/mod.rs:614` | Task 7 test now uses the real signature, following `mod.rs:1422` |
| `NeedsApproval { task_id } => task_id` | the variant also carries `reason`; destructuring does not compile — `mod.rs:589` | uses the public `outcome.task_id()` accessor |
| `supervisor::bounded(...)` | it is `pub(crate) async fn bounded` at `mod.rs:1382` | `crate::supervisor::bounded(...)` |
| "add `libc` to `Cargo.toml`" | already a dependency at `Cargo.toml:100` | step now says verify, not add |

One further hazard was found and written into the plan rather than left
implicit: **the Task 7 gate reads the registry**, so a test with an empty
registry never fires the gate and passes for the wrong reason. Both Task 7
tests now register `ShellBackend` first, and the plan says why.
