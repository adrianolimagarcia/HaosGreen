//! Real-bubblewrap tests. Run with:
//! `HAOS_GREEN_SHELL_LIVE=1 cargo test --test shell_sandbox_live -- --ignored --nocapture`
//!
//! These are `#[ignore]`d **and** re-checked at runtime against
//! `HAOS_GREEN_SHELL_LIVE=1`, so plain `cargo test` stays green on a host with no
//! usable bubblewrap — which is how CI runs it. The runtime check matters
//! because `--ignored` alone would run them on a host that cannot sandbox, and
//! the skip path prints a reason and returns, so libtest reports `ok` rather
//! than a failure that blames the code for a property of the host.
//!
//! The skip path is therefore indistinguishable from a pass in libtest's
//! summary. Confirm a real run by reading the output with `--nocapture` and
//! checking that no `SKIP:` line appears.
//!
//! **These tests exercise the public API only** — an integration test cannot
//! reach `#[cfg(test)] pub(crate)` helpers, so there is no
//! `supervisor::bounded` here. Each await on spawned work is bounded locally
//! instead; an unbounded await that wedges would hang the whole binary
//! silently, because libtest has no per-test timeout.

use haos_green::supervisor::backend::sandbox::{Grants, Isolation};
use haos_green::supervisor::backend::shell::ShellBackend;
// `run` is a `Backend` trait method, so the trait has to be in scope even though
// nothing in this file names it.
use haos_green::supervisor::backend::{Backend, RunContext};
use haos_green::supervisor::job::{Job, JobOutput, JobStatus, JobType};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// libtest has no per-test timeout, so every await in this file is bounded.
const TEST_BOUND: Duration = Duration::from_secs(90);

fn live() -> bool {
    std::env::var("HAOS_GREEN_SHELL_LIVE").as_deref() == Ok("1")
}

/// Print a reason and return, so the test reports `ok` on a host that cannot run
/// it. Grep the output for `SKIP:` to tell a skip from a real pass.
macro_rules! skip_unless_live {
    () => {
        if !live() {
            println!("SKIP: set HAOS_GREEN_SHELL_LIVE=1 to run the real-bubblewrap tests");
            return;
        }
    };
}

/// Run one command through the real sandboxed launch, with the given grant set.
///
/// `grants` is the whole grant set: `Grants::default()` is the empty set, which
/// is what an operator who has granted nothing holds.
async fn run_sandboxed(cmd: &str, grants: Grants) -> JobOutput {
    let root = tempfile::tempdir().expect("a temporary sandbox root");
    let held = Arc::new(RwLock::new(grants));
    let backend = ShellBackend::new(root.path().into())
        .with_isolation(Isolation::Sandboxed)
        .with_grants(held);
    let mut job = Job::new("live", JobType::ShellJob, "shell", cmd);
    // Long enough that the byte cap, not the deadline, is what ends a runaway
    // producer; short enough that a wedged run fails the bound below rather
    // than the harness.
    job.timeout_secs = 60;
    tokio::time::timeout(TEST_BOUND, backend.run(&mut job, &RunContext::new()))
        .await
        .expect("the sandboxed run did not finish within the test bound")
        .expect("the sandboxed run returned an error rather than a JobOutput")
}

/// A token the command echoes **last**, so an assertion can tell "the sandbox
/// refused to read this" from "nothing ever ran".
///
/// Every test below that asserts only the *absence* of a string needs this.
/// Without it a completely broken launch — no `bwrap`, a bad argv, a refused
/// job directory — produces an error message containing none of the forbidden
/// strings, and the test reports `ok` while proving nothing. Five of the nine
/// tests here were in exactly that state.
///
/// The token deliberately contains none of the names test 3 greps for
/// (`HAOS_GREEN`, `OPENROUTER`, `TELEGRAM`, `A2A`): the first spelling was
/// `HAOS_GREEN_LIVE_RAN=yes`, and test 3 caught it as a leak — which is the
/// new assertion doing exactly its job.
const RAN: &str = "LIVE_RAN=yes";

/// Everything the sandbox produced, so an assertion can search output *and*
/// errors without caring which stream a message arrived on.
fn all_text(out: &JobOutput) -> String {
    format!("{}\n{}", out.summary, out.errors.join("\n"))
}

/// 1. The original attack: the host hostname must not be readable.
///
/// `--hostname` replaces it, and `/etc/hostname` is not in the base set, so
/// either the command fails or it reads something that is not the host's. Both
/// outcomes are acceptable; reading the host's name is not.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn the_host_hostname_is_not_readable() {
    skip_unless_live!();
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let host = host.trim();
    assert!(
        !host.is_empty(),
        "this test needs /etc/hostname on the host"
    );

    let out = run_sandboxed(
        &format!("cat /etc/hostname; hostname; echo {RAN}"),
        Grants::default(),
    )
    .await;
    assert!(
        all_text(&out).contains(RAN),
        "the command never ran, so this test proves nothing: {out:?}"
    );
    assert!(
        !all_text(&out).contains(host),
        "the sandbox leaked the host hostname {host:?}: {out:?}"
    );
}

/// 2. The supervisor's own configuration, which holds the API key and every
/// peer token, must be unreachable.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn the_supervisor_config_is_unreachable() {
    skip_unless_live!();
    // A **canary** rather than the real config: this host may have no
    // `~/.haos-green/config.toml`, and a test that proves a non-existent file is
    // unreadable proves nothing. The canary sits at the sandbox root, which the
    // argv does not bind, and its existence on the host is asserted first — so
    // the failure it detects is a real one.
    let root = tempfile::tempdir().unwrap();
    let canary = root.path().join("config.toml");
    std::fs::write(
        &canary,
        "api_key = \"CANARY-NOT-A-REAL-KEY\"\nbot_token = \"x\"\n",
    )
    .unwrap();
    assert!(canary.exists(), "the canary must exist on the host");

    let mut job = Job::new("live", JobType::ShellJob, "shell", "live");
    job.prompt = Some(format!("cat '{}' 2>&1; echo {RAN}", canary.display()));
    job.timeout_secs = 60;
    let backend = ShellBackend::new(root.path().into()).with_isolation(Isolation::Sandboxed);
    let out = tokio::time::timeout(TEST_BOUND, backend.run(&mut job, &RunContext::new()))
        .await
        .expect("the sandboxed run did not finish within the test bound")
        .expect("the sandboxed run returned an error rather than a JobOutput");
    let text = all_text(&out);
    assert!(
        text.contains(RAN),
        "the command never ran, so this test proves nothing: {out:?}"
    );
    assert!(
        !text.contains("CANARY-NOT-A-REAL-KEY"),
        "the sandbox read a file at its own root: {out:?}"
    );
    assert!(
        !text.contains("api_key") && !text.contains("bot_token"),
        "the sandbox reached the supervisor config: {out:?}"
    );
}

/// 3. The environment leak is closed: `--clearenv` runs before every `--setenv`.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn the_supervisor_environment_is_not_inherited() {
    skip_unless_live!();
    let out = run_sandboxed(&format!("env; echo {RAN}"), Grants::default()).await;
    let text = all_text(&out);
    assert!(
        text.contains(RAN),
        "the command never ran, so this test proves nothing: {out:?}"
    );
    for leaked in ["HAOS_GREEN", "OPENROUTER", "TELEGRAM", "A2A"] {
        assert!(
            !text.contains(leaked),
            "the sandbox inherited {leaked} from the supervisor environment: {out:?}"
        );
    }
}

/// 4. Nested user namespaces are refused, so a job cannot build its own
/// namespace to escape the one it was given.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn nested_user_namespaces_are_refused() {
    skip_unless_live!();
    // `command -v` first: without it an absent `unshare` makes `$?` 127, which
    // is not 0 either, so the test would pass on a sandbox that never ran the
    // probe. `NO_UNSHARE` turns that into a visible failure instead.
    let out = run_sandboxed(
        &format!("command -v unshare >/dev/null 2>&1 && {{ unshare --user true 2>&1; echo exit=$?; }} || echo NO_UNSHARE; echo {RAN}"),
        Grants::default(),
    )
    .await;
    let text = all_text(&out);
    assert!(
        text.contains(RAN),
        "the command never ran, so this test proves nothing: {out:?}"
    );
    assert!(
        !text.contains("NO_UNSHARE"),
        "the probe could not run, so this test proves nothing: {out:?}"
    );
    assert!(
        text.contains("exit="),
        "the probe produced no exit status: {out:?}"
    );
    assert!(
        !text.contains("exit=0"),
        "a nested user namespace succeeded inside the sandbox: {out:?}"
    );
}

/// 5. The network grant is exactly what carries reachability: the same command,
/// one flag apart.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn loopback_is_unreachable_without_the_network_grant_and_reachable_with_it() {
    skip_unless_live!();
    // A service that actually **listens** on the host. Probing a port with no
    // listener cannot tell the two cases apart: with the grant the local stack
    // answers `Connection refused` after 0 ms, which is reachability, not its
    // absence — an earlier version of this test asserted the opposite and failed
    // for that reason. The LLM gateway is the one always-on local service, and
    // the test skips visibly when it is down.
    let port = "127.0.0.1:8790";
    let host_reachable = std::process::Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "--max-time",
            "3",
            &format!("http://{port}/v1/models"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !host_reachable {
        println!(
            "SKIP: nothing is listening on {port} on this host, so the network grant cannot be probed"
        );
        return;
    }

    // `curl` is in /usr, which the base set binds read-only.
    let probe = format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' --max-time 5 http://{port}/v1/models 2>&1"
    );

    let without = run_sandboxed(&probe, Grants::default()).await;
    assert!(
        !all_text(&without).contains("200"),
        "loopback reached a host service with no network grant held: {without:?}"
    );

    let with = run_sandboxed(
        &probe,
        Grants {
            network: true,
            ..Grants::default()
        },
    )
    .await;
    assert!(
        all_text(&with).contains("200"),
        "the network grant did not make the host's loopback service reachable: {with:?}"
    );
}

/// 6. `/etc/passwd` is not in the base set and must not be readable.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn the_host_passwd_file_is_unreadable() {
    skip_unless_live!();
    // The precondition matters here too: `root:x:0:0` is the *host's* first
    // line, so the test only means something if the host has that line.
    let host = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    assert!(
        host.contains("root:x:0:0"),
        "this test needs /etc/passwd with a root entry on the host"
    );

    let out = run_sandboxed(
        &format!("cat /etc/passwd 2>&1; echo {RAN}"),
        Grants::default(),
    )
    .await;
    let text = all_text(&out);
    assert!(
        text.contains(RAN),
        "the command never ran, so this test proves nothing: {out:?}"
    );
    assert!(
        !text.contains("root:x:0:0"),
        "the sandbox read the host /etc/passwd: {out:?}"
    );
}

/// 7. Killing the supervisor leaves no descendant, which is what
/// `--die-with-parent` is for.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn killing_the_supervisor_leaves_no_descendant() {
    skip_unless_live!();
    let count_sleeps = || {
        std::process::Command::new("pgrep")
            // `-f` with an anchored pattern, not `-x sleep`: counting every
            // `sleep` on the host makes the test fail when an unrelated one
            // starts, and — worse — pass when an unrelated one exits while the
            // sandboxed `sleep 300` survives, which is the exact property the
            // test exists to pin.
            .args(["-c", "-f", "^sleep 300$"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let before = count_sleeps();

    {
        let root = tempfile::tempdir().unwrap();
        let backend = ShellBackend::new(root.path().into())
            .with_isolation(Isolation::Sandboxed)
            .with_grants(Arc::new(RwLock::new(Grants::default())));
        let mut job = Job::new("live", JobType::ShellJob, "shell", "sleep 300");
        job.timeout_secs = 300;
        // Bound to a local: `run` borrows the context, so an inline
        // `&RunContext::new()` would be a temporary dropped while the future
        // still borrows it (E0716).
        let ctx = RunContext::new();
        // Dropped by the timeout, which is the cancellation path under test.
        let fut = backend.run(&mut job, &ctx);
        let _ = tokio::time::timeout(Duration::from_secs(3), fut).await;
    }

    // Polled to a deadline rather than slept on for a fixed delay. The kill is
    // asynchronous and its latency is not a constant: with a flat 3s wait this
    // test passed once and failed once on the same code, which makes it a test
    // that reports the scheduler rather than the property. The property is "no
    // descendant *survives*", so the assertion belongs at a deadline, not at a
    // guessed instant.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut after = count_sleeps();
    while after != before && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
        after = count_sleeps();
    }
    assert_eq!(
        before, after,
        "a `sleep 300` outlived the supervisor by more than 20s: pgrep count went \
         {before} -> {after}"
    );
}

/// 8. HTTPS works from inside the sandbox **under a network grant**.
///
/// This is the test the two certificate binds exist for. Without them it fails
/// with `curl: (77) error adding trust anchors from file:
/// /etc/ssl/certs/ca-certificates.crt`; with `/etc/ssl/certs` bound **alone** it
/// still fails, because on Arch/CachyOS that bundle is a symlink into
/// `/etc/ca-certificates`. Measured on this host: with both binds,
/// `openssl s_client` reports `Verify return code: 0 (ok)`.
///
/// Network-free hosts cannot reach the certificate at all, so this skips there
/// rather than failing — the `cabundle` smoke field covers the binds themselves
/// without a network.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn https_works_under_a_network_grant() {
    skip_unless_live!();
    let out = run_sandboxed(
        "curl -fsS -o /dev/null -w '%{http_code}' --max-time 20 https://example.com 2>&1",
        Grants {
            network: true,
            ..Grants::default()
        },
    )
    .await;
    let text = all_text(&out);
    if text.contains("Could not resolve") || text.contains("Network is unreachable") {
        println!("SKIP: this host has no outbound network, so HTTPS cannot be probed");
        return;
    }
    assert!(
        !text.contains("(77)"),
        "the certificate binds are not in effect: {out:?}"
    );
    assert!(
        text.contains("200") || text.contains("301") || text.contains("302"),
        "HTTPS from inside the sandbox did not succeed: {out:?}"
    );
}

/// 9. The byte cap holds on the **sandboxed** launch too.
///
/// `src/supervisor/backend/shell.rs` covers this arm in a unit test as well, and
/// this is the same property through the public API on a real `bwrap`. It is
/// the one place a real bubblewrap is required for the cap, and it is what
/// catches a change that applies the cap on the `Unconfined` arm only.
#[tokio::test]
#[ignore = "requires HAOS_GREEN_SHELL_LIVE=1 and a working bubblewrap >= 0.12.0"]
async fn an_infinite_producer_is_stopped_by_the_byte_cap_in_the_sandbox() {
    skip_unless_live!();
    let out = run_sandboxed("yes", Grants::default()).await;
    assert_eq!(
        out.status,
        JobStatus::Failed,
        "a runaway producer must not be reported as success: {out:?}"
    );
    assert!(
        out.errors.iter().any(|e| e.contains("byte cap")),
        "the byte cap must be what ended this run, got {:?}",
        out.errors
    );
}
