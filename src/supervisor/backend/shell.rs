use anyhow::Result;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

use crate::supervisor::backend::sandbox::{self, Grants, Isolation};
use crate::supervisor::backend::{Backend, BackendCapabilities, RunContext};
use crate::supervisor::job::{Evidence, Job, JobOutput, JobStatus, JobType};

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

impl ShellBackend {
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
}

/// Maximum bytes captured from **each** of stdout and stderr.
///
/// The sandbox bounds namespaces, not output. Before this cap the capture was
/// `wait_with_output`, which buffers without limit, so `yes` — or any command
/// with a large enough output — exhausted the supervisor's memory long before
/// `job.timeout_secs` could fire. The deadline bounds *time*; this bounds
/// *bytes*, and the two are independent.
///
/// `pub` because it is the contract the tests assert against, and because
/// `src/lib.rs` carries `#![deny(dead_code)]`: a reachable `pub` item in the
/// `pub` module chain is live, a private unused one is a hard error.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// How long the *other* pipe is still drained after the cap has killed the child.
///
/// Only reachable when a process that outlived the direct child still holds the
/// other pipe open — a shell that forked rather than `exec`ed (`sh -c 'a; yes'`
/// does not `exec`, though `sh -c yes` does). The direct child is dead, so this
/// normally returns at once; without a bound of its own that case would park the
/// capture until the job's own deadline, which is minutes away.
const POST_CAP_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// How many tasks the child may hold **beyond what the supervisor's real uid
/// already holds**.
///
/// A headroom rather than an absolute limit, and that is the whole correction
/// this file makes to the plan. `RLIMIT_NPROC` is counted per **real user ID**,
/// so a flat absolute value is a limit on the *uid*, not on the job: an absolute
/// 256 was measured here to break five tests as uid 1000 — including the
/// sandboxed launch, which failed with `bwrap: Creating new namespace failed:
/// Resource temporarily unavailable`, and the pre-existing
/// `a_dropped_run_does_not_leave_the_shell_child_running` — because uid 1000 held
/// 864 tasks (threads count, not just processes). Disabling this hook entirely
/// made all fourteen tests pass again as uid 1000, which is what attributes the
/// failures to this limit rather than to the host.
///
/// So the brake is sized from a measurement taken at spawn time: the job may add
/// this many tasks, and no more.
const JOB_PROCESS_HEADROOM: libc::rlim_t = 256;

/// How many tasks whose real uid is this process's exist right now, or `None`
/// when `/proc` could not be read.
///
/// **Tasks, not processes.** `RLIMIT_NPROC` is checked against the kernel's
/// per-uid task counter, which every `clone` increments — threads included — so
/// counting `/proc/<pid>` entries instead would under-count a browser-shaped uid
/// by an order of magnitude. Measured on this host: uid 1000 had 70 processes
/// and 864 tasks.
///
/// Read here, in the **parent**, because `pre_exec` runs in a forked child of a
/// multi-threaded process where `opendir`/`readdir` are not async-signal-safe.
/// This is a scan of `/proc`, so it is not free; it is one small read per process
/// on the host, once per job.
fn uid_task_count() -> Option<libc::rlim_t> {
    let me = unsafe { libc::getuid() };
    let mut total: libc::rlim_t = 0;
    let mut found = false;
    for entry in std::fs::read_dir("/proc").ok()? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A process that exited between the listing and the read is skipped, not
        // an error: the scan is a sample of a moving system either way.
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let mut mine = false;
        let mut threads: libc::rlim_t = 0;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // `Uid:\treal\teffective\tsaved\tfs`
                mine = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    == Some(me);
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                threads = rest.trim().parse().unwrap_or(0);
            }
        }
        if mine {
            found = true;
            total = total.saturating_add(threads);
        }
    }
    // This process is the caller's, so a scan that matched nothing did not
    // measure — it failed, and a failure must not be read as "the uid holds
    // nothing".
    found.then_some(total)
}

/// The `RLIMIT_NPROC` to install in the child, or `None` when it cannot be sized.
fn child_process_limit() -> Option<libc::rlim_t> {
    Some(uid_task_count()?.saturating_add(JOB_PROCESS_HEADROOM))
}

/// Install the child's process brake on a command, in the child.
///
/// **What this is:** a brake on a fork bomb, and nothing more. It is not a
/// security boundary — the sandbox is — and it is not what makes a shell job
/// safe to run.
///
/// **What it is measured to do, and not do, on Linux:**
///
/// - Linux skips the `RLIMIT_NPROC` check for a process holding `CAP_SYS_ADMIN`
///   or `CAP_SYS_RESOURCE`, so **as root this limit is a no-op.** Measured on
///   this host: with `ulimit -u 256` in a root shell, both `/bin/true` and a real
///   `bwrap` sandbox still run. It is enforced for a non-root supervisor only.
/// - The count is per **real user ID**, which is why the value is
///   [`child_process_limit`]'s measurement plus [`JOB_PROCESS_HEADROOM`] rather
///   than a constant. If the uid already holds more than the limit, *every*
///   `fork` in the job fails with `EAGAIN` — measured, as uid 1000, with a flat
///   256.
/// - It is only ever *lowered*, never raised, and never allowed to fail a spawn:
///   an operator's tighter `LimitNPROC` is a decision, and a brake that could not
///   be applied must not refuse the job.
///
/// This is a **second** `pre_exec` closure, registered after the one
/// `SandboxArgv::command` installs, and the two coexist: `std` runs every
/// registered closure in registration order and aborts the spawn if one returns
/// `Err`. Measured with a two-closure probe — both ran, in order, and the
/// `FD_CLOEXEC` clear performed by the first was visible to the second — so the
/// C1 property that closure carries is untouched.
fn limit_child_processes(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Sized here, in the parent: see `uid_task_count`.
    let Some(want) = child_process_limit() else {
        // No measurement, no brake. Failing *closed* would refuse the job over a
        // limit that is best-effort to begin with, and would do it on exactly the
        // hosts where the sizing is least understood.
        return;
    };
    // SAFETY: `pre_exec` runs between `fork` and `exec`, in the child. The
    // closure does two raw syscalls — `getrlimit` and `setrlimit` — and nothing
    // else: no allocation, no lock, no `errno` read. That matters because the
    // child is a copy of a multi-threaded process, so anything that could take a
    // lock another thread held at the fork would deadlock here. Neither call is
    // on POSIX's async-signal-safe list, which is a weaker guarantee than the
    // `fcntl` closure in `sandbox` claims; on Linux both are direct syscall
    // wrappers with no libc-side state, and that is what makes them safe in this
    // region in practice rather than by standard.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            let mut current = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // Never *raise* a limit the operator already set tighter: a systemd
            // `LimitNPROC=64` is a decision, and a job quietly given more would be
            // a widening of it. Lower, or leave alone.
            if libc::getrlimit(libc::RLIMIT_NPROC, &mut current) != 0 || current.rlim_cur <= want {
                return Ok(());
            }
            let limit = libc::rlimit {
                rlim_cur: want,
                rlim_max: want,
            };
            // Deliberately unchecked: a brake that could not be applied must not
            // fail the job. `rlim_max` is lowered with `rlim_cur`, so the job
            // cannot lift it again — raising it needs `CAP_SYS_RESOURCE`.
            libc::setrlimit(libc::RLIMIT_NPROC, &limit);
            Ok(())
        });
    }
}

/// What a bounded capture saw.
struct Capture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// At least one pipe reached [`MAX_OUTPUT_BYTES`], so the child was killed.
    truncated: bool,
    /// A pipe was still open when the capture stopped. Only
    /// [`POST_CAP_DRAIN_GRACE`] or the job's deadline can cause it, and
    /// `truncated` says which.
    gave_up: bool,
}

/// Read a pipe to EOF, or to `cap` bytes — whichever comes first. The `bool` is
/// `true` when the cap is what stopped it.
///
/// The reader is **owned**, not borrowed, and that is load-bearing: when this
/// future completes, the `ChildStdout`/`ChildStderr` it holds is dropped, which
/// closes that read end. A producer still writing to a pipe with no reader gets
/// `SIGPIPE`, so the cap does not merely stop *reading* — it stops the
/// *producer*, even one the shell forked instead of `exec`ed.
async fn read_capped<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut r: R,
    cap: usize,
) -> (Vec<u8>, bool) {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            // A read error is an end, not a failure: the child's exit status is
            // what reports failure, and a job whose pipe died has no more output
            // to give either way.
            Ok(0) | Err(_) => return (buf, false),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= cap {
                    buf.truncate(cap);
                    return (buf, true);
                }
            }
        }
    }
}

/// Read both pipes under the byte cap, killing the child as soon as either cap
/// is reached, and stop when both pipes end.
///
/// The readers are spawned rather than pinned in place, so a finished reader
/// drops its pipe and the producer dies of `SIGPIPE` — see [`read_capped`].
///
/// Spawning has one cost, stated rather than hidden: if this future is dropped
/// mid-capture — the lease-loss path drops `execute_now`, which drops `run` —
/// the two reader tasks are **detached, not cancelled**. They are still bounded:
/// `kill_on_drop` kills the direct child, both pipes then reach EOF, and each
/// reader stops at the cap in any case, so neither can outlive the pipes it
/// reads.
async fn capture_capped(
    child: &mut tokio::process::Child,
    deadline_at: tokio::time::Instant,
) -> Capture {
    // Both are `Stdio::piped()` at the spawn in `run`, so this arm is
    // unreachable; an empty capture is the safe reading rather than a panic in a
    // job runner.
    let (Some(stdout_pipe), Some(stderr_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        return Capture {
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            gave_up: false,
        };
    };
    let mut out = tokio::spawn(read_capped(stdout_pipe, MAX_OUTPUT_BYTES));
    let mut err = tokio::spawn(read_capped(stderr_pipe, MAX_OUTPUT_BYTES));

    let mut out_res: Option<(Vec<u8>, bool)> = None;
    let mut err_res: Option<(Vec<u8>, bool)> = None;
    let mut truncated = false;
    let mut killed = false;
    let mut drain_until: Option<tokio::time::Instant> = None;

    while out_res.is_none() || err_res.is_none() {
        // An absolute instant, so re-creating the sleep each turn does not
        // restart it. The grace only exists once the cap has fired.
        let until = drain_until.unwrap_or(deadline_at);
        tokio::select! {
            r = &mut out, if out_res.is_none() => {
                let (buf, hit) = r.unwrap_or_else(|_| (Vec::new(), false));
                truncated |= hit;
                out_res = Some((buf, hit));
            }
            r = &mut err, if err_res.is_none() => {
                let (buf, hit) = r.unwrap_or_else(|_| (Vec::new(), false));
                truncated |= hit;
                err_res = Some((buf, hit));
            }
            _ = tokio::time::sleep_until(until) => {
                return Capture {
                    stdout: out_res.take().map(|(b, _)| b).unwrap_or_default(),
                    stderr: err_res.take().map(|(b, _)| b).unwrap_or_default(),
                    truncated,
                    gave_up: true,
                };
            }
        }
        if truncated && !killed {
            killed = true;
            let _ = child.start_kill();
            drain_until = Some(tokio::time::Instant::now() + POST_CAP_DRAIN_GRACE);
        }
    }
    Capture {
        stdout: out_res.take().map(|(b, _)| b).unwrap_or_default(),
        stderr: err_res.take().map(|(b, _)| b).unwrap_or_default(),
        truncated,
        gave_up: false,
    }
}

// Containment used to live here, as `validate()`: a substring check for `cd /`,
// `cd ..` and `../`. It is **deleted**, not weakened — it was never containment
// (command substitution, `pushd` and any number of other forms walk past it).
//
// What replaced it is `supervisor::backend::sandbox`, and it is not one thing:
//
// - under `Isolation::Sandboxed`, the boundary is the bubblewrap argv built in
//   `supervisor::backend::sandbox` — a hardened argv whose only writable host
//   path is the job's own directory, bound by descriptor;
// - under `Isolation::Unconfined` there is **no boundary at all**. The operator
//   chose that with `[supervisor.shell].sandbox = "none"` (spec §4), and this
//   backend runs `sh -c` in the job directory exactly as it did before the
//   sandbox existed. Nothing in this file contains such a job;
// - under `Isolation::Unavailable` nothing runs at all.
//
// And even under `Sandboxed`, "the only writable host path is the job's own
// directory" is true only while no write grant is held: each grant adds a
// read-write `--bind` of a host path the operator named by hand (spec §3). The
// sentence is scoped that way here because a claim that is false in two of three
// modes is worse than no claim.

#[async_trait::async_trait]
impl Backend for ShellBackend {
    fn name(&self) -> &str {
        "shell"
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            shell: true,
            ..Default::default()
        }
    }
    fn can_handle(&self, jt: &JobType) -> bool {
        matches!(jt, JobType::ShellJob)
    }
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
                    "refusing to run a shell job without isolation: {reason}. {advice} \
                     A writable host path and the host network are released by name — \
                     `/allow <path>` and `/allow-net` — and neither substitutes for a \
                     sandbox that is not there.",
                    advice = reason.advice()
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
        // `kill_on_drop` is what makes the lease abort real: dropping the
        // `execute_now` future (see `run_until_lease_loss`) drops this future,
        // and without it the child would keep running in the sandbox while
        // another owner runs the same task. Mirrors `run_cli_process`.
        //
        // `spawn` rather than `output()` is what makes both bounds below
        // possible: `output()` offers neither a deadline nor a cap of its own, so
        // a hung command never returns on its own — and, with the lease
        // heartbeat renewing, its task stays locked forever, across processes —
        // and `yes` buffers without limit. Dropping the run future drops the
        // child, which `kill_on_drop` then kills.
        //
        // The stdio settings are **not** `output()`'s defaults, and the
        // difference is deliberate. `output()` sets only stdout and stderr to
        // `piped` (tokio 1.53.1, `process::Command::output`) and leaves stdin
        // **inherited**; here stdin is explicitly `Stdio::null()`, so a
        // sandboxed job cannot read the supervisor's stdin — a behaviour change
        // for the better, not an equivalence.
        let timeout_secs = job.timeout_secs;
        // Two launches, one decision. `Unconfined` runs `sh -c` in the job's
        // directory — exactly what this backend did before the sandbox existed
        // — and never invokes `bwrap`. That is what makes the refusal message's
        // way out real: the operator who reads it has no usable bubblewrap,
        // so a `bwrap` spawn there would fail the job for the same reason it
        // was refused, and the message would send them in a circle.
        let mut child = match &self.isolation {
            Isolation::Unconfined => {
                let mut unconfined = Command::new("sh");
                unconfined
                    .arg("-c")
                    .arg(&cmd)
                    .current_dir(job_dir.path())
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                limit_child_processes(&mut unconfined);
                unconfined.spawn()?
            }
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
                // LAYER 2 — a capability the job declares and the operator has
                // not granted is refused here, before anything is spawned.
                // bubblewrap cannot be widened once it has started, so a missing
                // grant can only mean "do not run".
                //
                // **Inside the `Sandboxed` arm on purpose, and that is not a
                // stylistic choice.** The plan's snippet put this refusal before
                // the `match`, which would refuse an `Unconfined` job too. That
                // contradicts spec §4 — "with `sandbox = \"none\"` nothing is
                // gated: that mode *is* the operator's consent" — and the plan's
                // own `shell_gate_reason` rationale, which states that under
                // `Unconfined` this arm "reads neither `Grants` nor
                // `declared_grants`". Under `Unconfined` there is no argv and no
                // bind, so a declaration buys the job nothing: refusing it would
                // cost an approval round-trip and change nothing about what
                // runs. Putting it in the arm also makes the exemption
                // structural — there is no single `if` above the `match` for a
                // later change to widen by accident.
                let missing = held.missing(&job.declared_grants);
                if !missing.is_empty() {
                    job.status = JobStatus::Failed;
                    return Ok(JobOutput {
                        status: JobStatus::Failed,
                        summary: String::new(),
                        evidence: vec![],
                        errors: vec![format!(
                            "refusing to run a shell job that needs what the supervisor \
                             does not hold: {}. Grant it by name, then approve the task \
                             again.",
                            missing.join("; ")
                        )],
                        changed_files: vec![],
                        next_step: None,
                    });
                }
                // `built` owns the descriptor the argv names, so it is open when
                // the child is spawned and closed when this arm ends — after the
                // spawn, never before it.
                //
                // `built.command` is the **only** place `FD_CLOEXEC` is cleared,
                // and it does so in the child, between `fork` and `exec`. Doing
                // it here instead would publish a handle into this job's
                // directory to every child this process spawns from any thread
                // while `built` is alive — the probe's `bwrap` invocations,
                // every other job's sandbox — and a second job's shell could
                // then read and write the first job's directory through
                // `/proc/self/fd`, past every mount in its own argv.
                let built = sandbox::build_argv(&job_dir, &held, &cmd)?;
                let mut sandboxed: Command = built.command("bwrap").into();
                sandboxed
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                // A **second** `pre_exec` closure on the same command as the
                // `FD_CLOEXEC` clear above. Both run, in registration order, and
                // the first is unaffected — measured, not assumed — so C1 still
                // holds. See `limit_child_processes`.
                limit_child_processes(&mut sandboxed);
                sandboxed.spawn()?
            }
        };
        // One absolute instant for both bounds below, so the capture and the exit
        // wait share the job's deadline instead of each getting a fresh
        // `timeout_secs`.
        let deadline_at = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let captured = capture_capped(&mut child, deadline_at).await;
        // The deadline is reported only when nothing else ended the job: once the
        // cap has fired, the cap is the reason, and the deadline is at most the
        // backstop that ended the drain.
        if captured.gave_up && !captured.truncated {
            job.status = JobStatus::Failed;
            return Ok(JobOutput {
                status: JobStatus::Failed,
                summary: String::new(),
                evidence: vec![],
                errors: vec![format!("shell command timed out after {timeout_secs}s")],
                changed_files: vec![],
                next_step: None,
            });
        }
        // The exit status, under the same deadline. On the cap path the child has
        // just been killed and on the ordinary path both pipes are already at
        // EOF, so this returns at once; the bound is for a child that closed its
        // pipes and kept running.
        let exit = if captured.gave_up {
            None
        } else {
            match tokio::time::timeout_at(deadline_at, child.wait()).await {
                Ok(Ok(status)) => Some(status),
                Ok(Err(_)) => None,
                Err(_) => {
                    job.status = JobStatus::Failed;
                    return Ok(JobOutput {
                        status: JobStatus::Failed,
                        summary: String::new(),
                        evidence: vec![],
                        errors: vec![format!("shell command timed out after {timeout_secs}s")],
                        changed_files: vec![],
                        next_step: None,
                    });
                }
            }
        };
        let stdout = String::from_utf8_lossy(&captured.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&captured.stderr).into_owned();
        let mut errors = Vec::new();
        if captured.truncated {
            errors.push(format!("output exceeded the {MAX_OUTPUT_BYTES}-byte cap"));
        }
        if !stderr.is_empty() {
            errors.push(stderr);
        }
        // A truncated capture is incomplete by construction, so the job is not a
        // success even when the child exited 0: `Backend::verify_result` reads
        // `Succeeded` as "this output can be trusted".
        let status = if captured.truncated || !exit.is_some_and(|s| s.success()) {
            JobStatus::Failed
        } else {
            JobStatus::Succeeded
        };
        job.status = status.clone();
        Ok(JobOutput {
            status,
            summary: stdout.trim().to_string(),
            evidence: vec![Evidence::ExitCode {
                code: exit.and_then(|s| s.code()).unwrap_or(-1),
            }],
            errors,
            changed_files: vec![],
            next_step: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ShellSandboxConfig;
    use crate::supervisor::backend::sandbox::{Grants, Isolation, IsolationUnavailable};

    /// The fail-closed default, from the outside: a `ShellBackend` built without
    /// an explicit decision must refuse to run — and must not name a cause it
    /// never established.
    ///
    /// This is the fourth direction `M14` is pinned from. The other three are in
    /// `sandbox`: the variant the default carries, the `advice()` text for every
    /// cause, and the message. A default that quietly became
    /// `Sandboxed` would run a job through a boundary that was never proven; one
    /// that became `Unconfined` would run it with no boundary at all. Both die
    /// here, on the `spawned` marker as well as on the status.
    /// A job that declares a capability the operator has not granted is refused
    /// **before anything is spawned**, and the refusal names the command that
    /// releases it rather than only the fact.
    ///
    /// `Isolation::Sandboxed` is passed directly, so this needs no working
    /// `bwrap`: the point is that the refusal precedes the spawn, and the
    /// `spawned` marker proves it did.
    #[tokio::test]
    async fn a_declared_capability_that_is_not_granted_refuses_to_spawn_anything() {
        let dir = tempfile::tempdir().unwrap();
        let spawned = dir.path().join("spawned");
        let b = ShellBackend::new(dir.path().into())
            .with_isolation(Isolation::Sandboxed)
            .with_grants(std::sync::Arc::new(std::sync::RwLock::new(
                Grants::default(),
            )));
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            &format!("touch '{}'", spawned.display()),
        );
        job.declared_grants
            .write
            .insert(std::path::PathBuf::from("/etc"));

        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Failed),
            "a declared capability that is not held must refuse, got {:?}",
            out.status
        );
        assert!(
            !spawned.exists(),
            "the refusal must happen before any spawn: {} exists",
            spawned.display()
        );
        assert!(
            out.errors.iter().any(|e| e.contains("/allow /etc")),
            "the refusal must name the command that releases the capability, got {:?}",
            out.errors
        );
    }

    /// **The same declaration is not refused under `Unconfined`, and this test
    /// is what pins the refusal inside the `Sandboxed` arm.**
    ///
    /// Move the coverage check above the `match` — which is what the plan's
    /// snippet does — and this test fails while the one above still passes.
    /// That asymmetry is the whole reason both exist: without this one, an
    /// implementation that gates every mode looks correct.
    ///
    /// Spec §4: "with `sandbox = \"none\"` nothing is gated: that mode *is* the
    /// operator's consent". Under `Unconfined` there is no argv and no bind, so
    /// the declaration buys the job nothing.
    #[tokio::test]
    async fn a_declared_capability_is_not_refused_under_unconfined() {
        let dir = tempfile::tempdir().unwrap();
        let spawned = dir.path().join("spawned");
        let b = ShellBackend::new(dir.path().into())
            .with_isolation(Isolation::Unconfined)
            .with_grants(std::sync::Arc::new(std::sync::RwLock::new(
                Grants::default(),
            )));
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            &format!("touch '{}'", spawned.display()),
        );
        job.declared_grants
            .write
            .insert(std::path::PathBuf::from("/etc"));

        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(
            spawned.exists(),
            "Unconfined is the operator's consent, so the declaration must not gate it; \
             got {out:?}"
        );
    }

    #[tokio::test]
    async fn a_backend_without_a_decision_refuses_to_spawn_anything() {
        let dir = tempfile::tempdir().unwrap();
        let spawned = dir.path().join("spawned");
        // `ShellBackend::new` and nothing else — no `with_isolation`.
        let b = ShellBackend::new(dir.path().into());
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "shell",
        );
        job.prompt = Some(format!("touch '{}'", spawned.display()));

        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Failed),
            "a backend with no decision must refuse, got {:?}",
            out.status
        );
        assert!(
            !spawned.exists(),
            "the refusal must happen before any spawn: {} exists",
            spawned.display()
        );
        assert!(
            out.errors
                .iter()
                .any(|e| e.contains("no isolation decision")),
            "the refusal must name the real cause rather than a guessed one, got {:?}",
            out.errors
        );
        // The whole reason `NotDecided` exists is that a plausible-sounding wrong
        // cause is the worst kind. `contains("no isolation decision")` alone let
        // the contradiction ship: the message named the right cause and then
        // advised installing a package nothing had looked for.
        assert!(
            !out.errors
                .iter()
                .any(|e| e.contains("Install bubblewrap") || e.contains("Upgrade bubblewrap")),
            "a backend that was never handed a decision must not be told to install or \
             upgrade bubblewrap: nothing was probed, so that is a guess. Got {:?}",
            out.errors
        );
        assert!(
            out.errors.iter().any(|e| e.contains("wiring bug")),
            "the NotDecided cause must name itself as a wiring bug, got {:?}",
            out.errors
        );
    }

    /// The boundary is absent, so nothing may be spawned — and the refusal has
    /// to name the cause, the standing way out, and the grant vocabulary. A
    /// refusal that does not name the way out is a dead end for the operator.
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
        assert!(matches!(
            out.status,
            crate::supervisor::job::JobStatus::Failed
        ));
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

        let out =
            crate::supervisor::bounded("the unconfined run", b.run(&mut job, &RunContext::new()))
                .await
                .unwrap();
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

    /// The replacement for `shell_backend_rejects_command_escaping_sandbox`.
    ///
    /// That test asserted the old string heuristic — `cd /`, `cd ..`, `../` —
    /// which this task deletes, because containment is the sandbox's job now
    /// and a substring check is not containment. The property it stood for is
    /// kept: a command that heuristic refused is no longer refused, and it is
    /// passed through **verbatim**, which the shell proves by running it.
    ///
    /// What it does **not** show, and must not be read as showing: the two
    /// launches are not distinguished by it. `pwd -P` after `cd ..` is
    /// `<job-dir>/..` under `Unconfined` and under the sandbox alike, because
    /// the argv's `--chdir` puts the sandbox in the same directory — so this
    /// test passes identically whichever arm ran, and it is deliberately built
    /// on `Unconfined` where `sh -c` is the documented behaviour. The mode
    /// distinction lives in `the_sandboxed_launch_is_a_real_sandbox`.
    #[tokio::test]
    async fn a_command_the_old_heuristic_refused_reaches_the_shell_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "shell",
        );
        // Both of the old refusals, in one command, plus output that proves the
        // shell ran it rather than that the string merely survived a check.
        job.prompt = Some("cd .. && pwd -P".into());
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let job_dir = root.join(&job.task_id).join(&job.id);

        let out = crate::supervisor::bounded(
            "the command the old heuristic refused",
            b.run(&mut job, &RunContext::new()),
        )
        .await
        .unwrap();

        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Succeeded),
            "the string heuristic must be gone, got {:?}",
            out.errors
        );
        assert_eq!(
            out.summary.trim(),
            job_dir.parent().unwrap().to_string_lossy(),
            "the command must reach the shell verbatim and run in the job directory"
        );
    }

    /// C1, end to end and with a real bubblewrap: job B's sandbox must not be
    /// able to read or write job A's directory.
    ///
    /// This is the experiment the review ran, as a test. Job A's argv is built
    /// and **held alive** — which is what `run_in_sandbox` does across its
    /// `await` — and then job B runs in a *different* job directory. With
    /// `FD_CLOEXEC` cleared in the parent, B's `bwrap` inherits A's descriptor
    /// and B's command reaches A's directory through `/proc/self/fd`, past every
    /// mount in its own argv.
    ///
    /// The failure is asserted on the **host filesystem**, not only on the
    /// transcript: `WRITTEN-BY-B` appearing inside job A's directory is the
    /// breach, and it is the assertion that cannot be satisfied by a command
    /// that merely printed something odd.
    #[tokio::test]
    async fn a_second_job_cannot_read_or_write_the_first_jobs_directory() {
        let root = tempfile::tempdir().unwrap();
        let job_a = sandbox::resolve_job_dir(root.path(), "task-a", "job-a").unwrap();
        let job_b = sandbox::resolve_job_dir(root.path(), "task-b", "job-b").unwrap();
        assert_ne!(
            job_a.path(),
            job_b.path(),
            "the two jobs must be different directories, or the test proves nothing"
        );
        std::fs::write(job_a.path().join("SECRET-A"), "A").unwrap();

        // Gate: the property below is bubblewrap's behaviour, so it needs a
        // bubblewrap that really works. The host is asked **independently of the
        // code under test** — a hand-written argv, straight at `bwrap` — so a
        // resolver that refused on a host that can sandbox fails here instead of
        // skipping, which is what makes this a check on `M16` rather than a test
        // that passes under it. The skip branch is not a silent pass either: it
        // asserts the fail-closed outcome the resolver owes.
        //
        // `host_path` is held for the whole test, because everything below that
        // spawns `bwrap` — this gate, `Isolation::resolve` and `b.run` — lets it
        // resolve through `PATH`. Without it a stub test on another libtest
        // thread answers for this host, and the gate reports a host that cannot
        // sandbox on a machine that can: the test would then take the skip
        // branch and prove nothing. `RealPath` is required by
        // `bwrap_can_sandbox_here` precisely so that omission is a compile error.
        let host_path = sandbox::tests::real_path();
        let host_can = sandbox::tests::bwrap_can_sandbox_here(&host_path).await;
        let isolation =
            Isolation::resolve(&ShellSandboxConfig::default(), &Grants::default()).await;
        if !host_can {
            sandbox::tests::no_real_bwrap(
                "a_second_job_cannot_read_or_write_the_first_jobs_directory",
            );
            assert!(
                matches!(isolation, Isolation::Unavailable(_)),
                "with no boundary proven the only other outcome is a refusal, got {isolation:?}"
            );
            return;
        }
        assert_eq!(
            isolation,
            Isolation::Sandboxed,
            "this host builds a sandbox, so `resolve` refusing ({isolation:?}) is a bug in \
             the resolver and not a property of the host"
        );

        // Job A's argv, alive for the whole of job B's run.
        let held_a = sandbox::build_argv(&job_a, &Grants::default(), "true").unwrap();

        let b = ShellBackend::new(root.path().into()).with_isolation(Isolation::Sandboxed);
        let mut job = crate::supervisor::job::Job::new(
            "task-b",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "shell",
        );
        job.id = "job-b".into();
        job.prompt = Some(sandbox::tests::JOB_DIR_SCAN.into());
        let out = crate::supervisor::bounded(
            "the second sandboxed job",
            b.run(&mut job, &RunContext::new()),
        )
        .await
        .unwrap();

        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Succeeded),
            "job B must run, or this test proves nothing: {:?}",
            out.errors
        );
        assert!(
            !out.summary.contains("leaked="),
            "job B reached job A's directory through an inherited descriptor:\n{}",
            out.summary
        );
        assert_eq!(
            std::fs::read_to_string(job_a.path().join("SECRET-A")).unwrap(),
            "A",
            "job A's file was rewritten through a leaked descriptor"
        );
        assert!(
            !job_a.path().join("WRITTEN-BY-B").exists(),
            "job B's sandbox wrote into job A's directory: {} exists",
            job_a.path().join("WRITTEN-BY-B").display()
        );
        drop(held_a);
    }

    /// The sandboxed launch is a **real** sandbox, asserted against the host.
    ///
    /// Every assertion here is false under a launch that runs `sh -c` instead of
    /// `bwrap` — which is the mutant (`M15`) that this test exists to kill, and
    /// which the whole suite passed before it existed. `/etc/shadow` is the
    /// read that proves the mount set; `hostname` is the UTS namespace; `$HOME`
    /// and the write are the job's own directory.
    #[tokio::test]
    async fn the_sandboxed_launch_is_a_real_sandbox() {
        let root = tempfile::tempdir().unwrap();
        // Held for the whole test — see the C1 test above: this gate,
        // `Isolation::resolve` and `b.run` all let `bwrap` resolve through
        // `PATH`, and a stub test on another libtest thread would otherwise
        // answer for this host and turn a real machine into a skip.
        let host_path = sandbox::tests::real_path();
        let host_can = sandbox::tests::bwrap_can_sandbox_here(&host_path).await;
        let isolation =
            Isolation::resolve(&ShellSandboxConfig::default(), &Grants::default()).await;
        if !host_can {
            sandbox::tests::no_real_bwrap("the_sandboxed_launch_is_a_real_sandbox");
            assert!(
                matches!(isolation, Isolation::Unavailable(_)),
                "with no boundary proven the only other outcome is a refusal, got {isolation:?}"
            );
            return;
        }
        assert_eq!(
            isolation,
            Isolation::Sandboxed,
            "this host builds a sandbox, so `resolve` refusing ({isolation:?}) is a bug in \
             the resolver and not a property of the host"
        );
        let b = ShellBackend::new(root.path().into()).with_isolation(isolation);
        let mut job = crate::supervisor::job::Job::new(
            "task-1",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "shell",
        );
        job.id = "job-1".into();
        // One command, five properties, each tagged so a failure names itself.
        job.prompt = Some(
            "if [ -e /etc/shadow ]; then echo shadow=present; else echo shadow=absent; fi; \
             if [ -r /etc/passwd ]; then echo passwd=readable; else echo passwd=unreadable; fi; \
             echo hostname=$(hostname); \
             echo home=$HOME; \
             touch wrote-in-the-sandbox && echo write=ok || echo write=failed"
                .into(),
        );
        let out =
            crate::supervisor::bounded("the sandboxed launch", b.run(&mut job, &RunContext::new()))
                .await
                .unwrap();
        let job_dir = std::fs::canonicalize(root.path())
            .unwrap()
            .join(&job.task_id)
            .join(&job.id);

        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Succeeded),
            "the sandboxed launch must run the command, got {:?}",
            out.errors
        );
        assert!(
            out.summary.contains("shadow=absent"),
            "the command was not sandboxed — /etc/shadow is visible: {}",
            out.summary
        );
        assert!(
            out.summary.contains("hostname=haos-sandbox"),
            "the command did not run under the argv's UTS namespace, so it did not run \
             under bubblewrap: {}",
            out.summary
        );
        assert!(
            out.summary.contains(&format!("home={}", job_dir.display())),
            "HOME must be the job directory, which only the argv sets: {}",
            out.summary
        );
        assert!(
            out.summary.contains("write=ok"),
            "the job directory must be writable inside the sandbox: {}",
            out.summary
        );
        assert!(
            job_dir.join("wrote-in-the-sandbox").exists(),
            "the write must land in the job's own directory on the host"
        );
    }

    /// The output plumbing: status, stdout into `summary`, exit code into
    /// evidence.
    ///
    /// `Unconfined`, like every test in this module that actually runs a
    /// command: `ShellBackend::new` fails closed to `Unavailable`, so a backend
    /// built without an explicit decision refuses everything, and these tests
    /// are about the launch and capture path rather than about the boundary.
    ///
    /// The boundary has its own tests. The **sandboxed** launch used to be
    /// claimed to be covered by `sandbox`'s argv tests plus "the real-bwrap
    /// suite" — that was wrong twice over: the argv tests stop at the argv and
    /// never reach a spawn, so they cannot see which arm ran, and no real-bwrap
    /// suite existed in this commit (Task 9 owns it). It is covered here now, by
    /// `the_sandboxed_launch_is_a_real_sandbox` and
    /// `a_second_job_cannot_read_or_write_the_first_jobs_directory`.
    #[tokio::test]
    async fn shell_backend_runs_a_command_and_reports_its_output() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "echo hi",
        );
        job.prompt = Some("echo hi".into());
        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(matches!(
            out.status,
            crate::supervisor::job::JobStatus::Succeeded
        ));
        assert!(out.summary.contains("hi"));
        assert!(matches!(
            out.evidence[0],
            crate::supervisor::job::Evidence::ExitCode { code: 0 }
        ));
    }

    /// The lease-abort path drops the `execute_now` future, and that drop is
    /// what stops the run's subprocesses. A shell child that outlives the drop
    /// keeps mutating the sandbox while another owner runs the same task — the
    /// exact race the lease exists to prevent — so this pins `kill_on_drop`.
    ///
    /// The command proves it started (`started`) before the future is dropped,
    /// then writes `finished` a second later. Without `kill_on_drop` the shell
    /// survives the drop and writes `finished`; with it, the shell is killed
    /// while it sleeps.
    #[tokio::test]
    async fn a_dropped_run_does_not_leave_the_shell_child_running() {
        let dir = tempfile::tempdir().unwrap();
        let started = dir.path().join("started");
        let finished = dir.path().join("finished");
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "shell",
        );
        job.prompt = Some(format!(
            "touch '{}'; sleep 1; touch '{}'",
            started.display(),
            finished.display()
        ));

        let ctx = RunContext::new();
        let mut run = Box::pin(b.run(&mut job, &ctx));
        // Poll until the child has really spawned and run its first command, so
        // the drop below happens mid-run rather than before the spawn.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !started.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the shell child never started; the test cannot prove anything"
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), &mut run)
                    .await
                    .is_err(),
                "the command was supposed to outlive the poll window"
            );
        }
        // This is the abort: the run future is dropped, exactly as the lease
        // select drops it.
        drop(run);

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(
            !finished.exists(),
            "the dropped run left its shell child running: {} appeared",
            finished.display()
        );
    }

    /// A hung shell job must end on its own `timeout_secs`. Without a deadline
    /// the run never returns, and because the execution lease heartbeat keeps
    /// renewing, the task stays locked forever — across processes.
    #[tokio::test]
    async fn shell_backend_times_out_instead_of_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "sleep 5",
        );
        job.prompt = Some("sleep 5".into());
        job.timeout_secs = 1;

        let started = std::time::Instant::now();
        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        let elapsed = started.elapsed();

        assert!(
            matches!(out.status, crate::supervisor::job::JobStatus::Failed),
            "a timed-out shell job must report Failed, got {:?}",
            out.status
        );
        assert!(matches!(
            job.status,
            crate::supervisor::job::JobStatus::Failed
        ));
        assert!(
            out.errors.iter().any(|e| e.contains("timed out")),
            "the timeout must be named in the errors, got {:?}",
            out.errors
        );
        assert!(
            elapsed.as_secs() < 5,
            "the run must return at the deadline, not when `sleep 5` ends: took {elapsed:?}"
        );
    }

    /// Returning `Failed` is not enough: the timed-out child must actually die,
    /// or the sandbox keeps running a command nobody is waiting for.
    ///
    /// The command would write `finished` at t=3s if it survived, and the run
    /// returns at t≈1s (the deadline), so the wait below outlives t=3s with a
    /// margin. A surviving child has provably written the file by then: this
    /// assertion cannot pass merely because the clock ran out first.
    #[tokio::test]
    async fn a_timed_out_shell_child_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let finished = dir.path().join("finished");
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "shell",
        );
        job.prompt = Some(format!("sleep 3; touch '{}'", finished.display()));
        job.timeout_secs = 1;

        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(matches!(
            out.status,
            crate::supervisor::job::JobStatus::Failed
        ));

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert!(
            !finished.exists(),
            "the timed-out shell child survived the deadline: {} appeared",
            finished.display()
        );
    }

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
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "yes",
        );
        job.timeout_secs = 60; // far longer than the test may take
        let out = crate::supervisor::bounded("yes", b.run(&mut job, &RunContext::new()))
            .await
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
        assert!(
            bytes <= MAX_OUTPUT_BYTES + 4096,
            "cap not enforced: {bytes}"
        );
    }

    /// The same cap, on the **sandboxed** launch arm.
    ///
    /// `an_infinite_producer_is_stopped_by_the_byte_cap` runs `Unconfined`, and
    /// the plan gives up sandboxed-arm coverage here on purpose (review finding
    /// M9): a cap test that needed a real `bwrap` would be a test of the host.
    /// That leaves one thing unproven — "the capture block is shared" is a claim
    /// about the *code*, and a change that moved the cap into the `Unconfined`
    /// arm alone would leave the test above green while the sandboxed launch
    /// buffered `yes` without limit. This test dies on that mutant, and it is
    /// gated exactly like `the_sandboxed_launch_is_a_real_sandbox`: a host with
    /// no usable bubblewrap skips (visibly, via `no_real_bwrap`) instead of
    /// failing on a spawn error.
    #[tokio::test]
    async fn the_sandboxed_launch_is_stopped_by_the_same_byte_cap() {
        let root = tempfile::tempdir().unwrap();
        // Held for the whole test: the gate, `Isolation::resolve` and `b.run`
        // all let `bwrap` resolve through `PATH`, and a stub alive on another
        // libtest thread would answer for this host.
        let host_path = sandbox::tests::real_path();
        let host_can = sandbox::tests::bwrap_can_sandbox_here(&host_path).await;
        // Deliberately read for the **skip branch only**. The two older
        // real-bwrap tests also assert `Sandboxed` on the non-skip path, because
        // they take their mode from `resolve`; this one hard-codes
        // `Isolation::Sandboxed` below, so a `resolve` that disagreed would not
        // change which arm ran and asserting it here would add an unrelated
        // failure mode. What the fail-closed outcome owes is asserted, and
        // `the_sandboxed_launch_is_a_real_sandbox` is where a resolver that
        // refuses a host that can sandbox is caught.
        let isolation =
            Isolation::resolve(&ShellSandboxConfig::default(), &Grants::default()).await;
        if !host_can {
            sandbox::tests::no_real_bwrap("the_sandboxed_launch_is_stopped_by_the_same_byte_cap");
            assert!(
                matches!(isolation, Isolation::Unavailable(_)),
                "with no boundary proven the only other outcome is a refusal, got {isolation:?}"
            );
            return;
        }
        let b = ShellBackend::new(root.path().into()).with_isolation(Isolation::Sandboxed);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "yes",
        );
        job.timeout_secs = 60;

        let out = crate::supervisor::bounded(
            "yes under the sandbox",
            b.run(&mut job, &RunContext::new()),
        )
        .await
        .unwrap();

        assert!(
            out.errors.iter().any(|e| e.contains("byte cap")),
            "the byte cap must stop the sandboxed launch too, got {:?}",
            out.errors
        );
        let bytes: usize = out.summary.len() + out.errors.iter().map(|e| e.len()).sum::<usize>();
        assert!(
            bytes >= MAX_OUTPUT_BYTES,
            "the cap must have been reached before the kill, got {bytes}"
        );
        assert!(
            bytes <= MAX_OUTPUT_BYTES + 4096,
            "cap not enforced: {bytes}"
        );
    }

    /// The cap on **stderr**, which neither test above can see.
    ///
    /// Both of them produce on stdout, so a mutation that gave the stderr reader
    /// its own unbounded cap — `read_capped(stderr_pipe, usize::MAX)` — leaves
    /// them green while `sh -c 'yes 1>&2'` runs to EOF and the whole thing lands
    /// in `errors`, which is `JobOutput` and therefore the job row. Spec §5
    /// lists stderr as a bound this change *adds*, and names the reason: a
    /// runaway producer must not inflate the database.
    ///
    /// This is also the only test that drives the capture's `err` branch to the
    /// cap: stdout ends immediately here, so the loop is waiting on stderr alone
    /// when the cap fires.
    #[tokio::test]
    async fn the_stderr_cap_stops_an_infinite_stderr_producer() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into()).with_isolation(Isolation::Unconfined);
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "yes 1>&2",
        );
        job.timeout_secs = 60; // far longer than the test may take
        let out = crate::supervisor::bounded("yes 1>&2", b.run(&mut job, &RunContext::new()))
            .await
            .unwrap();
        // The error strings are printed by length, not by value: the failure
        // case here is a 256 KiB run of `y`, and dumping it into the test log
        // would hide the assertion it is meant to explain.
        let lengths: Vec<usize> = out.errors.iter().map(|e| e.len()).collect();
        assert!(
            out.errors.iter().any(|e| e.contains("byte cap")),
            "the byte cap must stop an unbounded stderr producer too, got errors of {lengths:?} bytes"
        );
        let bytes: usize = out.summary.len() + out.errors.iter().map(|e| e.len()).sum::<usize>();
        assert!(
            bytes >= MAX_OUTPUT_BYTES,
            "the cap must have been reached before the kill, got {bytes}"
        );
        assert!(
            bytes <= MAX_OUTPUT_BYTES + 4096,
            "the stderr cap is not enforced: {bytes} bytes"
        );
    }
}
