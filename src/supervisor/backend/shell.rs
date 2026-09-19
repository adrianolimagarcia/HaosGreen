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

// Containment used to live here, as `validate()`: a substring check for `cd /`,
// `cd ..` and `../`. It is **deleted**, not weakened — it was never containment
// (command substitution, `pushd` and any number of other forms walk past it)
// and the boundary is now the sandbox itself, built in
// `supervisor::backend::sandbox`: a hardened argv whose only writable host path
// is the job's own directory, bound by descriptor.

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
        // `kill_on_drop` is what makes the lease abort real: dropping the
        // `execute_now` future (see `run_until_lease_loss`) drops this future,
        // and without it the child would keep running in the sandbox while
        // another owner runs the same task. Mirrors `run_cli_process`.
        //
        // `spawn` + `wait_with_output` rather than `output()` is what makes the
        // `job.timeout_secs` deadline possible: `output()` offers no deadline of
        // its own, so a hung command never returns on its own and — with the
        // lease heartbeat renewing — its task stays locked forever, across
        // processes. Dropping the timed-out `wait_with_output` future drops the
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
                // `built` owns the descriptor the argv names, so the duplicate
                // is open when the child is spawned and closed when this arm
                // ends — after the spawn, never before it.
                let built = sandbox::build_argv(&job_dir, &held, &cmd)?;
                Command::new("bwrap")
                    .args(built.argv())
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()?
            }
        };
        let output =
            match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
                .await
            {
                Ok(res) => res?,
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
            };
        let exit = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let status = if output.status.success() {
            JobStatus::Succeeded
        } else {
            JobStatus::Failed
        };
        job.status = status.clone();
        Ok(JobOutput {
            status,
            summary: stdout.trim().to_string(),
            evidence: vec![Evidence::ExitCode { code: exit }],
            errors: if stderr.is_empty() {
                vec![]
            } else {
                vec![stderr]
            },
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

    /// The output plumbing: status, stdout into `summary`, exit code into
    /// evidence.
    ///
    /// `Unconfined`, like every test in this module that actually runs a
    /// command: `ShellBackend::new` fails closed to `Unavailable`, so a backend
    /// built without an explicit decision refuses everything, and these tests
    /// are about the launch and capture path rather than about the boundary.
    /// The boundary has its own tests, and the sandboxed launch is covered by
    /// `sandbox`'s argv tests plus the real-bwrap suite.
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
}
