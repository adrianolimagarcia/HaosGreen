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

    /// The fail-closed default, from the outside: a `ShellBackend` built without
    /// an explicit decision must refuse to run — and must not name a cause it
    /// never established.
    ///
    /// This is the fourth direction `M14` is pinned from. The other three are in
    /// `sandbox`: the variant the default carries, the `needs_approval` predicate
    /// for every cause, and the message. A default that quietly became
    /// `Sandboxed` would run a job through a boundary that was never proven; one
    /// that became `Unconfined` would run it with no boundary at all. Both die
    /// here, on the `spawned` marker as well as on the status.
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
}
