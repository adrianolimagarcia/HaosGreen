use anyhow::Result;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

use crate::supervisor::backend::{Backend, BackendCapabilities, RunContext};
use crate::supervisor::job::{Evidence, Job, JobOutput, JobStatus, JobType};

pub struct ShellBackend {
    sandbox: PathBuf,
}

impl ShellBackend {
    pub fn new(sandbox: PathBuf) -> Self {
        Self { sandbox }
    }

    // TODO(security, M2.5): naive validation — only catches obvious `cd /…`,
    // `cd ..`, and `../` patterns. Determined callers can still escape via
    // `bash -c`, command substitution `$(...)`, or `pushd`. Replace with full
    // path canonicalization (see `validate_sandbox_path` in src/tools.rs) before
    // exposing ShellBackend through any user-facing entrypoint.
    fn validate(&self, cmd: &str) -> bool {
        let lower = cmd.trim_start();
        if lower.starts_with("cd /") || lower.contains("cd ..") {
            return false;
        }
        if lower.contains("../") {
            return false;
        }
        true
    }
}

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
        if !self.validate(&cmd) {
            job.status = JobStatus::Failed;
            return Ok(JobOutput {
                status: JobStatus::Failed,
                summary: String::new(),
                evidence: vec![],
                errors: vec!["sandbox-violation: cd outside sandbox".into()],
                changed_files: vec![],
                next_step: None,
            });
        }
        // `kill_on_drop` is what makes the lease abort real: dropping the
        // `execute_now` future (see `run_until_lease_loss`) drops this future,
        // and without it the `sh` child would keep running in the sandbox while
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
        let child = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .current_dir(&self.sandbox)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
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

    #[tokio::test]
    async fn shell_backend_runs_echo_in_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into());
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
        let b = ShellBackend::new(dir.path().into());
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
        let b = ShellBackend::new(dir.path().into());
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
        let b = ShellBackend::new(dir.path().into());
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
    async fn shell_backend_rejects_command_escaping_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let b = ShellBackend::new(dir.path().into());
        let mut job = crate::supervisor::job::Job::new(
            "t",
            crate::supervisor::job::JobType::ShellJob,
            "shell",
            "cd /etc && cat passwd",
        );
        job.prompt = Some("cd /etc && cat passwd".into());
        let out = b.run(&mut job, &RunContext::new()).await.unwrap();
        assert!(matches!(
            out.status,
            crate::supervisor::job::JobStatus::Failed
        ));
    }
}
