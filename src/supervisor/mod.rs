//! Generic autonomous task supervisor.
//! See `docs/plans/2026-04-30-autopilot-supervisor-design.md`.

pub mod artifact;
pub mod backend;
pub mod classifier;
pub mod intake;
pub mod job;
pub mod orchestrator;
pub mod planner;
pub mod policy;
pub mod redact;
pub mod reporter;
pub mod state;
pub mod store;
pub mod task;
pub mod verification;
pub mod workflow;
pub mod workspace;

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

use crate::supervisor::artifact::ArtifactManager;
use crate::supervisor::backend::sandbox::{Grants, Isolation};
use crate::supervisor::backend::{reasoning::ReasoningBackend, Registry};
use crate::supervisor::classifier::{Classifier, HeuristicClassifier};
use crate::supervisor::intake::IntakeRouter;
use crate::supervisor::orchestrator::Orchestrator;
use crate::supervisor::planner::Planner;
use crate::supervisor::policy::{PolicyDecision, PolicyEngine};
use crate::supervisor::reporter::Reporter;
use crate::supervisor::store::TaskStore;
use crate::supervisor::task::TaskStatus;
use crate::supervisor::verification::{VerificationEngine, VerificationOutcome};

/// Longest free-text task input the supervisor accepts from a chat command, in
/// **characters** (not bytes).
///
/// One bound, read by [`Supervisor::clarify`] and by the Telegram dispatcher's
/// `/supervise` and `/clarify` argument validation, so the two ends of the
/// command surface cannot disagree about what "too long" means. It bounds the
/// text before it reaches the classifier, the artifact store and the audit row;
/// it is deliberately generous — a task description, not a document.
pub const MAX_TASK_TEXT_CHARS: usize = 2000;

/// A supervisor refusal, as opposed to an internal fault.
///
/// # Why this is a type and not a message
///
/// The dashboard answers a refused lifecycle action with **409** and a genuine
/// failure with **500**. It used to tell them apart by matching substrings of
/// the error text (`"cannot pause a task in state"`, `"illegal state
/// transition"`, …), which is a trap: rewording a `bail!` anywhere in this
/// module silently reclassified every raced refusal as an internal error, with
/// nothing but a string-matching test to notice. Callers now classify with
/// [`anyhow::Error::downcast_ref`], so the compiler holds the two ends
/// together.
///
/// The route still reads the task's state *before* calling the supervisor and
/// answers 409 from that — this type only has to cover the window between that
/// read and the call, where a concurrent request can move the task.
#[derive(Debug)]
pub enum SupervisorError {
    /// No `sup_tasks` row with this id.
    NotFound { task_id: String },
    /// The task's persisted state does not allow the requested transition.
    ///
    /// `from` is the state the store actually holds (for a refusal raised by
    /// [`TaskStore::record_transition`]'s compare-and-swap) or the state the
    /// caller read before the race; `to` is the state it tried to reach.
    StateRefusal { from: TaskStatus, to: TaskStatus },
    /// An `execute_now` for this task is already running in this process.
    AlreadyRunning { task_id: String },
    /// This run's execution lease is gone: another owner took the task over, or
    /// the lease could not be renewed at all.
    ///
    /// The two causes are deliberately **not** distinguished by this type (only
    /// by the `LeaseLossReason` log line in the heartbeat), so nothing that
    /// renders this error may assert a takeover: `Display` says the lease "is
    /// no longer held by this run", which is true of both a takeover and a
    /// `LeaseLossReason::StoreUnavailable` outage.
    ///
    /// # What the abort does and does not guarantee
    ///
    /// The lease is a **TTL lease**, not a lock with a waiter list, so a
    /// takeover is only *detected* — never prevented — at the next heartbeat
    /// tick. Concretely, once another owner has taken the task over, this run
    /// keeps working until its heartbeat notices:
    ///
    /// * up to one `LEASE_HEARTBEAT_INTERVAL` (60 s) before the next renewal
    ///   attempt, plus
    /// * the bounded renew retries, whose worst case is ~20.7 s when SQLite's
    ///   busy handler blocks every attempt (see `LEASE_RENEW_BACKOFFS`),
    ///
    /// so **up to roughly 60–80 s of overlap** with the new owner is possible,
    /// and the abort is best-effort: it drops the pipeline and kills the
    /// backends' subprocesses, but nothing is rolled back. A job row, an
    /// artifact, a state transition or a shell command's effect on the
    /// workspace that was already committed before the abort **stays
    /// committed**.
    ///
    /// What the lease does guarantee is narrower and still worth having: only
    /// one owner at a time holds the row, and the displaced run stops as soon
    /// as it notices. It is not a distributed transaction.
    LeaseLost { task_id: String },
}

impl SupervisorError {
    /// No such task, as an `anyhow::Error` a caller can `downcast_ref`.
    pub fn not_found(task_id: &str) -> anyhow::Error {
        anyhow::Error::new(Self::NotFound {
            task_id: task_id.to_string(),
        })
    }

    /// A transition the task's state does not allow.
    pub fn state_refusal(from: TaskStatus, to: TaskStatus) -> anyhow::Error {
        anyhow::Error::new(Self::StateRefusal { from, to })
    }

    /// A second `execute_now` for a task that is already running.
    pub fn already_running(task_id: &str) -> anyhow::Error {
        anyhow::Error::new(Self::AlreadyRunning {
            task_id: task_id.to_string(),
        })
    }

    /// This run lost the execution lease while the pipeline was running.
    pub fn lease_lost(task_id: &str) -> anyhow::Error {
        anyhow::Error::new(Self::LeaseLost {
            task_id: task_id.to_string(),
        })
    }
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { task_id } => write!(f, "task not found: {task_id}"),
            Self::StateRefusal { from, to } => {
                write!(f, "illegal state transition {from:?} -> {to:?}")
            }
            Self::AlreadyRunning { task_id } => write!(
                f,
                "task {task_id} is already running; refusing to start a second run"
            ),
            Self::LeaseLost { task_id } => write!(
                f,
                "the execution lease for task {task_id} is no longer held by this run; \
                 the run was aborted"
            ),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// Task ids with an `execute_now` currently in flight **in this process**.
///
/// A `std::sync::Mutex` rather than a `tokio` one, and the difference is not
/// stylistic: the critical section contains no `await`, and the id has to be
/// released from [`InFlightGuard::drop`], which cannot await — a
/// `tokio::sync::Mutex` guard could not be released there. That `Drop` is what
/// makes a cancelled request (a dropped `execute_now` future) release its task
/// instead of wedging it forever.
#[derive(Default)]
struct InFlight {
    ids: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl InFlight {
    /// Claim `task_id`, or return `None` if a run already holds it.
    fn enter(self: &Arc<Self>, task_id: &str) -> Option<InFlightGuard> {
        let mut ids = self.ids.lock().unwrap_or_else(|e| e.into_inner());
        if !ids.insert(task_id.to_string()) {
            return None;
        }
        Some(InFlightGuard {
            owner: Arc::clone(self),
            task_id: task_id.to_string(),
        })
    }
}

/// Releases the claimed task id when the run ends — normally, on an error, or
/// when the `execute_now` future is dropped mid-flight.
struct InFlightGuard {
    owner: Arc<InFlight>,
    task_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.owner
            .ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.task_id);
    }
}

/// How often the heartbeat renews the execution lease.
const LEASE_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Execution-lease TTL in seconds: five heartbeat intervals, so a missed
/// renewal — or a bounded burst of retries — still leaves the lease live.
///
/// The TTL is measured against **wall clock**, not a monotonic clock:
/// [`TaskStore::acquire_lease`] and [`TaskStore::renew_lease`] compare
/// `expires_at` with `chrono::Utc::now().timestamp()`, and the row has to mean
/// the same thing to another process, so there is no monotonic clock to share.
/// Consequences of a clock step:
///
/// * **forward** (an NTP correction, resuming from suspend) makes the lease
///   look expired before this run has really spent `LEASE_TTL_SECS` working, so
///   another owner can take the task over while this run is still going. This
///   run notices at its next heartbeat tick and aborts — see
///   [`SupervisorError::LeaseLost`] for how long that overlap can last.
/// * **backward** keeps the row alive past the TTL, so a task abandoned by a
///   crashed process can stay refused for longer than `LEASE_TTL_SECS`.
///
/// Neither can make two owners hold the row at once: the row is one SQLite
/// value and every takeover is a conditional `UPDATE` on it.
///
/// A third way the lease can lapse, and the one nothing here can detect: the
/// heartbeat is an ordinary tokio task, so **starvation** — a blocking call
/// that stalls every runtime worker it is scheduled on (a synchronous SQLite
/// call, a long CPU-bound stretch in a backend) — stops the renewals too. The
/// row then expires with no signal at all, and this run neither aborts nor
/// notices unless a worker frees up and the heartbeat ticks again.
const LEASE_TTL_SECS: i64 = 300;

/// Backoff between renew attempts after a transient store error: one initial
/// attempt plus three retries, so a brief SQLite write-lock is not read as a
/// lost lease.
///
/// The sleeps total 700 ms, but that is **not** the worst case: each of the
/// four attempts can block for up to ~5 s inside SQLite's busy handler
/// (rusqlite installs a 5 s `busy_timeout` on every connection it opens — see
/// [`crate::memory::MemoryStore::open`]), so a fully saturated write lock costs
/// ~**20.7 s** before loss is declared. That is still more than an order of
/// magnitude below the 300 s TTL, so retrying cannot itself cost the lease.
const LEASE_RENEW_BACKOFFS: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(200),
    std::time::Duration::from_millis(400),
];

/// Why the heartbeat stopped renewing the lease.
///
/// Kept apart so the log line says which of the two happened: the store
/// answering `false` (another owner) is a normal takeover, while a store that
/// could not be asked at all is an operational fault. The distinction is *not*
/// carried in the error type — both abort the run as
/// [`SupervisorError::LeaseLost`], because from this run's point of view the
/// lease is equally unproven either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseLossReason {
    /// The store answered `false`: the row is gone or belongs to another owner.
    TakenOver,
    /// The store could not be reached again after every retry, so the lease's
    /// state is unknown and must be assumed lost.
    StoreUnavailable,
}

impl LeaseLossReason {
    /// A short, log-safe description. Deliberately mentions neither the owner
    /// id nor the underlying store error.
    fn as_str(self) -> &'static str {
        match self {
            Self::TakenOver => "another owner holds the lease",
            Self::StoreUnavailable => "the lease store could not be reached after every retry",
        }
    }
}

/// Resolve when the lease is lost: either the heartbeat signalled it, or the
/// heartbeat is gone and can no longer prove the lease is ours.
async fn wait_for_lease_loss(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Whether loss has been signalled, reading the value **and** the channel's
/// state: a heartbeat that is gone — returned, aborted or panicked — can no
/// longer prove the lease is ours, so its disappearance is itself a loss.
///
/// Reading the channel state is the whole point. The heartbeat owns the only
/// [`watch::Sender`]; if anything else held one, a panicked heartbeat would
/// leave the channel open and this would answer `false` forever.
fn loss_signalled(rx: &watch::Receiver<bool>) -> bool {
    *rx.borrow() || rx.has_changed().is_err()
}

/// Renew the lease once, retrying a transient store error with bounded backoff.
///
/// `Ok(())` means the lease is renewed. A `false` from the store is an *answer*
/// — another owner holds the lease — and becomes
/// [`LeaseLossReason::TakenOver`] without retrying; only a *persistent* `Err`,
/// where the store could not be asked again after every backoff, becomes
/// [`LeaseLossReason::StoreUnavailable`]. The distinction survives into the log
/// line, so an operator can tell a normal takeover from a store outage.
async fn renew_with_retry<R, F>(mut renew: R) -> std::result::Result<(), LeaseLossReason>
where
    R: FnMut() -> F,
    F: std::future::Future<Output = anyhow::Result<bool>>,
{
    let mut backoffs = LEASE_RENEW_BACKOFFS.iter();
    loop {
        match renew().await {
            Ok(true) => return Ok(()),
            Ok(false) => return Err(LeaseLossReason::TakenOver),
            Err(_) => match backoffs.next() {
                Some(backoff) => tokio::time::sleep(*backoff).await,
                None => return Err(LeaseLossReason::StoreUnavailable),
            },
        }
    }
}

/// Renew the lease until it is lost, then signal the loss on `tx`.
///
/// This loop never exits silently. It either signals loss or is aborted by
/// [`LeaseGuard::release`]; a loop that gave up without signalling would leave
/// `execute_now` running a plan for a task another owner now holds. Returning
/// also drops `tx`, the **only** sender, which [`loss_signalled`] reads as a
/// loss — so even a panic in here is not silent.
///
/// Only the task id is logged: never the owner id, which is a capability for
/// this task's lease.
async fn heartbeat_loop<R, F>(
    task_id: &str,
    mut renew: R,
    interval: std::time::Duration,
    tx: watch::Sender<bool>,
) where
    R: FnMut() -> F,
    F: std::future::Future<Output = anyhow::Result<bool>>,
{
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // the first tick completes immediately
    loop {
        tick.tick().await;
        if let Err(reason) = renew_with_retry(&mut renew).await {
            tracing::warn!(
                task_id,
                reason = reason.as_str(),
                "execution lease lost; signalling the run to abort"
            );
            let _ = tx.send(true);
            return;
        }
    }
}

/// Run `pipeline` to completion, or abandon it the moment the lease is lost.
///
/// Taking the pipeline **by value** is the point: the select stops polling it
/// and the future is then dropped, which is the abort. The process-spawning
/// backends hold their in-flight subprocess with `kill_on_drop(true)` (see
/// [`crate::supervisor::backend::run_cli_process`] and
/// [`crate::supervisor::backend::shell::ShellBackend`]), so dropping the
/// pipeline kills those children.
///
/// That reach is narrower than "the run stops", and the difference matters:
/// `kill_on_drop` sends `SIGKILL` to the **direct** child only, so a backgrounded
/// grandchild of a compound `sh -c` command can survive as an orphan, and
/// [`crate::supervisor::backend::mcp::McpBackend`] has neither a timeout nor
/// cancellation — an in-flight MCP tool call is **abandoned**, not stopped,
/// and may still complete on the server after this run has been aborted. The
/// reasoning backends are bounded by the pipeline future itself.
///
/// This is a **best-effort, bounded** abort, not an instant one, and it rolls
/// nothing back: see [`SupervisorError::LeaseLost`] for the overlap window and
/// for what a lost lease does *not* undo.
///
/// The caller must not write any further state on the lease-lost path — another
/// owner may hold the task by then.
async fn run_until_lease_loss<T>(
    pipeline: impl std::future::Future<Output = anyhow::Result<T>>,
    lost: &mut watch::Receiver<bool>,
    task_id: &str,
) -> anyhow::Result<T> {
    tokio::pin!(pipeline);
    tokio::select! {
        biased;
        _ = wait_for_lease_loss(lost) => {
            tracing::warn!(
                task_id,
                "aborting the run: the execution lease is no longer ours"
            );
            Err(SupervisorError::lease_lost(task_id))
        }
        res = &mut pipeline => res,
    }
}

/// The execution lease for one `execute_now`, held for the whole run.
///
/// [`Self::release`] is the release path and `execute_now` awaits it on every
/// path; `Drop` is the fallback, and it covers two different situations — see
/// [`Self::release_attempted`].
struct LeaseGuard {
    store: TaskStore,
    task_id: String,
    owner_id: String,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    /// [`Self::release`] reached a decision: the lease was removed, or was
    /// already gone. `Drop` then has nothing left to do.
    released: bool,
    /// [`Self::release`] ran at all. `released == false` has two causes — the
    /// `execute_now` future was dropped mid-run (cancelled), or `release` ran
    /// and its store call failed — and `Drop` has to tell them apart to log
    /// honestly: it is only a *cancelled* run that gets the cancelled-run
    /// wording. Both cases still get the best-effort second release below.
    release_attempted: bool,
    /// The **receiving** half of the heartbeat's channel.
    ///
    /// The guard deliberately holds no [`watch::Sender`]: the heartbeat task
    /// owns the only one, so a heartbeat that returns, is aborted or panics
    /// closes the channel, and [`loss_signalled`] reads that as a lost lease. A
    /// second sender here would keep the channel open and turn a panicked
    /// heartbeat into a run that continues unrenewed until the lease silently
    /// expires — the hole this shape closes.
    lost: watch::Receiver<bool>,
}

impl LeaseGuard {
    /// Stop the heartbeat, then remove the lease, and report whether this run
    /// still owned it.
    ///
    /// The loss state is read **before** the heartbeat is aborted, and the
    /// order matters: aborting drops the heartbeat's sender, which closes the
    /// channel, and a closed channel is indistinguishable from a signalled
    /// loss. Reading afterwards would report every release as a loss.
    ///
    /// The heartbeat is aborted and awaited *first*: a renewal in flight could
    /// otherwise write after the release, and a renewal that answers `false`
    /// after this run decided it had succeeded would be lost.
    async fn release(mut self) -> anyhow::Result<()> {
        self.release_attempted = true;
        let was_lost = loss_signalled(&self.lost);
        if let Some(handle) = self.heartbeat.take() {
            handle.abort();
            if let Err(error) = handle.await {
                // A cancelled join is this `abort()` doing its job. Anything
                // else is the heartbeat dying on its own — a panic — which the
                // run has to know about rather than swallow with `let _ =`.
                if !error.is_cancelled() {
                    let panic = error.into_panic();
                    let message = panic
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                        .unwrap_or("non-string panic payload");
                    tracing::warn!(
                        task_id = %self.task_id,
                        panic = message,
                        "execution-lease heartbeat task died; its lease state is unknown"
                    );
                }
            }
        }
        match self
            .store
            .release_lease(&self.task_id, &self.owner_id)
            .await
        {
            Ok(removed) => {
                self.released = true;
                if removed || was_lost {
                    // `Ok(false)` after a signalled loss is the takeover this
                    // run already reported as `SupervisorError::LeaseLost`;
                    // a second error here would only bury that one.
                    tracing::debug!(
                        task_id = %self.task_id,
                        removed,
                        lost = was_lost,
                        "execution lease released"
                    );
                    Ok(())
                } else {
                    // Nothing was signalled, yet the lease was not ours to
                    // remove: another owner took it over while we ran. This is
                    // typed so the dashboard answers 409 rather than 500.
                    tracing::warn!(
                        task_id = %self.task_id,
                        "execution lease was already gone at release; another owner holds the task"
                    );
                    Err(SupervisorError::lease_lost(&self.task_id))
                }
            }
            Err(error) => {
                tracing::warn!(
                    task_id = %self.task_id,
                    "failed to release the execution lease: {error}"
                );
                Err(error)
            }
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat.take() {
            handle.abort();
        }
        if self.released {
            return;
        }
        // Two ways to arrive here, and the log line has to say which:
        //
        // * `release_attempted == false` — the `execute_now` future was dropped
        //   mid-run (a cancelled request), so cleanup cannot be awaited;
        // * `release_attempted == true` — `release` ran and its store call
        //   failed, leaving `released` false.
        //
        // The second attempt below is **intentional** in both cases, not an
        // oversight: a transient store error on the first release must not
        // leave the row behind, because a stale row refuses the task until its
        // TTL elapses. It is safe to retry precisely because the release is
        // owner-checked *and* the owner id is minted per run (see
        // [`new_lease_owner_id`]) — a late detached release can only ever match
        // the run it came from, never a later run's live lease.
        //
        // Best effort: one detached release, and nothing at all when there is
        // no runtime to run it on — `Handle::try_current` rather than
        // `Handle::current`, which would panic in `Drop`.
        let cancelled = !self.release_attempted;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = self.store.clone();
        let task = self.task_id.clone();
        let owner = self.owner_id.clone();
        handle.spawn(async move {
            let run = if cancelled { "cancelled" } else { "finished" };
            match store.release_lease(&task, &owner).await {
                Ok(true) => tracing::debug!(
                    task_id = %task,
                    run,
                    "execution lease released on the fallback path"
                ),
                Ok(false) => tracing::warn!(
                    task_id = %task,
                    run,
                    "the execution lease was already gone at the fallback release"
                ),
                Err(error) => tracing::warn!(
                    task_id = %task,
                    run,
                    "failed to release the execution lease on the fallback path: {error}"
                ),
            }
        });
    }
}

/// A fresh execution-lease owner id, for one `execute_now` run.
///
/// Minted per **run**, not per [`Supervisor`]. The lease operations are
/// owner-checked and nothing else: if two runs of the same task in one process
/// shared an owner id, a detached release left behind by a cancelled run could
/// delete a *later* run's live lease for the same task — the later run would
/// keep working while another process was free to take the task over. A
/// per-run id makes that impossible: the stale release can only ever match the
/// run it belongs to, which is by then gone.
///
/// The `pid-` prefix is for an operator reading the row by hand; the uuid is
/// what makes it unique. Never logged — it is a capability for that task's
/// lease.
fn new_lease_owner_id() -> String {
    format!("pid-{}-{}", std::process::id(), uuid::Uuid::new_v4())
}

#[derive(Debug)]
pub enum SubmitOutcome {
    AutoExecutePlanned { task_id: String },
    NeedsClarification { task_id: String, question: String },
    NeedsApproval { task_id: String, reason: String },
}

impl SubmitOutcome {
    pub fn task_id(&self) -> String {
        match self {
            Self::AutoExecutePlanned { task_id }
            | Self::NeedsClarification { task_id, .. }
            | Self::NeedsApproval { task_id, .. } => task_id.clone(),
        }
    }
}

pub struct Supervisor {
    store: TaskStore,
    artifacts: Arc<ArtifactManager>,
    classifier: Box<dyn Classifier + Send + Sync>,
    policy: PolicyEngine,
    /// One `execute_now` per task id at a time; see [`InFlight`].
    in_flight: Arc<InFlight>,
    pub registry: Registry,
    pub workspace_mgr: Option<Arc<crate::supervisor::workspace::WorkspaceManager>>,
    /// The isolation decision `ShellBackend` was given, so Layer 1 and Layer 2
    /// cannot disagree about whether the boundary exists.
    ///
    /// `Unavailable` means the sandbox is absent, so a task that would select
    /// the shell backend is parked for approval instead of auto-executing.
    /// `Unconfined` is the operator's standing consent, so nothing is gated
    /// (spec §4). A second read of `[supervisor.shell].sandbox` here would be a
    /// second place the mode is decided, and two reads can drift.
    ///
    /// Fail-closed default: a `Supervisor` built without an explicit value must
    /// park shell tasks, never run them, or the constructor becomes a way to
    /// bypass the gate.
    shell_isolation: Isolation,
    /// The operator's live grant set, shared with `ShellBackend` — **the same
    /// `Arc`**, so a grant the operator issues is visible to both layers at
    /// once. A second `RwLock<Grants>` here would mean Layer 1 parks a task for
    /// a grant Layer 2 already holds, or worse, the reverse.
    grants: Arc<std::sync::RwLock<Grants>>,
    /// The sandbox root, if the supervisor was told it.
    ///
    /// `Option` rather than a `PathBuf` defaulted to something plausible: the
    /// root is what tells a grant of `/etc` apart from a grant that hands back
    /// the sandbox itself, and **a guessed root is a guessed containment check**.
    /// `None` makes the grant commands refuse instead.
    sandbox_root: Option<PathBuf>,
}

impl Supervisor {
    pub fn new_for_test(
        artifacts_root: PathBuf,
        conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        Self {
            store: TaskStore::new(conn.clone()),
            artifacts: Arc::new(ArtifactManager::new(artifacts_root, conn)),
            classifier: Box::new(HeuristicClassifier),
            policy: PolicyEngine::default(),
            in_flight: Arc::new(InFlight::default()),
            registry: Registry::new(),
            workspace_mgr: None,
            shell_isolation: Isolation::default(),
            grants: Arc::new(std::sync::RwLock::new(Grants::default())),
            sandbox_root: None,
        }
    }

    pub fn new_for_test_with_repo(
        artifacts_root: PathBuf,
        repo_path: PathBuf,
        conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        let mut sup = Self::new_for_test(artifacts_root, conn);
        sup.workspace_mgr = Some(Arc::new(
            crate::supervisor::workspace::WorkspaceManager::new(repo_path, false),
        ));
        sup
    }

    /// Production constructor. Registry should be pre-populated with backends.
    pub fn new(
        artifacts_root: PathBuf,
        conn: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
        registry: Registry,
        thresholds: crate::config::RiskThresholdsConfig,
    ) -> Self {
        Self {
            store: TaskStore::new(conn.clone()),
            artifacts: Arc::new(ArtifactManager::new(artifacts_root, conn)),
            classifier: Box::new(HeuristicClassifier),
            policy: PolicyEngine::with_thresholds(thresholds),
            in_flight: Arc::new(InFlight::default()),
            registry,
            workspace_mgr: None,
            shell_isolation: Isolation::default(),
            grants: Arc::new(std::sync::RwLock::new(Grants::default())),
            sandbox_root: None,
        }
    }

    /// Attach the isolation decision resolved at startup — the same value the
    /// shell backend holds, so the two layers cannot disagree.
    pub fn with_shell_isolation(mut self, r: Isolation) -> Self {
        self.shell_isolation = r;
        self
    }

    /// Attach the operator's grant set — the same `Arc` the shell backend holds.
    pub fn with_grants(mut self, grants: Arc<std::sync::RwLock<Grants>>) -> Self {
        self.grants = grants;
        self
    }

    /// Tell the supervisor where the sandbox root is, so a grant that would
    /// cover it (or an ancestor of it) can be refused. See `sandbox_root`.
    pub fn with_sandbox_root(mut self, root: PathBuf) -> Self {
        self.sandbox_root = Some(root);
        self
    }

    /// The live grant set, so a caller can hold the same handle the operator
    /// commands write through.
    pub fn grants_handle(&self) -> Arc<std::sync::RwLock<Grants>> {
        self.grants.clone()
    }

    /// Grant read-write access to one host path, for every future job until it
    /// is revoked. Refuses when the sandbox root is unknown, because the
    /// ancestor check is what stops a grant from handing back the sandbox.
    pub fn allow_path(&self, raw: &str) -> anyhow::Result<PathBuf> {
        let root = self.sandbox_root.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "the supervisor was not told its sandbox root, so it cannot tell a grant from \
                 one that hands back the sandbox itself; refusing rather than guessing"
            )
        })?;
        self.grants.write().unwrap().grant_write(raw, root)
    }

    /// Revoke a write grant. Lenient about a path that no longer exists, so a
    /// grant cannot outlive the operator's ability to take it back.
    pub fn deny_path(&self, raw: &str) -> anyhow::Result<PathBuf> {
        self.grants.write().unwrap().revoke_write(raw)
    }

    pub fn allow_network(&self) -> String {
        self.grants.write().unwrap().grant_network();
        self.grants.read().unwrap().describe()
    }

    pub fn deny_network(&self) -> String {
        self.grants.write().unwrap().revoke_network();
        self.grants.read().unwrap().describe()
    }

    /// What the operator currently holds, for `/grants` and the dashboard.
    pub fn granted(&self) -> String {
        self.grants.read().unwrap().describe()
    }

    /// Would this task select the shell backend?
    ///
    /// Derived from the registry rather than from a hand-written predicate, so
    /// it cannot drift from what the executor would actually select. An empty
    /// registry answers `false` for everything, which is why a test of this gate
    /// has to register the shell backend: with nothing registered the gate never
    /// fires and the test would pass for the wrong reason.
    /// The Layer-1 park reason for a task, or `None` if it is not gated.
    ///
    /// Extracted from `submit` so the gate is reachable from a test holding a
    /// task that **declares a capability**. `submit` cannot produce one in this
    /// revision — nothing populates `Task::declared_grants` from operator input
    /// yet — so a gate driven only through `submit` can never be shown to fire
    /// on the grant term, and a test that cannot make the gate fire cannot tell
    /// a working exemption from a gate that never runs.
    pub fn shell_gate_reason(&self, task: &crate::supervisor::task::Task) -> Option<String> {
        if !self.would_use_shell(task) {
            return None;
        }
        // **The whole gate is skipped under `Unconfined`, and that is spec §4,
        // not an optimisation.** "With `sandbox = \"none\"` nothing is gated:
        // that mode *is* the operator's consent, and Layer 1 does not apply."
        // The exemption is therefore the *outer* decision, not the isolation
        // term alone. Both terms exist to stop a job reaching a boundary wider
        // than the operator sanctioned: `Unavailable` because there is no
        // boundary to reach at all, and a missing grant because the sandboxed
        // launch would bind more than was granted. Under `Unconfined` there is
        // no argv and no bind: Layer 2 runs `sh -c` in the job directory and
        // reads neither `Grants` nor `declared_grants`. Parking on the grant
        // term there would cost one approval round-trip and change nothing
        // about what runs.
        //
        // A `match` rather than `needs_approval() || !missing.is_empty()`:
        // `needs_approval()` is a pure function of the isolation decision and
        // has no grant set to look at, so it cannot express the second term.
        // Keeping both terms in one `match` on the mode makes the exemption
        // structural — there is exactly one place `Unconfined` is answered, and
        // it answers before either term is evaluated.
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
                        &task.user_request,
                    ))
                }
            }
        }
    }

    fn would_use_shell(&self, task: &crate::supervisor::task::Task) -> bool {
        self.registry
            .select_for(&task.required_capabilities)
            .is_some_and(|b| b.name() == "shell")
    }

    pub fn register_test_reasoning_backend<F, Fut>(&mut self, f: F)
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        self.registry
            .register(Arc::new(ReasoningBackend::new_with_executor(f)));
    }

    /// Plan, execute, verify and report a task, synchronously, on this future.
    ///
    /// # Precondition
    ///
    /// The task must be in a state the machine allows to reach `Plan` — this
    /// method's first transition is `task.status -> Plan`. `Intake` and
    /// `Classify` are **not** among them (`Intake -> Plan` is not an edge), and
    /// neither is `PrepareWorkspace`; a task in one of those states is refused
    /// with [`SupervisorError::StateRefusal`]. That refusal is raised inside the
    /// pipeline, so by the time it is returned the execution lease below has
    /// already been taken and given back; what it still guarantees is that no
    /// plan, job, artifact or audit row is written. An earlier version had no
    /// such guard, so `execute_now` on an `Intake` task panicked through
    /// `record_transition`'s `debug_assert!` in debug builds and wrote an
    /// illegal `state` in release. The four dashboard routes cannot reach it
    /// (they pre-check), but this is a public method and an unstated
    /// precondition is a bug waiting for its second caller.
    ///
    /// # One run per task at a time — in this process and across processes
    ///
    /// Two guards, in this order, and both refuse with
    /// [`SupervisorError::AlreadyRunning`]:
    ///
    /// 1. a process-local in-flight set ([`InFlight`]), which catches a second
    ///    `execute_now` for the same task on this `Supervisor`;
    /// 2. a **persistent execution lease** — one row in `sup_execution_leases`,
    ///    claimed through [`TaskStore::acquire_lease`] with a
    ///    [`LEASE_TTL_SECS`] TTL and renewed by a background heartbeat every
    ///    [`LEASE_HEARTBEAT_INTERVAL`] until the run ends. The row lives in the
    ///    shared database, so this is what makes "one run per task" hold across
    ///    **processes** (a second bot, a second dashboard, a CLI run against the
    ///    same `haos-green.db`), not just across calls in this one. A refused
    ///    claim is logged at `warn!`.
    ///
    /// The compare-and-swap in [`TaskStore::record_transition`] is not enough
    /// on its own: two calls on a task that is already in `Execute` both ask
    /// for `Execute -> Plan`, which *is* a legal edge, so both would be
    /// accepted and both would run the plan — duplicate jobs, duplicate
    /// artifact writes and a duplicated audit trail.
    ///
    /// Because the lease is persistent, `AlreadyRunning` has a third meaning
    /// beyond "a run is live in this process" and "another process is running
    /// it": a **stale row left by a crashed process** refuses the task until
    /// its TTL elapses, i.e. for up to [`LEASE_TTL_SECS`] (300 s) after the
    /// crash. There is no liveness probe, no resumption and no operator
    /// override — waiting out the TTL is the recovery path.
    ///
    /// # Lease loss
    ///
    /// The lease is a TTL lease, so it can be taken over underneath this run.
    /// When the heartbeat notices — the row is gone, or the store cannot be
    /// reached even after its retries — the run is aborted with
    /// [`SupervisorError::LeaseLost`] and the in-flight pipeline is dropped.
    /// That kills the direct subprocess of each process-spawning backend
    /// (`kill_on_drop`), but it is not a general stop: see
    /// [`run_until_lease_loss`] for what survives it. Read
    /// [`SupervisorError::LeaseLost`] before treating that as a clean stop: the
    /// abort is detected at the next heartbeat tick, so a bounded overlap with
    /// the new owner is possible and committed side effects are not rolled
    /// back.
    ///
    /// The lease row is released on every path: normally, on error, and — best
    /// effort, through [`LeaseGuard`]'s `Drop` — when this future is dropped
    /// mid-run by a cancelled request.
    pub async fn execute_now(&self, task_id: &str) -> anyhow::Result<String> {
        // Held for the whole run and released on drop, including when this
        // future is cancelled.
        let _in_flight = self
            .in_flight
            .enter(task_id)
            .ok_or_else(|| SupervisorError::already_running(task_id))?;
        // One owner id for this run only — its acquire, its heartbeat's
        // renewals and its release all use this value. See
        // [`new_lease_owner_id`].
        let lease_owner = new_lease_owner_id();
        if !self
            .store
            .acquire_lease(task_id, &lease_owner, LEASE_TTL_SECS)
            .await?
        {
            // Two meanings, and the log line deliberately cannot tell them
            // apart: another process holds a live lease, or a crashed process
            // left a row that has not expired yet. Either way the task is
            // refused until `LEASE_TTL_SECS` past the last renewal. The owner
            // id is never logged.
            tracing::warn!(
                task_id,
                ttl_secs = LEASE_TTL_SECS,
                "refusing to run: an execution lease is already held for this task"
            );
            return Err(SupervisorError::already_running(task_id));
        }
        tracing::debug!(
            task_id,
            ttl_secs = LEASE_TTL_SECS,
            "execution lease acquired"
        );
        let heartbeat_store = self.store.clone();
        let heartbeat_task = task_id.to_string();
        let heartbeat_label = heartbeat_task.clone();
        let heartbeat_owner = lease_owner.clone();
        // The heartbeat task owns the **only** sender. The guard keeps the
        // receiver, so the heartbeat's death — return, abort or panic — closes
        // the channel and reads as a lost lease.
        let (lost_tx, lost_rx) = watch::channel(false);
        let heartbeat = tokio::spawn(async move {
            heartbeat_loop(
                &heartbeat_label,
                move || {
                    let store = heartbeat_store.clone();
                    let task = heartbeat_task.clone();
                    let owner = heartbeat_owner.clone();
                    async move { store.renew_lease(&task, &owner, LEASE_TTL_SECS).await }
                },
                LEASE_HEARTBEAT_INTERVAL,
                lost_tx,
            )
            .await;
        });
        let mut lease_guard = LeaseGuard {
            store: self.store.clone(),
            task_id: task_id.to_string(),
            owner_id: lease_owner,
            heartbeat: Some(heartbeat),
            released: false,
            release_attempted: false,
            lost: lost_rx,
        };

        let result = run_until_lease_loss(
            async {
                let task = self
                    .store
                    .get(task_id)
                    .await?
                    .ok_or_else(|| SupervisorError::not_found(task_id))?;

                // PLAN — transition from the task's actual persisted status so that
                // resumed/mid-pipeline tasks produce a correct audit trail.
                if !crate::supervisor::state::transition_allowed(
                    task.status.clone(),
                    TaskStatus::Plan,
                ) {
                    return Err(SupervisorError::state_refusal(
                        task.status,
                        TaskStatus::Plan,
                    ));
                }
                self.store
                    .record_transition(
                        task_id,
                        task.status.clone(),
                        TaskStatus::Plan,
                        "supervisor",
                        None,
                    )
                    .await?;
                let plan = Planner::new().plan(&task);
                // Track the IDs of jobs planned for this execution so that, on resume,
                // orphan rows from a previous aborted run are excluded from verification.
                let current_job_ids: std::collections::HashSet<String> =
                    plan.jobs.iter().map(|j| j.id.clone()).collect();
                self.artifacts
                    .write_text(
                        task_id,
                        None,
                        "plan",
                        "plan.json",
                        &serde_json::to_string_pretty(&serde_json::json!({
                            "jobs": plan.jobs.iter().map(|j| serde_json::json!({
                                "type": j.job_type, "backend": j.backend, "goal": j.goal,
                            })).collect::<Vec<_>>()
                        }))?,
                    )
                    .await?;

                // PREPARE_WORKSPACE (only for code-modifying tasks when configured)
                let needs_ws = matches!(
                    task.task_type,
                    crate::supervisor::task::TaskType::CodeChange
                        | crate::supervisor::task::TaskType::BugFix
                        | crate::supervisor::task::TaskType::Refactor
                );
                let workspace_active = needs_ws && self.workspace_mgr.is_some();
                if workspace_active {
                    if let Some(wm) = &self.workspace_mgr {
                        self.store
                            .record_transition(
                                task_id,
                                TaskStatus::Plan,
                                TaskStatus::PrepareWorkspace,
                                "supervisor",
                                None,
                            )
                            .await?;
                        let ws = wm.prepare(task_id, &task.title).await?;
                        self.artifacts
                            .write_text(
                                task_id,
                                None,
                                "workspace",
                                "workspace.json",
                                &serde_json::to_string_pretty(&serde_json::json!({
                                    "branch": ws.branch,
                                    "path": ws.path.display().to_string(),
                                }))?,
                            )
                            .await?;
                    }
                }

                // EXECUTE
                let pre_execute_state = if workspace_active {
                    TaskStatus::PrepareWorkspace
                } else {
                    TaskStatus::Plan
                };
                self.store
                    .record_transition(
                        task_id,
                        pre_execute_state,
                        TaskStatus::Execute,
                        "supervisor",
                        None,
                    )
                    .await?;
                let orch = Orchestrator::new(self.registry.clone(), self.store.clone());
                let res = orch.execute_plan(&task, plan).await?;
                // Only verify jobs from the current execution cycle (not orphans from prior runs).
                let all_jobs = self.store.jobs_for_task(task_id).await?;
                let jobs: Vec<_> = all_jobs
                    .into_iter()
                    .filter(|j| current_job_ids.contains(&j.id))
                    .collect();

                // VERIFY
                // M3: regardless of orchestrator outcome we transition Execute->Verify
                // and let VerificationEngine produce the final pass/fail.
                let _ = res;
                if matches!(
                    task.execution_mode,
                    crate::supervisor::task::ExecutionMode::Rigorous
                ) {
                    self.store
                        .record_transition(
                            task_id,
                            TaskStatus::Execute,
                            TaskStatus::Review,
                            "supervisor",
                            None,
                        )
                        .await?;
                    self.store
                        .record_transition(
                            task_id,
                            TaskStatus::Review,
                            TaskStatus::Verify,
                            "supervisor",
                            None,
                        )
                        .await?;
                } else {
                    self.store
                        .record_transition(
                            task_id,
                            TaskStatus::Execute,
                            TaskStatus::Verify,
                            "supervisor",
                            None,
                        )
                        .await?;
                }
                let v = VerificationEngine.verify(&jobs);

                // REPORT + ARCHIVE
                let report = Reporter::render(&jobs);
                self.artifacts
                    .write_text(task_id, None, "result", "report.md", &report)
                    .await?;
                match v {
                    VerificationOutcome::Passed => {
                        self.store
                            .record_transition(
                                task_id,
                                TaskStatus::Verify,
                                TaskStatus::Report,
                                "supervisor",
                                None,
                            )
                            .await?;
                        self.store
                            .record_transition(
                                task_id,
                                TaskStatus::Report,
                                TaskStatus::Archive,
                                "supervisor",
                                None,
                            )
                            .await?;
                        self.store
                            .record_transition(
                                task_id,
                                TaskStatus::Archive,
                                TaskStatus::Done,
                                "supervisor",
                                None,
                            )
                            .await?;
                        Ok(report)
                    }
                    VerificationOutcome::Failed(reason) => {
                        self.store
                            .record_transition(
                                task_id,
                                TaskStatus::Verify,
                                TaskStatus::Failed,
                                "verifier",
                                Some(&reason),
                            )
                            .await?;
                        Ok(format!("VERIFICATION FAILED: {reason}\n\n{report}"))
                    }
                }
            },
            &mut lease_guard.lost,
            task_id,
        )
        .await;
        let release_result = lease_guard.release().await;
        match (result, release_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            // The pipeline succeeded but the lease could not be given back.
            // Deliberately still an error, and not a `warn!` over a success
            // return: a run that cannot prove it released its lease may still
            // hold the task's only claim on it, and reporting a clean success
            // would invite a caller to re-run a task that is not free. The
            // pipeline's own work is not undone — the artifacts, job rows and
            // audit transitions it committed stay committed, exactly as on the
            // lease-lost path (see [`SupervisorError::LeaseLost`]); what the
            // caller loses is the success *report*, not the side effects.
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(release_error)) => Err(error.context(format!(
                "failed to release execution lease: {release_error}"
            ))),
        }
    }

    /// Mark a task as `Paused`. Records the transition unconditionally —
    /// the strict transition-table check is deferred to a later milestone.
    /// Pause a running task.
    ///
    /// Refuses a task the state machine does not allow to be paused. Without
    /// this guard `record_transition` would only catch the mistake through its
    /// `debug_assert!`, which is compiled out of release builds — so a pause of
    /// a finished task would write `Done → Paused` into `sup_tasks` and leave
    /// the supervisor in a state the rest of the code treats as a bug.
    pub async fn pause(&self, task_id: &str) -> anyhow::Result<()> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        if !crate::supervisor::state::transition_allowed(task.status.clone(), TaskStatus::Paused) {
            return Err(SupervisorError::state_refusal(
                task.status,
                TaskStatus::Paused,
            ));
        }
        self.store
            .record_transition(
                task_id,
                task.status,
                TaskStatus::Paused,
                "user",
                Some("paused"),
            )
            .await?;
        Ok(())
    }

    /// Resume a previously-paused task by re-entering `Execute` and running
    /// the rest of the pipeline.
    ///
    /// Only a `Paused` task may be resumed. An earlier version silently skipped
    /// the transition for any other state and called `execute_now` anyway,
    /// which had two consequences: a task parked in `Route` awaiting approval
    /// would run without one, and a finished task would attempt `Done → Plan`,
    /// panicking in debug and writing an illegal state in release.
    pub async fn resume(&self, task_id: &str) -> anyhow::Result<String> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        if task.status != TaskStatus::Paused {
            return Err(SupervisorError::state_refusal(
                task.status,
                TaskStatus::Execute,
            ));
        }
        self.store
            .record_transition(
                task_id,
                TaskStatus::Paused,
                TaskStatus::Execute,
                "user",
                Some("resumed"),
            )
            .await?;
        self.execute_now(task_id).await
    }

    /// IDs of tasks that look resumable on startup (paused or mid-pipeline).
    pub async fn resumable_task_ids(&self) -> anyhow::Result<Vec<String>> {
        self.store.list_resumable_task_ids().await
    }

    pub async fn state(&self, task_id: &str) -> anyhow::Result<TaskStatus> {
        Ok(self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?
            .status)
    }

    pub fn artifacts(&self) -> &ArtifactManager {
        &self.artifacts
    }

    /// Read access to the task store, for callers that need the persisted task
    /// list, a task's jobs, or its audit trail (`TaskStore::list_recent`,
    /// `jobs_for_task`, `transitions`) rather than just the current state.
    pub fn store(&self) -> &TaskStore {
        &self.store
    }

    /// Cancel a task: record `current state -> Cancelled` and nothing else.
    ///
    /// The transition is gated on [`state::transition_allowed`], the single
    /// source of truth for the state machine. From `Cancelled` is refused
    /// (`Cancelled -> Cancelled` is not an edge), as is cancelling a task in a
    /// state the table does not allow to be cancelled — notably `Verify`,
    /// `Report`, `Archive`, `Done`, `Failed` and `Classify`. This method does
    /// **not** invent an edge to make a button work: extending the state machine
    /// is a deliberate change to `state.rs`, not a side effect of a route.
    ///
    /// Scope: this marks the task. It does not abort work already in flight —
    /// `execute_now` runs its plan synchronously through the `Orchestrator`,
    /// which has no cancellation token (`Backend::cancel` is a per-job default
    /// with no supervisor-side caller). Cancelling a task that is mid-`execute_now`
    /// therefore records the state but the running plan still finishes.
    pub async fn cancel(&self, task_id: &str) -> anyhow::Result<()> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        let from = task.status;
        if !crate::supervisor::state::transition_allowed(from.clone(), TaskStatus::Cancelled) {
            return Err(SupervisorError::state_refusal(from, TaskStatus::Cancelled));
        }
        self.store
            .record_transition(
                task_id,
                from,
                TaskStatus::Cancelled,
                "user",
                Some("cancelled"),
            )
            .await?;
        Ok(())
    }

    /// Approve a task awaiting a human decision: drive it into `Execute` and run
    /// the existing pipeline.
    ///
    /// `submit` parks a `PolicyDecision::RequireApproval` task in `Route` (see
    /// the `RequireApproval` arm above, which returns
    /// [`SubmitOutcome::NeedsApproval`] without recording any further
    /// transition), so `Route -> Execute` is the edge this method normally
    /// takes. Approving is otherwise equivalent to resuming execution from
    /// wherever `submit` left the task, so it is implemented in terms of the
    /// existing [`Supervisor::execute_now`] path rather than duplicating the
    /// plan/execute/verify/report orchestration — exactly as
    /// [`Supervisor::resume`] does from `Paused`.
    ///
    /// `Execute` and not `Plan` is the intermediate state: `execute_now` records
    /// `task.status -> Plan` as its first transition, so a `Plan -> Plan` step
    /// would be illegal. `Execute -> Plan` is a legal edge.
    ///
    /// The gate is [`state::transition_allowed`] alone, which means approval is
    /// accepted from the states the table allows to reach `Execute` (`Route`,
    /// `Clarify`, `Plan`, `PrepareWorkspace`, `Paused`, `Review`, `Verify`) and
    /// refused from `Intake`, `Classify`, `Execute`, `Report`, `Archive`,
    /// `Done`, `Failed` and `Cancelled`. Note that approving a mid-pipeline task
    /// re-runs it (new plan, new jobs) — the same semantics `resume` already has,
    /// since both go through `execute_now`.
    pub async fn approve(&self, task_id: &str) -> anyhow::Result<String> {
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        let from = task.status;
        if !crate::supervisor::state::transition_allowed(from.clone(), TaskStatus::Execute) {
            return Err(SupervisorError::state_refusal(from, TaskStatus::Execute));
        }
        self.store
            .record_transition(task_id, from, TaskStatus::Execute, "user", Some("approved"))
            .await?;
        self.execute_now(task_id).await
    }

    /// Answer a `Clarify` prompt: record the answer and resume the existing
    /// pipeline.
    ///
    /// `submit` parks a `PolicyDecision::Clarify` task in `Clarify` (see the
    /// `Clarify` arm above, which returns [`SubmitOutcome::NeedsClarification`]
    /// without recording any further transition), so `Clarify -> Execute` is the
    /// edge this method takes before handing the task to
    /// [`Supervisor::execute_now`] — the same shape [`Supervisor::resume`] and
    /// [`Supervisor::approve`] have, so there is no second execution path.
    ///
    /// `Execute` and not `Plan` is the intermediate state: `execute_now` records
    /// `task.status -> Plan` as its first transition, so a `Plan -> Plan` step
    /// would be illegal. `Clarify -> Execute` is a legal edge.
    ///
    /// # The gate is stricter than the state table, deliberately
    ///
    /// `Clarify -> Execute` and `Clarify -> Plan` are both legal edges, but only
    /// a task that is actually in `Clarify` may be clarified — exactly the
    /// argument [`Supervisor::resume`] makes for `Paused`. Without the exact
    /// check, a task parked in `Route` awaiting approval would be run by
    /// `/clarify`, i.e. an approval in disguise.
    ///
    /// The answer is validated **before** the task is read, so a blank or
    /// oversized one is refused without touching the store at all, and it is
    /// stored as the transition's `reason` after
    /// [`crate::supervisor::redact::redact`], because it is operator-supplied
    /// text that lands in the audit trail.
    pub async fn clarify(&self, task_id: &str, text: &str) -> anyhow::Result<String> {
        let text = text.trim();
        if text.is_empty() {
            anyhow::bail!("the clarification text must not be empty");
        }
        if text.chars().count() > MAX_TASK_TEXT_CHARS {
            anyhow::bail!(
                "the clarification text must be at most {MAX_TASK_TEXT_CHARS} characters"
            );
        }
        let task = self
            .store
            .get(task_id)
            .await?
            .ok_or_else(|| SupervisorError::not_found(task_id))?;
        if task.status != TaskStatus::Clarify {
            return Err(SupervisorError::state_refusal(
                task.status,
                TaskStatus::Execute,
            ));
        }
        // Redacted before it reaches the audit row: `record_transition` stores
        // the reason verbatim, and this is free text a human typed.
        let reason = crate::supervisor::redact::redact(text);
        self.store
            .record_transition(
                task_id,
                TaskStatus::Clarify,
                TaskStatus::Execute,
                "user",
                Some(&reason),
            )
            .await?;
        self.execute_now(task_id).await
    }

    pub async fn submit(
        &self,
        platform: &str,
        user_id: &str,
        chat_id: Option<&str>,
        text: &str,
    ) -> Result<SubmitOutcome> {
        let mut task = IntakeRouter::normalize(text);
        self.store.create(&task, platform, user_id, chat_id).await?;
        self.artifacts
            .write_text(
                &task.id,
                None,
                "intake",
                "intake.json",
                &serde_json::to_string_pretty(&task)?,
            )
            .await?;

        // CLASSIFY
        self.store
            .record_transition(
                &task.id,
                TaskStatus::Intake,
                TaskStatus::Classify,
                "supervisor",
                Some("auto"),
            )
            .await?;
        let outcome = (*self.classifier).classify(text);
        task.task_type = outcome.task_type.clone();
        task.risk_level = outcome.risk_level.clone();
        task.execution_mode = outcome.execution_mode.clone();
        task.required_capabilities = outcome.required_capabilities.clone();
        self.store.update_classification(&task).await?;
        self.artifacts
            .write_text(
                &task.id,
                None,
                "classification",
                "classification.json",
                &serde_json::to_string_pretty(&serde_json::json!({
                    "task_type": task.task_type,
                    "risk_level": task.risk_level,
                    "execution_mode": task.execution_mode,
                    "required_capabilities": task.required_capabilities,
                    "confidence": outcome.confidence,
                }))?,
            )
            .await?;

        // ROUTE → POLICY
        self.store
            .record_transition(
                &task.id,
                TaskStatus::Classify,
                TaskStatus::Route,
                "supervisor",
                None,
            )
            .await?;
        // LAYER 1 — route-time gate. This asks the same registry the executor
        // uses, rather than duplicating a routing predicate that could drift.
        //
        // `needs_approval()` is the whole condition, and it is `false` for
        // `Unconfined`: `sandbox = "none"` is the operator's consent, and under
        // it nothing is gated (spec §4).
        //
        // Known and deliberate at this step: the `RequireApproval` arm below
        // builds its `reason` from `task.risk_level`, so a task parked *here*
        // is told "medium-risk task requires approval" when the real cause is
        // the missing sandbox. Task 8 replaces this with `shell_gate_reason`,
        // which names the sandbox.
        let decision = self.policy.decide(&task);
        // The gate **shadows** the policy's decision rather than replacing it:
        // the `None` arm is the policy's own answer, so the two cannot drift.
        let gate_reason = self.shell_gate_reason(&task);
        let decision = match &gate_reason {
            Some(reason) => {
                tracing::warn!(task_id = %task.id, %reason, "shell task parked for approval");
                PolicyDecision::RequireApproval
            }
            None => decision,
        };
        self.artifacts
            .write_text(
                &task.id,
                None,
                "policy",
                "policy.json",
                &serde_json::to_string_pretty(&serde_json::json!({
                    "decision": format!("{decision:?}")
                }))?,
            )
            .await?;

        Ok(match decision {
            PolicyDecision::AutoExecute => SubmitOutcome::AutoExecutePlanned { task_id: task.id },
            PolicyDecision::Clarify => {
                self.store
                    .record_transition(
                        &task.id,
                        TaskStatus::Route,
                        TaskStatus::Clarify,
                        "policy",
                        Some("ambiguous"),
                    )
                    .await?;
                SubmitOutcome::NeedsClarification {
                    task_id: task.id,
                    question: "I'm not sure what you want me to do — can you clarify?".into(),
                }
            }
            PolicyDecision::RequireApproval => {
                // The gate's own reason wins over the risk-level one. Without
                // this a task parked *because the sandbox is missing* was told
                // "medium-risk task requires approval", which names a cause the
                // operator cannot act on and hides the one they can.
                let reason = gate_reason.unwrap_or_else(|| match task.risk_level {
                    crate::supervisor::task::RiskLevel::High => {
                        "high-risk task requires approval".to_string()
                    }
                    crate::supervisor::task::RiskLevel::Medium => {
                        if self.policy.thresholds().require_approval_for_medium {
                            "medium-risk task requires approval (threshold config)".to_string()
                        } else if self.policy.thresholds().auto_execute_only_low {
                            "medium-risk task requires approval (auto_execute_only_low)".to_string()
                        } else {
                            "medium-risk task requires approval".to_string()
                        }
                    }
                    crate::supervisor::task::RiskLevel::Low => {
                        "low-risk task requires approval (threshold config)".to_string()
                    }
                });
                SubmitOutcome::NeedsApproval {
                    task_id: task.id,
                    reason,
                }
            }
            other => SubmitOutcome::NeedsApproval {
                task_id: task.id,
                reason: format!("{other:?}"),
            },
        })
    }
}

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

/// Await `fut` under a bound, so a run that never finishes fails **the calling
/// test** with a named message instead of wedging the whole binary.
///
/// The supervisor's tests deliberately park spawned `execute_now` futures inside
/// a test backend until the test releases them, so an un-bounded `handle.await`
/// has exactly one failure mode: waiting forever. That is worse than a failing
/// test, because libtest has no per-test timeout and prints nothing about a test
/// still in flight — a hang here is completely silent. One run of this suite
/// really did sit for 15 minutes with every worker idle before it was killed,
/// and the stuck test could not be named from the captured output afterwards.
///
/// The bound is a hang detector, not a performance assertion, so it sits far
/// above the work these tests do.
#[cfg(test)]
pub(crate) async fn bounded<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    const HANG_DETECTOR: std::time::Duration = std::time::Duration::from_secs(60);
    match tokio::time::timeout(HANG_DETECTOR, fut).await {
        Ok(value) => value,
        Err(_) => panic!(
            "{what} did not finish within {}s, so it is being treated as a hang. \
             Without this bound the test would wait forever and name nothing.",
            HANG_DETECTOR.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::backend::sandbox::IsolationUnavailable;
    use crate::supervisor::backend::shell::ShellBackend;
    use crate::supervisor::task::{Task, TaskStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Supervisor whose policy escalates a Medium-risk task to `RequireApproval`,
    /// so `submit` really parks the task in `Route` (the only way to get there
    /// through the public API — the heuristic classifier never emits High risk).
    fn supervisor_requiring_approval(
        dir: &std::path::Path,
        memory: &crate::memory::MemoryStore,
    ) -> Supervisor {
        let mut sup = Supervisor::new(
            dir.to_path_buf(),
            memory.connection(),
            Registry::new(),
            crate::config::RiskThresholdsConfig {
                require_approval_for_medium: true,
                ..Default::default()
            },
        );
        sup.register_test_reasoning_backend(|p| async move { Ok(format!("ran:{p}")) });
        sup
    }

    fn plain_supervisor(dir: &std::path::Path, memory: &crate::memory::MemoryStore) -> Supervisor {
        let mut sup = Supervisor::new_for_test(dir.to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|p| async move { Ok(format!("ran:{p}")) });
        sup
    }

    /// The `owner_id` of the live execution-lease row for `task_id`, or `None`
    /// when there is no row. Read straight from the connection: the owner id is
    /// never logged and never returned by the lease API, so the row is the only
    /// place it can be observed.
    async fn lease_owner(memory: &crate::memory::MemoryStore, task_id: &str) -> Option<String> {
        let conn = memory.connection();
        let conn = conn.lock().await;
        conn.query_row(
            "SELECT owner_id FROM sup_execution_leases WHERE task_id=?1",
            [task_id],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    #[tokio::test]
    async fn store_accessor_exposes_the_store_the_supervisor_reads_from() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = Supervisor::new_for_test(dir.path().into(), memory.connection());

        let t = Task::new("listing", "req");
        sup.store().create(&t, "web", "u1", None).await.unwrap();

        // `state()` reads through `self.store`; agreeing with the accessor proves
        // the accessor is not a detached copy.
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Intake);
        assert_eq!(
            sup.store().get(&t.id).await.unwrap().unwrap().title,
            "listing"
        );
        assert_eq!(sup.store().list_recent(20).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn approve_runs_a_task_that_submit_parked_for_approval() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = supervisor_requiring_approval(dir.path(), &memory);

        let outcome = sup
            .submit("web", "u1", None, "refactor the parser")
            .await
            .unwrap();
        assert!(matches!(outcome, SubmitOutcome::NeedsApproval { .. }));
        let id = outcome.task_id();
        // The premise of this test: submit leaves an approval-pending task in Route.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);

        let report = sup.approve(&id).await.unwrap();
        assert!(report.contains("ran:"), "unexpected report: {report}");
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);

        let trail = sup.store().transitions(&id).await.unwrap();
        assert!(
            trail
                .iter()
                .any(|r| r.from == TaskStatus::Route && r.to == TaskStatus::Execute),
            "approve must record Route -> Execute, got {trail:?}"
        );
    }

    #[tokio::test]
    async fn approve_refuses_a_task_the_state_machine_does_not_allow() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let err = sup.approve(&id).await.unwrap_err().to_string();
        assert!(
            err.contains("Done") && err.contains("Execute"),
            "unexpected error: {err}"
        );
        // Refused means nothing was written.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        assert_eq!(sup.store().transitions(&id).await.unwrap().len(), before);
    }

    #[tokio::test]
    async fn cancel_marks_a_pending_task_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);

        sup.cancel(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Cancelled);

        let trail = sup.store().transitions(&id).await.unwrap();
        let last = trail.last().unwrap();
        assert_eq!(last.from, TaskStatus::Route);
        assert_eq!(last.to, TaskStatus::Cancelled);
        assert_eq!(last.actor, "user");
    }

    #[tokio::test]
    async fn cancel_refuses_a_task_that_already_finished() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let err = sup.cancel(&id).await.unwrap_err().to_string();
        assert!(
            err.contains("Done") && err.contains("Cancelled"),
            "unexpected error: {err}"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        assert_eq!(sup.store().transitions(&id).await.unwrap().len(), before);
    }

    /// `Verify -> Cancelled` is not an edge in `state.rs`, so a task under
    /// verification must be refused too — the guard is the state machine, not a
    /// "terminal states only" check.
    #[tokio::test]
    async fn cancel_is_refused_while_a_task_is_being_verified() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let t = Task::new("verify me", "req");
        sup.store().create(&t, "web", "u1", None).await.unwrap();
        for (from, to) in [
            (TaskStatus::Intake, TaskStatus::Classify),
            (TaskStatus::Classify, TaskStatus::Route),
            (TaskStatus::Route, TaskStatus::Plan),
            (TaskStatus::Plan, TaskStatus::Execute),
            (TaskStatus::Execute, TaskStatus::Verify),
        ] {
            sup.store()
                .record_transition(&t.id, from, to, "test", None)
                .await
                .unwrap();
        }
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Verify);

        assert!(sup.cancel(&t.id).await.is_err());
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Verify);
    }

    /// An unknown id must be a *typed* not-found, so the dashboard can answer
    /// 404 rather than 500 for a task that vanished under a request.
    #[tokio::test]
    async fn the_lifecycle_methods_report_a_missing_task_as_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let cancel_err = sup.cancel("does-not-exist").await.unwrap_err();
        assert!(
            matches!(
                cancel_err.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::NotFound { .. })
            ),
            "unexpected error: {cancel_err:?}"
        );
        let approve_err = sup.approve("does-not-exist").await.unwrap_err();
        assert!(
            matches!(
                approve_err.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::NotFound { .. })
            ),
            "unexpected error: {approve_err:?}"
        );
        for error in [
            sup.pause("does-not-exist").await.unwrap_err(),
            sup.resume("does-not-exist").await.unwrap_err(),
            sup.state("does-not-exist").await.unwrap_err(),
            sup.execute_now("does-not-exist").await.unwrap_err(),
        ] {
            assert!(
                matches!(
                    error.downcast_ref::<SupervisorError>(),
                    Some(SupervisorError::NotFound { .. })
                ),
                "unexpected error: {error:?}"
            );
            assert!(
                error.to_string().contains("task not found"),
                "unexpected message: {error}"
            );
        }
    }

    /// A task parked in `Route` by `submit` is awaiting approval. Resuming it
    /// must be refused: an earlier version skipped the `Paused` check and ran
    /// `execute_now` anyway, so a task awaiting a human decision would execute
    /// without one.
    #[tokio::test]
    async fn resume_refuses_a_task_that_is_awaiting_approval() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = supervisor_requiring_approval(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "refactor the parser")
            .await
            .unwrap()
            .task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let err = sup.resume(&id).await.unwrap_err();
        // Asserted on the typed refusal rather than on the message text: the
        // route classifies with `downcast_ref`, so what has to hold is the
        // *type* of the error, and `from` has to be the state it actually read.
        assert!(
            matches!(
                err.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::StateRefusal {
                    from: TaskStatus::Route,
                    to: TaskStatus::Execute,
                })
            ),
            "unexpected error: {err:?}"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
        assert_eq!(
            sup.store().transitions(&id).await.unwrap().len(),
            before,
            "a refused resume must not record a transition"
        );
    }

    /// `Done -> Plan` is not an edge, so resuming a finished task used to panic
    /// through `record_transition`'s `debug_assert!` in debug builds and write
    /// an illegal state in release builds.
    #[tokio::test]
    async fn resume_refuses_a_finished_task_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);

        let err = sup.resume(&id).await.unwrap_err().to_string();
        assert!(err.contains("Done"), "unexpected error: {err}");
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    #[tokio::test]
    async fn resume_accepts_a_paused_task() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.pause(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Paused);

        assert!(sup.resume(&id).await.is_ok());
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    /// `pause` had the same missing guard as `resume`: without it a finished
    /// task would take the illegal `Done -> Paused` edge.
    #[tokio::test]
    async fn pause_refuses_a_finished_task() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        let before = sup.store().transitions(&id).await.unwrap().len();

        assert!(sup.pause(&id).await.is_err());
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
        assert_eq!(sup.store().transitions(&id).await.unwrap().len(), before);
    }

    // ── clarify ─────────────────────────────────────────────────────────────

    /// A task parked in `Clarify`.
    ///
    /// Written through the store rather than through `submit`, so no test here
    /// depends on the heuristic classifier deciding a request is ambiguous — the
    /// fixture states the precondition instead of hoping for it.
    async fn task_awaiting_clarification(sup: &Supervisor) -> String {
        let t = Task::new("do the thing", "do the thing");
        sup.store().create(&t, "web", "u1", None).await.unwrap();
        for (from, to) in [
            (TaskStatus::Intake, TaskStatus::Classify),
            (TaskStatus::Classify, TaskStatus::Route),
            (TaskStatus::Route, TaskStatus::Clarify),
        ] {
            sup.store()
                .record_transition(&t.id, from, to, "test", None)
                .await
                .unwrap();
        }
        t.id
    }

    #[tokio::test]
    async fn clarify_records_the_answer_and_runs_a_task_parked_for_clarification() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);
        let id = task_awaiting_clarification(&sup).await;

        let report = sup
            .clarify(&id, "  it is about the parser  ")
            .await
            .unwrap();
        assert!(report.contains("ran:"), "unexpected report: {report}");
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);

        let trail = sup.store().transitions(&id).await.unwrap();
        let row = trail
            .iter()
            .find(|r| r.from == TaskStatus::Clarify && r.to == TaskStatus::Execute)
            .expect("clarify must take Clarify -> Execute");
        // Trimmed before it is recorded, so the audit row holds the answer the
        // user meant rather than the whitespace they typed around it.
        assert_eq!(row.reason.as_deref(), Some("it is about the parser"));
    }

    /// The exact-state gate, and the reason it exists: `Clarify -> Execute` is a
    /// legal edge, so without the `task.status != Clarify` check a task parked in
    /// `Route` awaiting approval would be run by `clarify` — an approval in
    /// disguise, which is the same failure `resume` was fixed for.
    #[tokio::test]
    async fn clarify_refuses_a_task_that_is_not_in_clarify() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
        let before = sup.store().transitions(&id).await.unwrap().len();

        let error = sup.clarify(&id, "just do it").await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::StateRefusal { .. })
            ),
            "clarify must raise a typed refusal, got {error:?}"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
        assert_eq!(
            sup.store().transitions(&id).await.unwrap().len(),
            before,
            "a refused clarify must write nothing"
        );
    }

    /// The text is validated **before** the task is read, so a blank or
    /// oversized answer costs no store access at all.
    #[tokio::test]
    async fn clarify_refuses_blank_and_oversized_answers() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);
        let id = task_awaiting_clarification(&sup).await;
        let before = sup.store().transitions(&id).await.unwrap().len();

        // Whitespace-only is blank. (A zero-width space is *not* whitespace by
        // `char::is_whitespace`, so a `"\u{200b}"`-only answer is accepted as
        // text — it is one character the user typed, not an empty answer.)
        for answer in ["", "   ", "\n\t ", "\r\n"] {
            let error = sup.clarify(&id, answer).await.unwrap_err();
            assert!(
                error.to_string().contains("must not be empty"),
                "unexpected error for {answer:?}: {error}"
            );
        }

        let too_long = "x".repeat(MAX_TASK_TEXT_CHARS + 1);
        let error = sup.clarify(&id, &too_long).await.unwrap_err();
        assert!(
            error.to_string().contains("at most"),
            "unexpected error for an oversized answer: {error}"
        );

        // Every refusal left the task exactly where it was: still parked, with
        // no audit row and no execution.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Clarify);
        assert_eq!(
            sup.store().transitions(&id).await.unwrap().len(),
            before,
            "a refused clarify must write nothing"
        );

        // Exactly the limit is accepted and really runs the task.
        assert!(sup
            .clarify(&id, &"x".repeat(MAX_TASK_TEXT_CHARS))
            .await
            .is_ok());
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    #[tokio::test]
    async fn clarify_refuses_an_unknown_task_as_a_typed_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let error = sup.clarify("no-such-task", "an answer").await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::NotFound { .. })
            ),
            "clarify must raise a typed not-found, got {error:?}"
        );
    }

    /// The answer is free text a human typed and `record_transition` stores the
    /// reason verbatim, so it is scrubbed before it reaches the audit row.
    #[tokio::test]
    async fn clarify_redacts_the_answer_before_it_reaches_the_audit_row() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);
        let id = task_awaiting_clarification(&sup).await;

        // Assembled at runtime so the contiguous `key=value` spelling is not in
        // this file's source.
        let answer = format!("{}={}", "api_key", "zz9leaky9value");
        sup.clarify(&id, &answer).await.unwrap();

        let trail = sup.store().transitions(&id).await.unwrap();
        let row = trail
            .iter()
            .find(|r| r.from == TaskStatus::Clarify && r.to == TaskStatus::Execute)
            .expect("clarify must take Clarify -> Execute");
        let reason = row.reason.as_deref().unwrap_or_default();
        assert!(
            !reason.contains("zz9leaky9value"),
            "the audit reason must be redacted: {reason:?}"
        );
        assert!(
            reason.contains("***"),
            "the mask must be present: {reason:?}"
        );
    }

    // ── Concurrency ─────────────────────────────────────────────────────────
    //
    // Everything above runs on the default current-thread runtime, which is
    // exactly why the lost-update bug these tests guard survived the suite:
    // with one thread the two requests only interleave at `await` points, and
    // the registered test backend never yields, so the whole read-check-write
    // of a lifecycle method ran to completion before the second request was
    // even polled. Production is `#[tokio::main]` — multi-thread — and
    // reproduced it every time.

    /// A second `execute_now` for a task that is already running must be
    /// refused.
    ///
    /// The compare-and-swap in `record_transition` cannot catch this pair on
    /// its own: the task is in `Execute`, and `Execute -> Plan` **is** a legal
    /// edge, so both runs are accepted by the state machine and both run the
    /// plan. One reviewer reproduced exactly that, and in a debug build it
    /// surfaced as a `Plan -> Plan` panic out of `record_transition`.
    ///
    /// The backend parks the first run inside the orchestrator and reports on a
    /// channel when it got there, so the second call is issued against a task
    /// that is provably mid-plan: the interleaving is a fact of the test, not a
    /// matter of timing. The park has a short timeout because a *duplicate* run
    /// (the bug) waits for a release that only arrives after the second call
    /// has returned — without it this test would deadlock instead of failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn execute_now_refuses_a_second_run_of_a_task_already_running() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();

        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);

        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(move |prompt: String| {
            let entered_tx = entered_tx.clone();
            let mut release_rx = release_rx.clone();
            async move {
                let _ = entered_tx.send(());
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    while !*release_rx.borrow_and_update() {
                        if release_rx.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await;
                Ok(format!("ran:{prompt}"))
            }
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        // The premise of the test: `submit` leaves an auto-executed task in
        // Route, and `Route -> Plan` is a legal edge, so the state machine
        // accepts both runs.
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);

        let first = {
            let sup = Arc::clone(&sup);
            let id = id.clone();
            tokio::spawn(async move { sup.execute_now(&id).await })
        };
        // The first run only reaches the backend after its `Route -> Plan` and
        // `Plan -> Execute` transitions, so by the time this returns the task
        // is demonstrably mid-plan.
        entered_rx
            .recv()
            .await
            .expect("the first run must reach the backend");

        let second = sup.execute_now(&id).await;
        assert!(
            matches!(
                second
                    .as_ref()
                    .err()
                    .and_then(|e| e.downcast_ref::<SupervisorError>()),
                Some(SupervisorError::AlreadyRunning { .. })
            ),
            "the second run must be refused as already running, got {second:?}"
        );

        release_tx.send(true).unwrap();
        let first = first.await.expect("the first run must not panic");
        assert!(first.is_ok(), "the first run must complete: {first:?}");

        let task = sup.store().get(&id).await.unwrap().unwrap();
        let planned = Planner::new().plan(&task).jobs.len();
        assert_eq!(
            sup.store().jobs_for_task(&id).await.unwrap().len(),
            planned,
            "a refused second run must not create a second set of jobs"
        );
        let trail = sup.store().transitions(&id).await.unwrap();
        let plan_edges = trail.iter().filter(|r| r.to == TaskStatus::Plan).count();
        assert_eq!(
            plan_edges, 1,
            "the plan must be entered exactly once: {trail:?}"
        );
    }

    /// The reviewer's reproduction, as a regression test: eight concurrent
    /// `resume`s of the same paused task.
    ///
    /// Before the fix, every one of them that read the task while it was still
    /// `Paused` recorded its own `Paused -> Execute` edge and ran the plan:
    /// several successes, several sets of job rows, several artifact rows for
    /// the same paths with different `sha256`, and — in debug builds — a
    /// `Plan -> Plan` panic out of `record_transition`. With the
    /// compare-and-swap exactly one can win, because after the first the row is
    /// no longer `Paused`.
    ///
    /// This test is deliberately on a **multi-thread** runtime. On the default
    /// current-thread runtime the futures only interleave at `await` points, so
    /// it would prove nothing — which is precisely how the old suite stayed
    /// green at 0/20 while production failed 20/20.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_resumes_start_the_plan_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|prompt| async move {
            tokio::task::yield_now().await;
            Ok(format!("ran:{prompt}"))
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.pause(&id).await.unwrap();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Paused);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let sup = Arc::clone(&sup);
            let id = id.clone();
            handles.push(tokio::spawn(async move { sup.resume(&id).await }));
        }

        let mut accepted = 0usize;
        let mut refused = 0usize;
        let mut panicked: Vec<String> = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(_report)) => accepted += 1,
                Ok(Err(e)) => {
                    assert!(
                        matches!(
                            e.downcast_ref::<SupervisorError>(),
                            Some(SupervisorError::StateRefusal { .. })
                                | Some(SupervisorError::AlreadyRunning { .. })
                        ),
                        "a refused resume must be a typed refusal, got {e:?}"
                    );
                    refused += 1;
                }
                // A panic is not a refusal. It is counted separately so the
                // failure message says which of the two happened.
                Err(join) => panicked.push(join.to_string()),
            }
        }
        assert!(panicked.is_empty(), "no run may panic: {panicked:?}");
        assert_eq!(
            accepted,
            1,
            "exactly one resume may start the plan (refused {refused}, panicked {})",
            panicked.len()
        );
        assert_eq!(refused, 7, "every other resume must be refused");

        let trail = sup.store().transitions(&id).await.unwrap();
        let resumed_edges = trail
            .iter()
            .filter(|r| r.from == TaskStatus::Paused && r.to == TaskStatus::Execute)
            .count();
        assert_eq!(
            resumed_edges, 1,
            "the audit trail must not carry duplicate edges: {trail:?}"
        );

        let task = sup.store().get(&id).await.unwrap().unwrap();
        let planned = Planner::new().plan(&task).jobs.len();
        assert_eq!(
            sup.store().jobs_for_task(&id).await.unwrap().len(),
            planned,
            "the task must have exactly one set of jobs"
        );
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Done);
    }

    /// `Intake -> Plan` is not an edge, so `execute_now` on a task that has not
    /// been classified has no legal first transition. It used to reach
    /// `record_transition`'s `debug_assert!` and panic — a public method with an
    /// unstated precondition. It must be refused, and refuse *before* writing
    /// anything.
    #[tokio::test]
    async fn execute_now_refuses_a_task_that_has_not_been_classified() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup = plain_supervisor(dir.path(), &memory);

        let t = Task::new("raw", "req");
        sup.store().create(&t, "web", "u1", None).await.unwrap();
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Intake);

        let error = sup.execute_now(&t.id).await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::StateRefusal {
                    from: TaskStatus::Intake,
                    to: TaskStatus::Plan,
                })
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(sup.state(&t.id).await.unwrap(), TaskStatus::Intake);
        assert!(sup.store().transitions(&t.id).await.unwrap().is_empty());
        assert!(sup.store().jobs_for_task(&t.id).await.unwrap().is_empty());
    }

    /// The in-flight guard is released even when the run fails, or a task that
    /// hit a bad backend could never be run again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_in_flight_guard_is_released_after_a_failed_run() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|_prompt| async move {
            anyhow::bail!("the backend refused to run")
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        // The orchestrator records the failure as a failed job rather than
        // propagating it, so the run itself returns Ok; what matters is that
        // the guard is not still held afterwards.
        sup.execute_now(&id).await.unwrap();
        let error = sup.execute_now(&id).await.unwrap_err();
        assert!(
            !matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::AlreadyRunning { .. })
            ),
            "the guard must have been released: {error:?}"
        );
    }

    /// Lease loss must win against a pipeline that never finishes, and the
    /// abandoned pipeline must be **dropped** — that drop is the abort, because
    /// every backend holds its in-flight subprocess with `kill_on_drop(true)`.
    #[tokio::test]
    async fn lease_loss_aborts_a_hanging_pipeline_and_drops_it() {
        let (lost_tx, mut lost_rx) = tokio::sync::watch::channel(false);
        // The pipeline owns one reference; the test holds the other. The count
        // is 2 while the pipeline is alive and 1 once it has been dropped.
        let owned = Arc::new(());
        let pipeline_owns = Arc::clone(&owned);
        let pipeline = async move {
            let _keep = pipeline_owns;
            std::future::pending::<()>().await;
            Ok::<String, anyhow::Error>(String::new())
        };

        lost_tx.send(true).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_until_lease_loss(pipeline, &mut lost_rx, "task-1"),
        )
        .await
        .expect("lease loss must abort the pipeline, not wait for it to finish");

        let error = result.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::LeaseLost { task_id }) if task_id == "task-1"
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(
            Arc::strong_count(&owned),
            1,
            "the abandoned pipeline must be dropped, not left running"
        );
    }

    /// A heartbeat that died — dropped, aborted or panicked — can no longer
    /// prove the lease is ours, so the wait must end rather than hang forever.
    #[tokio::test]
    async fn a_dropped_heartbeat_is_treated_as_lease_loss() {
        let (lost_tx, mut lost_rx) = tokio::sync::watch::channel(false);
        drop(lost_tx);

        tokio::time::timeout(Duration::from_secs(2), wait_for_lease_loss(&mut lost_rx))
            .await
            .expect("a dropped sender must end the wait");
        assert!(loss_signalled(&lost_rx));
    }

    /// The heartbeat-panic hole, pinned end to end through the guard.
    ///
    /// The guard holds only a `watch::Receiver`, so the heartbeat task owning
    /// the only sender means a panic closes the channel and both loss readers
    /// see it. Had the guard kept a second `Sender` — which is what the first
    /// version did — the channel would stay open, `wait_for_lease_loss` would
    /// never fire, and `execute_now` would keep running a plan for a task it no
    /// longer holds until the lease silently expired.
    #[tokio::test]
    async fn a_panicking_heartbeat_is_treated_as_lease_loss() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task-1", "owner-a", 60).await.unwrap());

        let (lost_tx, lost_rx) = tokio::sync::watch::channel(false);
        let heartbeat = tokio::spawn(async move {
            // The heartbeat owns the only sender; panicking drops it.
            let _only_sender = lost_tx;
            panic!("the heartbeat task died");
        });
        let mut guard = LeaseGuard {
            store: store.clone(),
            task_id: "task-1".to_string(),
            owner_id: "owner-a".to_string(),
            heartbeat: Some(heartbeat),
            released: false,
            release_attempted: false,
            lost: lost_rx,
        };

        tokio::time::timeout(Duration::from_secs(2), wait_for_lease_loss(&mut guard.lost))
            .await
            .expect("a panicked heartbeat must be read as a lost lease, not as a live one");
        assert!(loss_signalled(&guard.lost));

        // What this test asserts: `release` still succeeds — a dead heartbeat
        // must not be turned into a release error — and the (still ours) row is
        // handed back. The panic itself is *logged* by `release` at `warn!`
        // (`execution-lease heartbeat task died`), not asserted here: catching a
        // tracing event would need a subscriber of its own, and the claim that
        // mattered — a panicked heartbeat reads as a loss — is asserted above.
        guard.release().await.unwrap();
        assert!(
            store.acquire_lease("task-1", "owner-b", 60).await.unwrap(),
            "the lease must be free after a release that survived a dead heartbeat"
        );
    }

    /// `release` reads the loss state *before* aborting the heartbeat. Reading
    /// it afterwards would see the channel the abort just closed and call every
    /// ordinary release a loss — so the takeover below must still be reported.
    #[tokio::test]
    async fn release_after_a_takeover_reports_the_loss_and_leaves_the_new_lease() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task-1", "owner-a", 60).await.unwrap());

        // Owner A's lease expires, and owner B takes the task over.
        {
            let conn = memory.connection();
            let conn = conn.lock().await;
            conn.execute("UPDATE sup_execution_leases SET expires_at=0", [])
                .unwrap();
        }
        assert!(store.acquire_lease("task-1", "owner-b", 60).await.unwrap());

        // A real heartbeat, so `release` really does abort something: aborting
        // closes the channel, which is exactly the reading this test pins.
        let (lost_tx, lost_rx) = tokio::sync::watch::channel(false);
        let heartbeat = tokio::spawn(async move {
            let _only_sender = lost_tx;
            std::future::pending::<()>().await;
        });
        let guard = LeaseGuard {
            store: store.clone(),
            task_id: "task-1".to_string(),
            owner_id: "owner-a".to_string(),
            heartbeat: Some(heartbeat),
            released: false,
            release_attempted: false,
            lost: lost_rx,
        };

        let error = guard.release().await.unwrap_err();
        // Typed, not a bare `anyhow::bail!`: the dashboard turns this into a
        // 409 by downcasting, and an untyped error would be answered as a 500.
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::LeaseLost { task_id }) if task_id == "task-1"
            ),
            "the loss must carry the typed error: {error:?}"
        );
        assert!(error.to_string().contains("task-1"), "{error}");
        assert!(
            store.renew_lease("task-1", "owner-b", 60).await.unwrap(),
            "the new owner's lease must survive the old owner's release"
        );
    }

    /// The ordinary path: the lease is still ours, so release removes it and
    /// says nothing.
    #[tokio::test]
    async fn release_removes_a_lease_this_run_still_owns() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task-1", "owner-a", 60).await.unwrap());

        // The sender stays alive: nothing has been signalled, so `release` has
        // to decide from the row alone.
        let (_lost_tx, lost_rx) = tokio::sync::watch::channel(false);
        let guard = LeaseGuard {
            store: store.clone(),
            task_id: "task-1".to_string(),
            owner_id: "owner-a".to_string(),
            heartbeat: None,
            released: false,
            release_attempted: false,
            lost: lost_rx,
        };
        guard.release().await.unwrap();

        assert!(
            store.acquire_lease("task-1", "owner-b", 60).await.unwrap(),
            "the lease must be free after a successful release"
        );
    }

    /// Once loss has been signalled the pipeline's own error reports it, so
    /// `release` must stay quiet — but it must still try to remove the row.
    #[tokio::test]
    async fn release_after_a_signalled_loss_is_quiet() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task-1", "owner-a", 60).await.unwrap());

        let (lost_tx, lost_rx) = tokio::sync::watch::channel(false);
        lost_tx.send(true).unwrap();
        let guard = LeaseGuard {
            store: store.clone(),
            task_id: "task-1".to_string(),
            owner_id: "owner-a".to_string(),
            heartbeat: None,
            released: false,
            release_attempted: false,
            lost: lost_rx,
        };

        guard
            .release()
            .await
            .expect("a signalled loss must not be reported twice");
        assert!(
            store.acquire_lease("task-1", "owner-b", 60).await.unwrap(),
            "release must still have removed the row"
        );
    }

    /// A transient renewal fault must not be read as a lost lease; a persistent
    /// one must be, after a bounded number of retries.
    #[tokio::test]
    async fn a_transient_renew_fault_is_retried_but_a_persistent_one_declares_loss() {
        // Transient: the first attempt faults, the next one answers.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let heartbeat = tokio::spawn(heartbeat_loop(
            "task-1",
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        anyhow::bail!("database is locked")
                    }
                    Ok(true)
                }
            },
            Duration::from_millis(10),
            tx,
        ));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !heartbeat.is_finished(),
            "a transient fault must not end the heartbeat"
        );
        assert!(
            !*rx.borrow(),
            "a transient fault must not declare the lease lost"
        );
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "the faulted renewal must have been retried"
        );
        heartbeat.abort();
        let _ = heartbeat.await;

        // Persistent: every attempt faults.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let started = std::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(5),
            heartbeat_loop(
                "task-1",
                move || {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        anyhow::bail!("database is locked")
                    }
                },
                Duration::from_millis(10),
                tx,
            ),
        )
        .await
        .expect("a persistent fault must end the heartbeat by declaring loss");
        let elapsed = started.elapsed();

        assert!(
            *rx.borrow(),
            "a persistent fault must declare the lease lost"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1 + LEASE_RENEW_BACKOFFS.len(),
            "one attempt, one per backoff, and no more"
        );
        assert!(
            elapsed >= LEASE_RENEW_BACKOFFS.iter().sum::<Duration>(),
            "the retries must be spaced by the backoff, took only {elapsed:?}"
        );
    }

    /// A run that fails must still give the lease back, or no other process
    /// could ever pick the task up again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_failed_run_releases_the_execution_lease() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|_prompt| async move {
            anyhow::bail!("the backend refused to run")
        });
        let sup = Arc::new(sup);

        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();
        sup.execute_now(&id).await.unwrap();

        assert!(
            sup.store()
                .acquire_lease(&id, "another-process", 60)
                .await
                .unwrap(),
            "the execution lease must be free after the run"
        );
    }

    /// `execute_now` must *claim* the persistent lease, not merely consult it.
    /// The row is pre-held by a foreign owner — which is all this process can
    /// see of another process — and the run must refuse rather than start.
    ///
    /// This is the test the process-local in-flight guard cannot cover: nothing
    /// is in flight here, so only the lease claim can produce the refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn execute_now_refuses_a_task_whose_execution_lease_is_held_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        sup.register_test_reasoning_backend(|p| async move { Ok(format!("ran:{p}")) });
        let sup = Arc::new(sup);
        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();

        // A live lease owned by somebody else — a second process, from this
        // one's point of view.
        assert!(sup
            .store()
            .acquire_lease(&id, "another-process", LEASE_TTL_SECS)
            .await
            .unwrap());

        let error = sup.execute_now(&id).await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SupervisorError>(),
                Some(SupervisorError::AlreadyRunning { task_id }) if task_id == &id
            ),
            "a lease held elsewhere must refuse the run as AlreadyRunning: {error:?}"
        );

        // The refused run wrote nothing: no plan transition, no jobs.
        let task = sup.store().get(&id).await.unwrap().unwrap();
        assert!(
            !matches!(task.status, TaskStatus::Plan | TaskStatus::Execute),
            "a refused run must not have planned the task, status is {:?}",
            task.status
        );
        assert!(
            sup.store().jobs_for_task(&id).await.unwrap().is_empty(),
            "a refused run must not have dispatched jobs"
        );
        // And it did not steal or release the foreign lease.
        assert!(
            sup.store()
                .renew_lease(&id, "another-process", LEASE_TTL_SECS)
                .await
                .unwrap(),
            "the foreign lease must be untouched by the refused run"
        );
    }

    /// While a run is in flight, its lease must be visible to a **second store
    /// over the same database** — that is the whole point of the row existing
    /// on disk instead of in this process's memory.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_store_cannot_acquire_the_lease_while_a_run_is_in_flight() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let backend_entered = Arc::clone(&entered);
        let backend_resume = Arc::clone(&resume);
        sup.register_test_reasoning_backend(move |_prompt| {
            let entered = Arc::clone(&backend_entered);
            let resume = Arc::clone(&backend_resume);
            async move {
                entered.notify_one();
                resume.notified().await;
                Ok("done".to_string())
            }
        });
        let sup = Arc::new(sup);
        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();

        let running = tokio::spawn({
            let sup = Arc::clone(&sup);
            let id = id.clone();
            async move { sup.execute_now(&id).await }
        });
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .expect("the run never reached the backend");

        let other = TaskStore::new(memory.connection());
        assert!(
            !other
                .acquire_lease(&id, "another-process", LEASE_TTL_SECS)
                .await
                .unwrap(),
            "an in-flight run's lease must be visible to a second store"
        );
        assert!(
            !other
                .acquire_lease(&id, "another-process", LEASE_TTL_SECS)
                .await
                .unwrap(),
            "the refusal must be repeatable, not a one-off"
        );

        resume.notify_one();
        bounded("the run after its backend was released", running)
            .await
            .unwrap()
            .unwrap();

        assert!(
            other
                .acquire_lease(&id, "another-process", LEASE_TTL_SECS)
                .await
                .unwrap(),
            "the lease must be free again once the run has finished"
        );
    }

    /// Two runs of the **same task in one process** must not share a lease
    /// owner id. The lease operations are owner-checked and nothing else, so a
    /// shared id would let the detached release left behind by a cancelled run
    /// delete a later run's live lease for that task: the later run would keep
    /// working while another process was free to take the task over — the
    /// double execution the lease exists to prevent.
    ///
    /// The two owner ids are read from the lease row while each run is in
    /// flight, which is the only place they are observable — they are never
    /// logged, and the row is gone once the run releases it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_runs_of_one_task_in_one_process_use_different_lease_owners() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let backend_entered = Arc::clone(&entered);
        let backend_resume = Arc::clone(&resume);
        sup.register_test_reasoning_backend(move |_prompt| {
            let entered = Arc::clone(&backend_entered);
            let resume = Arc::clone(&backend_resume);
            async move {
                entered.notify_one();
                resume.notified().await;
                Ok("done".to_string())
            }
        });
        let sup = Arc::new(sup);
        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();

        // Run 1, cancelled mid-flight. It leaves the task in `Execute`, so a
        // second `execute_now` on the same task is legal (`Execute -> Plan`).
        let first = tokio::spawn({
            let sup = Arc::clone(&sup);
            let id = id.clone();
            async move { sup.execute_now(&id).await }
        });
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .expect("the first run never reached the backend");
        let first_owner = lease_owner(&memory, &id)
            .await
            .expect("the in-flight run must hold a lease row");

        first.abort();
        assert!(
            bounded("the cancelled first run", first)
                .await
                .unwrap_err()
                .is_cancelled(),
            "the first run was supposed to be cancelled, not to finish"
        );
        // Wait for the detached release, so run 2 below claims a free row
        // rather than the cancelled run's leftovers.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lease_owner(&memory, &id).await.is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the cancelled run never released its lease"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Run 2, same task, same `Supervisor`, same process.
        let second = tokio::spawn({
            let sup = Arc::clone(&sup);
            let id = id.clone();
            async move { sup.execute_now(&id).await }
        });
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .expect("the second run never reached the backend");
        let second_owner = lease_owner(&memory, &id)
            .await
            .expect("the second run must hold a lease row");

        assert_ne!(
            first_owner, second_owner,
            "two runs of one task in one process must not share a lease owner id, \
             or the cancelled run's detached release can free the later run's lease"
        );

        resume.notify_one();
        bounded("the second run after its backend was released", second)
            .await
            .unwrap()
            .unwrap();
        assert!(
            lease_owner(&memory, &id).await.is_none(),
            "the finished run must have released its lease"
        );
    }

    /// The cancellation path: a dropped `execute_now` future cannot await its
    /// cleanup, so `LeaseGuard::drop` releases the row with a detached task.
    /// Without that, a cancelled request would wedge the task for every process
    /// until the TTL ran out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cancelled_run_eventually_releases_the_execution_lease() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        let entered = Arc::new(tokio::sync::Notify::new());
        let backend_entered = Arc::clone(&entered);
        sup.register_test_reasoning_backend(move |_prompt| {
            let entered = Arc::clone(&backend_entered);
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                Ok(String::new())
            }
        });
        let sup = Arc::new(sup);
        let id = sup
            .submit("web", "u1", None, "summarize the readme")
            .await
            .unwrap()
            .task_id();

        let running = tokio::spawn({
            let sup = Arc::clone(&sup);
            let id = id.clone();
            async move { sup.execute_now(&id).await }
        });
        tokio::time::timeout(Duration::from_secs(10), entered.notified())
            .await
            .expect("the run never reached the backend");
        // The run holds the lease right now, or the rest of this proves nothing.
        let other = TaskStore::new(memory.connection());
        assert!(
            !other
                .acquire_lease(&id, "another-process", LEASE_TTL_SECS)
                .await
                .unwrap(),
            "the in-flight run must hold the lease before it is cancelled"
        );

        // Cancelling the request drops the `execute_now` future mid-run.
        running.abort();
        assert!(
            bounded("the cancelled run", running)
                .await
                .unwrap_err()
                .is_cancelled(),
            "the run was supposed to be cancelled, not to finish"
        );

        // `Drop` cannot await, so the release is detached: poll for it with a
        // bound instead of assuming it already happened.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if other
                .acquire_lease(&id, "another-process", LEASE_TTL_SECS)
                .await
                .unwrap()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a cancelled run never released its execution lease"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A shell task that declares a capability the operator has not granted is
    /// parked, and the reason names **the capability and the command that
    /// releases it** — not merely "approval required".
    ///
    /// Driven through `shell_gate_reason` rather than `submit`, and that is a
    /// real limitation rather than a preference: nothing populates
    /// `Task::declared_grants` from operator input in this revision, so a task
    /// reaching `submit` can never carry a declaration. A gate that cannot be
    /// made to fire cannot be shown to work, and a test that cannot make it fire
    /// cannot tell a working gate from one that never runs.
    #[tokio::test]
    async fn a_shell_task_declaring_an_ungranted_capability_is_parked_and_named() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup = sup.with_shell_isolation(Isolation::Sandboxed);

        let mut task = crate::supervisor::task::Task::new("t", "run the build");
        task.task_type = crate::supervisor::task::TaskType::OpsAutomation;
        task.risk_level = crate::supervisor::task::RiskLevel::Medium;
        task.required_capabilities = vec!["shell".into()];
        task.declared_grants
            .write
            .insert(std::path::PathBuf::from("/etc"));

        let reason = sup
            .shell_gate_reason(&task)
            .expect("an ungranted declaration must park the task");
        assert!(reason.contains("/etc"), "must name the path: {reason}");
        assert!(
            reason.contains("/allow /etc"),
            "must name the command that releases it: {reason}"
        );
        assert!(
            reason.contains(&task.id),
            "must name the task to approve: {reason}"
        );
    }

    /// The gate releases as soon as the capability is granted, and the grant is
    /// seen **through the operator's own handle** — which is what proves the
    /// supervisor and the shell backend share one `Arc<RwLock<Grants>>` rather
    /// than each holding a copy. Two copies would park a task for a grant the
    /// backend already had.
    #[tokio::test]
    async fn the_gate_releases_once_the_capability_is_granted_through_the_operators_handle() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let grants = std::sync::Arc::new(std::sync::RwLock::new(Grants::default()));
        let sup = sup
            .with_shell_isolation(Isolation::Sandboxed)
            .with_grants(grants.clone());

        let mut task = crate::supervisor::task::Task::new("t", "run the build");
        task.task_type = crate::supervisor::task::TaskType::OpsAutomation;
        task.risk_level = crate::supervisor::task::RiskLevel::Medium;
        task.required_capabilities = vec!["shell".into()];
        task.declared_grants
            .write
            .insert(std::path::PathBuf::from("/etc"));

        assert!(
            sup.shell_gate_reason(&task).is_some(),
            "ungranted must park"
        );
        grants
            .write()
            .unwrap()
            .grant_write("/etc", dir.path())
            .unwrap();
        assert!(
            sup.shell_gate_reason(&task).is_none(),
            "once granted, the gate must release: {:?}",
            sup.shell_gate_reason(&task)
        );
    }

    /// **The grant term does not apply under `Unconfined`, and this is spec §4
    /// at Layer 1.**
    ///
    /// `sandbox = "none"` *is* the operator's consent, so a declaration buys the
    /// job nothing and parking on it would cost an approval round-trip that
    /// changes nothing about what runs. Without this test, a gate that parked
    /// every mode would look correct.
    #[tokio::test]
    async fn an_unconfined_supervisor_does_not_park_on_the_grant_term() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup = sup.with_shell_isolation(Isolation::Unconfined);

        let mut task = crate::supervisor::task::Task::new("t", "run the build");
        task.task_type = crate::supervisor::task::TaskType::OpsAutomation;
        task.risk_level = crate::supervisor::task::RiskLevel::Medium;
        task.required_capabilities = vec!["shell".into()];
        task.declared_grants
            .write
            .insert(std::path::PathBuf::from("/etc"));

        assert!(
            sup.shell_gate_reason(&task).is_none(),
            "Unconfined is consent: got {:?}",
            sup.shell_gate_reason(&task)
        );
    }

    /// A shell task is parked for approval when the boundary is absent.
    ///
    /// The registry is registered **deliberately**: the gate asks it, so with an
    /// empty registry `select_for` returns `None`, the gate never fires, and the
    /// task auto-executes — the test would pass for the wrong reason. This is
    /// also the only proof that `Isolation::needs_approval` has a production
    /// caller at all.
    #[tokio::test]
    async fn a_shell_task_is_parked_for_approval_when_isolation_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup =
            sup.with_shell_isolation(Isolation::Unavailable(IsolationUnavailable::NotInstalled));

        let outcome = bounded("submit", sup.submit("test", "u1", None, "run the build"))
            .await
            .unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::NeedsApproval { .. }),
            "got {outcome:?}"
        );
        let id = outcome.task_id();
        assert_eq!(sup.state(&id).await.unwrap(), TaskStatus::Route);
    }

    /// A task that does not select the shell backend is not gated by its gate.
    #[tokio::test]
    async fn a_reasoning_task_is_not_gated_by_the_shell_gate() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup =
            sup.with_shell_isolation(Isolation::Unavailable(IsolationUnavailable::NotInstalled));

        let outcome = bounded(
            "submit",
            // **American spelling, and it is load-bearing.** The plan's snippet
            // said "summarise"; `HeuristicClassifier` matches the literal
            // `starts_with("summarize")`, so the British spelling falls through
            // to `TaskType::Unknown`, and `PolicyEngine` answers `Clarify` for an
            // Unknown low-risk task — the test would then fail on
            // `NeedsClarification` without the gate ever being consulted. This
            // spelling classifies as `GeneralAssistant`/Low, which auto-executes
            // and requires only `["reasoning"]`.
            sup.submit("test", "u1", None, "summarize this document"),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::AutoExecutePlanned { .. }),
            "a task that does not select the shell backend must not be gated, got {outcome:?}"
        );
    }

    /// Spec §4: with `sandbox = "none"` **nothing is gated**.
    ///
    /// This is the mode the refusal message sends an operator to, so parking
    /// their shell tasks anyway would make the way out a dead end.
    ///
    /// Task 8 supersedes this as the coverage for §4 — it adds a second gate
    /// term this test cannot see (the task it submits declares no capability, so
    /// `missing` is empty either way) and adds
    /// `an_unconfined_shell_task_declaring_an_ungranted_capability_is_not_gated`.
    /// It is kept as the `submit`-level integration check.
    #[tokio::test]
    async fn a_shell_task_is_not_gated_when_the_operator_chose_none() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut sup = Supervisor::new_for_test(dir.path().into(), memory.connection());
        sup.registry
            .register(std::sync::Arc::new(ShellBackend::new(dir.path().into())));
        let sup = sup.with_shell_isolation(Isolation::Unconfined);

        let outcome = bounded("submit", sup.submit("test", "u1", None, "run the build"))
            .await
            .unwrap();
        assert!(
            matches!(outcome, SubmitOutcome::AutoExecutePlanned { .. }),
            "`sandbox = \"none\"` is consent: nothing is gated, got {outcome:?}"
        );
    }
}
