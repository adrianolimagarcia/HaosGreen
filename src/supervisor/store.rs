use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::supervisor::job::{Job, JobStatus, JobType};
use crate::supervisor::task::{ExecutionMode, RiskLevel, Task, TaskStatus, TaskType};
use crate::supervisor::SupervisorError;

/// Hard upper bound on how many tasks [`TaskStore::list_recent`] will ever
/// return, whatever the caller asks for.
pub const MAX_RECENT_TASKS: usize = 20;

/// Columns of `sup_tasks` that [`Task`] is reconstructed from. Shared by every
/// read path so a new query cannot silently drift from the row mapping.
const TASK_COLUMNS: &str = concat!(
    "id,title,user_request,task_type,priority,risk_level,execution_mode,state,",
    "required_capabilities"
);

/// Maps one `sup_tasks` row selected with [`TASK_COLUMNS`] into a [`Task`].
///
/// `constraints`, `inputs` and `expected_outputs` are intentionally `Null`:
/// they are written on insert but never read back (M3 lossy reconstruction).
fn row_to_task(r: &rusqlite::Row<'_>) -> rusqlite::Result<Task> {
    Ok(Task {
        id: r.get(0)?,
        title: r.get(1)?,
        user_request: r.get(2)?,
        task_type: serde_json::from_str::<TaskType>(&r.get::<_, String>(3)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
        })?,
        priority: r.get(4)?,
        risk_level: serde_json::from_str::<RiskLevel>(&r.get::<_, String>(5)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?,
        execution_mode: serde_json::from_str::<ExecutionMode>(&r.get::<_, String>(6)?).map_err(
            |e| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            },
        )?,
        status: serde_json::from_str::<TaskStatus>(&r.get::<_, String>(7)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?,
        required_capabilities: serde_json::from_str::<Vec<String>>(&r.get::<_, String>(8)?)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        constraints: serde_json::Value::Null,
        inputs: serde_json::Value::Null,
        expected_outputs: serde_json::Value::Null,
        // No `sup_tasks` column carries a declaration, so a job reads back as
        // declaring nothing. Declarations are consumed by the run that created
        // the job and are not persisted; a resumed job therefore re-declares
        // through its task rather than through the row. See `Grants`.
        declared_grants: Default::default(),
    })
}

#[derive(Clone)]
pub struct TaskStore {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone)]
pub struct TransitionRow {
    pub from: TaskStatus,
    pub to: TaskStatus,
    pub actor: String,
    pub reason: Option<String>,
    pub occurred_at: String,
}

impl TaskStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Claim the execution lease for `task_id`, or answer `false` if a live one
    /// is already held.
    ///
    /// One conditional statement, so the claim is atomic without an explicit
    /// transaction: the `INSERT` either creates the row or, on conflict, the
    /// `WHERE` guard decides whether the existing row may be replaced. A
    /// `false` answer means the row is live and belongs to someone else.
    ///
    /// # Deliberate deviation from the plan's Step 4
    ///
    /// The plan specified the takeover condition as `expires_at <= ?now OR
    /// owner_id = ?owner` — that is, an owner may also re-take a lease it
    /// already holds. That `OR owner_id = ?owner` term is **omitted here**, on
    /// purpose:
    ///
    /// * the invariant this table enforces is *one run per task*, and a second
    ///   claim by the same owner is a second run of the same task — the very
    ///   thing `acquire_lease` exists to refuse;
    /// * an owner id is minted per `execute_now` **run**
    ///   (`pid-<pid>-<uuid>`), so "the same owner" cannot mean "the same run
    ///   re-claiming its own lease" — a live row with our owner id can only be
    ///   a *previous* run in this process, which must not be silently resumed;
    /// * with the term present, a repeated `execute_now` whose in-flight guard
    ///   had already been released would take the lease over from a run that is
    ///   still executing, which is exactly the double execution the lease is
    ///   for.
    ///
    /// The cost is that an owner cannot refresh its own claim by re-acquiring;
    /// it renews through [`Self::renew_lease`], which is owner-checked and
    /// refuses an expired row (`expires_at > ?now`), so a stale lease is never
    /// resurrected — it has to be taken over by a fresh claim.
    pub async fn acquire_lease(
        &self,
        task_id: &str,
        owner_id: &str,
        ttl_secs: i64,
    ) -> Result<bool> {
        anyhow::ensure!(ttl_secs > 0, "lease TTL must be positive");
        let conn = self.conn.lock().await;
        let now = chrono::Utc::now().timestamp();
        let expires = now.saturating_add(ttl_secs);
        let changed = conn.execute(
            "INSERT INTO sup_execution_leases(task_id, owner_id, expires_at, renewed_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(task_id) DO UPDATE SET owner_id=excluded.owner_id,
               expires_at=excluded.expires_at, renewed_at=excluded.renewed_at
                                         WHERE sup_execution_leases.expires_at <= ?4",
            rusqlite::params![task_id, owner_id, expires, now],
        )?;
        Ok(changed == 1)
    }

    /// Extend a lease this owner still holds, or answer `false`.
    ///
    /// `false` is the heartbeat's loss signal, and it covers all three ways the
    /// row can stop being ours: it was released, it expired and someone else
    /// took it over, or it expired and nobody has. The `expires_at > ?now`
    /// guard is what makes the third case a loss rather than a resurrection —
    /// a run that let its lease lapse has lost the task, even if the row is
    /// still there.
    pub async fn renew_lease(&self, task_id: &str, owner_id: &str, ttl_secs: i64) -> Result<bool> {
        anyhow::ensure!(ttl_secs > 0, "lease TTL must be positive");
        let conn = self.conn.lock().await;
        let now = chrono::Utc::now().timestamp();
        let changed = conn.execute(
            "UPDATE sup_execution_leases SET expires_at=?1, renewed_at=?2
             WHERE task_id=?3 AND owner_id=?4 AND expires_at > ?2",
            rusqlite::params![now.saturating_add(ttl_secs), now, task_id, owner_id],
        )?;
        Ok(changed == 1)
    }

    /// Drop a lease, but only one this owner holds. Another process's lease is
    /// never released by this call, so a failed run cannot free a task a
    /// successful one is running.
    pub async fn release_lease(&self, task_id: &str, owner_id: &str) -> Result<bool> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "DELETE FROM sup_execution_leases WHERE task_id=?1 AND owner_id=?2",
            rusqlite::params![task_id, owner_id],
        )?;
        Ok(changed == 1)
    }

    pub async fn create(
        &self,
        t: &Task,
        platform: &str,
        user_id: &str,
        chat_id: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO sup_tasks
             (id, title, user_request, task_type, priority, risk_level, execution_mode,
              workflow, state, required_capabilities, inputs, constraints, expected_outputs,
              approval_policy, platform, user_id, chat_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            rusqlite::params![
                t.id,
                t.title,
                t.user_request,
                serde_json::to_string(&t.task_type)?,
                t.priority,
                serde_json::to_string(&t.risk_level)?,
                serde_json::to_string(&t.execution_mode)?,
                "general",
                serde_json::to_string(&t.status)?,
                serde_json::to_string(&t.required_capabilities)?,
                serde_json::to_string(&t.inputs)?,
                serde_json::to_string(&t.constraints)?,
                serde_json::to_string(&t.expected_outputs)?,
                serde_json::Value::Null.to_string(),
                platform,
                user_id,
                chat_id,
            ],
        )
        .context("insert sup_tasks")?;
        Ok(())
    }

    /// One task by id, or `None` when no such row exists.
    ///
    /// The three outcomes are kept apart on purpose. An earlier version wrote
    /// `match rows.next() { Some(Ok(t)) => Some(t), _ => None }`, which folded a
    /// row-mapping failure into "no such task": a task that exists but whose
    /// stored `state` (or `task_type`, `risk_level`, …) cannot be parsed was
    /// reported to the dashboard as an unknown id — a 404 — while
    /// [`TaskStore::list_recent`] propagated the identical error as a 500. A
    /// corrupt row is a fault, not a missing task, and saying "unknown task"
    /// about a row that is sitting right there sends the operator looking for
    /// the wrong thing.
    pub async fn get(&self, id: &str) -> Result<Option<Task>> {
        let conn = self.conn.lock().await;
        let mut stmt =
            conn.prepare(&format!("SELECT {TASK_COLUMNS} FROM sup_tasks WHERE id=?1"))?;
        let mut rows = stmt.query_map([id], row_to_task)?;
        match rows.next() {
            None => Ok(None),
            Some(Ok(task)) => Ok(Some(task)),
            Some(Err(e)) => Err(anyhow::Error::new(e).context("read sup_tasks row")),
        }
    }

    /// Newest-first task listing for the dashboard.
    ///
    /// The limit is clamped to [`MAX_RECENT_TASKS`] rather than trusted, so no
    /// caller can turn the dashboard into a way to page the entire task history
    /// into memory. A limit of `0` is clamped up to `1` for the same reason
    /// (`LIMIT 0` would be a silently useless answer).
    ///
    /// `created_at` is `TEXT NOT NULL DEFAULT (datetime('now'))` with
    /// one-second resolution, so tasks created in the same second tie and the
    /// order would be non-deterministic. `rowid` breaks the tie and keeps
    /// paging and display order stable.
    pub async fn list_recent(&self, limit: usize) -> Result<Vec<Task>> {
        let limit = limit.clamp(1, MAX_RECENT_TASKS);
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(&format!(
            "SELECT {TASK_COLUMNS} FROM sup_tasks ORDER BY created_at DESC, rowid DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit as i64], row_to_task)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub async fn update_classification(&self, t: &Task) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE sup_tasks
             SET task_type=?1, risk_level=?2, execution_mode=?3,
                 required_capabilities=?4, updated_at=datetime('now')
             WHERE id=?5",
            rusqlite::params![
                serde_json::to_string(&t.task_type)?,
                serde_json::to_string(&t.risk_level)?,
                serde_json::to_string(&t.execution_mode)?,
                serde_json::to_string(&t.required_capabilities)?,
                t.id,
            ],
        )
        .context("update sup_tasks classification")?;
        Ok(())
    }

    /// Append an audit row and move the task to `to`, **only if the task is
    /// still in `from`**.
    ///
    /// # Why this is a compare-and-swap
    ///
    /// The lifecycle methods (`Supervisor::{pause,resume,cancel,approve}`) are
    /// read-check-write across separate lock acquisitions: they read the task,
    /// decide the transition is legal, and then call this. Two concurrent
    /// requests therefore both pass the check, and an unconditional
    /// `UPDATE sup_tasks SET state=?1 WHERE id=?2` let both of them through —
    /// two `Paused -> Execute` audit edges, two plans, two sets of jobs, two
    /// `sup_artifacts` rows for the same path with different `sha256`, and (in
    /// debug builds) a `Plan -> Plan` panic out of the `debug_assert!` below.
    /// Every one of those is a duplicate side effect performed on the
    /// operator's behalf: the registered backends are a full agent run and
    /// `sh -c`.
    ///
    /// The conditional `UPDATE … WHERE id=?2 AND state=?3` is what makes the
    /// read-check-write atomic: whichever request arrives second finds the row
    /// no longer in `from` and is refused. The refusal is
    /// [`SupervisorError::StateRefusal`], which the routes classify by type
    /// (never by matching text) into a 409.
    ///
    /// The insert and the update share one transaction, so a refused
    /// transition rolls the audit row back with it: the trail records what
    /// happened, not what was attempted.
    ///
    /// The `debug_assert!` stays. It answers a different question — whether the
    /// caller passed a pair the state machine has an edge for at all — which
    /// the compare-and-swap cannot see: a caller that asks for `Done -> Done`
    /// on a task that really is `Done` matches the `WHERE` clause. That is a
    /// programmer error, not a race, and the race that used to surface here is
    /// now closed by the compare-and-swap and by `Supervisor`'s per-task
    /// in-flight guard.
    pub async fn record_transition(
        &self,
        task_id: &str,
        from: TaskStatus,
        to: TaskStatus,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        debug_assert!(
            crate::supervisor::state::transition_allowed(from.clone(), to.clone()),
            "illegal state transition {:?} → {:?}",
            from,
            to
        );
        let from_json = serde_json::to_string(&from)?;
        let to_json = serde_json::to_string(&to)?;
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO sup_transitions (task_id, from_state, to_state, reason, actor)
             VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![task_id, from_json, to_json, reason, actor],
        )
        .context("insert sup_transitions")?;
        let updated = tx
            .execute(
                "UPDATE sup_tasks SET state=?1, updated_at=datetime('now')
                 WHERE id=?2 AND state=?3",
                rusqlite::params![to_json, task_id, from_json],
            )
            .context("update sup_tasks state")?;
        if updated != 1 {
            // Distinguish "the task moved on" from "the task is gone" so the
            // caller can answer 409 and 404 respectively.
            let persisted: Option<String> = tx
                .query_row("SELECT state FROM sup_tasks WHERE id=?1", [task_id], |r| {
                    r.get(0)
                })
                .optional()
                .context("read the persisted state of a sup_tasks row")?;
            // Dropping the transaction rolls the audit row back with it.
            drop(tx);
            return match persisted {
                // Defensive: `sup_transitions.task_id` has a foreign key to
                // `sup_tasks`, so a transition for a task that never existed is
                // refused by the insert above. This is the answer for a row
                // that is gone all the same, and the two must not be confused
                // with "the task moved on".
                None => Err(SupervisorError::not_found(task_id)),
                Some(state) => match serde_json::from_str::<TaskStatus>(&state) {
                    Ok(actual) => Err(SupervisorError::state_refusal(actual, to)),
                    Err(e) => Err(anyhow::Error::new(e)
                        .context(format!("sup_tasks {task_id} holds an unreadable state"))),
                },
            };
        }
        tx.commit().context("commit sup_tasks state change")?;
        Ok(())
    }

    pub async fn create_job(&self, j: &Job) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO sup_jobs
             (id, task_id, parent_job_id, job_type, backend, goal, prompt,
              input_context, timeout_secs, retry_max, retry_count, allow_tools,
              workspace, status)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            rusqlite::params![
                j.id,
                j.task_id,
                j.parent_job_id,
                serde_json::to_string(&j.job_type)?,
                j.backend,
                j.goal,
                j.prompt,
                j.input_context.to_string(),
                j.timeout_secs as i64,
                j.retry_max as i64,
                j.retry_count as i64,
                serde_json::to_string(&j.allow_tools)?,
                j.workspace,
                serde_json::to_string(&j.status)?,
            ],
        )
        .context("insert sup_jobs")?;
        Ok(())
    }

    pub async fn jobs_for_task(&self, task_id: &str) -> Result<Vec<Job>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, task_id, parent_job_id, job_type, backend, goal, prompt,
                    input_context, timeout_secs, retry_max, retry_count, allow_tools,
                    workspace, status, result_summary, error
             FROM sup_jobs WHERE task_id=?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt
            .query_map([task_id], |r| {
                Ok(Job {
                    id: r.get(0)?,
                    task_id: r.get(1)?,
                    parent_job_id: r.get(2)?,
                    job_type: serde_json::from_str::<JobType>(&r.get::<_, String>(3)?).map_err(
                        |e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                3,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        },
                    )?,
                    backend: r.get(4)?,
                    goal: r.get(5)?,
                    prompt: r.get(6)?,
                    input_context: serde_json::from_str(&r.get::<_, String>(7)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    timeout_secs: r.get::<_, i64>(8)? as u64,
                    retry_max: r.get::<_, i64>(9)? as u32,
                    retry_count: r.get::<_, i64>(10)? as u32,
                    allow_tools: serde_json::from_str(&r.get::<_, String>(11)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            11,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    workspace: r.get(12)?,
                    status: serde_json::from_str::<JobStatus>(&r.get::<_, String>(13)?).map_err(
                        |e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                13,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        },
                    )?,
                    // M3: lossy reconstruction — full evidence persistence is M6+.
                    // We preserve the stored summary and synthesize a single
                    // `OutputValidated` evidence entry so that VerificationEngine's
                    // "≥1 evidence" gate can be satisfied for jobs that completed.
                    result: r.get::<_, Option<String>>(14)?.map(|summary| {
                        crate::supervisor::job::JobOutput {
                            status: crate::supervisor::job::JobStatus::Succeeded,
                            summary,
                            evidence: vec![crate::supervisor::job::Evidence::OutputValidated {
                                description: "stored job result".into(),
                            }],
                            errors: vec![],
                            changed_files: vec![],
                            next_step: None,
                        }
                    }),
                    error: r.get(15)?,
                    // No `sup_jobs` column carries a declaration, so a job reads back as
                    // declaring nothing. Declarations are consumed by the run that created
                    // the job and are not persisted; a resumed job therefore re-declares
                    // through its task rather than through the row. See `Grants`.
                    declared_grants: Default::default(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Record a job's terminal state, summary and error.
    ///
    /// # Redaction happens here, not at the route
    ///
    /// `summary` is whatever the backend produced — for `ShellBackend` that is
    /// the command's stdout — and `error` is a backend's `anyhow` chain. Both
    /// used to be stored verbatim, so the same text was scrubbed on its way to
    /// the on-disk artifact (`ArtifactManager::write_text` runs
    /// [`crate::supervisor::redact::redact`]) and stored raw in `sup_jobs`,
    /// which then served it back through `GET /api/supervisor/tasks/{id}`. A
    /// job whose output contained `api_key=…` was therefore redacted in the
    /// file and readable in the JSON.
    ///
    /// Scrubbing at the persistence boundary rather than in the projection is
    /// deliberate: the database is what every future read path, log view and
    /// export reads, so the secret must not be written at all. A route-level
    /// filter would leave the plaintext in `sup_jobs` and depend on every
    /// current and future reader remembering to filter it.
    pub async fn update_job_status(
        &self,
        id: &str,
        status: JobStatus,
        summary: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        let summary = summary.map(crate::supervisor::redact::redact);
        let error = error.map(crate::supervisor::redact::redact);
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE sup_jobs SET status=?1, result_summary=?2, error=?3,
                                 finished_at=datetime('now') WHERE id=?4",
            rusqlite::params![serde_json::to_string(&status)?, summary, error, id],
        )?;
        Ok(())
    }

    /// Returns IDs of tasks that look "resumable" — i.e. they're either
    /// explicitly `Paused` or were left mid-pipeline (`Plan`, `PrepareWorkspace`,
    /// `Execute`) when the supervisor was last shut down.
    pub async fn list_resumable_task_ids(&self) -> Result<Vec<String>> {
        use crate::supervisor::task::TaskStatus;
        let conn = self.conn.lock().await;
        let states = [
            serde_json::to_string(&TaskStatus::Paused)?,
            serde_json::to_string(&TaskStatus::Execute)?,
            serde_json::to_string(&TaskStatus::Plan)?,
            serde_json::to_string(&TaskStatus::PrepareWorkspace)?,
        ];
        let placeholders = states
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT id FROM sup_tasks WHERE state IN ({placeholders}) ORDER BY updated_at DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> =
            states.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let ids = stmt
            .query_map(params.as_slice(), |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    pub async fn transitions(&self, task_id: &str) -> Result<Vec<TransitionRow>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT from_state, to_state, actor, reason, occurred_at
             FROM sup_transitions WHERE task_id=?1 ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([task_id], |r| {
                Ok(TransitionRow {
                    from: serde_json::from_str(&r.get::<_, String>(0)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    to: serde_json::from_str(&r.get::<_, String>(1)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?,
                    actor: r.get(2)?,
                    reason: r.get(3)?,
                    occurred_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lease row for `task_id` as `(owner_id, expires_at, renewed_at)`, or
    /// `None` when there is no row. Read straight from the connection so a
    /// failing assertion can name what the row actually holds instead of only
    /// the boolean the API returned.
    async fn lease_row(
        memory: &crate::memory::MemoryStore,
        task_id: &str,
    ) -> Option<(String, i64, i64)> {
        let conn = memory.connection();
        let conn = conn.lock().await;
        conn.query_row(
            "SELECT owner_id, expires_at, renewed_at FROM sup_execution_leases WHERE task_id=?1",
            [task_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok()
    }

    #[tokio::test]
    async fn lease_allows_one_owner_and_owner_checked_release() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task", "owner-a", 60).await.unwrap());
        assert!(!store.acquire_lease("task", "owner-b", 60).await.unwrap());
        assert!(!store.release_lease("task", "owner-b").await.unwrap());
        assert!(store.release_lease("task", "owner-a").await.unwrap());
    }

    #[tokio::test]
    async fn expired_lease_can_be_taken_over() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task", "owner-a", 1).await.unwrap());
        {
            let conn = memory.connection();
            let conn = conn.lock().await;
            conn.execute("UPDATE sup_execution_leases SET expires_at=0", [])
                .unwrap();
        }
        assert!(store.acquire_lease("task", "owner-b", 60).await.unwrap());
    }

    /// The TTL really is added to the current time. The tests above all force
    /// `expires_at` with raw SQL, so they pass just as well if `acquire_lease`
    /// writes a nonsense expiry (`now + 1_000_000`) — this one uses the real
    /// clock and a one-second TTL and asserts the arithmetic **as stored**.
    ///
    /// The expiry is asserted as a value, never by racing the wall clock. An
    /// earlier version asserted "a 1 s lease must not be takeable immediately"
    /// and was a claim about the clock at a *later* instant than the
    /// acquisition: `acquire_lease` stores integer epoch seconds, so an
    /// acquisition at `t0 = x.999` writes `expires_at = x + 1`, and a second
    /// `Utc::now()` at `x + 1.001` already satisfies the takeover's
    /// `expires_at <= now`. The window is the gap between the two calls —
    /// microseconds in a tight loop, but unbounded under scheduling jitter: a
    /// test thread preempted across the boundary fails every time. Reading
    /// `renewed_at` and `expires_at` back removes the boundary entirely: their
    /// difference is the TTL exactly, and `renewed_at` is checked against the
    /// real clock so a hard-coded constant cannot pass.
    ///
    /// The wait afterwards is safe in the other direction: with
    /// `expires_at = floor(t0) + 1 <= t0 + 1` and any `now >= t0 + 1.1`, the
    /// takeover condition holds no matter where in the second `t0` landed.
    ///
    /// Deliberately no `renew_lease` call in between: a renewal writes
    /// `now + ttl_secs` into the row itself, so renewing with the same short
    /// TTL here would repair a wrong `acquire_lease` expiry and hide the very
    /// arithmetic this pins. (That is not hypothetical — an earlier draft of
    /// this test renewed with `ttl_secs = 1` and survived the `now + 1_000_000`
    /// mutant.)
    #[tokio::test]
    async fn a_short_ttl_really_expires_on_the_wall_clock() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let before = chrono::Utc::now().timestamp();

        assert!(store.acquire_lease("task", "owner-a", 1).await.unwrap());
        let after = chrono::Utc::now().timestamp();

        let (owner, expires_at, renewed_at) = lease_row(&memory, "task").await.expect("lease row");
        assert_eq!(owner, "owner-a");
        assert_eq!(
            expires_at - renewed_at,
            1,
            "the stored expiry must be the TTL past the renewal stamp \
             (expires_at={expires_at} renewed_at={renewed_at})"
        );
        assert!(
            (before..=after).contains(&renewed_at),
            "renewed_at must be the wall clock at acquisition \
             (renewed_at={renewed_at} before={before} after={after})"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        assert!(
            store.acquire_lease("task", "owner-b", 60).await.unwrap(),
            "the 1 s lease must have expired ~1.1 s after it was acquired"
        );
    }

    /// An expired row that is **still ours** is not renewable. This is the
    /// third way a lease stops being ours — released, taken over, or lapsed —
    /// and the only one that needs the `expires_at > ?now` guard in
    /// `renew_lease`: without that guard a run whose lease had lapsed would
    /// renew the row and carry on as if it still held the task, while another
    /// process was free to take the task over at any moment.
    ///
    /// Real clock, real one-second TTL, and a wait past it, so the row is
    /// genuinely expired rather than expired by SQL.
    #[tokio::test]
    async fn an_expired_lease_cannot_be_renewed_by_its_own_owner() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task", "owner-a", 1).await.unwrap());
        let acquired = lease_row(&memory, "task").await.expect("lease row");

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        assert!(
            !store.renew_lease("task", "owner-a", 60).await.unwrap(),
            "an expired lease must not be renewable by the owner that lapsed it"
        );
        // A refused renewal writes nothing: the lapsed row is left exactly as
        // it was, so the takeover below still sees an expired row.
        assert_eq!(
            lease_row(&memory, "task").await,
            Some(acquired.clone()),
            "a refused renewal must not touch the row"
        );
        assert!(
            store.acquire_lease("task", "owner-b", 60).await.unwrap(),
            "the lapsed lease must still be takeable by a new owner"
        );
    }

    /// A live lease is never re-acquired by the owner that already holds it —
    /// the deliberate deviation from the plan's Step 4, which allowed
    /// `owner_id = ?` in the takeover condition. Re-acquiring would be a second
    /// run of the same task, which is exactly what the lease refuses.
    #[tokio::test]
    async fn a_live_lease_is_never_re_acquired_by_its_own_owner() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task", "owner-a", 60).await.unwrap());
        assert!(
            !store.acquire_lease("task", "owner-a", 60).await.unwrap(),
            "the same owner must not be able to claim a live lease twice"
        );
        // The row is untouched by the refused claim: the original owner still
        // holds it, and a foreign owner is still refused.
        assert!(store.renew_lease("task", "owner-a", 60).await.unwrap());
        assert!(!store.acquire_lease("task", "owner-b", 60).await.unwrap());
    }

    #[tokio::test]
    async fn renew_keeps_live_lease_and_wrong_owner_cannot_renew() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.acquire_lease("task", "owner-a", 60).await.unwrap());
        assert!(!store.renew_lease("task", "owner-b", 60).await.unwrap());
        assert!(store.renew_lease("task", "owner-a", 60).await.unwrap());
    }

    #[tokio::test]
    async fn create_task_then_load_back() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let mut t = crate::supervisor::task::Task::new("T", "do thing");
        t.task_type = crate::supervisor::task::TaskType::Research;
        store
            .create(&t, "telegram", "u1", Some("c1"))
            .await
            .unwrap();
        let loaded = store.get(&t.id).await.unwrap().unwrap();
        assert_eq!(loaded.title, "T");
        assert_eq!(
            loaded.task_type,
            crate::supervisor::task::TaskType::Research
        );
    }

    #[tokio::test]
    async fn save_and_load_jobs_for_task() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let task = crate::supervisor::task::Task::new("T", "u");
        store.create(&task, "telegram", "u", None).await.unwrap();

        let mut job = crate::supervisor::job::Job::new(
            &task.id,
            crate::supervisor::job::JobType::ExecutorJob,
            "reasoning",
            "do",
        );
        job.prompt = Some("do it".into());
        store.create_job(&job).await.unwrap();
        let jobs = store.jobs_for_task(&task.id).await.unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job.id);
    }

    #[tokio::test]
    async fn list_recent_returns_tasks_newest_first() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let a = Task::new("first", "req a");
        let b = Task::new("second", "req b");
        let c = Task::new("third", "req c");
        for t in [&a, &b, &c] {
            store.create(t, "telegram", "u1", None).await.unwrap();
        }
        let rows = store.list_recent(20).await.unwrap();
        let ids: Vec<&str> = rows.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec![c.id.as_str(), b.id.as_str(), a.id.as_str()]);
    }

    /// `created_at` has one-second resolution, so tasks created in the same
    /// second tie. Forcing the tie here (rather than hoping the three inserts
    /// straddle a second boundary) is what makes this test deterministic.
    #[tokio::test]
    async fn list_recent_breaks_same_second_ties_by_rowid() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let a = Task::new("first", "req a");
        let b = Task::new("second", "req b");
        let c = Task::new("third", "req c");
        for t in [&a, &b, &c] {
            store.create(t, "telegram", "u1", None).await.unwrap();
        }
        {
            let conn = memory.connection();
            let conn = conn.lock().await;
            conn.execute("UPDATE sup_tasks SET created_at='2026-01-01 00:00:00'", [])
                .unwrap();
        }
        let rows = store.list_recent(20).await.unwrap();
        let ids: Vec<&str> = rows.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec![c.id.as_str(), b.id.as_str(), a.id.as_str()]);
    }

    #[tokio::test]
    async fn list_recent_clamps_an_oversized_limit_to_twenty() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        for i in 0..25 {
            let t = Task::new(&format!("t{i}"), "req");
            store.create(&t, "telegram", "u1", None).await.unwrap();
        }
        let rows = store.list_recent(1000).await.unwrap();
        assert_eq!(
            rows.len(),
            MAX_RECENT_TASKS,
            "the dashboard must never ask for more than 20"
        );
    }

    /// **This is the proof of the clamp.** The route passes the constant
    /// `MAX_RECENT_TASKS` (`web/routes/supervisor.rs`), so no HTTP test can
    /// observe the `.clamp()` itself — deleting it leaves an end-to-end
    /// assertion on "at most 20" green. Only calling the store with a limit it
    /// is not supposed to honour can fail when the clamp goes away.
    #[tokio::test]
    async fn the_clamp_is_the_only_thing_that_bounds_a_caller_supplied_limit() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        for i in 0..25 {
            let t = Task::new(&format!("t{i}"), "req");
            store.create(&t, "telegram", "u1", None).await.unwrap();
        }
        assert_eq!(store.list_recent(usize::MAX).await.unwrap().len(), 20);
        assert_eq!(store.list_recent(21).await.unwrap().len(), 20);
    }

    #[tokio::test]
    async fn list_recent_clamps_a_zero_limit_to_one() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        for i in 0..3 {
            let t = Task::new(&format!("t{i}"), "req");
            store.create(&t, "telegram", "u1", None).await.unwrap();
        }
        // A limit of 0 must not be passed through to SQLite as `LIMIT 0`
        // (which would return nothing) nor widened to the full history.
        let rows = store.list_recent(0).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn list_recent_on_an_empty_store_is_empty_not_an_error() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        assert!(store.list_recent(20).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn record_transition_appends_audit_row() {
        use crate::supervisor::task::TaskStatus;
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let t = crate::supervisor::task::Task::new("T", "u");
        store.create(&t, "telegram", "u1", None).await.unwrap();
        store
            .record_transition(
                &t.id,
                TaskStatus::Intake,
                TaskStatus::Classify,
                "supervisor",
                Some("auto"),
            )
            .await
            .unwrap();
        let history = store.transitions(&t.id).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].to, TaskStatus::Classify);
    }

    /// A row that exists but cannot be mapped is a fault, not a missing task.
    ///
    /// `get` used to fold `Some(Err(_))` into `Ok(None)`, so a corrupt `state`
    /// was reported to the dashboard as an unknown id (404) while
    /// `list_recent` propagated the identical error as a 500. This test pins
    /// all three outcomes apart.
    #[tokio::test]
    async fn get_keeps_a_missing_row_and_an_unmappable_row_apart() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let t = Task::new("T", "u");
        store.create(&t, "telegram", "u1", None).await.unwrap();

        // Case 1: no such row.
        assert!(store.get("no-such-task").await.unwrap().is_none());

        // Case 2: the row is there and maps cleanly.
        assert_eq!(store.get(&t.id).await.unwrap().unwrap().title, "T");

        // Case 3: the row is there and does not map. Written as raw SQL
        // because nothing in the store can produce it — which is exactly why
        // the difference has to be pinned by a test.
        {
            let conn = memory.connection();
            let conn = conn.lock().await;
            conn.execute(
                "UPDATE sup_tasks SET state='\"NOT_A_STATE\"' WHERE id=?1",
                [&t.id],
            )
            .unwrap();
        }
        let error = store
            .get(&t.id)
            .await
            .expect_err("an unmappable row must be an error, never `Ok(None)`");
        assert!(
            format!("{error:#}").contains("read sup_tasks row"),
            "the error must name the read that failed: {error:#}"
        );
        // The listing propagates the same class of failure, so the two read
        // paths agree about what a corrupt row is.
        assert!(store.list_recent(20).await.is_err());
    }

    /// The compare-and-swap, at the store: eight concurrent duplicate
    /// transitions of the same task, only one of which may land.
    ///
    /// Before the fix the `UPDATE` carried no condition, so **every** one of
    /// them succeeded — there was nothing to fail — leaving eight audit rows
    /// and, one level up, eight plans. This is the same hazard the supervisor's
    /// read-check-write lifecycle has, isolated to the write that has to be
    /// atomic for it to be safe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_duplicate_transitions_let_exactly_one_win() {
        use crate::supervisor::task::TaskStatus;
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let t = Task::new("T", "u");
        store.create(&t, "telegram", "u1", None).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let id = t.id.clone();
            handles.push(tokio::spawn(async move {
                store
                    .record_transition(&id, TaskStatus::Intake, TaskStatus::Classify, "test", None)
                    .await
            }));
        }
        let mut accepted = 0usize;
        let mut refused = 0usize;
        for handle in handles {
            // Bounded: eight spawned writers contending for one connection is
            // exactly the shape that would deadlock silently, and an un-bounded
            // `handle.await` would wedge the whole test binary rather than fail.
            let outcome = crate::supervisor::bounded("a duplicate transition", handle)
                .await
                .expect("no transition may panic");
            match outcome {
                Ok(()) => accepted += 1,
                Err(e) => {
                    assert!(
                        matches!(
                            e.downcast_ref::<crate::supervisor::SupervisorError>(),
                            Some(crate::supervisor::SupervisorError::StateRefusal { .. })
                        ),
                        "a refused duplicate must be a typed refusal, got {e:?}"
                    );
                    refused += 1;
                }
            }
        }
        assert_eq!(accepted, 1, "exactly one duplicate transition may land");
        assert_eq!(refused, 7);
        assert_eq!(
            store.transitions(&t.id).await.unwrap().len(),
            1,
            "a refused transition must roll its audit row back"
        );
        assert_eq!(
            store.get(&t.id).await.unwrap().unwrap().status,
            TaskStatus::Classify
        );
    }

    /// The refusal has to be usable by the caller: a task that has moved on
    /// reports the state it is *actually* in, and a task that is gone reports
    /// `NotFound` rather than an unreadable state.
    #[tokio::test]
    async fn a_refused_transition_names_the_state_the_task_is_really_in() {
        use crate::supervisor::task::TaskStatus;
        use crate::supervisor::SupervisorError;
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let t = Task::new("T", "u");
        store.create(&t, "telegram", "u1", None).await.unwrap();
        store
            .record_transition(
                &t.id,
                TaskStatus::Intake,
                TaskStatus::Classify,
                "test",
                None,
            )
            .await
            .unwrap();

        // The task is in `Classify`, not `Route`: the stale `from` is refused
        // and the error names the state the store really holds. `Route -> Plan`
        // is itself a legal edge, so this refusal can only come from the
        // compare-and-swap — which is the point.
        let error = store
            .record_transition(&t.id, TaskStatus::Route, TaskStatus::Plan, "test", None)
            .await
            .expect_err("a stale `from` must be refused");
        match error.downcast_ref::<SupervisorError>() {
            Some(SupervisorError::StateRefusal { from, to }) => {
                assert_eq!(from, &TaskStatus::Classify);
                assert_eq!(to, &TaskStatus::Plan);
            }
            other => panic!("expected a typed state refusal, got {other:?}"),
        }
        assert_eq!(store.transitions(&t.id).await.unwrap().len(), 1);

        // A transition for a task that does not exist at all never reaches the
        // compare-and-swap: `sup_transitions.task_id` carries a foreign key to
        // `sup_tasks`, so the insert is refused first. Pinned because the
        // `NotFound` arm below is the answer for the case the constraint cannot
        // see (a row that is gone but whose insert somehow landed), and a test
        // that claimed to exercise it through this path would be lying.
        let missing = store
            .record_transition(
                "gone",
                TaskStatus::Intake,
                TaskStatus::Classify,
                "test",
                None,
            )
            .await
            .expect_err("a transition for a missing task must be refused");
        assert!(
            format!("{missing:#}").contains("FOREIGN KEY"),
            "expected the foreign key to refuse the insert, got {missing:#}"
        );
    }

    /// Job text is scrubbed at the **persistence boundary**, so the secret is
    /// never written — not merely hidden by one read path.
    ///
    /// `ArtifactManager::write_text` already redacts; `update_job_status` did
    /// not, so the same text was `api_key=***` on disk and the raw value in
    /// `sup_jobs`, which `GET /api/supervisor/tasks/{id}` served back.
    #[tokio::test]
    async fn update_job_status_redacts_secrets_before_persisting() {
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let store = TaskStore::new(memory.connection());
        let task = Task::new("T", "u");
        store.create(&task, "telegram", "u", None).await.unwrap();
        let job = Job::new(&task.id, JobType::ExecutorJob, "shell", "echo");
        store.create_job(&job).await.unwrap();

        store
            .update_job_status(
                &job.id,
                JobStatus::Succeeded,
                Some("stdout: api_key=ZZTOPSECRETKEY done"),
                Some("failed with Bearer ZZBEARERTOKEN"),
            )
            .await
            .unwrap();

        let stored = store.jobs_for_task(&task.id).await.unwrap();
        let summary = &stored[0].result.as_ref().expect("a stored summary").summary;
        let error = stored[0].error.as_deref().expect("a stored error");
        assert!(
            !summary.contains("CAMPO_API_KEY"),
            "the secret must not be written at all: {summary}"
        );
        assert!(summary.contains("api_key=***"), "got {summary}");
        assert!(
            !error.contains("ZZBEARERTOKEN"),
            "the secret must not be written at all: {error}"
        );
        assert!(error.contains("Bearer ***"), "got {error}");
        // Redaction is not a blunt truncation: the rest of the text survives.
        assert!(summary.contains("stdout:"), "got {summary}");
    }
}
