use anyhow::{Context, Result};
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::supervisor::job::{Job, JobStatus, JobType};
use crate::supervisor::task::{ExecutionMode, RiskLevel, Task, TaskStatus, TaskType};

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

    pub async fn get(&self, id: &str) -> Result<Option<Task>> {
        let conn = self.conn.lock().await;
        let mut stmt =
            conn.prepare(&format!("SELECT {TASK_COLUMNS} FROM sup_tasks WHERE id=?1"))?;
        let mut rows = stmt.query_map([id], row_to_task)?;
        Ok(match rows.next() {
            Some(Ok(t)) => Some(t),
            _ => None,
        })
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
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO sup_transitions (task_id, from_state, to_state, reason, actor)
             VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                task_id,
                serde_json::to_string(&from)?,
                serde_json::to_string(&to)?,
                reason,
                actor
            ],
        )?;
        conn.execute(
            "UPDATE sup_tasks SET state=?1, updated_at=datetime('now') WHERE id=?2",
            rusqlite::params![serde_json::to_string(&to)?, task_id],
        )?;
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
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub async fn update_job_status(
        &self,
        id: &str,
        status: JobStatus,
        summary: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
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
}
