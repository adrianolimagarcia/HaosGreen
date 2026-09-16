//! SQLite-backed [`TaskStore`] over the existing RustFox database.
//!
//! Mirrors `src/supervisor/store.rs`: a cloneable handle over the shared
//! connection, with `async fn` methods that lock it.
//!
//! The whole `a2a::Task` is stored as JSON in `a2a_tasks.data` rather than
//! shredded into columns, so the SDK can round-trip every field it cares about
//! without this module mirroring (and drifting from) its schema. The columns
//! exist only for querying: `state` and `peer`.
//!
//! [`TaskStore`]: a2a_server::TaskStore

use a2a::errors::{error_code, A2AError};
use a2a::types::{ListTasksRequest, ListTasksResponse, Task};
use a2a_server::task_store::{TaskStore, TaskVersion};
use std::sync::Arc;
use tokio::sync::Mutex;

/// SQLite-backed task store.
#[derive(Clone)]
pub struct SqliteTaskStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteTaskStore {
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        Self { conn }
    }
}

/// The lowercase state string used for the `state` column.
///
/// `TaskState` has no `Display`; `Debug` yields the variant name, which is
/// what we want lowercased (`Submitted` -> `submitted`).
fn state_str(task: &Task) -> String {
    format!("{:?}", task.status.state).to_lowercase()
}

fn internal(e: impl std::fmt::Display) -> A2AError {
    A2AError::new(error_code::INTERNAL_ERROR, e.to_string())
}

#[async_trait::async_trait]
impl TaskStore for SqliteTaskStore {
    async fn create(&self, task: Task) -> Result<TaskVersion, A2AError> {
        let data = serde_json::to_string(&task).map_err(internal)?;
        let state = state_str(&task);
        let conn = self.conn.lock().await;
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO a2a_tasks (id, context_id, peer, state, data, version)
                 VALUES (?1, ?2, '', ?3, ?4, 1)",
                rusqlite::params![task.id, task.context_id, state, data],
            )
            .map_err(internal)?;
        if changed == 0 {
            // Matches `InMemoryTaskStore`, which errors on a duplicate id
            // rather than silently overwriting.
            return Err(internal(format!("task '{}' already exists", task.id)));
        }
        Ok(1)
    }

    async fn update(&self, task: Task) -> Result<TaskVersion, A2AError> {
        let data = serde_json::to_string(&task).map_err(internal)?;
        let state = state_str(&task);
        let conn = self.conn.lock().await;
        let changed = conn
            .execute(
                "UPDATE a2a_tasks
                    SET context_id = ?2, state = ?3, data = ?4,
                        version = version + 1, updated_at = datetime('now')
                  WHERE id = ?1",
                rusqlite::params![task.id, task.context_id, state, data],
            )
            .map_err(internal)?;
        if changed == 0 {
            // MUST be exactly TASK_NOT_FOUND. `DefaultRequestHandler::save_task`
            // (handler.rs:201-210) calls `update` first and only falls back to
            // `create` when the error code is this one. Returning anything
            // else -- including Ok -- means the task is silently never created.
            return Err(A2AError::task_not_found(&task.id));
        }
        let version: i64 = conn
            .query_row(
                "SELECT version FROM a2a_tasks WHERE id = ?1",
                [&task.id],
                |r| r.get(0),
            )
            .map_err(internal)?;
        Ok(version as TaskVersion)
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT data FROM a2a_tasks WHERE id = ?1")
            .map_err(internal)?;
        let mut rows = stmt.query([task_id]).map_err(internal)?;
        match rows.next().map_err(internal)? {
            // A missing task is `None`, not an error: the SDK distinguishes
            // "absent" from "failed" and expects this shape.
            None => Ok(None),
            Some(row) => {
                let data: String = row.get(0).map_err(internal)?;
                serde_json::from_str(&data).map(Some).map_err(internal)
            }
        }
    }

    async fn list(&self, _req: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        // Phase 2 does not implement listing; `GetTask` and `ListTasks` are
        // Phase 3. Refuse explicitly rather than returning a misleading empty
        // page, which a client would read as "no tasks exist".
        Err(A2AError::unsupported_operation(
            "ListTasks is not implemented until Phase 3",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2a::types::{TaskState, TaskStatus};

    fn store() -> SqliteTaskStore {
        let mem = crate::memory::MemoryStore::open_in_memory().expect("open in-memory store");
        SqliteTaskStore::new(mem.connection())
    }

    fn task(id: &str, state: TaskState) -> Task {
        Task {
            id: id.to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus {
                state,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn update_on_a_missing_row_reports_task_not_found() {
        // Load-bearing. `save_task` only falls back to `create` when the error
        // code is exactly TASK_NOT_FOUND; any other code (or Ok) means the
        // task is never created, and the failure is silent.
        let err = store()
            .update(task("missing", TaskState::Working))
            .await
            .expect_err("update on a missing row must fail");
        assert_eq!(
            err.code,
            error_code::TASK_NOT_FOUND,
            "the SDK branches on this exact code"
        );
    }

    #[tokio::test]
    async fn create_then_get_round_trips_the_task() {
        let s = store();
        s.create(task("t1", TaskState::Submitted)).await.unwrap();
        let got = s.get("t1").await.unwrap().expect("task must exist");
        assert_eq!(got.id, "t1");
        assert_eq!(got.context_id, "ctx-1");
        assert_eq!(got.status.state, TaskState::Submitted);
    }

    #[tokio::test]
    async fn update_persists_the_new_state_and_bumps_the_version() {
        let s = store();
        let v1 = s.create(task("t2", TaskState::Submitted)).await.unwrap();
        let v2 = s.update(task("t2", TaskState::Completed)).await.unwrap();
        assert!(v2 > v1, "version must increase: {v1} -> {v2}");
        let got = s.get("t2").await.unwrap().unwrap();
        assert_eq!(got.status.state, TaskState::Completed);
    }

    #[tokio::test]
    async fn get_on_a_missing_task_is_none_not_an_error() {
        assert!(store().get("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn create_on_an_existing_id_is_an_error() {
        let s = store();
        s.create(task("dup", TaskState::Submitted)).await.unwrap();
        assert!(
            s.create(task("dup", TaskState::Submitted)).await.is_err(),
            "a duplicate id must not silently overwrite"
        );
    }

    #[tokio::test]
    async fn list_refuses_rather_than_returning_an_empty_page() {
        let err = store()
            .list(&ListTasksRequest {
                context_id: None,
                status: None,
                page_size: None,
                page_token: None,
                history_length: None,
                status_timestamp_after: None,
                include_artifacts: None,
                tenant: None,
            })
            .await
            .expect_err("list is not implemented in Phase 2");
        assert_eq!(err.code, error_code::UNSUPPORTED_OPERATION);
    }
}
