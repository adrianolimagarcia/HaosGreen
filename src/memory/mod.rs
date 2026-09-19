pub mod conversations;
pub mod embeddings;
pub mod knowledge;
pub mod query_rewriter;
pub mod rag;
pub mod summarizer;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::config::MemoryConfig;
use crate::memory::embeddings::{EmbeddingConfig, EmbeddingEngine};

/// Thread-safe SQLite memory store with hybrid vector+FTS5 search
#[derive(Clone)]
pub struct MemoryStore {
    conn: Arc<Mutex<Connection>>,
    pub embeddings: Arc<EmbeddingEngine>,
    pub config: MemoryConfig,
}

impl MemoryStore {
    /// Open or create the SQLite database at the given path.
    /// If `embedding_config` is provided, vector search is enabled alongside FTS5.
    /// If None, falls back to FTS5-only search.
    pub fn open(
        path: &Path,
        embedding_config: Option<EmbeddingConfig>,
        memory_config: MemoryConfig,
    ) -> Result<Self> {
        // Register sqlite-vec extension before opening any connection
        unsafe {
            type VecInitFn = unsafe extern "C" fn(
                *mut rusqlite::ffi::sqlite3,
                *mut *mut i8,
                *const rusqlite::ffi::sqlite3_api_routines,
            ) -> i32;
            rusqlite::ffi::sqlite3_auto_extension(Some(
                std::mem::transmute::<*const (), VecInitFn>(
                    sqlite_vec::sqlite3_vec_init as *const (),
                ),
            ));
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open database: {}", path.display()))?;

        // No `busy_timeout` call here: rusqlite already sets one. Every
        // connection it opens calls `sqlite3_busy_timeout(db, 5000)` inside
        // `InnerConnection::open_with_flags`, so the 5 s default is in force
        // without this file asking for it — and calling `busy_timeout(5 s)`
        // here would be a no-op that only looks like it does something. The
        // 5 s value is what bounds a contended write in the lease paths; see
        // `LEASE_RENEW_BACKOFFS` in `src/supervisor/mod.rs`.
        // Enable WAL mode for better concurrent read performance
        // journal_mode PRAGMA always returns the resulting mode, so use query_row
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        let embeddings = EmbeddingEngine::new(embedding_config);

        // Run migrations on the raw connection before wrapping in Mutex.
        // This avoids blocking_lock() panic when called from async context.
        Self::run_migrations(&conn, embeddings.dimensions())?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            embeddings: Arc::new(embeddings),
            config: memory_config,
        };

        info!("Memory store initialized at: {}", path.display());
        Ok(store)
    }

    /// Open an in-memory database (for testing)
    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self> {
        unsafe {
            type VecInitFn = unsafe extern "C" fn(
                *mut rusqlite::ffi::sqlite3,
                *mut *mut i8,
                *const rusqlite::ffi::sqlite3_api_routines,
            ) -> i32;
            rusqlite::ffi::sqlite3_auto_extension(Some(
                std::mem::transmute::<*const (), VecInitFn>(
                    sqlite_vec::sqlite3_vec_init as *const (),
                ),
            ));
        }

        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        let embeddings = EmbeddingEngine::new(None);

        Self::run_migrations(&conn, embeddings.dimensions())?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
            embeddings: Arc::new(embeddings),
            config: MemoryConfig::default(),
        };
        Ok(store)
    }

    /// Expose the underlying connection for modules that share the DB.
    #[allow(dead_code)]
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    fn run_migrations(conn: &Connection, dims: usize) -> Result<()> {
        conn.execute_batch(
            "
            -- Conversations table
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                user_id TEXT NOT NULL,
                started_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Messages table
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT,
                tool_calls TEXT,
                tool_call_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conversation
                ON messages(conversation_id, created_at);

            CREATE INDEX IF NOT EXISTS idx_conversations_user
                ON conversations(platform, user_id, updated_at);

            -- Knowledge table
            CREATE TABLE IF NOT EXISTS knowledge (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_knowledge_key
                ON knowledge(category, key);

            -- FTS5 virtual tables for full-text search
            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                content,
                content=messages,
                content_rowid=rowid
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                key,
                value,
                content=knowledge,
                content_rowid=rowid
            );

            -- Triggers to keep FTS in sync
            CREATE TRIGGER IF NOT EXISTS messages_fts_insert AFTER INSERT ON messages
            WHEN NEW.content IS NOT NULL BEGIN
                INSERT INTO messages_fts(rowid, content) VALUES (NEW.rowid, NEW.content);
            END;

            CREATE TRIGGER IF NOT EXISTS messages_fts_delete AFTER DELETE ON messages
            WHEN OLD.content IS NOT NULL BEGIN
                INSERT INTO messages_fts(messages_fts, rowid, content)
                    VALUES('delete', OLD.rowid, OLD.content);
            END;

            CREATE TRIGGER IF NOT EXISTS knowledge_fts_insert AFTER INSERT ON knowledge BEGIN
                INSERT INTO knowledge_fts(rowid, key, value)
                    VALUES (NEW.rowid, NEW.key, NEW.value);
            END;

            CREATE TRIGGER IF NOT EXISTS knowledge_fts_delete AFTER DELETE ON knowledge BEGIN
                INSERT INTO knowledge_fts(knowledge_fts, rowid, key, value)
                    VALUES('delete', OLD.rowid, OLD.key, OLD.value);
            END;

            CREATE TRIGGER IF NOT EXISTS knowledge_fts_update AFTER UPDATE ON knowledge BEGIN
                INSERT INTO knowledge_fts(knowledge_fts, rowid, key, value)
                    VALUES('delete', OLD.rowid, OLD.key, OLD.value);
                INSERT INTO knowledge_fts(rowid, key, value)
                    VALUES (NEW.rowid, NEW.key, NEW.value);
            END;

            -- Schema metadata (e.g. embedding dimension for vec tables)
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- Scheduled tasks for user-registered reminders / recurring jobs
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id               TEXT PRIMARY KEY,
                scheduler_job_id TEXT,
                user_id          TEXT NOT NULL,
                chat_id          TEXT NOT NULL,
                platform         TEXT NOT NULL,
                trigger_type     TEXT NOT NULL,
                trigger_value    TEXT NOT NULL,
                prompt           TEXT NOT NULL,
                description      TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'active',
                created_at       TEXT NOT NULL DEFAULT (datetime('now')),
                next_run_at      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_user
                ON scheduled_tasks(user_id, status);

            -- Scheduled task execution history
            CREATE TABLE IF NOT EXISTS scheduled_task_runs (
                id          TEXT PRIMARY KEY,
                task_id     TEXT NOT NULL,
                run_at      TEXT NOT NULL,
                response    TEXT,
                error       TEXT,
                status      TEXT NOT NULL DEFAULT 'completed',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (task_id) REFERENCES scheduled_tasks(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scheduled_task_runs_task
                ON scheduled_task_runs(task_id, run_at);

            -- Supervisor: tasks
            CREATE TABLE IF NOT EXISTS sup_tasks (
                id              TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                user_request    TEXT NOT NULL,
                task_type       TEXT NOT NULL,
                priority        INTEGER NOT NULL DEFAULT 5,
                risk_level      TEXT NOT NULL,
                execution_mode  TEXT NOT NULL,
                workflow        TEXT NOT NULL,
                state           TEXT NOT NULL,
                required_capabilities TEXT NOT NULL DEFAULT '[]',
                inputs          TEXT,
                constraints     TEXT,
                expected_outputs TEXT,
                approval_policy TEXT,
                platform        TEXT NOT NULL,
                user_id         TEXT NOT NULL,
                chat_id         TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_sup_tasks_state ON sup_tasks(state, updated_at);
            CREATE INDEX IF NOT EXISTS idx_sup_tasks_user  ON sup_tasks(user_id, state);

            -- Supervisor: jobs
            CREATE TABLE IF NOT EXISTS sup_jobs (
                id              TEXT PRIMARY KEY,
                task_id         TEXT NOT NULL,
                parent_job_id   TEXT,
                job_type        TEXT NOT NULL,
                backend         TEXT NOT NULL,
                goal            TEXT NOT NULL,
                prompt          TEXT,
                input_context   TEXT,
                timeout_secs    INTEGER NOT NULL,
                retry_max       INTEGER NOT NULL DEFAULT 0,
                retry_count     INTEGER NOT NULL DEFAULT 0,
                allow_tools     TEXT,
                workspace       TEXT,
                status          TEXT NOT NULL,
                result_summary  TEXT,
                result_evidence TEXT,
                error           TEXT,
                started_at      TEXT,
                finished_at     TEXT,
                FOREIGN KEY (task_id) REFERENCES sup_tasks(id)
            );
            CREATE INDEX IF NOT EXISTS idx_sup_jobs_task ON sup_jobs(task_id, status);

            -- Supervisor: state transitions
            CREATE TABLE IF NOT EXISTS sup_transitions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id     TEXT NOT NULL,
                from_state  TEXT NOT NULL,
                to_state    TEXT NOT NULL,
                reason      TEXT,
                actor       TEXT NOT NULL,
                occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (task_id) REFERENCES sup_tasks(id)
            );

            -- Supervisor: artifacts
            CREATE TABLE IF NOT EXISTS sup_artifacts (
                id          TEXT PRIMARY KEY,
                task_id     TEXT NOT NULL,
                job_id      TEXT,
                kind        TEXT NOT NULL,
                path        TEXT NOT NULL,
                sha256      TEXT,
                bytes       INTEGER,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (task_id) REFERENCES sup_tasks(id)
            );
            CREATE INDEX IF NOT EXISTS idx_sup_artifacts_task ON sup_artifacts(task_id, kind);

            -- Supervisor: cross-process execution leases. One row per task that
            -- is currently being run, `expires_at`/`renewed_at` are integer
            -- epoch seconds so a competing process reads the same meaning.
            --
            -- Deviation from the plan's Step 3 schema, which named the second
            -- timestamp column `acquired_at`: this table stores `renewed_at`
            -- instead. The column is written by both `acquire_lease` (as the
            -- acquisition stamp) and `renew_lease` (as the last renewal), so
            -- `acquired_at` would be a name that lies about half its writes.
            -- No production code reads `renewed_at` today (`expires_at` is read
            -- only by the takeover predicate inside `acquire_lease` and the
            -- lapse guard inside `renew_lease`; tests do read both); the columns
            -- are there so an operator can read the row by hand and see when it
            -- was last touched.
            CREATE TABLE IF NOT EXISTS sup_execution_leases (
                task_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                renewed_at INTEGER NOT NULL
            );
            -- Read by exactly one query: the expiry-driven sweep in
            -- `TaskStore::sweep_expired_leases` (`DELETE ... WHERE expires_at <=
            -- ?1`), called once at startup. `renew_lease` and `release_lease`
            -- both report `SEARCH sup_execution_leases USING INDEX
            -- sqlite_autoindex_sup_execution_leases_1 (task_id=?)` under
            -- `EXPLAIN QUERY PLAN` — they are key- and owner-addressed, so they
            -- cannot use this index — and the takeover is an upsert whose
            -- conflict target is the PRIMARY KEY, so its `expires_at <= ?now`
            -- predicate is applied to the one row that key lookup found. The
            -- sweep is therefore the **only** reader, and this comment used to
            -- say the opposite: it described the index as write-only
            -- amplification for now, kept for a sweep that did not exist, and
            -- warned not to cite a benefit the current paths did not have. That
            -- was accurate and was the defect — an index rewritten on every 60 s
            -- heartbeat renewal, per running task, read by nothing. The sweep
            -- exists now, and `the_lease_sweep_is_the_query_the_expiry_index_
            -- exists_for` asserts the plan still names this index, so it cannot
            -- quietly become dead weight again.
            CREATE INDEX IF NOT EXISTS idx_sup_execution_leases_expiry
                ON sup_execution_leases(expires_at);

            -- A2A: one row per remote task. `state` is the A2A TaskState
            -- lowercased so it can be filtered; `data` holds the whole
            -- serialized `a2a::Task` so the SDK's TaskStore round-trips every
            -- field it cares about without us mirroring its schema.
            --
            -- History lives inside `data`, not a separate table: the SDK's
            -- `Task` already carries its own `history`, and a second table
            -- would be a second source of truth with no reader. Add one in the
            -- phase that actually queries messages.
            CREATE TABLE IF NOT EXISTS a2a_tasks (
                id          TEXT PRIMARY KEY,
                context_id  TEXT NOT NULL,
                peer        TEXT NOT NULL DEFAULT '',
                state       TEXT NOT NULL,
                data        TEXT NOT NULL,
                version     INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_a2a_tasks_peer ON a2a_tasks(peer, updated_at);
            ",
        )?;

        // Migration: add is_summarized column (safe no-op if column already exists)
        conn.execute_batch("ALTER TABLE messages ADD COLUMN is_summarized BOOLEAN DEFAULT 0;")
            .ok(); // ok() because ALTER TABLE fails if column already exists — that's intentional

        conn.execute_batch("ALTER TABLE conversations ADD COLUMN is_archived INTEGER DEFAULT 0;")
            .ok(); // safe no-op: ALTER TABLE fails with "duplicate column" on re-run

        // Stored embedding dimension (None if legacy DB without schema_meta row)
        let raw: Option<String> = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'embedding_dims'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("schema_meta query")?;
        let stored_dims: Option<usize> = raw.and_then(|s| s.parse().ok());

        let need_migrate = !matches!(stored_dims, Some(s) if s == dims);

        let table_exists = |conn: &Connection, name: &str| -> bool {
            conn.query_row(
                &format!(
                    "SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name='{}'",
                    name
                ),
                [],
                |row| row.get(0),
            )
            .unwrap_or(false)
        };

        if need_migrate {
            // Drop vec tables so we can recreate with new dimension
            if table_exists(conn, "message_embeddings") {
                conn.execute_batch("DROP TABLE message_embeddings;")?;
            }
            if table_exists(conn, "knowledge_embeddings") {
                conn.execute_batch("DROP TABLE knowledge_embeddings;")?;
            }
            conn.execute_batch(&format!(
                "CREATE VIRTUAL TABLE message_embeddings USING vec0(embedding float[{}]);",
                dims
            ))?;
            conn.execute_batch(&format!(
                "CREATE VIRTUAL TABLE knowledge_embeddings USING vec0(embedding float[{}]);",
                dims
            ))?;
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('embedding_dims', ?1)",
                [dims.to_string()],
            )?;
            if let Some(prev_dims) = stored_dims {
                info!(
                    "Embedding dimension changed from {} to {}; vector tables recreated.",
                    prev_dims, dims
                );
            }
        } else {
            // Create vec tables only if they don't exist (same dimension)
            if !table_exists(conn, "message_embeddings") {
                conn.execute_batch(&format!(
                    "CREATE VIRTUAL TABLE message_embeddings USING vec0(embedding float[{}]);",
                    dims
                ))?;
                conn.execute(
                    "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('embedding_dims', ?1)",
                    [dims.to_string()],
                )?;
            }
            if !table_exists(conn, "knowledge_embeddings") {
                conn.execute_batch(&format!(
                    "CREATE VIRTUAL TABLE knowledge_embeddings USING vec0(embedding float[{}]);",
                    dims
                ))?;
                if stored_dims.is_none() {
                    conn.execute(
                        "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('embedding_dims', ?1)",
                        [dims.to_string()],
                    )?;
                }
            }
        }

        // Migration: ensure message_embeddings has metadata columns (is_summarized, role)
        // for pre-filtering, and no existing rows with NULL metadata.
        // ALTER TABLE is not supported for vec0, so we must DROP and recreate.
        if table_exists(conn, "message_embeddings") {
            let cols: Vec<String> = conn
                .prepare("PRAGMA table_info(message_embeddings)")
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| row.get(1))?
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap_or_default();

            let has_meta = cols.contains(&"is_summarized".to_string());

            let needs_recreate = if has_meta {
                // Columns exist but old rows may have NULL metadata because the
                // original INSERT didn't write metadata columns. Check for NULLs.
                conn.query_row(
                    "SELECT COUNT(*) FROM message_embeddings WHERE is_summarized IS NULL",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .map(|count| count > 0)
                .unwrap_or(false)
            } else {
                true
            };

            if needs_recreate {
                conn.execute_batch("DROP TABLE message_embeddings;")?;
                conn.execute_batch(&format!(
                    "CREATE VIRTUAL TABLE message_embeddings USING vec0(\
                     embedding float[{}], is_summarized integer, role text);",
                    dims
                ))?;
                info!(
                    "Migrated message_embeddings with metadata columns (is_summarized, role){}",
                    if has_meta {
                        " and rebuilt existing data"
                    } else {
                        ""
                    }
                );
            }
        }

        // Migration: `sup_transitions.task_id` must be nullable.
        //
        // A grant is process-wide, not task-scoped: `/allow /etc` is not a
        // transition of any task, so its audit row has no `sup_tasks` row to
        // point at. The column was declared NOT NULL with a foreign key, which
        // makes that row impossible to write. NULL is allowed in a foreign key
        // column, so the rebuild is enough — no foreign key is dropped.
        //
        // `PRAGMA foreign_keys=OFF` must precede `BEGIN`: SQLite ignores the
        // pragma inside a transaction, and with it on, `DROP TABLE` would
        // cascade or refuse. It is restored after `COMMIT`.
        //
        // `DROP TABLE` takes the table's indexes with it, so the rebuild is
        // lossy for anything declared in the DDL batch above. `sup_transitions`
        // had no index when this was written and the comment said so; it has one
        // now, created **below** rather than in the batch, precisely so this
        // `DROP` cannot silently remove it. Do not move that statement up.
        // `notnull` is a **reserved SQLite keyword**, so the unquoted form is a
        // syntax error, not a false answer: `SELECT notnull FROM
        // pragma_table_info(...)` fails to parse. The plan's snippet wrote it
        // unquoted and then wrapped the result in `.unwrap_or(false)`, which
        // swallowed that syntax error and read it as "no rebuild needed" — so
        // the migration was dead code that looked alive, and the only symptom
        // was a NOT NULL violation much later, at the first audit write. The
        // identifier is quoted, and a real error is propagated rather than
        // collapsed into `false`.
        let not_null: bool = match conn.query_row(
            "SELECT \"notnull\" FROM pragma_table_info('sup_transitions') WHERE name = 'task_id'",
            [],
            |r| r.get::<_, i64>(0),
        ) {
            Ok(n) => n == 1,
            // The table does not exist yet: nothing to rebuild.
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(e) => {
                return Err(e).context("read sup_transitions.task_id nullability");
            }
        };
        if not_null {
            conn.execute_batch(
                "PRAGMA foreign_keys=OFF;
                 BEGIN;
                 CREATE TABLE sup_transitions_new (
                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                     task_id     TEXT,
                     from_state  TEXT NOT NULL,
                     to_state    TEXT NOT NULL,
                     reason      TEXT,
                     actor       TEXT NOT NULL,
                     occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
                     FOREIGN KEY (task_id) REFERENCES sup_tasks(id)
                 );
                 INSERT INTO sup_transitions_new
                     (id, task_id, from_state, to_state, reason, actor, occurred_at)
                     SELECT id, task_id, from_state, to_state, reason, actor, occurred_at
                     FROM sup_transitions;
                 DROP TABLE sup_transitions;
                 ALTER TABLE sup_transitions_new RENAME TO sup_transitions;
                 COMMIT;
                 PRAGMA foreign_keys=ON;",
            )
            .context("rebuild sup_transitions so task_id is nullable")?;
            info!("Rebuilt sup_transitions so a grant audit row can be written");
        }

        // Index the audit log by task, which is how the task-detail route reads
        // it (`TaskStore::transitions`: `WHERE task_id=?1 ORDER BY id ASC`).
        //
        // Measured on 200k rows: `SCAN sup_transitions` 11.55 ms against
        // `SEARCH sup_transitions USING INDEX idx_sup_transitions_task
        // (task_id=?)` 0.27 ms — a 43x factor. The table is append-only and never
        // pruned, so the scan only degrades. Every sibling table already carries
        // the matching index (`idx_sup_jobs_task`, `idx_sup_artifacts_task`);
        // this one did not.
        //
        // **It is created here, after the rebuild, and must not be moved into
        // the DDL batch above.** The batch declares `sup_transitions.task_id` as
        // `NOT NULL` and the rebuild above drops and recreates the table on
        // *every* database — fresh ones included, not just pre-existing ones — so
        // an index declared in the batch would be created and then immediately
        // dropped, and would never exist anywhere. The placement is the fix, not
        // a detail of it.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sup_transitions_task \
             ON sup_transitions(task_id, id)",
            [],
        )
        .context("index sup_transitions by task_id")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_tasks_table_exists() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let conn = conn.blocking_lock();
        let exists: bool = conn
            .query_row(
                "SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name='scheduled_tasks'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists);
    }

    #[test]
    fn sup_tables_exist_after_migration() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let conn = conn.blocking_lock();
        for tbl in [
            "sup_tasks",
            "sup_jobs",
            "sup_transitions",
            "sup_artifacts",
            "sup_execution_leases",
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT count(*)>0 FROM sqlite_master WHERE type='table' AND name=?1",
                    [tbl],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "table {tbl} missing");
        }
        // The index is present, as the approved plan requires. This asserts its
        // *existence*, not a performance property: no current path queries
        // `expires_at` on its own, so nothing today is made cheaper by it (see
        // the schema comment above).
        let indexed: bool = conn
            .query_row(
                "SELECT count(*)>0 FROM sqlite_master WHERE type='index' AND name=?1",
                ["idx_sup_execution_leases_expiry"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            indexed,
            "index idx_sup_execution_leases_expiry missing on sup_execution_leases(expires_at)"
        );
    }

    /// The audit log is indexed by task — **and the index survives the rebuild**.
    ///
    /// That second half is the whole point. `run_migrations` declares
    /// `sup_transitions.task_id` as `NOT NULL` and then rebuilds the table to make
    /// it nullable, dropping the original. So an index declared in the DDL batch
    /// would be created and then immediately dropped, and would exist on **no**
    /// database at all — fresh ones included, because the batch DDL always
    /// creates the `NOT NULL` form and the rebuild always fires.
    ///
    /// A test that only asserted "the index exists" on an already-migrated
    /// database would pass under that mistake. Asserting it **after a full
    /// `run_migrations`**, together with the query plan that consumes it, is what
    /// pins the placement rather than the statement.
    #[test]
    fn sup_transitions_is_indexed_by_task_after_the_rebuild() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let conn = conn.blocking_lock();

        // The rebuild really ran: this is a fresh store, so a nullable `task_id`
        // can only have come from it.
        let not_null: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('sup_transitions') WHERE name='task_id'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            not_null, 0,
            "the rebuild must have run and made task_id nullable"
        );

        // And the index is there after it, not merely before.
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' \
                 AND name='idx_sup_transitions_task'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            idx, 1,
            "the index must survive the rebuild; an index declared in the DDL batch is dropped by it"
        );

        // Which is only worth anything if the reader uses it.
        let mut stmt = conn
            .prepare(
                "EXPLAIN QUERY PLAN SELECT task_id, from_state, to_state, reason, actor, \
                 occurred_at FROM sup_transitions WHERE task_id=?1 ORDER BY id ASC",
            )
            .unwrap();
        let plan: Vec<String> = stmt
            .query_map(["t"], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let plan = plan.join(" | ");
        assert!(
            plan.contains("idx_sup_transitions_task"),
            "the task-detail query must use the index, or it is a full scan of an \
             append-only table: {plan}"
        );
    }

    /// The rebuild's job is to **preserve** the audit log while making `task_id`
    /// nullable, and nothing exercised the copy.
    ///
    /// The rebuild fires on every database — the DDL batch declares
    /// `task_id TEXT NOT NULL`, so a fresh store creates that form and the
    /// rebuild immediately replaces it. But on a fresh store the table is
    /// **empty**, so `INSERT INTO sup_transitions_new SELECT ...` copies zero
    /// rows, and a rebuild that dropped every row would still pass every other
    /// test in the suite. This one builds the shipped schema on disk, fills it,
    /// and then opens it through the real entry point.
    ///
    /// It is also the only test that observes the index on a **migrated**
    /// database rather than a fresh one, which is the case the placement in
    /// `run_migrations` exists for.
    #[test]
    fn the_rebuild_preserves_existing_audit_rows_and_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("haos-green.db");

        // The schema as it shipped: `sup_transitions.task_id` NOT NULL with a
        // foreign key to `sup_tasks`, and no index on it. `sup_tasks` carries
        // its full column set because `run_migrations` indexes two of them.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE sup_tasks (
                     id TEXT PRIMARY KEY, title TEXT NOT NULL, user_request TEXT NOT NULL,
                     task_type TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 5,
                     risk_level TEXT NOT NULL, execution_mode TEXT NOT NULL,
                     workflow TEXT NOT NULL, state TEXT NOT NULL,
                     required_capabilities TEXT NOT NULL DEFAULT '[]', inputs TEXT,
                     constraints TEXT, expected_outputs TEXT, approval_policy TEXT,
                     platform TEXT NOT NULL, user_id TEXT NOT NULL, chat_id TEXT,
                     created_at TEXT NOT NULL DEFAULT (datetime('now')),
                     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                 );
                 CREATE TABLE sup_transitions (
                     id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
                     from_state TEXT NOT NULL, to_state TEXT NOT NULL, reason TEXT,
                     actor TEXT NOT NULL, occurred_at TEXT NOT NULL DEFAULT (datetime('now')),
                     FOREIGN KEY (task_id) REFERENCES sup_tasks(id)
                 );
                 INSERT INTO sup_tasks (id, title, user_request, task_type, risk_level, execution_mode, workflow, state, platform, user_id)
                     VALUES ('task-old', 't', 'r', 'Ops', 'Low', 'AutoExecute', 'Fast', 'DONE', 'telegram', 'u');
                 INSERT INTO sup_transitions (task_id, from_state, to_state, reason, actor)
                     VALUES ('task-old', 'Route', 'Plan', 'the row that must survive', 'operator');",
            )
            .unwrap();
        }

        // The real entry point: this runs the migrations, rebuild included.
        let store = MemoryStore::open(&path, None, MemoryConfig::default()).unwrap();
        let conn = store.connection();
        let conn = conn.blocking_lock();

        let (task_id, reason): (String, String) = conn
            .query_row(
                "SELECT task_id, reason FROM sup_transitions WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("the pre-existing audit row must survive the rebuild");
        assert_eq!(task_id, "task-old");
        assert_eq!(reason, "the row that must survive");

        // And the column really is nullable now, which is the point of the
        // rebuild: a grant audit row belongs to no task.
        conn.execute(
            "INSERT INTO sup_transitions (task_id, from_state, to_state, actor) VALUES (NULL, 'grant', 'write', 'dashboard')",
            [],
        )
        .expect("a NULL task_id must be accepted after the rebuild");

        // A migrated database gets the index too, not only a fresh one.
        let idx: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_sup_transitions_task'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(idx, 1, "a migrated database must have the index as well");
    }

    #[test]
    fn a2a_tasks_table_exists_after_migration() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let conn = conn.blocking_lock();
        let exists: bool = conn
            .query_row(
                "SELECT count(*)>0 FROM sqlite_master WHERE type='table' AND name=?1",
                ["a2a_tasks"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "table a2a_tasks missing");
    }

    #[test]
    fn a2a_tasks_accepts_a_round_trip_row() {
        // Guards the column set the SqliteTaskStore writes: a NOT NULL column
        // added later without a default would break the store's INSERT.
        let memory = MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let conn = conn.blocking_lock();
        conn.execute(
            "INSERT INTO a2a_tasks (id, context_id, peer, state, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["t1", "ctx", "laptop", "submitted", "{}"],
        )
        .expect("insert must succeed with the columns the store supplies");
        let version: i64 = conn
            .query_row("SELECT version FROM a2a_tasks WHERE id='t1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, 1, "version must default to 1");
    }

    #[test]
    fn test_connection_accessor_returns_working_connection() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let conn = conn.blocking_lock();
        let n: i64 = conn.query_row("SELECT 42", [], |row| row.get(0)).unwrap();
        assert_eq!(n, 42);
    }
}
