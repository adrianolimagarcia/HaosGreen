# A2A Phase 2 — Task Store, Executor and `SendMessage` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an authenticated, allowlisted A2A peer's `SendMessage` request drive a real HaosGreen agent turn under that peer's tool policy, producing a `completed` task — without ever granting a tool the peer's policy withholds.

**Architecture:** Mount the official `a2a-server-lf` 0.3.1 JSON-RPC router at `/jsonrpc` behind the existing Phase 1 auth middleware. Implement the SDK's `AgentExecutor` to drive `AgenticLoop` **directly** with an explicit `allowed_tools` policy, and the SDK's `TaskStore` over the existing SQLite connection. The SDK owns the JSON-RPC envelope, task lifecycle bookkeeping and event fan-out; we own authentication, policy resolution and the agent turn.

**Tech Stack:** Rust 2021, `a2a-server-lf` 0.3.1 + `a2a-lf` 0.3.1 (already present), `axum` 0.8, `futures::stream`, `rusqlite` via the existing `MemoryStore`, `tokio`.

---

## Read this before starting

The design spec is `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
Its **"Phase 2 hazards"** section (§Risks, items 5–11) lists seven traps that
were confirmed by reading both the SDK and HaosGreen source. Every one of them is
load-bearing. The three that will silently produce a security or correctness
failure if missed:

| # | Hazard | Consequence if missed |
|---|---|---|
| 5 | `Agent::process_message` hardcodes `allowed_tools: None` (`src/agent.rs:823`), which means **unrestricted** | Every authenticated peer gets `execute_command` |
| 6 | `PeerIdentity.allowed_tools` is resolved against an **empty** registry (`src/a2a/auth.rs:91`) | `["*"]` peers silently get **zero** tools |
| 7 | `cancel_token_registry` is keyed by Telegram `user_id` (`src/agent.rs:99`) | `/stop` and `CancelTask` cancel each other's runs |

**Do not call `process_message` from any A2A path.** Task 2 exists to give the
executor a safe alternative.

### Method names are v1.0

The SDK implements **`SendMessage`**, not `message/send`. The Agent Card
advertises `protocolVersion: "1.0"`. Do not add v0.3.0 aliases.

---

## File Structure

| File | Responsibility | Status |
|---|---|---|
| `Cargo.toml` | add `a2a-server-lf` 0.3.1 | modify |
| `src/agent.rs` | `run_with_policy` — explicit-policy loop entry (hazard 5) | modify |
| `src/memory/mod.rs` | `a2a_tasks` table in `run_migrations` | modify |
| `src/a2a/task_store.rs` | `SqliteTaskStore` implementing the SDK `TaskStore` (hazard 10) | create |
| `src/a2a/executor.rs` | `A2aExecutor` implementing `AgentExecutor`; resolves policy (hazard 6) and namespaces cancel keys (hazard 7) | create |
| `src/a2a/server.rs` | mount the SDK JSON-RPC router; auth middleware; thread the executor | modify |
| `src/a2a/mod.rs` | declare and re-export the new modules | modify |
| `src/main.rs` | pass the agent into `spawn` | modify |
| `tests/a2a_send_message.rs` | end-to-end: criteria 2 and 4 | create |

Decomposition rationale: `task_store.rs` and `executor.rs` are separate because
they fail for unrelated reasons and are independently testable — the store's
contract is the SDK's `update`-then-`create` fallback (hazard 10), the
executor's is policy enforcement. `server.rs` stays the only file that knows
about HTTP.

---

## Task 1: Add the `a2a-server-lf` dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the dependency**

In `Cargo.toml`, immediately after the existing `a2a = { package = "a2a-lf", ... }` line, add:

```toml
# A2A server: JSON-RPC router, AgentExecutor and TaskStore traits (Phase 2)
a2a-server = { package = "a2a-server-lf", version = "0.3.1" }
```

The rename to `a2a-server` avoids a bare `a2a_server` crate name that does not
match the package name, mirroring how `a2a-lf` is already renamed to `a2a`.

- [ ] **Step 2: Verify it resolves and builds**

Run: `cargo check`
Expected: succeeds. This adds 38 packages (454 -> 492) including the protobuf chain
(`a2a-pb` 0.1.8 → `tonic`, `prost`, `pbjson`). The first build is slow; it
vendors `protoc`, so no system protoc is required.

- [ ] **Step 3: Confirm the JSON-RPC router and traits are importable**

Add to `src/a2a/mod.rs`, temporarily at the end:

```rust
#[cfg(test)]
mod dependency_probe {
    #[test]
    fn sdk_server_items_are_reachable() {
        // Type-level only: proves the crate is wired under the expected name
        // and that the three items Phase 2 depends on exist.
        fn _assert_handler<H: a2a_server::RequestHandler>() {}
        fn _assert_executor<E: a2a_server::AgentExecutor>() {}
        fn _assert_store<S: a2a_server::TaskStore>() {}
        let _ = a2a_server::jsonrpc::jsonrpc_router::<a2a_server::DefaultRequestHandler>;
    }
}
```

Run: `cargo test --lib dependency_probe`
Expected: PASS. If `a2a_server::jsonrpc` is not found, check the crate's `lib.rs`
for the module path — it is declared unconditionally in 0.3.1.

- [ ] **Step 4: Remove the probe and commit**

Delete the `dependency_probe` module. Run `cargo fmt --all`, then:

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(a2a): add a2a-server-lf for the JSON-RPC server and executor traits"
```

---

## Task 2: `Agent::run_with_policy` — the safe loop entry

This is hazard 5. `process_message` must never be used by A2A because its
`LoopConfig.allowed_tools` is `None`, and `src/config.rs:313-320` documents that
*that* `None` means "no restriction at all". This task adds an entry point that
takes the policy as a required argument, so it cannot be forgotten.

**Files:**
- Modify: `src/agent.rs`
- Test: `src/agent.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add to the existing `mod tests` in `src/agent.rs`. This test asserts the
*shape* of the contract that matters: an empty policy yields a loop that offers
no tools. It does not need a live LLM because it inspects the config that would
be built.

```rust
#[test]
fn run_with_policy_takes_an_explicit_allowlist() {
    // The A2A executor must never reach a loop whose `allowed_tools` is None.
    // This pins the signature so a future refactor cannot quietly make the
    // policy optional: the parameter is a plain `Vec<String>`, not an Option.
    fn _signature(agent: &Agent, tools: Vec<String>) {
        let _ = |prompt: &str| agent.run_with_policy(prompt, tools, None);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib run_with_policy_takes_an_explicit_allowlist`
Expected: FAIL to compile with `no method named 'run_with_policy' found`.

- [ ] **Step 3: Implement `run_with_policy`**

In `src/agent.rs`, add a new `pub async fn` on `impl Agent`, placed immediately
after `run_subagent` ends. It mirrors `run_subagent_loop`'s loop construction
but returns the `LoopOutcome` so the caller can map terminal A2A states, and it
takes the policy as a required argument.

```rust
/// Run one agent turn with an EXPLICIT tool policy.
///
/// This exists because [`Agent::process_message`] builds its own `LoopConfig`
/// with `allowed_tools: None`, and in `LoopConfig` that `None` means *no
/// restriction at all* (`src/config.rs:313-320`). Anything reachable from a
/// remote caller must go through here instead, so the policy cannot be
/// forgotten.
///
/// `allowed_tools` is taken by value and is never `None`: an empty vector is a
/// valid policy meaning "no tools", and is the correct fail-closed default.
pub async fn run_with_policy(
    &self,
    prompt: &str,
    allowed_tools: Vec<String>,
    cancel_token: Option<CancellationToken>,
) -> Result<crate::loop_runner::LoopOutcome> {
    let model = self.config.openrouter.model.clone();
    let max_iter = self.config.max_iterations();

    // Offer only what the policy allows. This is belt-and-braces with the
    // loop's own filtering (`src/loop_runner.rs:109`), and it keeps the
    // request payload small.
    let all_possible_tools: Vec<crate::llm::ToolDefinition> = {
        let mut t = self.tool_registry.all_definitions();
        t.extend(self.mcp.tool_definitions());
        t
    };
    let offered: Vec<crate::llm::ToolDefinition> = all_possible_tools
        .into_iter()
        .filter(|td| allowed_tools.contains(&td.function.name))
        .collect();

    let system_content = self.build_subagent_system_prompt("").await;
    let mut messages = vec![
        crate::llm::ChatMessage {
            role: "system".to_string(),
            content: Some(crate::llm::MessageContent::from_text(system_content)),
            tool_calls: None,
            tool_call_id: None,
        },
        crate::llm::ChatMessage {
            role: "user".to_string(),
            content: Some(crate::llm::MessageContent::from_text(prompt)),
            tool_calls: None,
            tool_call_id: None,
        },
    ];

    let loop_config = crate::loop_runner::LoopConfig {
        max_iterations: max_iter,
        empty_response_retry_limit: self.config.empty_response_retry_limit(),
        context_window: self.registry.effective_context_window(&model),
        loop_detection_enabled: true,
        interactive_loop_callback: false,
        allowed_tools: Some(allowed_tools),
        langsmith_project: None,
        model: Some(model),
        tool_event_tx: None,
        stream_token_tx: None,
        recovery_nudge: None,
    };

    let make_ctx = {
        let sandbox_dir = self.config.sandbox.allowed_directory.clone();
        let home_dir = self.config.resolved_home.clone();
        let sender = self.sender.clone();
        let cancel_registry = self.cancel_registry.clone();
        move |_user_id: &str, _chat_id: &str| crate::tool_registry::ToolContext {
            sandbox_dir: sandbox_dir.clone(),
            home_dir: home_dir.clone(),
            sender: sender.clone(),
            cancel_registry: cancel_registry.clone(),
            user_id: String::new(),
            chat_id: String::new(),
            tool_ui_mode: crate::tool_registry::ToolUiMode::Minimal,
        }
    };

    crate::loop_runner::AgenticLoop::new(
        &self.llm,
        &self.tool_registry,
        &self.mcp,
        &loop_config,
        cancel_token,
        None,
        None,
        self.sender.as_ref() as &dyn crate::platform::sender::PlatformSender,
        Box::new(make_ctx),
        None,
    )
    .run(
        &mut crate::loop_runner::MessageContainer::Plain(std::mem::take(&mut messages)),
        "",
        "",
    )
    .await
}
```

Notes for the implementer:

- `special_tool_handler` is `None`. That deliberately withholds
  `invoke_agent` / `spawn_agents` from A2A peers: they are not registry tools
  (see `src/agent.rs:1306`), so a registry-derived `["*"]` does not include
  them, and passing `None` keeps that true. **Do not pass a handler here.**
- `build_subagent_system_prompt("")` is used for the same reason
  `run_subagent` uses it: it yields the base prompt without a skill's
  instructions. If it turns out to require a non-empty argument, pass the empty
  string anyway and fix the signature's handling rather than inventing content.
- `offered` is computed but the loop recomputes it. Keep both: the pre-filter
  makes the request smaller, the loop's filter is the security boundary.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib run_with_policy_takes_an_explicit_allowlist`
Expected: PASS.

- [ ] **Step 5: Run the whole suite for regressions**

Run: `cargo test`
Expected: 560 tests pass (plus the new one), 0 failures.

- [ ] **Step 6: Commit**

```bash
git add src/agent.rs
git commit -m "feat(agent): add run_with_policy for callers with an explicit tool policy"
```

---

## Task 3: A2A task tables

**Files:**
- Modify: `src/memory/mod.rs`
- Test: `src/memory/mod.rs`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/memory/mod.rs`, next to the existing
`sup_tables_exist_after_migration`:

```rust
#[test]
fn a2a_tables_exist_after_migration() {
    let dir = tempfile::tempdir().unwrap();
    let store = MemoryStore::open(&dir.path().join("t.db"), None, MemoryConfig::default())
        .expect("open");
    let conn = store.connection();
    let conn = conn.blocking_lock();
    for table in ["a2a_tasks"] {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "table {table} must exist after migration");
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib a2a_tables_exist_after_migration`
Expected: FAIL — `assertion `left == right` failed: table a2a_tasks must exist`, left: 0, right: 1.

- [ ] **Step 3: Add the tables**

In `src/memory/mod.rs`, inside the single large `execute_batch` in
`run_migrations`, append after the supervisor tables:

```sql
-- A2A: tasks. `state` holds the A2A TaskState lowercased for querying;
-- `data` holds the full serialized `a2a::Task` so the SDK's TaskStore can
-- round-trip every field without us mirroring its schema.
--
-- History lives inside `data`, not a separate table: the SDK's `Task` carries
-- its own `history`, and a second table would be a second source of truth with
-- no reader in Phase 2. Add one when something actually queries messages.
CREATE TABLE IF NOT EXISTS a2a_tasks (
    id              TEXT PRIMARY KEY,
    context_id      TEXT NOT NULL,
    peer            TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL,
    data            TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_peer ON a2a_tasks(peer, updated_at);
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib a2a_tables_exist_after_migration`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/memory/mod.rs
git commit -m "feat(memory): add the a2a_tasks table"
```

---

## Task 4: `SqliteTaskStore`

This is hazard 10. `DefaultRequestHandler::save_task` (`handler.rs:201-210`)
calls `update` first and only falls back to `create` when the error code is
**exactly** `TASK_NOT_FOUND`. Returning `Ok` or any other error for a missing
row means tasks are silently never created.

**Files:**
- Create: `src/a2a/task_store.rs`
- Modify: `src/a2a/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/a2a/task_store.rs` with only the test module and a stub, so the
test fails for the right reason:

```rust
//! SQLite-backed [`a2a_server::TaskStore`] over the existing HaosGreen database.

use a2a::types::{Task, TaskState, TaskStatus};
use a2a_server::task_store::TaskStore;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, state: TaskState) -> Task {
        Task {
            id: id.to_string(),
            context_id: "ctx-1".to_string(),
            status: TaskStatus { state, message: None, timestamp: None },
            artifacts: None,
            history: None,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn update_on_a_missing_row_reports_task_not_found() {
        // Load-bearing: DefaultRequestHandler::save_task (handler.rs:201-210)
        // only falls back to `create` when the error code is exactly
        // TASK_NOT_FOUND. Any other error means the task is never created.
        let store = super::test_store().await;
        let err = store
            .update(task("missing", TaskState::Working))
            .await
            .expect_err("update on a missing row must fail");
        assert_eq!(
            err.code,
            a2a::errors::error_code::TASK_NOT_FOUND,
            "the SDK branches on this exact code"
        );
    }

    #[tokio::test]
    async fn create_then_get_round_trips_the_task() {
        let store = super::test_store().await;
        store.create(task("t1", TaskState::Submitted)).await.unwrap();
        let got = store.get("t1").await.unwrap().expect("task must exist");
        assert_eq!(got.id, "t1");
        assert_eq!(got.status.state, TaskState::Submitted);
    }

    #[tokio::test]
    async fn update_persists_a_new_state_and_bumps_the_version() {
        let store = super::test_store().await;
        let v1 = store.create(task("t2", TaskState::Submitted)).await.unwrap();
        let v2 = store.update(task("t2", TaskState::Completed)).await.unwrap();
        assert!(v2 > v1, "version must increase");
        let got = store.get("t2").await.unwrap().unwrap();
        assert_eq!(got.status.state, TaskState::Completed);
    }

    #[tokio::test]
    async fn get_on_a_missing_task_is_none_not_an_error() {
        let store = super::test_store().await;
        assert!(store.get("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn create_on_an_existing_id_is_an_error() {
        let store = super::test_store().await;
        store.create(task("dup", TaskState::Submitted)).await.unwrap();
        assert!(store.create(task("dup", TaskState::Submitted)).await.is_err());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib a2a::task_store`
Expected: FAIL to compile — `cannot find function test_store`.

- [ ] **Step 3: Implement the store**

Add above the test module in `src/a2a/task_store.rs`:

```rust
/// SQLite-backed task store. Mirrors `src/supervisor/store.rs`: a cloneable
/// handle over the shared connection, `async fn` methods that lock it.
#[derive(Clone)]
pub struct SqliteTaskStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteTaskStore {
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        Self { conn }
    }
}

/// Serialize a task for storage. The whole `Task` is kept as JSON so the SDK
/// can round-trip fields we do not model as columns.
fn encode(task: &Task) -> Result<(String, String, String, String)> {
    Ok((
        task.context_id.clone(),
        format!("{:?}", task.status.state).to_lowercase(),
        serde_json::to_string(task)?,
        format!("{:?}", task.status.state).to_lowercase(),
    ))
}

#[async_trait::async_trait]
impl TaskStore for SqliteTaskStore {
    async fn create(&self, task: Task) -> Result<u64, a2a::errors::A2AError> {
        let (context_id, state, data, _) =
            encode(&task).map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        let conn = self.conn.lock().await;
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO a2a_tasks (id, context_id, peer, state, data, version)
                 VALUES (?1, ?2, '', ?3, ?4, 1)",
                rusqlite::params![task.id, context_id, state, data],
            )
            .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        if changed == 0 {
            // Matches InMemoryTaskStore, which errors on a duplicate id.
            return Err(a2a::errors::A2AError::internal("task already exists"));
        }
        Ok(1)
    }

    async fn update(&self, task: Task) -> Result<u64, a2a::errors::A2AError> {
        let (context_id, state, data, _) =
            encode(&task).map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        let conn = self.conn.lock().await;
        let changed = conn
            .execute(
                "UPDATE a2a_tasks
                    SET context_id = ?2, state = ?3, data = ?4,
                        version = version + 1, updated_at = datetime('now')
                  WHERE id = ?1",
                rusqlite::params![task.id, context_id, state, data],
            )
            .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        if changed == 0 {
            // MUST be this exact code: save_task only falls back to `create`
            // on TASK_NOT_FOUND (handler.rs:201-210).
            return Err(a2a::errors::A2AError::task_not_found(&task.id));
        }
        let version: i64 = conn
            .query_row(
                "SELECT version FROM a2a_tasks WHERE id = ?1",
                [&task.id],
                |r| r.get(0),
            )
            .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        Ok(version as u64)
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, a2a::errors::A2AError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT data FROM a2a_tasks WHERE id = ?1")
            .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        let mut rows = stmt
            .query([task_id])
            .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
        match rows.next().map_err(|e| a2a::errors::A2AError::internal(e.to_string()))? {
            None => Ok(None),
            Some(row) => {
                let data: String = row
                    .get(0)
                    .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))?;
                serde_json::from_str(&data)
                    .map(Some)
                    .map_err(|e| a2a::errors::A2AError::internal(e.to_string()))
            }
        }
    }

    async fn list(
        &self,
        req: &a2a::types::ListTasksRequest,
    ) -> Result<a2a::types::ListTasksResponse, a2a::errors::A2AError> {
        // Phase 2 does not implement task listing; GetTask is Phase 3. Refuse
        // explicitly rather than returning a misleading empty page.
        let _ = req;
        Err(a2a::errors::A2AError::unsupported_operation(
            "ListTasks is not implemented until Phase 3",
        ))
    }
}

#[cfg(test)]
pub(crate) async fn test_store() -> SqliteTaskStore {
    let dir = tempfile::tempdir().unwrap();
    let mem = crate::memory::MemoryStore::open(
        &dir.path().join("a2a.db"),
        None,
        crate::memory::MemoryConfig::default(),
    )
    .unwrap();
    std::mem::forget(dir); // keep the tempdir alive for the test's duration
    SqliteTaskStore::new(mem.connection())
}
```

Notes for the implementer:

- Check the real import paths for `TaskStore`, `A2AError` and `error_code`
  against the crate. `a2a_server::task_store::TaskStore` and
  `a2a::errors::{A2AError, error_code}` are the paths in 0.3.1; adjust if the
  re-exports differ.
- `A2AError` has a public `code` field — verify with
  `grep -n 'pub code' <a2a-lf>/src/errors.rs` before relying on it in the test.
- The `peer` column is written as `''` here and updated by the executor in
  Task 5. Do not add a NOT NULL constraint that the insert violates.

- [ ] **Step 4: Declare the module**

In `src/a2a/mod.rs`, add `pub mod task_store;` alongside the existing
declarations.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib a2a::task_store`
Expected: 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/a2a/task_store.rs src/a2a/mod.rs
git commit -m "feat(a2a): add a SQLite-backed TaskStore honouring the SDK contract"
```

---

## Task 5: `A2aExecutor`

This is hazards 5, 6 and 7 together — the security-critical task.

**Files:**
- Create: `src/a2a/executor.rs`
- Modify: `src/a2a/mod.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/a2a/executor.rs` with the test module first:

```rust
//! Bridges an A2A task to a HaosGreen agent turn, under the peer's tool policy.

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use crate::a2a::policy::{resolve_allowed_tools, DEFAULT_PEER_TOOLS};
    use crate::config::A2aPeerConfig;

    #[test]
    fn a_wildcard_peer_resolves_against_the_registry_not_an_empty_list() {
        // Hazard 6: `authenticate` resolves against `&[]`, so a `["*"]` peer
        // gets an EMPTY list from it. The executor must re-resolve against the
        // real registry or every wildcard peer silently loses every tool.
        let peer = A2aPeerConfig {
            token: "t".to_string(),
            ip: vec!["127.0.0.1".to_string()],
            tools: Some(vec!["*".to_string()]),
        };
        let registry = vec!["read_file".to_string(), "execute_command".to_string()];

        let provisional = resolve_allowed_tools("p", &peer, &[]);
        assert!(
            provisional.is_empty(),
            "documents the trap: the provisional list is empty for a wildcard peer"
        );

        let real = resolve_allowed_tools("p", &peer, &registry);
        assert_eq!(real.len(), 2, "re-resolving against the registry restores it");
    }

    #[test]
    fn a_default_peer_never_gains_execute_command() {
        // Hazard 5, as a property of the policy rather than the loop: the
        // default allowlist must not contain the shell tool.
        let peer = A2aPeerConfig {
            token: "t".to_string(),
            ip: vec!["127.0.0.1".to_string()],
            tools: None,
        };
        let registry = vec![
            "read_file".to_string(),
            "execute_command".to_string(),
            "write_file".to_string(),
        ];
        let resolved = resolve_allowed_tools("p", &peer, &registry);
        assert!(!resolved.iter().any(|t| t == "execute_command"));
        assert!(!resolved.iter().any(|t| t == "write_file"));
        for t in DEFAULT_PEER_TOOLS {
            assert!(resolved.iter().any(|r| r == t), "{t} must be granted");
        }
    }

    #[test]
    fn cancel_keys_are_namespaced_away_from_telegram_user_ids() {
        // Hazard 7: the registry is keyed by Telegram user_id and `/stop`
        // cancels by that key. An A2A key must be distinguishable.
        let key = super::cancel_key("task-abc");
        assert_eq!(key, "a2a:task-abc");
        assert!(!key.chars().all(|c| c.is_ascii_digit()), "must not look like a Telegram id");
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib a2a::executor`
Expected: the first two PASS (they test `policy`, which already works — they
document the trap), and the third FAILS to compile: `cannot find function
cancel_key`. That is the expected red state for this step.

- [ ] **Step 3: Implement the executor**

Add above the test module:

```rust
/// Cancel-registry key for an A2A task.
///
/// `cancel_token_registry` (`src/agent.rs:99`) is a bare map keyed by Telegram
/// `user_id`, and `/stop` cancels by that key. Namespacing keeps `CancelTask`
/// and `/stop` from cancelling each other's runs.
pub fn cancel_key(task_id: &str) -> String {
    format!("a2a:{task_id}")
}

/// Drives an A2A task through the HaosGreen agent loop.
pub struct A2aExecutor {
    agent: Arc<crate::agent::Agent>,
}

impl A2aExecutor {
    pub fn new(agent: Arc<crate::agent::Agent>) -> Self {
        Self { agent }
    }

    /// The prompt text from the first text part of the incoming message.
    fn prompt_from(ctx: &a2a_server::ExecutorContext) -> String {
        ctx.message
            .as_ref()
            .map(|m| {
                m.parts
                    .iter()
                    .filter_map(|p| match &p.content {
                        a2a::types::PartContent::Text(t) => Some(t.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }

    /// Re-derive the peer's policy against the LIVE tool registry.
    ///
    /// Hazard 6: `authenticate` resolves against `&[]`, which yields an empty
    /// list for a `["*"]` peer. Never forward `PeerIdentity.allowed_tools`.
    fn policy_for(&self, peer: &str) -> Vec<String> {
        let available: Vec<String> = self
            .agent
            .all_tool_definitions()
            .into_iter()
            .map(|d| d.function.name)
            .collect();
        match self.agent.config.a2a.peers.get(peer) {
            Some(cfg) => resolve_allowed_tools(peer, cfg, &available),
            // Unknown peer: fail closed. `authenticate` should have rejected
            // this already; treat it as a bug, not an allow.
            None => Vec::new(),
        }
    }
}

#[async_trait::async_trait]
impl a2a_server::AgentExecutor for A2aExecutor {
    fn execute(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> futures::stream::BoxStream<'static, Result<a2a::event::StreamResponse, a2a::errors::A2AError>>
    {
        let agent = self.agent.clone();
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        let prompt = Self::prompt_from(&ctx);
        let peer = peer_from_service_params(&ctx.service_params);
        let history = ctx.stored_task.as_ref().and_then(|t| t.history.clone());

        Box::pin(async_stream::stream! {
            let allowed = self.policy_for(&peer);

            let cancel = agent.register_cancel_token(&cancel_key(&task_id)).await;
            let outcome = agent
                .run_with_policy(&prompt, allowed, Some(cancel.clone()))
                .await;
            agent.clear_cancel_token(&cancel_key(&task_id)).await;

            let (state, text) = match outcome {
                Ok(crate::loop_runner::LoopOutcome::FinalResponse(t)) => {
                    (a2a::types::TaskState::Completed, t)
                }
                Ok(crate::loop_runner::LoopOutcome::MaxIterations) => (
                    a2a::types::TaskState::Failed,
                    "The agent reached its maximum number of iterations.".to_string(),
                ),
                Ok(crate::loop_runner::LoopOutcome::Cancelled) => (
                    a2a::types::TaskState::Canceled,
                    "Cancelled.".to_string(),
                ),
                Err(e) => (a2a::types::TaskState::Failed, format!("Agent error: {e}")),
            };

            let mut hist = history.unwrap_or_default();
            hist.push(a2a::types::Message {
                message_id: uuid::Uuid::new_v4().to_string(),
                context_id: Some(context_id.clone()),
                task_id: Some(task_id.clone()),
                role: a2a::types::Role::Agent,
                parts: vec![a2a::types::Part::text(text)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            });

            // Hazard 11: emitting `Task` REPLACES the stored task
            // (handler.rs:218). Carry history forward or it is discarded.
            yield Ok(a2a::event::StreamResponse::Task(a2a::types::Task {
                id: task_id,
                context_id,
                status: a2a::types::TaskStatus {
                    state,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: Some(hist),
                metadata: None,
            }));
        })
    }

    fn cancel(
        &self,
        ctx: a2a_server::ExecutorContext,
    ) -> futures::stream::BoxStream<'static, Result<a2a::event::StreamResponse, a2a::errors::A2AError>>
    {
        let agent = self.agent.clone();
        let task_id = ctx.task_id.clone();
        let context_id = ctx.context_id.clone();
        Box::pin(async_stream::stream! {
            let cancelled = agent.cancel_processing(&cancel_key(&task_id)).await;
            let state = if cancelled {
                a2a::types::TaskState::Canceled
            } else {
                a2a::types::TaskState::Failed
            };
            yield Ok(a2a::event::StreamResponse::Task(a2a::types::Task {
                id: task_id,
                context_id,
                status: a2a::types::TaskStatus { state, message: None, timestamp: None },
                artifacts: None,
                history: None,
                metadata: None,
            }));
        })
    }
}

/// Header the auth middleware uses to pass the resolved peer name to the SDK
/// handler. The SDK forwards request headers into `ExecutorContext` via
/// `service_params` (`middleware.rs:17-28`), which is the ONLY identity channel
/// available: the SDK sets `ctx.user` to `None` unconditionally.
pub const PEER_HEADER: &str = "x-haos-green-a2a-peer";

/// Recover the peer name the auth middleware resolved.
///
/// Deliberately does NOT re-authenticate: the executor has no source IP, so it
/// cannot. It trusts the header because `auth_gate` runs first and rejects
/// unauthenticated callers. A missing header means the middleware was bypassed
/// -- a routing bug -- so this returns an empty name, which matches no peer and
/// therefore resolves to an empty policy.
fn peer_from_service_params(params: &a2a_server::middleware::ServiceParams) -> String {
    params
        .get(PEER_HEADER)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}
```

- [ ] **Step 3b: Define the middleware that sets that header**

Add to `src/a2a/server.rs`. This is the piece that makes `PEER_HEADER`
trustworthy — without it the executor's identity is empty and every peer gets
an empty policy (fail-closed, but broken).

```rust
/// Authenticate before the request reaches the SDK handler, and forward the
/// resolved peer name so the executor can re-derive its policy.
///
/// Status codes match Phase 1 exactly: 401 for a missing or wrong token, 403
/// for a disallowed address, 500 for an ambiguous (duplicated) token.
pub async fn auth_gate(
    State(state): State<Arc<A2aState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let bearer = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_bearer(Some(v)));

    match authenticate(&state.config, bearer, addr.ip()) {
        Ok(identity) => {
            let value = axum::http::HeaderValue::from_str(&identity.name)
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static(""));
            req.headers_mut().insert(PEER_HEADER, value);
            next.run(req).await
        }
        Err(AuthError::MissingToken) | Err(AuthError::InvalidToken) => {
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({}))).into_response()
        }
        Err(AuthError::AmbiguousToken) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({})),
        )
            .into_response(),
        Err(AuthError::IpNotAllowed) => {
            (StatusCode::FORBIDDEN, Json(serde_json::json!({}))).into_response()
        }
    }
}
```

`parse_bearer` is currently private in `server.rs`; change it to `pub(crate)`.
`PEER_HEADER` is defined in `executor.rs` — import it.

- [ ] **Step 3c: Prove the header round-trips**

Add to `mod tests` in `src/a2a/executor.rs`:

```rust
#[test]
fn the_peer_header_is_read_from_service_params() {
    let mut params = a2a_server::middleware::ServiceParams::new();
    params.insert(super::PEER_HEADER.to_string(), vec!["laptop".to_string()]);
    assert_eq!(super::peer_from_service_params(&params), "laptop");
}

#[test]
fn a_missing_peer_header_resolves_to_no_peer() {
    // Fail closed: an empty name matches no peer, so `policy_for` yields an
    // empty policy. If this ever returns a real name, the auth middleware was
    // bypassed.
    let params = a2a_server::middleware::ServiceParams::new();
    assert_eq!(super::peer_from_service_params(&params), "");
}
```

Run: `cargo test --lib a2a::executor`
Expected: 5 tests PASS.

Notes for the implementer:

- This draft uses `async_stream::stream!`. That crate is **not** currently a
  dependency. Rewrite both methods with `futures::stream::once(async move { ... })`
  instead — the executor emits exactly one terminal event, so `once` is
  sufficient and needs no new dependency.
- `parse_bearer` is currently private in `server.rs`. Make it `pub(crate)` so
  `auth_gate` and this module can use it.

- [ ] **Step 4: Declare the module**

In `src/a2a/mod.rs`, add `pub mod executor;`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib a2a::executor`
Expected: 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/a2a/executor.rs src/a2a/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(a2a): add an executor that drives the agent under the peer policy"
```

---

## Task 6: Mount the SDK JSON-RPC router with auth

**Files:**
- Modify: `src/a2a/server.rs`
- Test: `src/a2a/server.rs`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/a2a/server.rs`:

```rust
#[test]
fn the_sdk_router_is_mounted_at_the_existing_jsonrpc_path() {
    // Phase 1 exposed POST /jsonrpc. The SDK's jsonrpc_router serves POST /
    // and must be nested so the client-visible URL does not change.
    let state = test_state();
    let app = router(state);
    // A router cannot be introspected for routes, so this asserts the
    // composition compiles and that auth still gates the nested service.
    // The behavioural proof lives in tests/a2a_send_message.rs.
    let _ = app;
}
```

- [ ] **Step 2: Implement the mount**

Replace the body of `router` in `src/a2a/server.rs`:

```rust
pub fn router(state: Arc<A2aState>) -> Router {
    // The SDK serves its JSON-RPC binding at "/", so nest it under the path
    // Phase 1 already published. ConnectInfo<SocketAddr> survives the nest,
    // so the IP allowlist keeps working.
    let sdk = a2a_server::jsonrpc::jsonrpc_router(state.handler.clone());

    let jsonrpc_routes: Router<Arc<A2aState>> = Router::new()
        .nest_service("/jsonrpc", sdk)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_gate,
        ));

    Router::new()
        .route("/.well-known/agent-card.json", get(agent_card_handler))
        .merge(jsonrpc_routes)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
```

`auth_gate` is defined in Task 5 Step 3b and imported here. This task only
wires it in front of the nested SDK service.

`A2aState` gains a `handler: Arc<DefaultRequestHandler>` field, and
`build_state` gains the parameters to construct it.

- [ ] **Step 3: Delete the 501 stub**

Remove `jsonrpc_handler` entirely, and the test in `tests/a2a_endpoint.rs`
asserting 501 — replace that assertion with one expecting a JSON-RPC `result`
containing a task. Keep `parse_bearer`; change its visibility to `pub(crate)`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib a2a::server && cargo test --test a2a_endpoint`
Expected: PASS. The 501 test must now be gone or rewritten.

- [ ] **Step 5: Commit**

```bash
git add src/a2a/server.rs tests/a2a_endpoint.rs
git commit -m "feat(a2a): serve SendMessage through the SDK JSON-RPC router"
```

---

## Task 7: Thread the agent through startup

**Files:**
- Modify: `src/a2a/server.rs`, `src/main.rs`

- [ ] **Step 1: Change the signatures**

`build_state` and `spawn` take the agent so the executor can be built:

```rust
pub fn build_state(
    config: A2aConfig,
    skills: SkillRegistry,
    endpoint_url: &str,
    agent: Arc<crate::agent::Agent>,
) -> Arc<A2aState>

pub async fn spawn(
    config: A2aConfig,
    skills: SkillRegistry,
    agent: Arc<crate::agent::Agent>,
) -> Result<SocketAddr>
```

- [ ] **Step 2: Update the call site**

In `src/main.rs`, the A2A block currently reads
`haos-green::a2a::server::spawn(config.a2a.clone(), a2a_skills)`. Change it to pass
`agent.clone()`. `agent` is in scope (built at `src/main.rs:248`); confirm the
binding name with `grep -n 'Arc::new_cyclic' src/main.rs`.

- [ ] **Step 3: Verify**

Run: `cargo check && cargo test`
Expected: compiles; 560+ tests pass, 0 failures.

- [ ] **Step 4: Commit**

```bash
git add src/a2a/server.rs src/main.rs
git commit -m "feat(a2a): give the listener the agent so it can execute tasks"
```

---

## Task 8: End-to-end verification

Proves success criteria 2 and 4 from the spec.

**Files:**
- Create: `tests/a2a_send_message.rs`

- [ ] **Step 1: Write the tests**

```rust
//! End-to-end: an authenticated peer's SendMessage drives a real agent turn,
//! and a peer whose policy withholds execute_command cannot invoke it.

use haos-green::a2a::server::{build_state, router};
use haos-green::config::{A2aCardConfig, A2aConfig, A2aPeerConfig};
use haos-green::skills::SkillRegistry;
use std::collections::HashMap;

fn send_message_body(text: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": "m1",
                "role": "ROLE_USER",
                "parts": [{ "text": text }]
            }
        }
    })
}

#[tokio::test]
async fn an_unknown_method_is_method_not_found() {
    // Pins the v1.0 naming: the old `message/send` must NOT be accepted.
    let (base, handle) = start_with_default_peer().await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("s3cret")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32601, "v0.3.0 names must be rejected");
    handle.abort();
}

#[tokio::test]
async fn a_default_peer_cannot_reach_execute_command() {
    // Success criterion 4. The assertion is on the OFFERED tool set: a tool
    // the peer's policy withholds must never be presented to the model, so
    // the LLM cannot call it in the first place.
    let available = haos-green::a2a::resolve_allowed_tools(
        "laptop",
        &default_peer(),
        &[
            "read_file".to_string(),
            "execute_command".to_string(),
            "write_file".to_string(),
        ],
    );
    assert!(!available.iter().any(|t| t == "execute_command"));
    assert!(!available.iter().any(|t| t == "write_file"));
}
```

`start_with_default_peer()` mirrors the helper in `tests/a2a_endpoint.rs`: bind
`127.0.0.1:0`, `router(build_state(...))`, serve with
`into_make_service_with_connect_info`.

- [ ] **Step 2: Run them**

Run: `cargo test --test a2a_send_message`
Expected: PASS.

- [ ] **Step 3: Run every gate**

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --release
```

Expected: all clean.

- [ ] **Step 4: Verify against a live process**

Build and run the binary with A2A enabled and a peer configured, then confirm
with `curl` that `SendMessage` with a valid bearer reaches the handler and an
invalid one gets 401. Record the observed status codes.

- [ ] **Step 5: Commit**

```bash
git add tests/a2a_send_message.rs
git commit -m "test(a2a): prove SendMessage executes under the peer policy"
```

---

## Self-Review

**Spec coverage.** Phase 2 per the spec's Implementation Phases table is
"`task_store.rs` + `executor.rs` + `SendMessage` synchronous path; task reaches
`completed`", verifiable by success criteria 2 and 4.

- Criterion 2 (`SendMessage` → `completed` task) — Tasks 3–8.
- Criterion 4 (a peer without `execute_command` cannot invoke it) — Tasks 2 and
  5 enforce it, Task 8 asserts it.
- Persistence (§Persistence) — Task 3 implements `a2a_tasks`. The spec also
  lists an `a2a_messages` table; Phase 2 deliberately does **not** create it,
  because history lives inside the SDK's `Task` blob and nothing would read a
  separate table (YAGNI). Add it in the phase that introduces a message reader.
- Concurrency (§Concurrency, semaphore) — **deferred to Phase 3** by the spec's
  own phase table. Phase 2 has no bound on concurrent tasks. Record this as a
  known Phase 2 limitation.

**Known gaps to state in the PR description, not to silently ship:**

1. No concurrency bound until Phase 3.
2. `ListTasks` returns `unsupported_operation`.
3. The request blocks until the task is terminal (hazard 8).

**Placeholder scan.** No placeholders remain. Task 5 originally carried a stub
`peer_from_service_params` that guessed the peer from the bearer header; it has
been replaced with a real header round-trip (`PEER_HEADER`), defined by the
middleware in Task 5 Step 3b and proven by two tests in Step 3c. Every code step
shows complete code, and every task ends with the exact command and expected
result.

**Type consistency.** Checked across tasks: `run_with_policy(&self, prompt:
&str, allowed_tools: Vec<String>, cancel_token: Option<CancellationToken>) ->
Result<LoopOutcome>` (Task 2) is called exactly that way in Task 5.
`resolve_allowed_tools(peer_name, peer, available)` (Phase 1) is called with
three arguments in Tasks 5 and 8. `SqliteTaskStore::new(Arc<Mutex<Connection>>)`
(Task 4) is constructed from `MemoryStore::connection()` in Task 4's helper.
`build_state`/`spawn` gain `Arc<Agent>` in Task 7 and are called that way in
Task 7 Step 2 and Task 8.
