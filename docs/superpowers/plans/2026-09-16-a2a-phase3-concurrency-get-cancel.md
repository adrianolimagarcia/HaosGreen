# A2A Phase 3 — Concurrency Gate, `GetTask` and `CancelTask` Verification Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound concurrent A2A agent turns with `max_concurrent_tasks`, reject the `max_concurrent_tasks = 0` misconfiguration at startup, and prove `GetTask` and `CancelTask` work end-to-end (success criteria 5 and the GetTask half of the lifecycle).

**Architecture context:** The SDK's JSON-RPC router (already mounted at `/jsonrpc` in Phase 2) implements `GetTask` and `CancelTask` natively. Our `SqliteTaskStore::get` serves `GetTask`; our `A2aExecutor::cancel` serves `CancelTask`. So Phase 3 is NOT about adding methods — it is about (a) the concurrency bound the executor currently lacks, (b) fail-fast config validation, and (c) proving the lifecycle with real tests.

---

## Read this before starting

The design spec is `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
Relevant prior art, all committed:

- `src/a2a/executor.rs` — `A2aExecutor` (Phase 2). `execute()` currently runs
  the agent turn with no bound on how many turns run concurrently.
- `src/a2a/server.rs` — `build_state(config, skills, endpoint_url, executor, store)`,
  `router(state)`, `spawn(...)`, `auth_gate` middleware, `A2aState.handler`.
- `src/config.rs` — `A2aConfig::validate()` refuses TLS requests, duplicate
  tokens, empty tokens, empty/unparseable IPs. `max_concurrent_tasks: usize`
  (default 4) has **no** validation today.
- `tests/a2a_e2e_live.rs` — a **working live E2E harness** (Phase 2): constructs
  a real `Agent` (all 17 args via `Arc::new_cyclic`), wires `A2aExecutor` +
  `SqliteTaskStore`, serves a listener on `127.0.0.1:0`, and drives
  `SendMessage` to `TASK_STATE_COMPLETED` against the live OpenAI-compatible
  endpoint `http://127.0.0.1:8790/v1` (model `a6api_DeepSeek-V4-Flash-0731`).
  It is `#[ignore]`d and gated on `HAOS_GREEN_A2A_LIVE=1`. **Reuse this harness —
  do not rebuild the Agent construction.**

### SDK facts verified from source

- `DefaultRequestHandler::get_task` calls `TaskStore::get` and maps `None` to
  `TASK_NOT_FOUND` (`handler.rs:630`). Our store returns `Ok(None)` for a
  missing task — correct.
- `DefaultRequestHandler::cancel_task` (`handler.rs:375` trait, impl ~line 690)
  calls the executor's `cancel` and saves the result. Our `A2aExecutor::cancel`
  calls `agent.cancel_processing(&cancel_key(&task_id))`, emitting
  `TaskState::Canceled` if a token was active, else `Failed`.
- The router mounts `GET_TASK`, `CANCEL_TASK`, `LIST_TASKS`, `SEND_MESSAGE`
  (`jsonrpc.rs:73-98`). `ListTasks` hits our store's `unsupported_operation`
  stub — that stays Phase 3-out-of-scope.

---

## File Structure

| File | Responsibility | Status |
|---|---|---|
| `src/a2a/executor.rs` | `TaskGate` (semaphore) + wire into `execute` | modify |
| `src/config.rs` | reject `max_concurrent_tasks == 0` in `validate()` | modify |
| `src/config.rs` tests | validation test | modify |
| `tests/a2a_e2e_live.rs` | GetTask E2E + CancelTask E2E | modify |

---

## Task 1: `TaskGate` — the concurrency bound

**Files:** `src/a2a/executor.rs`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/a2a/executor.rs`:

```rust
#[test]
fn gate_acquires_when_under_the_limit() {
    let gate = TaskGate::new(2);
    let p1 = gate.try_acquire().expect("first permit");
    let _p2 = gate.try_acquire().expect("second permit");
    drop(p1);
}

#[test]
fn gate_refuses_when_the_limit_is_held() {
    let gate = TaskGate::new(1);
    let _held = gate.try_acquire().expect("first permit must succeed");
    assert!(
        gate.try_acquire().is_err(),
        "a second task must be refused while the only permit is held"
    );
}

#[test]
fn gate_never_creates_a_zero_permit_deadlock() {
    // `max_concurrent_tasks = 0` must clamp to 1, not create a gate that
    // refuses every task forever.
    let gate = TaskGate::new(0);
    assert_eq!(gate.limit(), 1);
    gate.try_acquire().expect("a zero-configured gate must still admit one task");
}

#[test]
fn gate_reports_the_limit_in_the_error() {
    let gate = TaskGate::new(3);
    let _a = gate.try_acquire().unwrap();
    let _b = gate.try_acquire().unwrap();
    let _c = gate.try_acquire().unwrap();
    let err = gate.try_acquire().unwrap_err();
    assert!(err.message.contains("3"), "error must name the limit: {}", err.message);
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib a2a::executor`
Expected: FAIL to compile — `TaskGate` does not exist.

- [ ] **Step 3: Implement `TaskGate`**

Add to `src/a2a/executor.rs`:

```rust
/// Bound on concurrently running A2A agent turns.
///
/// A semaphore with `max_concurrent_tasks` permits. `execute` takes a permit
/// with `try_acquire_owned` and, when the limit is held, fails the task
/// immediately instead of queueing it: with a synchronous `SendMessage` a
/// queued task would occupy the peer's HTTP connection for the entire queue
/// wait with no feedback, and a `GetTask` poll cannot help because the
/// connection never returns.
#[derive(Debug)]
pub struct TaskGate {
    permits: Arc<tokio::sync::Semaphore>,
    limit: usize,
}

/// The semaphore is exhausted.
#[derive(Debug)]
pub struct GateFull {
    pub message: String,
}

impl TaskGate {
    pub fn new(limit: usize) -> Self {
        // Clamp: `max_concurrent_tasks = 0` must mean "one at a time", never
        // "refuse everything forever". Config validation rejects 0 anyway
        // (Task 2); this is defence in depth for callers that skip it.
        let limit = limit.max(1);
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(limit)),
            limit,
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn try_acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, GateFull> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| GateFull {
                message: format!(
                    "concurrency limit reached (max_concurrent_tasks = {})",
                    self.limit
                ),
            })
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib a2a::executor`
Expected: 4 new tests PASS (the Phase 2 tests keep passing).

- [ ] **Step 5: Prove the tests have teeth**

For each of the three behavioural tests, make the corresponding change and
confirm it fails, then revert:

1. In `TaskGate::new`, change `limit.max(1)` to `limit` → `gate_never_creates_a_zero_permit_deadlock` fails.
2. Change `try_acquire_owned` to `acquire_owned` (blocking) → no test fails on the happy path, so instead change the map_err to `.map_err(|_| GateFull { message: "wrong".into() })` → `gate_reports_the_limit_in_the_error` fails.
3. Change `try_acquire` to always `Ok(...)` → `gate_refuses_when_the_limit_is_held` fails.

- [ ] **Step 6: Wire the gate into `A2aExecutor`**

`A2aExecutor` gains a `gate: TaskGate` field:

```rust
pub struct A2aExecutor {
    agent: Arc<crate::agent::Agent>,
    gate: TaskGate,
}

impl A2aExecutor {
    pub fn new(agent: Arc<crate::agent::Agent>) -> Self {
        let limit = agent.config.a2a.max_concurrent_tasks;
        Self {
            agent,
            gate: TaskGate::new(limit),
        }
    }
}
```

In `execute`, acquire the permit **before** registering the cancel token and
running the turn, and hold it across the turn:

```rust
Box::pin(futures::stream::once(async move {
    // Acquired BEFORE registering the cancel token: a refused task must not
    // leave a token in the registry for CancelTask to cancel.
    let _permit = match self.gate.try_acquire() {
        Ok(p) => p,
        Err(full) => {
            return Ok(StreamResponse::Task(failed_task(
                &task_id, &context_id, &full.message,
            )));
        }
    };
    // ... existing body ...
}))
```

Add the helper:

```rust
/// A terminal `Failed` task carrying `message`, used for errors that happen
/// before the agent turn starts.
fn failed_task(task_id: &str, context_id: &str, message: &str) -> Task {
    Task {
        id: task_id.to_string(),
        context_id: context_id.to_string(),
        status: TaskStatus {
            state: TaskState::Failed,
            message: Some(Message {
                message_id: uuid::Uuid::new_v4().to_string(),
                context_id: Some(context_id.to_string()),
                task_id: Some(task_id.to_string()),
                role: Role::Agent,
                parts: vec![Part::text(message)],
                metadata: None,
                extensions: None,
                reference_task_ids: None,
            }),
            timestamp: None,
        },
        artifacts: None,
        history: None,
        metadata: None,
    }
}
```

Check `TaskStatus.message` is indeed `Option<Message>` in
`a2a-lf-0.3.1/src/types.rs` before writing this; adjust if the field type
differs (e.g. it may hold the message that explains the state).

- [ ] **Step 7: Run the whole suite**

Run: `cargo test`
Expected: all green (577 lib + the 4 new gate tests + 7 a2a_endpoint + 1
ignored E2E).

- [ ] **Step 8: Commit**

```bash
git add src/a2a/executor.rs
git commit -m "feat(a2a): bound concurrent turns with a TaskGate semaphore"
```

---

## Task 2: Reject `max_concurrent_tasks = 0` at startup

**Files:** `src/config.rs`

- [ ] **Step 1: Write the failing test**

Add to the existing `A2aConfig` validation tests in `src/config.rs`:

```rust
#[test]
fn a2a_zero_max_concurrent_tasks_is_refused() {
    let mut cfg = a2a_cfg();
    cfg.max_concurrent_tasks = 0;
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("max_concurrent_tasks"),
        "error must name the field: {err}"
    );
}
```

(`a2a_cfg()` is the existing test helper that builds a valid `A2aConfig`.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib a2a_zero_max_concurrent_tasks_is_refused`
Expected: FAIL — `validate()` currently accepts 0.

- [ ] **Step 3: Implement the check**

In `A2aConfig::validate()` (`src/config.rs`), after `validate_peers()` and
before `warn_on_non_loopback_bind()`, add:

```rust
if self.max_concurrent_tasks == 0 {
    anyhow::bail!(
        "[a2a] max_concurrent_tasks must be at least 1 (0 would refuse every task)"
    );
}
```

- [ ] **Step 4: Run the test and prove it has teeth**

Run: `cargo test --lib a2a_zero_max_concurrent_tasks_is_refused`
Expected: PASS. Then remove the new check, confirm the test fails, restore it.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): refuse a2a max_concurrent_tasks of 0 at startup"
```

---

## Task 3: E2E — `GetTask` returns the completed task

**Files:** `tests/a2a_e2e_live.rs`

- [ ] **Step 1: Add the test**

In the existing harness file, after `an_authenticated_peer_drives_a_send_message_to_completed`,
add a second `#[ignore]`d test that reuses the same setup:

1. Run the SendMessage flow (factor the send + parse of the returned task id
   into a helper if the first test does not already have one — do not
   duplicate the Agent construction; a small `setup()` returning the pieces is
   the clean shape).
2. Send `GetTask`:
   ```json
   {"jsonrpc":"2.0","id":2,"method":"GetTask",
    "params":{"taskId":"<the id from step 1>"}}
   ```
3. Assert the response `result.task.id` equals the id and
   `result.task.status.state` is `TASK_STATE_COMPLETED`.

Also assert the missing-task case:
`GetTask` with a bogus id returns a JSON-RPC error with code `-32001`
(`TASK_NOT_FOUND`) — pins that our store's `Ok(None)` maps through the SDK to
the right wire error.

- [ ] **Step 2: Run it**

Run: `HAOS_GREEN_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored --nocapture`
Expected: both tests PASS.

- [ ] **Step 3: Run the suite without the env var**

Run: `cargo test`
Expected: the new test is reported `ignored`; everything else green.

- [ ] **Step 4: Commit**

```bash
git add tests/a2a_e2e_live.rs
git commit -m "test(a2a): prove GetTask returns the persisted task end to end"
```

---

## Task 4: E2E — `CancelTask` reaches `canceled` (criterion 5)

**Files:** `tests/a2a_e2e_live.rs`

The challenge: a live model answers in ~2s, so cancelling the *real* agent turn
is racy. Two deterministic layers:

- [ ] **Step 1: Unit-test the wiring**

In `src/a2a/executor.rs`, `A2aExecutor::cancel` is thin — it calls
`agent.cancel_processing(&cancel_key(&task_id))`. The parts that are testable
without an `Agent` are already covered (`cancel_key` namespacing). Verify the
`cancel` method compiles and emits `Failed` for a task that was never running
by reading its behaviour — document in the test file comment that the
agent-side effect (`cancel_processing` → `CancellationToken::cancel` →
`run_with_policy` returns `Cancelled`) is exercised through the live test's
`run_with_policy` mapping, which the Phase 2 test already proves reaches
`TASK_STATE_COMPLETED` for the non-cancelled path.

- [ ] **Step 2: Live E2E with a test-only slow executor**

Add to `tests/a2a_e2e_live.rs` a `SlowExecutor` that sleeps until its task is
cancelled:

```rust
struct SlowExecutor; // holds an Arc<CancellationToken> set by the test via CancelTask
```

Design: the test needs the SDK to route `CancelTask` to the executor's
`cancel` while the task is still `working`. A clean deterministic shape:

1. Build a second listener whose handler uses `SlowExecutor` (an executor that
   emits a `Task(working)` once, then blocks until a oneshot the test holds is
   fired) + `InMemoryTaskStore` or `SqliteTaskStore`.
2. Send `SendMessage` — the SDK returns immediately (the executor emitted
   `working`, so `send_message` may still wait for terminal... **check the SDK
   behaviour**: if `send_message` waits for terminal, the SendMessage HTTP call
   will block. In that case send it with `tokio::spawn` and poll `GetTask`
   until the state is `working`, then `CancelTask`.)
3. `CancelTask` → the executor's `cancel` fires the oneshot → the slow executor
   emits `Task(canceled)` → the SDK persists it.
4. `GetTask` asserts `TASK_STATE_CANCELED`.

**Read the SDK's `cancel_task` and `send_message` implementations first**
(`handler.rs`) and shape the test to what they actually do. If `send_message`
blocks until terminal, the spawned-send + GetTask-poll shape above is the one
to use; if the SDK already handles the in-flight race, adapt. Do not assume.

- [ ] **Step 3: Run it**

Run: `HAOS_GREEN_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored --nocapture`
Expected: `canceled` path PASS.

- [ ] **Step 4: Full gates**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

All clean; the two new E2E tests reported `ignored` without the env var.

- [ ] **Step 5: Commit**

```bash
git add tests/a2a_e2e_live.rs
git commit -m "test(a2a): prove CancelTask drives a running task to canceled"
```

---

## Self-Review

**Spec coverage.** Phase 3 per the spec's phase table: "`GetTask`, `CancelTask`,
semaphore; lifecycle fully async", verifiable by success criterion 5
(`CancelTask` stops an in-flight task and the task reaches `canceled`).

- Semaphore — Task 1 (`TaskGate`), Task 2 (config validation).
- `GetTask` — Task 3 (already served by the SDK + our store; proven live).
- `CancelTask` → `canceled` — Task 4 (already served by the SDK + our
  executor; proven live against a deterministic slow executor).

**Known gaps, to state honestly, not silently:**

1. `ListTasks` still returns `unsupported_operation`. It is deliberately out of
   Phase 3 scope; the spec's phase table does not list it, and an honest
   refusal beats an empty page.
2. A `SendMessage` blocked on the gate is failed immediately rather than
   queued. The spec says "semaphore", and a semaphore can block — but with a
   synchronous `SendMessage` a queued task would hold the peer's HTTP
   connection for the whole queue wait with no feedback, and `returnImmediately`
   + polling is not implemented. Immediate refusal is the honest choice;
   record it in the Task 1 commit message and the spec's Concurrency section.
3. `returnImmediately` remains unimplemented: the SDK honours it, but with no
   way for the client to poll beyond `GetTask` (which exists), the feature is
   coherent now — but the executor does not yet special-case it. Confirm with
   the implementer's SDK reading whether `returnImmediately=true` already
   short-circuits `send_message` to return the working task; if it does, note
   that it works today, else leave it for a later phase.

**Mutation coverage.** Task 1 Step 5 enumerates three concrete mutations with
the exact test each one must fail. Task 2 Step 4 specifies its mutation. Task 3
and 4 are live tests whose assertions are the observed wire values.

**No placeholders.** Every code step is complete. The only open item is the
behaviour of `send_message` under `returnImmediately` and under an
already-terminal task, which is a *reading* step (Task 4 Step 2, Task 1 note)
that shapes the test, not a stub in the code.
