# HaosGreen Robustness Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden HaosGreen shutdown, outbound A2A timeouts, supervisor multi-process coordination, and complete Telegram supervisor commands without regressing the verified dashboard/A2A behavior.

**Architecture:** Keep the four concerns isolated: a shared shutdown abstraction is injected into the A2A and web listener tasks; A2A timeout policy remains in `A2aClient`; supervisor leases live in SQLite beside task state and complement the existing CAS/in-flight guard; Telegram command handling delegates to the existing `Supervisor` API and Telegram sender. Each concern gets focused tests and a review before integration.

**Tech Stack:** Rust 2021, Tokio, Axum 0.8, rusqlite/SQLite, reqwest, teloxide, anyhow, serde, existing HaosGreen test helpers.

---

## Files and boundaries

- Modify `src/main.rs`: create and broadcast the process shutdown signal; route complete Telegram supervisor commands; preserve startup ordering and non-fatal listener failures.
- Modify `src/a2a/server.rs`: accept a shutdown future and graceful Axum serving; preserve the existing public spawn wrapper where possible.
- Modify `src/web/mod.rs`: accept shutdown subscription and graceful Axum serving; expose a test-only shutdown hook through existing test helpers.
- Modify `src/web/routes/logs.rs` and `src/web/routes/chat.rs`: observe shutdown cancellation in SSE streams and terminate cleanly.
- Modify `src/config.rs`, `src/a2a/client.rs`, `src/a2a/tool.rs`: optional synchronous outbound timeout, validation/defaults, typed timeout behavior, no POST retries.
- Modify `src/supervisor/store.rs`, `src/supervisor/mod.rs`, migrations/startup memory initialization: SQLite execution lease lifecycle.
- Modify `src/platform/telegram.rs`: parse and dispatch `/supervise`, `/tasks`, `/resume`, `/cancel`, `/approve`, `/clarify` through bounded safe replies.
- Modify `tests/a2a_endpoint.rs`, `tests/web_endpoint.rs`, `tests/a2a_e2e_live.rs` and focused unit modules for regression coverage.
- Modify `CLAUDE.md`, `README.md`, and `config.example.toml` only after implementation, to document new keys and shutdown/lease semantics.

---

### Task 1: Graceful shutdown for A2A and Web

**Files:**
- Modify: `src/main.rs`
- Modify: `src/a2a/server.rs`
- Modify: `src/web/mod.rs`
- Modify: `src/web/routes/logs.rs`
- Modify: `src/web/routes/chat.rs`
- Test: `tests/a2a_endpoint.rs`, `tests/web_endpoint.rs`

- [ ] **Step 1: Write shutdown tests first.** Add tests that start each listener on an ephemeral port, verify a health/static request succeeds, signal a `broadcast::Sender<()>`, await the listener task with a bounded timeout, and assert a new connection is refused. Add an SSE test that opens the log stream, sends shutdown, and asserts the stream terminates without waiting for the normal ticker. Use `tokio::time::timeout(Duration::from_secs(2), ...)` so failure is deterministic.

- [ ] **Step 2: Run the focused tests and observe failure.** Run `cargo test --test web_endpoint shutdown -- --nocapture` and `cargo test --test a2a_endpoint shutdown -- --nocapture`. Expected: compile failure or timeout because the current listener tasks have no shutdown receiver.

- [ ] **Step 3: Add one shared shutdown signal in `main.rs`.** Create a `tokio::sync::broadcast::channel::<()>(1)` before starting optional listeners. Pass `shutdown_tx.subscribe()` to A2A and web startup. In the process shutdown branch, send once and ignore `SendError`; retain existing Telegram/MCP/scheduler cleanup. Do not create a replacement process-wide runtime or second server.

- [ ] **Step 4: Add graceful serving to A2A.** Change the internal server startup to use `axum::serve(listener, router).with_graceful_shutdown(async move { let _ = shutdown_rx.recv().await; })`. Keep the existing `spawn` compatibility wrapper by giving it a never-triggered receiver only where tests or callers intentionally request no shutdown. Return the actual bound address and preserve non-fatal startup error behavior.

- [ ] **Step 5: Add graceful serving to Web.** Apply the same `with_graceful_shutdown` pattern to the Axum web listener. Ensure `spawn_for_test*` helpers create and retain a sender so tests can signal shutdown without global process state.

- [ ] **Step 6: Make active SSE routes observe shutdown.** Add a shutdown receiver to web state or a dedicated cancellation token. In `/api/logs/stream` and chat SSE stream generation, include shutdown in `tokio::select!` alongside the ticker/channel receive and return the stream cleanly. Drop per-stream resources and retry timers on termination.

- [ ] **Step 7: Prove mutations have teeth.** In a scratch copy, remove `with_graceful_shutdown` and rerun the shutdown tests; assert the bounded await fails. Remove the shutdown branch from the SSE `select!`; assert the SSE termination test fails. Restore the source and rerun focused tests.

- [ ] **Step 8: Run gates and commit.** Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and focused plus existing A2A/web tests. Commit with `feat(runtime): gracefully shut down axum listeners`.

---

### Task 2: Configurable synchronous A2A `SendMessage` timeout

**Files:**
- Modify: `src/config.rs`
- Modify: `src/a2a/client.rs`
- Modify: `src/a2a/tool.rs`
- Test: `src/a2a/client.rs`, `tests/a2a_endpoint.rs`

- [ ] **Step 1: Define the compatibility contract.** Add an optional `send_timeout_secs: Option<u64>` to `A2aOutboundPeerConfig`, defaulting to `None`; document that `None` uses the existing `timeout_secs`, zero is rejected, and the value is capped at a fixed safe maximum constant. Keep serialized configs without the field valid.

- [ ] **Step 2: Write failing timeout tests.** Add a local A2A stub that accepts `SendMessage` but delays its response. Test that `send_timeout_secs` aborts the complete request future before the peer transport timeout, returns a typed timeout error, and sends no automatic second POST. Test that `None` retains existing behavior and that zero/over-limit values fail validation.

- [ ] **Step 3: Run the focused tests to observe failure.** Run `cargo test --lib a2a::client` and the new integration filter. Expected: unknown field/constructor errors or the delayed request exceeds the configured synchronous deadline.

- [ ] **Step 4: Implement timeout selection.** Add a helper on the peer config/client that chooses `send_timeout_secs.unwrap_or(timeout_secs)`, validates/caps it, and wraps only the `SendMessage` future in `tokio::time::timeout`. Leave `GetTask` polling governed by `poll_timeout_secs`. Preserve the no-automatic-POST-retry rule and sanitize timeout errors before returning them through `call_a2a_agent`.

- [ ] **Step 5: Update config examples and redacted Debug.** Include the optional key in `config.example.toml`; ensure `A2aOutboundPeerConfig` Debug still excludes token values and includes the timeout safely.

- [ ] **Step 6: Prove mutation teeth.** In a scratch copy, bypass the `tokio::time::timeout` wrapper and assert the delayed stub test exceeds its deadline/fails. Mutate the code to retry POST and assert the request counter becomes 2 while the test requires exactly 1. Restore and rerun.

- [ ] **Step 7: Run gates and commit.** Run focused A2A tests, `cargo fmt`, clippy and the full test suite. Commit with `feat(a2a): configure synchronous send timeout`.

---

### Task 3: SQLite multi-process supervisor execution lease

**Files:**
- Modify: `src/supervisor/store.rs`
- Modify: `src/supervisor/mod.rs`
- Modify: `src/memory/mod.rs` or the existing supervisor schema initialization site
- Test: `src/supervisor/store.rs`, `src/supervisor/mod.rs`

- [ ] **Step 1: Write failing lease tests.** Create two independent `TaskStore` instances over the same temporary SQLite database. Assert the first owner acquires a task lease, the second is refused while unexpired, the first releases it, and the second then acquires. Add an expiry test using a short injected TTL/clock value, and a crash-recovery test that leaves the first lease un-released and lets the second reclaim after expiry.

- [ ] **Step 2: Run lease tests and observe failure.** Run `cargo test --lib supervisor::store` and `cargo test --lib supervisor::` with the new filters. Expected: missing table/API or duplicate execution because no persistent lease exists.

- [ ] **Step 3: Add the lease schema.** Create an idempotent `sup_execution_leases` table with `task_id PRIMARY KEY`, `owner_id`, `acquired_at`, and `expires_at`, plus an index on expiry. Use SQLite UTC timestamps or integer epoch seconds consistently with existing store conventions.

- [ ] **Step 4: Implement atomic acquire/release.** Add `try_acquire_execution_lease(task_id, owner_id, now, ttl)` using one transaction and a conditional insert/update that only replaces an existing row when `expires_at <= now` or `owner_id` matches. Return a typed conflict error for a live foreign owner. Add `release_execution_lease(task_id, owner_id)` conditioned on owner identity; never let one process release another's lease.

- [ ] **Step 5: Integrate with `Supervisor::execute_now`.** Acquire the persistent lease before the existing process-local `InFlight` guard's execution begins; keep the existing guard for same-process duplicate work. Wrap execution in an owned guard whose `Drop`/async cleanup releases on success, error and cancellation. Do not hold SQLite mutex guards across `.await`; renew only if execution can exceed the TTL, and use a bounded renewal task if required by the chosen TTL.

- [ ] **Step 6: Preserve state CAS semantics.** Keep `TaskStore::record_transition` compare-and-swap unchanged as the state authority. Map lease conflicts to `SupervisorError::AlreadyRunning` so HTTP and Telegram callers receive the existing conflict semantics without raw database details.

- [ ] **Step 7: Prove mutation teeth.** In a scratch copy, replace the conditional acquisition with unconditional insert/update and assert the two-store contention test fails. Remove release cleanup and assert the post-release acquisition test fails. Reduce/disable expiry reclamation and assert crash-recovery fails. Restore and rerun all lease tests.

- [ ] **Step 8: Run gates and commit.** Run supervisor unit tests, concurrency tests under multi-thread Tokio, full `cargo fmt`, clippy and `cargo test`. Commit with `feat(supervisor): persist execution leases across processes`.

---

### Task 4: Complete Telegram supervisor command integration

**Files:**
- Modify: `src/platform/telegram.rs`
- Modify: `src/main.rs`
- Modify: `src/supervisor/mod.rs` only if a clarification API is missing
- Test: `src/platform/telegram.rs`, integration tests using a recording sender

- [ ] **Step 1: Inventory existing public APIs.** Confirm exact signatures and state/error behavior for `Supervisor::submit`, `execute_now`, `list_recent`, `pause`, `resume`, `cancel`, `approve`, and any clarification method. Do not invent a second supervisor execution path. If clarification has no API, add the smallest typed method that updates the task context and resumes the existing workflow.

- [ ] **Step 2: Write parser and authorization tests first.** Test `/supervise <text>`, `/tasks`, `/resume <id>`, `/cancel <id>`, `/approve <id>`, and `/clarify <id> <text>` with missing arguments, extra whitespace, malformed IDs, and bounded long text. Test a user outside `telegram.allowed_user_ids` receives no supervisor action. Test errors are bounded and do not contain raw anyhow chains or secret-shaped values.

- [ ] **Step 3: Write dispatcher tests with a recording sender.** For each command, use a fake/recording `PlatformSender` and an isolated supervisor store. Assert the exact supervisor method called, actor/user identity, bounded reply, and no duplicate invocation on retries. Test `/tasks` caps output and marks state clearly.

- [ ] **Step 4: Implement a dedicated command dispatcher.** In `telegram.rs`, add one function that receives the parsed command, authorized user context, `Arc<Supervisor>`, and sender. Match the six command names, validate argument count, call the existing API, redact task/error text, and send concise success/conflict/not-found messages. Keep unrelated bot commands byte-for-byte behaviorally unchanged.

- [ ] **Step 5: Wire supervisor dependency injection.** In `main.rs`, pass the already-created `Arc<Supervisor>` into the Telegram dispatcher/dptree handler. Ensure no second Supervisor or separate SQLite store is constructed. Preserve startup when supervisor is unavailable by returning a bounded configuration error.

- [ ] **Step 6: Add clarification behavior.** If the existing supervisor supports clarification, call it directly. Otherwise add a typed `Supervisor::clarify(task_id, text)` that validates non-empty bounded text, records the reason, and resumes only a task in `Clarify`; all other states return a conflict without executing work.

- [ ] **Step 7: Prove mutation teeth.** In a scratch copy, bypass the allowed-user check and assert the unauthorized-command test fails. Replace one command match with a no-op and assert its recording-sender test fails. Remove reply truncation and assert the bounded-output test fails. Restore and rerun.

- [ ] **Step 8: Run gates and commit.** Run Telegram/supervisor tests, full fmt, clippy and cargo test. Commit with `feat(telegram): integrate supervisor commands`.

---

### Task 5: Documentation and integrated verification

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `config.example.toml`
- Test: all existing suites and live E2E tests

- [ ] **Step 1: Document verified behavior.** Add the optional A2A send timeout key and cap; describe graceful shutdown signal ordering and SSE termination; describe SQLite lease ownership/expiry/recovery; document all six Telegram commands and their authorization/bounded-output rules.

- [ ] **Step 2: Run static and unit gates.** Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`; capture exact outputs and investigate every failure.

- [ ] **Step 3: Run live gates.** With the configured local provider, run `HAOS_GREEN_A2A_LIVE=1 cargo test --test a2a_e2e_live -- --ignored` and `HAOS_GREEN_WEB_LIVE=1 cargo test --test web_endpoint a_live_chat_message_streams_tokens_and_exactly_one_done_event -- --ignored`. Report each observed result separately.

- [ ] **Step 4: Run final mutation smoke tests.** Re-run the shutdown, timeout, lease, authorization and output-boundary mutations in scratch copies. Confirm every mutant fails and every source revert restores green. Never mutate or commit `.measure/`.

- [ ] **Step 5: Inspect regression scope.** Review `git diff --check`, `git status --short`, staged paths, and recent commits. Confirm no `config.toml`, `.env`, `target/`, or `.measure/` content is staged.

- [ ] **Step 6: Commit documentation and integration.** Commit docs with `docs: document robustness hardening`, then run the final full gates once more and record the resulting commit list and residual risks.
