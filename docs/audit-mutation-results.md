# Directed Mutation Verification Report

Date: 2026-09-20  
Workspace: `/tmp/rustfox-directed-mut` (target directory: `/tmp/rustfox-directed-mut/target`)  
Scope: 3 Directed Mutants tested sequentially, verifying failure on mutation and baseline pass on restoration.

---

## Executive Summary

All 3 directed mutation tests were executed in the isolated scratch workspace `/tmp/rustfox-directed-mut`. Each mutant produced the expected assertion failure with exit code 101. Following restoration of each mutated file, the corresponding test was re-run and verified to pass cleanly (exit code 0). No production files in the main repository were modified.

| Mutant # | Description | Target Test | Mutated Result | Restored Result |
|---|---|---|---|---|
| **Mutant 1** | Model Snapshot Race (`process_message` model read race) | `tests/runtime_wiring.rs::runtime_inflight_turn_keeps_model_snapshot` | **FAILED** (Exit code 101) | **PASSED** (Exit code 0) |
| **Mutant 2** | Scheduler Clean Removal (`cancel_scheduled_task` skips `remove_job`) | `src/scheduling_tools.rs::scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback` | **FAILED** (Exit code 101) | **PASSED** (Exit code 0) |
| **Mutant 3** | Registration Readiness Gate (`dispatch_registered` early fire / bypass `ready_rx`) | `src/scheduling_tools.rs::scheduling_tools::tests::registration_gate_holds_early_fire_until_decision` | **FAILED** (Exit code 101) | **PASSED** (Exit code 0) |

---

## Detailed Mutant Test Results

### Mutant 1: Model Snapshot Race

- **Target File**: `/tmp/rustfox-directed-mut/src/agent.rs` (`process_message`)
- **Mutation Applied**:
  Moved `let current_model = self.current_model.read().await.clone();` from before the conversation creation to *after* the database await (`self.memory.get_or_create_conversation`).
- **Test Command**:
  ```bash
  CARGO_TARGET_DIR=/tmp/rustfox-directed-mut/target cargo test --test runtime_wiring runtime_inflight_turn_keeps_model_snapshot --locked
  ```
- **Observed Mutation Failure**:
  ```text
  running 1 test
  test runtime_inflight_turn_keeps_model_snapshot ... FAILED

  failures:

  ---- runtime_inflight_turn_keeps_model_snapshot stdout ----

  thread 'runtime_inflight_turn_keeps_model_snapshot' (4117084) panicked at tests/runtime_wiring.rs:348:5:
  assertion `left == right` failed
    left: "modelB"
   right: "modelA"

  failures:
      runtime_inflight_turn_keeps_model_snapshot

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.07s
  error: test failed, to rerun pass `--test runtime_wiring`
  Exit code: 101
  ```
- **Restoration**:
  Restored `let current_model = self.current_model.read().await.clone();` to run before any database await or message processing, ensuring the model snapshot is immutable for the entire inflight turn.
- **Observed Restored Baseline**:
  ```text
  running 1 test
  test runtime_inflight_turn_keeps_model_snapshot ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.07s
  Exit code: 0
  ```

---

### Mutant 2: Scheduler Clean Removal

- **Target File**: `/tmp/rustfox-directed-mut/src/scheduling_tools.rs` (`cancel_scheduled_task`)
- **Mutation Applied**:
  Commented out the `self.scheduler.remove_job(sched_uuid).await` call inside `cancel_scheduled_task`.
- **Test Command**:
  ```bash
  CARGO_TARGET_DIR=/tmp/rustfox-directed-mut/target cargo test --lib scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback --locked
  ```
- **Observed Mutation Failure**:
  ```text
  running 1 test
  test scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback ... FAILED

  failures:

  ---- scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback stdout ----

  thread 'scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback' (4126454) panicked at src/scheduling_tools.rs:549:9:
  assertion failed: tokio::time::timeout(std::time::Duration::from_secs(3),
              raw_rx.recv()).await.is_err()

  failures:
      scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1094 filtered out; finished in 0.54s
  error: test failed, to rerun pass `--lib`
  Exit code: 101
  ```
- **Restoration**:
  Uncommented and restored `self.scheduler.remove_job(sched_uuid).await`, ensuring raw scheduler callbacks are cleaned up upon task cancellation.
- **Observed Restored Baseline**:
  ```text
  running 1 test
  test scheduling_tools::tests::cancel_tool_removes_raw_scheduler_callback ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1094 filtered out; finished in 4.04s
  Exit code: 0
  ```

---

### Mutant 3: Registration Readiness Gate

- **Target File**: `/tmp/rustfox-directed-mut/src/agent.rs` (`dispatch_registered`)
- **Mutation Applied**:
  Bypassed awaiting the readiness decision on `ready_rx` by setting `decision = Ok(true)` immediately and removing the wait on `ready.changed().await`.
- **Test Command**:
  ```bash
  CARGO_TARGET_DIR=/tmp/rustfox-directed-mut/target cargo test --lib scheduling_tools::tests::registration_gate_holds_early_fire_until_decision --locked
  ```
- **Observed Mutation Failure**:
  ```text
  running 1 test
  test scheduling_tools::tests::registration_gate_holds_early_fire_until_decision ... FAILED

  failures:

  ---- scheduling_tools::tests::registration_gate_holds_early_fire_until_decision stdout ----

  thread 'scheduling_tools::tests::registration_gate_holds_early_fire_until_decision' (4128822) panicked at src/scheduling_tools.rs:672:13:
  assertion failed: futures::poll!(&mut fire).is_pending()

  failures:
      scheduling_tools::tests::registration_gate_holds_early_fire_until_decision

  test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1094 filtered out; finished in 0.05s
  error: test failed, to rerun pass `--lib`
  Exit code: 101
  ```
- **Restoration**:
  Restored `tokio::time::timeout(std::time::Duration::from_secs(30), ...)` loop observing `ready.borrow_and_update()` and `ready.changed().await`, holding dispatch until the registration decision is committed.
- **Observed Restored Baseline**:
  ```text
  running 1 test
  test scheduling_tools::tests::registration_gate_holds_early_fire_until_decision has been running for over 60 seconds
  test scheduling_tools::tests::registration_gate_holds_early_fire_until_decision ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1094 filtered out; finished in 60.34s
  Exit code: 0
  ```

---

## File Integrity Verification

Post-test verification confirms that all modified files in `/tmp/rustfox-directed-mut` match the source files in `/run/media/adriano/e681b5ac-a4fb-44d4-aebf-9d6584065787/dsh-projetos/rustfox`:
- `diff -u src/agent.rs /tmp/rustfox-directed-mut/src/agent.rs` -> identical (exit code 0)
- `diff -u src/scheduling_tools.rs /tmp/rustfox-directed-mut/src/scheduling_tools.rs` -> identical (exit code 0)
- In the main repository, only `docs/audit-mutation-results.md` was created/updated.
