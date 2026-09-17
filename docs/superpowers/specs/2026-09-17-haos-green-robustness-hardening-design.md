# HaosGreen Robustness Hardening Design

## Objective

Harden the completed HaosGreen dashboard and supervisor integration across four independent areas:

1. Graceful shutdown for A2A and web Axum listeners.
2. Configurable synchronous outbound A2A `SendMessage` timeout.
3. Crash-tolerant multi-process supervisor execution coordination.
4. Complete Telegram supervisor command integration.

## Constraints

- Preserve existing APIs and configuration compatibility unless a new field is explicitly optional.
- Keep the dashboard and A2A listeners optional and non-blocking for Telegram startup.
- Never expose credentials, prompts, stack traces, or unbounded remote text in Telegram or HTTP responses.
- Preserve the existing supervisor transition CAS and process-local in-flight guard.
- Never modify or commit `.measure/`, `config.toml`, `.env`, or generated artifacts.
- Every security/concurrency property must have a mutation proving the test has teeth.

## Architecture

### Global shutdown

`main` owns a broadcast/oneshot shutdown signal. A2A and web startup receive shutdown subscriptions. Their Axum servers use `with_graceful_shutdown`; active SSE streams observe cancellation and terminate. The main shutdown path signals listeners before stopping Telegram/MCP/scheduler resources, with a bounded grace period and no panic if a receiver is absent.

### A2A synchronous timeout

Add an optional outbound configuration timeout for the synchronous `SendMessage` request, preserving the existing peer transport timeout as the default. The timeout applies to the complete request future, is validated and bounded, and produces a typed timeout error without automatic POST retry. Polling retains its existing `poll_timeout_secs` behavior.

### Multi-process supervisor lease

Add a SQLite-backed execution lease keyed by task id, with owner identity, acquisition time, expiry, and optional renewal. Acquisition is atomic (`INSERT ... ON CONFLICT`/conditional update) and refuses a live lease. Expired leases can be reclaimed. Release occurs on all normal/error/cancel paths; stale leases are recoverable after process crash. The existing transition CAS remains authoritative for state changes. Tests cover two independent store/supervisor instances, expiry takeover, release, and mutation of the atomic acquisition.

### Telegram supervisor commands

Wire the complete command set into the existing Telegram dispatcher:

- `/supervise <request>` submits and executes/routes according to supervisor policy.
- `/tasks` lists recent/active tasks with bounded output.
- `/resume <id>` resumes only paused tasks.
- `/cancel <id>` cancels eligible tasks.
- `/approve <id>` approves eligible tasks.
- `/clarify <id> <text>` supplies clarification where supported.

All commands use the existing Telegram allowed-user gate, redact task text and errors, handle missing/malformed arguments, and send bounded replies. Existing command behavior remains unchanged.

## Error handling

- Listener bind/serve failures are logged and do not abort the bot.
- Shutdown is idempotent and bounded.
- Timeout and lease conflicts map to actionable, non-sensitive messages.
- Telegram command failures are user-readable and never include raw anyhow chains or secrets.
- Every async task releases or expires its lease even on cancellation.

## Testing and verification

- Unit tests for shutdown signal behavior, timeout semantics, lease CAS/TTL/recovery, command parsing and reply bounding.
- Integration tests with real ephemeral HTTP servers for A2A/Web shutdown and timeout.
- Multi-process lease tests using two independent SQLite connections/stores.
- Telegram dispatcher tests through the public command handling surface.
- Mutation tests for rename/lease atomicity, timeout bypass, shutdown wiring, and command authorization.
- Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, live A2A E2E and live web chat E2E where applicable.

## Delivery sequence

Implement each area with a focused agent. Run spec-compliance and code-quality review before each commit. Resolve all findings, run full gates, then commit the area. Finish with an integrated regression pass and documentation update.
