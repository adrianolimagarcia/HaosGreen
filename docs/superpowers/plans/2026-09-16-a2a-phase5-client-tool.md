# A2A Phase 5 Client and Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe outbound A2A client and `call_a2a_agent` tool, proving Agent Card discovery, authenticated messaging, bounded polling, and failure handling.

**Architecture:** `src/a2a/client.rs` owns outbound HTTP/SDK interaction and exposes a small `A2aClient` API. It uses an explicit reqwest timeout, bearer interceptor for RPC calls, authenticated card discovery, and bounded polling with a deadline. `src/a2a/tool.rs` adapts that API to HaosGreen's `ToolHandler`; peers are selected only from configured outbound entries and secrets are never logged. Tests use local ephemeral A2A routers and real HTTP without external services.

**Tech Stack:** Rust 2021, `a2a-client-lf 0.2.5`, `a2a-lf 0.3.1`, reqwest 0.12, axum, Tokio, serde_json, HaosGreen ToolHandler.

---

### Task 1: Add and probe the official client dependency

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `src/a2a/mod.rs`

- [ ] Add `a2a-client = { package = "a2a-client-lf", version = "0.2.5" }`.
- [ ] Add a compile probe test importing `A2AClient`, `A2AClientFactory`, `AgentCardResolver`, and `AuthInterceptor` with exact SDK signatures.
- [ ] Run `cargo test --lib a2a::dependency_probe`, then fmt/clippy.
- [ ] Commit the dependency probe.

### Task 2: Implement outbound client configuration and discovery

**Files:**
- Modify: `src/config.rs`
- Modify: `src/a2a/mod.rs`
- Create: `src/a2a/client.rs`
- Test: `src/a2a/client.rs`

- [ ] Add `A2aOutboundPeerConfig` with `url`, `token`, `timeout_secs`, `poll_interval_ms`, and `poll_timeout_secs`; deserialize under `[a2a.outbound.peers.<name>]`.
- [ ] Validate non-empty HTTPS/HTTP URL, non-empty token, timeout values >= 1, and duplicate names naturally through the map. Never include token values in errors.
- [ ] Implement `A2aClient::discover(name, config)` with a reqwest client timeout and an Agent Card GET carrying `Authorization: Bearer <token>`; reject cards without a JSON-RPC interface or without a compatible streaming/message binding.
- [ ] Implement `A2aClient::from_card` using `A2AClientFactory::builder().with_interceptor(Arc::new(AuthInterceptor::bearer(token))).build()` and the SDK card factory.
- [ ] Add tests for config validation, authenticated card discovery, missing card, malformed card, and timeout behavior using a local axum server.
- [ ] Run focused tests and prove validation mutation (remove URL/token/timeout check and observe failure).
- [ ] Commit client discovery.

### Task 3: Implement bounded SendMessage and polling

**Files:**
- Modify: `src/a2a/client.rs`
- Test: `src/a2a/client.rs`

- [ ] Implement `send_message(text)` creating a valid A2A v1 request with UUID message id and `ROLE_USER`.
- [ ] Implement `get_task(id)` and `poll_task(id)` with `tokio::time::Instant` deadline, interval sleep, and terminal-state check; return a clear error on timeout, task-not-found, or failed/canceled terminal state.
- [ ] Do not retry POST SendMessage automatically; duplicate task creation is not safely idempotent without a caller-supplied idempotency key. Poll GET only.
- [ ] Add local-router tests proving bearer auth, SendMessage response parsing, completed polling, timeout, missing task, and failed task errors.
- [ ] Run focused tests and full unit suite.
- [ ] Commit bounded client operations.

### Task 4: Implement and register `call_a2a_agent`

**Files:**
- Create: `src/a2a/tool.rs`
- Modify: `src/a2a/mod.rs`
- Modify: `src/main.rs`
- Modify: `config.example.toml`
- Test: `src/a2a/tool.rs`

- [ ] Implement a `CallA2aAgent` ToolHandler with arguments `{peer, prompt}`. `peer` must match configured outbound peers; unknown peers fail closed.
- [ ] Define the tool as disabled unless at least one outbound peer is configured; do not add it to `DEFAULT_PEER_TOOLS` to avoid remote recursion.
- [ ] Use the client timeout/poll bounds and return only the remote assistant text/task result. Never expose bearer tokens in returned errors or logs.
- [ ] Register the handler in the main tool registry only when outbound configuration is present.
- [ ] Add tests for definition shape, unknown peer rejection, successful local call, timeout, and secret-redaction behavior.
- [ ] Run fmt, clippy, complete tests, and local HTTP E2E.
- [ ] Commit tool integration.

### Task 5: Documentation and final review

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`
- Modify: `config.example.toml`

- [ ] Document outbound configuration, discovery authentication, polling deadlines, no automatic POST retries, and `call_a2a_agent` recursion boundary.
- [ ] State that server SSE lifecycle events are available and outbound streaming remains a separate future enhancement unless implemented by the client tool.
- [ ] Scan for stale Phase 5 claims and secrets.
- [ ] Run fmt, clippy, cargo test, and all local A2A integration tests.
- [ ] Commit documentation.

## Explicit non-goals

- No automatic POST retries.
- No outbound peer wildcard that bypasses configured peer names.
- No token logging.
- No adding `call_a2a_agent` to inbound peer default tools.
- No TLS certificate generation; HTTP remains allowed only for explicitly trusted LAN/VPN deployments, while HTTPS is recommended.
