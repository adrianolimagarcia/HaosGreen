# A2A (Agent2Agent) Client + Server Design

Date: 2026-09-16
Status: Server phases 1–4 implemented; Phase 5 outbound client remains

## Current implementation status

The server-side phases are implemented and covered by unit and live E2E tests:
`AgentExecutor` drives the RustFox agent loop under the authenticated peer tool
policy; `SendMessage`, `SendStreamingMessage`, `GetTask`, and `CancelTask` use
the SDK router and SQLite task store; and `TaskGate` bounds concurrent tasks.
The SDK JSON-RPC router is mounted at `/jsonrpc`; its streaming method returns
`text/event-stream` with one JSON-RPC response in each SSE `data:` event. The
provider response is locally chunked into token-sized pieces internally, but
these are not emitted as A2A Message events; SSE currently streams lifecycle
transitions. The production `A2aExecutor` emits `TASK_STATE_WORKING`, then emits
a terminal task whose state reflects the agent outcome (`TASK_STATE_COMPLETED`,
`TASK_STATE_FAILED`, or `TASK_STATE_CANCELED`) and whose history includes the
terminal reply. The
remaining work is Phase 5 outbound client support (`client.rs` and the
`call_a2a_agent` tool).

## Goal

Make RustFox interoperate with other agents over the A2A protocol, in both
directions:

- **Server** — expose RustFox as an A2A agent so peers can discover it via an
  Agent Card and submit tasks.
- **Client** — let RustFox call remote A2A agents, as a new tool alongside the
  existing `invoke_agent` (which only reaches local subagents).

Target deployment: **LAN/VPN**, peers are the operator's own machines or their
team's. Public-internet exposure is explicitly out of scope.

## Evidence

Research performed against primary sources before this design:

- Protocol: [a2aproject/A2A](https://github.com/a2aproject/A2A) — Apache-2.0,
  Linux Foundation. JSON-RPC 2.0 over HTTP, plus REST, gRPC and SLIMRPC
  bindings. Discovery via Agent Card at `/.well-known/agent-card.json`.
  Streaming uses SSE.

  **Method names are v1.0 PascalCase, not v0.3.0 slash-paths.** v1.0 renamed
  every operation ([What's New in v1.0](https://a2a-protocol.org/latest/whats-new-v1/)):

  | v0.3.0 (obsolete) | v1.0 (use these) |
  |---|---|
  | `message/send` | `SendMessage` |
  | `message/stream` | `SendStreamingMessage` |
  | `tasks/get` | `GetTask` |
  | `tasks/list` | `ListTasks` |
  | `tasks/cancel` | `CancelTask` |
  | `tasks/resubscribe` | `SubscribeToTask` |
  | `tasks/pushNotificationConfig/*` | `CreateTaskPushNotificationConfig`, `GetTaskPushNotificationConfig`, `ListTaskPushNotificationConfigs`, `DeleteTaskPushNotificationConfig` |
  | `agent/getAuthenticatedExtendedCard` | `GetExtendedAgentCard` |

  The SDK implements the v1.0 names only (`a2a-lf/src/jsonrpc.rs`, `methods`
  module) and rejects `message/send` with `-32601`. Since the Agent Card
  advertises `protocolVersion: "1.0"`, v1.0 naming is the consistent choice.
  A v0.3.0-only client will not interoperate; that is accepted.
- Official Rust SDK: [a2aproject/a2a-rs](https://github.com/a2aproject/a2a-rs),
  published as `a2a-lf` 0.3.1, `a2a-server-lf` 0.3.1, `a2a-client-lf` 0.2.5,
  `a2a-pb` **0.1.8**. Requires Rust 1.85+ (toolchain here is 1.98.1).
  `a2a-pb` carries a `build.rs` that generates protobuf + pbjson code, using
  `protoc_bin_vendored` when `PROTOC` is unset, so **no system protoc is
  needed**.

Dependency fit verified against this repo's `Cargo.lock`:

| SDK requires | RustFox already has |
|---|---|
| `axum ^0.8` | 0.8.9 |
| `reqwest ^0.12` | 0.12.28 |
| `chrono`, `serde`, `serde_json`, `uuid`, `async-trait`, `futures`, `tracing` | all present |

Phase 1 added `a2a-lf` 0.3.1 and `base64 0.23.1` (RustFox already has 0.22;
the two coexist as separate majors and cannot be deduplicated because `reqwest`,
`rmcp` and `teloxide-core` still require 0.22). `ipnet` 2.12.1, `subtle` 2.6.1
and `tower-http` 0.6.11 were **already present transitively** and were only
promoted to direct dependencies.

> **Phase 2 adds 38 packages, measured.** `a2a-server-lf` 0.3.1 takes the
> lockfile from 454 to 492 packages (`grep -c '^\[\[package\]\]' Cargo.lock`
> before and after). The additions include the protobuf chain (`a2a-pb` 0.1.8
> → `prost`, `prost-build`, `pbjson`, `tonic`, `petgraph`, `prettyplease`) and
> `aws-lc-rs`/`aws-lc-sys`, which pull in `cmake`.
>
> An earlier revision of this document said ~224. That was wrong: it came from
> a measurement in a standalone scratch crate, where the SDK's *entire*
> transitive tree counts as new. Against RustFox's existing 454 packages the
> true delta is 38. The build also gains a protobuf codegen step; it uses
> `protoc_bin_vendored`, so no system protoc is required, and `cargo check`
> completed in 1m01s from cold on this machine.


Server extension points confirmed **by reading the crate source** for
`a2a-server-lf` 0.3.1: `AgentExecutor`, `ExecutorContext`, `TaskStore` +
`InMemoryTaskStore`, `AgentCardProducer` + `StaticAgentCard`,
`DefaultRequestHandler`, `RequestHandler`, and the `jsonrpc`, `rest`, `sse`
modules.

> **`CallInterceptor` is NOT a usable extension point.** `InterceptedHandler`
> does not implement `RequestHandler`, and `CallInterceptor::before`/`after` are
> invoked only from the crate's own tests — no transport ever consults them.
> An earlier revision of this document listed it as the auth mechanism; that was
> wrong. Phase 1's plain-function `authenticate` plus our own axum route is the
> correct foundation, and Phase 2 extends it with
> `axum::middleware::from_fn_with_state` + `route_layer`.

> **The executor's only identity channel is `ctx.service_params`.** The SDK sets
> `ctx.user` to `None` unconditionally (`handler.rs:558`, `handler.rs:668`).
> HTTP headers, including `authorization`, arrive via `extract_service_params`
> (`middleware.rs:17-28`). Phase 2 must re-derive the peer from that, or gate
> the route before it reaches the SDK handler.


Existing RustFox machinery this design reuses (all verified in-tree):

- `LoopConfig.allowed_tools: Option<Vec<String>>` (`src/loop_runner.rs:33`),
  enforced both when offering tool definitions to the LLM
  (`src/loop_runner.rs:109`) and at execution (`src/loop_runner.rs:176`). This
  is the mechanism subagents already use for their declared tool whitelist.
- Background runner pattern: `mpsc` channel + spawned runner in
  `src/main.rs:206` and `src/main.rs:269`.
- `cancel_token_registry: Arc<Mutex<HashMap<String, CancellationToken>>>`
  (`src/agent.rs:99`) already backing `/stop`.
- `LoopConfig.stream_token_tx` / `tool_event_tx` (`src/loop_runner.rs:36-37`)
  already carrying LLM tokens and tool events.
- SQLite store with WAL already enabled (`src/memory/mod.rs:54`).

## Security Context (read before implementing)

This is not a greenfield system. A prior audit of this repo established:

- `execute_command` runs `sh -c` with **no validation of the command string**;
  the sandbox is only `current_dir()` (`src/command_tool.rs:80-88`).
- There is **no approval gate** anywhere in the tool execution path.
- `self_upgrade` replaces the running binary; `schedule_task` persists cron jobs.
- The only access control today is `telegram.allowed_user_ids`.

**Consequence:** exposing RustFox as an A2A server puts `execute_command` on the
network. Every security control in §6 exists because of this, and none of them
is optional. A peer that authenticates and is granted `["*"]` has unvalidated
shell on the host — this is a deliberate, configured decision, not an accident,
and the default must not be `["*"]`.

## Scope

In scope:

- A2A server: Agent Card, JSON-RPC + REST bindings, SSE streaming, full
  asynchronous task lifecycle, task persistence, cancel.
- A2A client: discover a remote Agent Card, send messages, stream, poll and
  cancel tasks. Exposed to the LLM as a `call_a2a_agent` tool.
- Per-peer authentication, IP allowlist, per-peer tool policy.
- Optional in-process TLS via the SDK's `rustls` feature.

Out of scope for this design (candidates for later):

- gRPC and SLIMRPC bindings.
- Push notifications (`CreateTaskPushNotificationConfig` and siblings). The SDK provides
  `HttpPushSender` and `PushConfigStore`, but no RustFox use case requires it yet.
- Public-internet hardening (rate limiting, OAuth2, mTLS).
- Reworking the `execute_command` sandbox. This design gates access to tools; it
  does not make the tools themselves safe.

## Architecture

New module `src/a2a/`:

| File | Responsibility | Mirrors |
|---|---|---|
| `mod.rs` | facade, config, wiring into `main.rs` | — |
| `card.rs` | `AgentCardProducer` built from `skills/` + config | `src/skills/loader.rs` |
| `auth.rs` | bearer + IP allowlist, fail-closed (plain function + axum middleware) | — |
| `policy.rs` | resolve peer → `allowed_tools` (`["*"]` = all) | `src/loop_runner.rs:33` |
| `executor.rs` | `AgentExecutor` → RustFox agentic loop | `src/main.rs:269` |
| `task_store.rs` | `TaskStore` over the existing SQLite connection | `src/supervisor/store.rs` |
| `server.rs` | axum listener, bind address, TLS | `src/setup/wizard.rs` |
| `client.rs` | A2A client + `call_a2a_agent` tool | `src/skill_tools.rs` |

The server runs as an axum listener in a spawned tokio task **inside the bot
process**, sharing `Arc<Agent>`. It is not a separate binary: the executor needs
the live agent, its tool registry, MCP connections and memory store.

## Task State Machine

| A2A state | RustFox origin |
|---|---|
| `submitted` | task row created, queued behind the concurrency semaphore |
| `working` | agentic loop running |
| `input-required` | see §7(a) — multi-turn continuation |
| `completed` | `LoopOutcome::FinalResponse` |
| `failed` | loop error, or `LoopOutcome::MaxIterations` |
| `canceled` | `CancelTask` → existing `CancellationToken` |
| `rejected` | peer authenticated but not permitted for the requested skill |

`LoopOutcome` is defined in `src/loop_runner.rs:41`.

## Execution Flow

```
POST /jsonrpc   SendMessage
  └─ axum auth middleware (bearer + IP)
       ├─ bearer token → peer identity          (401 on no match)
       ├─ source IP against peer allowlist      (403 on no match)
       └─ peer → allowed_tools                  (§6)
     └─ TaskStore::create  → Task(submitted)
        └─ enqueue on mpsc
           └─ runner task (mirrors src/main.rs:269)
                ├─ acquire concurrency semaphore (§5)
                ├─ status → working; emit TaskStatusUpdateEvent
                ├─ AgentExecutor → agentic loop
                │    ├─ LoopConfig.allowed_tools = peer policy
                │    ├─ stream_token_tx → SSE artifact/status events
                │    └─ cancel_token ← CancelTask
                └─ terminal state persisted
     └─ respond: Task (long) or Message (fast resolution)
```

`SendStreamingMessage` uses the SDK JSON-RPC SSE binding mounted at `/jsonrpc`.
The production `A2aExecutor` emits `working`, then the terminal task; provider output is chunked internally but not emitted as A2A Message events. `CancelTask` resolves through
`cancel_token_registry`, the same mechanism `/stop` uses.

## Security Model

| Control | Detail | Failure mode |
|---|---|---|
| TLS | optional; in-process `rustls` via SDK feature, or terminate at a reverse proxy | config must state which explicitly |
| Bind address | configurable; **default `127.0.0.1`** | must be raised deliberately for LAN |
| Bearer token | per peer, in config | no match → 401 |
| IP allowlist | per peer | no match → 403 |
| Tool policy | per peer `allowed_tools` | **default deny-all except read-only tools** |
| Concurrency | semaphore, `max_concurrent_tasks` | excess queued as `submitted`, not rejected |

The tool policy default is deliberately conservative. A peer block with no
`tools` key resolves to exactly this list, and nothing else:

```
read_file, list_files, read_skill_file, read_agent_file,
search_memory, recall, remember
```

Explicitly **absent** from the default, and reachable only by naming them or by
`["*"]`: `execute_command`, `write_file`, `send_file`, `self_upgrade`,
`schedule_task`, `cancel_scheduled_task`, `rerun_scheduled_task`,
`try_new_tech`, `write_skill_file`, `write_agent_file`, `update_soul_file`,
`revert_soul_file`, `patch_skill`, `read_soul_file`, `plan_view`.

### Why `read_soul_file` and `plan_view` are excluded

Both were originally in this list and were **removed** after review (commits
`6cdc8f8`, `fe7fe2c`, `e667ccb`). An earlier revision of this document listed
them as safe because they are "read-only" — but read-only is not the same as
*confined*, and that framing is precisely what let the problem survive design
review:

- **`read_soul_file`** reads relative to the RustFox **home**, not the sandbox.
  Its JSON-schema `enum` was only a hint to the LLM, never enforced at runtime,
  so `file_name = "config.toml"` returned `~/.rustfox/config.toml` — the
  OpenRouter API key and **every peer bearer token in this system**. The tool
  has since been hardened (allowlist plus `O_NOFOLLOW`), but it remains the only
  read primitive that reaches the credential store, so it stays out on
  defence-in-depth grounds: a future regression in either control would be a
  remote credential disclosure.
- **`plan_view`** read a path derived from an LLM-supplied `title`. Now
  validated and sandbox-contained, but it is a second, weaker route to the
  filesystem that `read_file` already covers properly.

Neither is needed for a peer to do useful work: `read_file` and `list_files`
cover the sandbox through a single, well-tested containment check. Keeping the
wider primitives out means a regression in either cannot become a remote
credential disclosure. **Do not add them back to match an older revision of
this document.**

Note on `["*"]`: the wildcard expands to the tool names the runtime actually
exposes, derived from the registered tool handlers. `invoke_agent` and
`spawn_agents` are handled in the agent loop but are **not** defined as tool
handlers — a circular dependency prevents registering them in `ToolRegistry`
(see the comment at `src/agent.rs:1306`); they are dispatched through a
`special_tool_handler` closure instead. A registry-derived wildcard therefore
does **not** grant them. Treat the wildcard as "every registered tool", not as
an exhaustive escalation path.

This is a property Phase 2 must preserve: whatever set `["*"]` expands to has to
come from the registry, never from a hand-written list of "everything", or the
wildcard will silently start granting subagent delegation that Phase 1 does not.

The default is an allowlist, not a denylist: a tool added to RustFox in the
future is **not** granted to peers until it is added here. This matters because
the denylist alternative would silently grant every new tool to every peer.
Granting `["*"]` must be an explicit, visible line in `config.toml`.

## Persistence

New tables in the existing `rustfox.db`, created idempotently at startup, the
same way `MemoryStore::run_migrations` (`src/memory/mod.rs:110`) does today:

- `a2a_tasks` — id, context_id, peer, state, skill, timestamps
- `a2a_messages` — task_id, role, content, parts
- `a2a_artifacts` — task_id, kind, content, sha256

State is persisted **on transitions only**, never per streamed token.

## Concurrency

`MemoryStore` holds a single `rusqlite::Connection` behind a
`tokio::sync::Mutex` (`src/memory/mod.rs:21`). WAL is already enabled, so
intra-process contention is mutex wait, not SQLite lock conflict. The mutex is
held for milliseconds per operation while the agent loop waits seconds on the
LLM provider.

Decision: **bound concurrency with a semaphore rather than build a connection
pool.** The real risk is starvation of the Telegram path, not throughput.
Optimizing throughput before measuring would be guesswork.

Also included:

- `PRAGMA busy_timeout = 5000` — guards against a second process touching the
  same database (setup wizard, or an isolated instance via `RUSTFOX_HOME`).
- Note for future work: rusqlite calls are synchronous and currently run inside
  async functions while holding the mutex, so they block a tokio worker for the
  duration of the query. Acceptable under bounded concurrency; the escalation
  path is `spawn_blocking`.

Escalation trigger: if Telegram latency rises while A2A tasks are active, move
to a read-pool plus a single writer.

## Configuration

```toml
[a2a]
enabled      = false            # opt-in; default off
bind         = "127.0.0.1:8443"
tls          = "none"           # "none" | "rustls"
tls_cert     = "/path/cert.pem"
tls_key      = "/path/key.pem"
max_concurrent_tasks = 4

[a2a.card]
name         = "RustFox"
description  = "Self-hosted Telegram AI assistant"
version      = "1.0.2"

# One block per peer. Absent block = no access at all.
[a2a.peers.laptop]
token    = "<bearer>"
ip       = ["192.168.1.0/24"]
tools    = ["read_file", "list_files", "search_memory", "recall"]

[a2a.peers.buildbox]
token    = "<bearer>"
ip       = ["10.8.0.4"]
tools    = ["*"]                # explicit full access, including shell
```

## Open Items

**(a) `input-required`** — decided: multi-turn continuation. The agent loop runs
to completion and does not pause mid-run. When the agent needs more information,
the task reaches a terminal state carrying a question; the peer resends with the
same `taskId` and the conversation continues. This avoids building a mid-loop
pause/resume mechanism. Accepted limitation: the task is not literally parked in
`input-required`, so a peer that strictly expects to poll that state will see a
completed task with a question instead.

**(b) Concurrency** — decided: semaphore, no pool. See §5.

**(c) TLS** — decided: optional, in-process rustls when enabled.

## Implementation Phases

The phase table below records the original delivery plan; the current status is
summarized above. Each phase was designed to be independently useful and
verifiable; later phases were not started before the security controls they
depend on were in place.

| Phase | Content | Depends on | Verifiable by |
|---|---|---|---|
| 1 | `card.rs` + `auth.rs` + `policy.rs` + config plumbing; Agent Card served, endpoints reject unauthenticated requests | — | success criteria 1 and 3 |
| 2 | `task_store.rs` + `executor.rs` + `SendMessage` synchronous path; task reaches `completed` | 1 | success criteria 2 and 4 |
| 3 | `GetTask`, `CancelTask`, semaphore; lifecycle fully async | 2 | success criteria 5 |
| 4 | `SendStreamingMessage` SSE | 3 | streaming interop test (implemented) |
| 5 | `client.rs` + `call_a2a_agent` tool | 2 | success criterion 6 |

Phase 1 established authentication before the executor was introduced. The
server-side implementation now covers Phases 1–4; Phase 5 remains future work
as noted above.

## Risks

1. **Pre-1.0 SDKs.** `a2a-client-lf` 0.2.5 / `a2a-lf` 0.3.1 / `a2a-server-lf`
   0.3.1 are pre-1.0 with inconsistent versions across the workspace. Pin exact
   versions and expect breaking changes on upgrade.
2. **`["*"]` is remote shell.** Per §2, a peer with `["*"]` has unvalidated
   `sh -c` with the process's privileges. The approval-gate design (separate,
   pending) is the intended complement.
3. **Task store shares the bot's database.** A corrupt or runaway A2A task
   write affects conversation history. Consider a separate database file if
   this proves fragile.
4. **`AgentExecutor` runs inside the bot process.** A panic in the A2A path must
   not take down the Telegram dispatcher. Executor work belongs in spawned tasks
   with error capture, never unwrapped on the dispatcher task.

### Phase 2 hazards (found by reading the SDK and RustFox source before implementing)

These are not hypotheticals — each was confirmed in the code. They are recorded
here because getting any of them wrong is either a security failure or a silent
loss of function.

5. **`Agent::process_message` MUST NOT be used by the executor.** It builds its
   own `LoopConfig` with `allowed_tools: None` (`src/agent.rs:823`), and per
   `src/config.rs:313-320` that `None` means **no restriction at all** — every
   tool, including `execute_command`. Driving a peer's request through it would
   hand remote shell to any authenticated peer. The executor must construct
   `AgenticLoop` directly with an explicit `allowed_tools: Some(vec)`, copying
   the `run_subagent` pattern (`src/agent.rs:1470-1503`).

6. **`PeerIdentity.allowed_tools` is resolved against an EMPTY tool registry.**
   `authenticate` calls `resolve_allowed_tools(matched_name, peer, &[])`
   (`src/a2a/auth.rs:91`), so for a `["*"]` peer — the most privileged
   configuration that exists — it returns an **empty** list. Phase 2 must
   re-resolve against `agent.all_tool_definitions()` before building
   `LoopConfig`. Forwarding `PeerIdentity.allowed_tools` verbatim would give
   every wildcard peer zero tools: fail-closed, but broken.

7. **The cancel-token key space is shared with Telegram.** `cancel_token_registry`
   is a bare `HashMap<String, CancellationToken>` keyed by Telegram `user_id`
   (`src/agent.rs:99`), and `/stop` cancels by that key. An A2A task must
   namespace its key (`"a2a:{task_id}"`) or `/stop` and `CancelTask` will cancel
   each other's runs.

8. **`DefaultRequestHandler::send_message` blocks until terminal.** It drives the
   executor stream to a terminal event before responding (`handler.rs:583-619`)
   and the SDK applies **no timeout**. With `max_iterations` at 25 and a slow
   provider this is a multi-minute HTTP request holding a connection. Phase 2
   accepts this deliberately (the spec calls for the synchronous path); the
   escalation is `configuration.returnImmediately`, which is only *useful* once
   `GetTask` exists in Phase 3, since otherwise the peer cannot poll.

9. **`spawn` / `build_state` / `router` take no agent.** All three signatures
   (`src/a2a/server.rs:31, 84, 196`) must gain the executor, and the call site
   `src/main.rs:457` must change. `agent` is in scope there (built at
   `src/main.rs:248`).

10. **The SDK's `TaskStore::update` contract is load-bearing.** `save_task`
    (`handler.rs:201-210`) calls `update` first and only falls back to `create`
    when the error code is exactly `TASK_NOT_FOUND`. A SQLite store that returns
    any other error (or `Ok`) for a missing row means tasks are **silently never
    created**.

11. **`StreamResponse::Task` replaces the stored task; status/artifact updates
    merge.** Emitting a `Task` with `history: None` (`handler.rs:218`) discards
    accumulated history. Carry `ctx.stored_task` history forward, as the crate's
    own `PushEventExecutor` does (`handler.rs:895`).


## Testing Strategy

- `card.rs` — Agent Card generated from a fixture `skills/` directory matches
  the A2A schema; skills without required frontmatter are skipped, not fatal.
- `auth.rs` — table-driven: valid/invalid bearer, IP inside/outside allowlist,
  missing peer block, and that the default is deny.
- `policy.rs` — `["*"]` expands to all; an explicit list filters; an absent list
  yields the conservative default and never includes `execute_command`.
- `task_store.rs` — create/transition/read round-trip; invalid transitions
  rejected; idempotent table creation.
- `executor.rs` — a task reaches `completed` on `FinalResponse` and `failed` on
  `MaxIterations`; cancellation mid-run reaches `canceled`.
- Concurrency — with `max_concurrent_tasks = 1`, a second task stays `submitted`
  until the first terminates.
- Interop — run the SDK's `helloworld` example agent and have RustFox call it as
  a client; verify the Agent Card parses and a task completes.

## Success Criteria

1. A remote A2A client can fetch `/.well-known/agent-card.json` and see RustFox's
   skills.
2. `SendMessage` from an authenticated, allowlisted peer produces a `completed`
   task whose result is the agent's answer.
3. An unauthenticated or non-allowlisted peer receives 401/403 and no agent work
   is performed.
4. A peer without `execute_command` in its policy cannot invoke it, even if the
   LLM attempts the call.
5. `CancelTask` stops an in-flight task and the task reaches `canceled`.
6. RustFox can discover and call a remote A2A agent through `call_a2a_agent`.
