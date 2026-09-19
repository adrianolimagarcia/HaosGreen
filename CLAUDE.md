# CLAUDE.md - HaosGreen Development Guide

## Project Overview

HaosGreen is a Telegram AI assistant written in Rust. It connects to Telegram as a
bot, uses OpenRouter for inference (default model `moonshotai/kimi-k2.6`, see
`default_model()` in `src/config.rs`), provides built-in sandboxed tools plus
MCP (Model Context Protocol) servers for extensible tool integration, and runs
an agentic loop that iterates tool calls until a final text response is produced
(`[agent] max_iterations`, default **25**).

It also carries an autonomous supervisor (see [Supervisor](#supervisor-autopilot-v2)),
an optional Agent2Agent listener (see [A2A](#a2a-agent2agent-protocol)), and an
optional embedded web dashboard (see [Web Dashboard](#web-dashboard)).

## Build & Run

```bash
cargo build                 # debug
cargo build --release
cargo run                   # uses ./config.toml
cargo run -- /path/to/config.toml
cargo check
cargo fmt
cargo clippy
```

### Configuration

Copy `config.example.toml` to `config.toml` and fill in credentials.
`config.toml` is gitignored and must never be committed. Required fields:

- `telegram.bot_token` - Telegram Bot API token
- `telegram.allowed_user_ids` - Whitelist of Telegram user IDs
- `openrouter.api_key` - OpenRouter API key
- `sandbox.allowed_directory` - Directory for sandboxed file/command operations

### Home directory

HaosGreen stores all state under a single home directory (default `~/.haos-green`),
resolved as: `HAOS_GREEN_HOME` env (absolute) → `[general].home` config → `~/.haos-green`.
Layout: `config.toml`, `haos-green.db`, `skills/`, `agents/`, `workspace/` (the
sandbox), `artifacts/`, `user_model.md`, and `web-auth.toml` (the dashboard
credentials, mode 0600, created on the first dashboard start). Each path can be
pinned to an absolute location in `config.toml`; unset paths fall back to the
home default. Run isolated instances with `HAOS_GREEN_HOME=...`. See
`docs/persistent-home-directory.md`. Path resolution lives in `src/home.rs`
(`Config::resolve` writes the resolved absolute paths back into the config).
Bundled skills/agents are seed-copied on first run; `/update-skills` re-syncs
them using `<home>/skills-lock.json`.

### Shutdown

One `tokio::sync::broadcast::<()>` (capacity 1, shared as `Arc`) is the single
shutdown signal. The A2A listener (`start_listener_with_shutdown`), the web
dashboard (`spawn_with_shutdown`) and the Telegram platform each hold a
`subscribe()`. A listener that fails to start is logged and never fatal to the
others, so a bad A2A bind cannot stop the bot.

The trigger is SIGINT or SIGTERM, or the Telegram dispatcher returning on its
own. On a signal the order is deliberate: abort the dispatch handle and wait up
to **1 s** for it, broadcast shutdown, send the Telegram "shutting down"
notification under a **1 s** bound, sleep **2 s** so it can be delivered, then
log `Shutdown complete.` — so no detached work outlives the broadcast and the
notification still has a window. When the dispatcher returns by itself the
broadcast and notification happen *before* its error is propagated, so the
process never exits leaving the listeners running.

Two semantics are load-bearing:

- **A dropped sender is not a shutdown.** `wait_for_shutdown` maps
  `broadcast::error::RecvError::Closed` to `pending` and keeps looping, so a
  vanished sender cannot silently stop a listener; only an actual `()` does.
  `Lagged` continues too — the payload is `()` and carries no state.
- **Active SSE streams must end.** The chat and log SSE handlers select on the
  same broadcast, so a graceful shutdown terminates them instead of hanging on a
  client that is holding the connection open.

The broadcast is idempotent: it may be sent on both paths, and a receiver that
already saw it stays stopped rather than treating a second send as a restart.

## Architecture

The crate is both a library (`src/lib.rs`) and a binary (`src/main.rs`).
`src/lib.rs` carries `#![deny(dead_code)]`, so anything you add must be reachable.

```
src/
├── main.rs             # Entry: logging, config load, home resolution, MCP setup,
│                       #   supervisor wiring, optional A2A listener, Telegram dispatch
├── lib.rs              # Library root; `#![deny(dead_code)]`
├── config.rs           # TOML config types (Config, TelegramConfig, OpenRouterConfig,
│                       #   SandboxConfig, McpServerConfig, A2aConfig, ...) + resolve
├── home.rs             # Home-directory resolution
├── llm.rs              # OpenRouter client (ChatMessage, ToolCall, ToolDefinition)
├── provider.rs         # Provider abstraction over the LLM client
├── agent.rs            # Agent: system-prompt assembly, loop entry, subagent dispatch
│                       #   (invoke_agent / spawn_agents), cancel-token registry
├── agent_prompt.rs     # System-prompt construction
├── loop_runner.rs      # The agentic loop: tool offering + execution; LoopConfig
│                       #   (`allowed_tools` filtering lives here)
├── loop_detector.rs    # Repeated-tool-call detection
├── conversation.rs     # Per-user conversation state
├── tool_registry.rs    # Tool registry: handlers, define() -> ToolDefinition
├── builtin_tools.rs    # Built-in tool definitions AND execution (the real tool impls)
├── tools.rs            # ONLY path validation: validate_sandbox_path, validate_home_path
├── command_tool.rs     # Shell-command tool
├── memory_tools.rs     # search_memory / recall / remember
├── skill_tools.rs      # read_skill_file / write_skill_file / patch_skill
├── scheduling_tools.rs # schedule_task and friends
├── mcp.rs              # MCP client manager; tools namespaced mcp_{server}_{tool}
├── langsmith.rs        # Optional LangSmith tracing
├── learning.rs         # Self-learning: skill extraction, user model
├── memory/             # SQLite store (FTS5 + sqlite-vec), migrations, WAL
├── skills/             # SkillRegistry: markdown skills with YAML frontmatter
├── scheduler/          # Cron-style scheduled tasks
├── setup/              # Setup wizard (includes an axum OAuth callback server)
├── platform/           # Platform abstraction
│   ├── mod.rs
│   ├── sender.rs       # PlatformSender trait
│   ├── telegram.rs     # teloxide bot: dispatch, handle_message, all bot commands
│   └── tool_notifier.rs# Friendly per-tool progress messages
├── a2a/                # Agent2Agent protocol (server phases 1–4: card, auth,
│                       #   policy, executor, task store, GetTask/CancelTask,
│                       #   concurrency gate, SSE streaming; Phase 5 client & tool)
│   ├── mod.rs
│   ├── card.rs         # Agent Card generation (/.well-known/agent-card.json)
│   ├── auth.rs         # Bearer + IP authentication -> PeerIdentity
│   ├── policy.rs       # Per-peer tool allowlist (DEFAULT_PEER_TOOLS)
│   ├── executor.rs     # AgentExecutor and TaskGate concurrency control
│   ├── task_store.rs   # SQLite-backed A2A task persistence
│   ├── server.rs       # axum listener: card + authenticated JSON-RPC routes
│   ├── client.rs       # Outbound A2A client: card discovery, auth, message/poll
│   └── tool.rs         # `call_a2a_agent` tool implementation and secret redaction
├── web/                # Embedded dashboard (see "Web Dashboard" below)
│   ├── mod.rs          # Router, layer order, and the fallible listener (`spawn`)
│   ├── state.rs        # `WebState`: shared handles; a missing one answers 503
│   ├── auth.rs         # Argon2id credentials, sessions, IP gate, login limiter
│   ├── middleware.rs   # Host allowlist, security headers, IP/CSRF/session guard
│   ├── chat.rs         # Bounded in-memory chat session store
│   ├── logs.rs         # Bounded log ring + the tracing layer that feeds it
│   └── routes/         # Route modules (guarded router + the public login router)
│       ├── mod.rs        # Guarded router and the public (login) router
│       ├── auth_routes.rs # Login/logout and the session cookie
│       ├── settings.rs   # Password, bearer toggle, IP allowlist
│       ├── chat.rs       # Chat sessions and the SSE message stream
│       ├── supervisor.rs # Supervisor task list, detail and lifecycle
│       ├── logs.rs       # Log history and the live SSE tail
│       └── a2a.rs        # Listener status, peer listings, outbound editor, card test
├── supervisor/         # Autonomous task runner (see below)
└── utils/
```

### Data Flow

1. User sends a Telegram message.
2. `platform/telegram.rs` filters by `allowed_user_ids` and routes commands
   (`/start`, `/clear`, `/tools`, `/update-skills`, ...) inside `handle_message`
   (`src/platform/telegram.rs:669`).
3. Non-command messages enter the agentic loop (`loop_runner.rs`).
4. `llm.rs` sends conversation history + tool definitions to OpenRouter.
5. Tool calls dispatch through `tool_registry.rs` to `builtin_tools.rs` or MCP.
6. Tool results are appended and the loop repeats (up to `max_iterations`, default 25).
7. The final text is split into <=4000-char chunks and sent back via Telegram.

### Key Components

- **Agent** (`agent.rs`): holds the LLM client, config, skill/agent registries and
  the cancel-token registry; assembles the system prompt and drives the loop.
- **LlmClient** (`llm.rs`): HTTP client for OpenRouter's `/chat/completions` with
  tool-calling support.
- **ToolRegistry** (`tool_registry.rs`): maps tool names to handlers; each handler
  exposes a `define()` producing the `ToolDefinition` offered to the model.
- **McpManager** (`mcp.rs`): stdio and streamable-HTTP MCP servers.
- **Sandbox validation** (`tools.rs`): `validate_sandbox_path` canonicalises the
  sandbox root and the requested path, then checks containment.

## Code Conventions

### Rust Patterns

- **Edition**: 2021
- **Async runtime**: Tokio (`full` features)
- **Error handling**: `anyhow::Result` throughout, with `.context()` /
  `.with_context()` for error messages
- **Logging**: `tracing` (`RUST_LOG`, default `info,haos_green=debug`)
- **Serialization**: `serde` derive with
  `#[serde(skip_serializing_if = "Option::is_none")]` for optional fields
- **Shared state**: `Arc<Agent>` and friends, passed via teloxide's `dptree`
  dependency injection
- **Concurrency**: `tokio::sync::Mutex` / `RwLock`, not the `std::sync` variants

### Naming

- Module names are single words where practical (`config`, `llm`, `mcp`)
- Struct fields use `snake_case`
- JSON field renames use `#[serde(rename = "type")]` where the Rust name differs

### Error Handling Style

- `anyhow::bail!()` for early returns with messages
- `.context("message")` on `Result` chains
- MCP connection failures are logged but do not abort startup
- Tool execution errors return error strings to the LLM rather than crashing

## Security

- File and command operations are contained by `validate_sandbox_path()`
  (`src/tools.rs`). It canonicalises when the target exists, and otherwise
  canonicalises the **parent** and re-joins the file name.
  **`ShellBackend` is the exception: it does not call `validate_sandbox_path()`
  at all.** A `shell` job is contained by a real bubblewrap sandbox instead —
  see "Shell sandbox" under Supervisor. Read that section before assuming a
  shell job is bounded by the sandbox directory, because it is not: it is
  bounded by the argv.
- Tools that read relative to the **home** (not the sandbox) use
  `validate_home_path()` plus an explicit name allowlist. `read_soul_file`,
  `update_soul_file` and `revert_soul_file` are restricted to `SOUL_FILE_NAMES`
  and open with `O_NOFOLLOW`.
- `plan_create` / `plan_update` / `plan_view` validate the LLM-supplied title and
  re-establish containment on the resolved path.
- The bot only responds to user IDs in `telegram.allowed_user_ids`. On the
  Telegram side this is the **only** access control.
- `config.toml` (containing secrets) is gitignored.

> **Do not treat "read-only" as "safe".** Two of the worst bugs found in this
> codebase were read-only tools that reached outside their sandbox:
> `read_soul_file` could return `~/.haos-green/config.toml` (API key + every peer
> token) because its JSON-schema `enum` was only an LLM hint, never enforced at
> runtime. Validate at runtime, on the **resolved path**, and fail closed —
> never `unwrap_or_else` a validation error into a default path.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `teloxide` | Telegram bot framework |
| `reqwest` | HTTP client (OpenRouter, MCP HTTP, integration tests) |
| `serde` / `serde_json` | Serialization |
| `toml` | Config parsing |
| `toml_edit` | Format-preserving edits to `config.toml` (`PUT /api/a2a/outbound`) |
| `rmcp` | Official MCP Rust SDK |
| `axum` / `tower-http` | A2A listener; web dashboard; setup wizard's OAuth callback |
| `a2a` (`a2a-lf`) | A2A protocol types |
| `argon2` | Argon2id password hashing for the dashboard |
| `ipnet` | CIDR matching for the A2A peer IP allowlist and `[web].allow_ips` |
| `subtle` | Constant-time bearer-token comparison (A2A and the dashboard) |
| `rusqlite` + `sqlite-vec` | Memory store |
| `tracing` / `tracing-subscriber` | Structured logging |
| `anyhow` | Error handling |
| `futures` | Async utilities |

## CI (GitHub Actions)

CI runs on every push to `main` and on PRs targeting `main`, defined in
`.github/workflows/ci.yml`, five parallel jobs:

| Job | Command |
|-----|---------|
| **Check** | `cargo check` |
| **Format** | `cargo fmt --all -- --check` |
| **Clippy** | `cargo clippy -- -D warnings` |
| **Test** | `cargo test` |
| **Build** | `cargo build --release` (after the others pass) |

Before opening a PR, make `cargo fmt`, `cargo clippy --all-targets -- -D warnings`
and `cargo test` pass locally.

## Testing

The suite is large and must stay green (~835 unit tests in `src/**` plus 13
integration files in `tests/`). When adding tests:

- Unit tests go in `#[cfg(test)] mod tests` blocks in the file under test.
- Integration tests go in `tests/`.
- Prefer testing through the public API. For HTTP surfaces, bind an ephemeral
  port (`127.0.0.1:0`) and make real requests — see `tests/a2a_endpoint.rs` and
  `tests/web_endpoint.rs`.
- A test that passes for the wrong reason is worse than no test. When a test
  guards a security property, **prove it has teeth** by mutating the
  implementation and confirming the test fails.
- `tests/web_endpoint.rs` covers the dashboard end to end: the guard, the CSRF
  and Host checks, the IP allowlist, login and rate limiting, chat SSE, the
  supervisor lifecycle, the log routes and the A2A routes.
- The live tests in `tests/web_endpoint.rs` and `tests/a2a_e2e_live.rs` are
  `#[ignore]`d **and** re-checked at runtime against `HAOS_GREEN_WEB_LIVE=1` and
  `HAOS_GREEN_A2A_LIVE=1` respectively, so plain `cargo test` passes with both
  unset — which is how CI runs it.
- Both live tests talk to an OpenAI-compatible endpoint on
  `127.0.0.1:8790` and ask for a specific model. Endpoint and model are
  overridable with `HAOS_GREEN_LIVE_LLM_BASE_URL` and
  `HAOS_GREEN_LIVE_LLM_MODEL`, so moving the gateway or replacing a model is an
  env change rather than an edit to two files.
- **The model must be one the endpoint actually serves** — check
  `GET /v1/models`. These tests used `a6api_DeepSeek-V4-Flash-0731` until that
  name left the gateway's routing pool, at which point every live run failed
  with HTTP **503 `smart_route_no_active_candidates`**. That message describes
  the gateway's marketplace having no active merchants, so it reads like broken
  infrastructure rather than a stale model name; the endpoint and the model were
  both fine, and a one-line `curl` against `/chat/completions` settles it in
  seconds. Verify with `HAOS_GREEN_LIVE_LLM_MODEL=<candidate>` before changing
  the default — that override failing is how you know it is wired.

> **Mutation testing: never share `target/` between the repo and a scratch copy.**
> Cargo does **not** key build artifacts by source directory — the unit hash
> depends on the target's relative path, not the package directory — so a
> scratch tree that builds with `CARGO_TARGET_DIR=<this repo>/target` writes
> artifacts with the *same filenames* as this repo's, and cargo will then happily
> run a **mutant binary** for a plain `cargo test` here. The target-dir lock only
> serializes writers; it does not isolate projects. This actually happened: a
> mutation script running with `cwd=/tmp/rfmut` and this repo's target dir made
> the lease concurrency test fail with `left: 2` — the mutant's signature, not a
> real defect — which cost a full root-cause investigation. Two rules follow:
> mutate only in a copy with its **own** `CARGO_TARGET_DIR`, and after any
> mutation round rebuild here (`cargo clean -p haos-green`) before trusting a
> result. A failure whose signature exactly matches a mutant you just ran is a
> stale artifact until proven otherwise; a failure that does **not** reproduce on
> a freshly built binary is not a flake to be re-run away.

> **A test that waits forever is worse than a failing test.** libtest has no
> per-test timeout and prints nothing about a test still in flight, so a hang in
> this suite is completely silent: one was killed after 15 minutes with every
> worker idle and the captured output could not name the stuck test. So any
> await on spawned work goes through `supervisor::bounded("what", handle)`, a
> 60 s hang detector, and a lost wakeup then fails with the test's own name
> instead of wedging the binary. (Proven: deleting the single `notify_one` that
> releases a test backend makes that test fail at 60 s with
> `did not finish within 60s, so it is being treated as a hang` — un-bounded, it
> would have waited forever.) When a hang does happen anyway, identify it from
> the process, not from guesswork:
>
> - `ls /proc/<pid>/task | wc -l` gives the shape. A `multi_thread` test costs
>   `1 + worker_threads` threads, so **5 means one `worker_threads = 4` test
>   running alone** — that narrows 900 tests to the handful with that flavour.
>   A `#[tokio::test]` without a flavour costs one thread per running test.
> - Capture the run to a file and diff it: `grep -oE "^test [a-z0-9_:]+ \.\.\."
>   run.txt | sed 's/ \.\.\..*//;s/^test //' | sort` against
>   `cargo test --lib -- --list` names every test that never reported.
> - Idle workers with frozen CPU time and no established sockets mean a future
>   that will never be woken — not a busy loop, and not a slow test.

## Common Tasks

### Adding a new built-in tool

1. Add a `ToolDefinition` in `src/builtin_tools.rs` (the `define()` site).
2. Add the matching dispatch arm in the same file.
3. Use `validate_sandbox_path()` (sandbox-relative) or `validate_home_path()`
   (home-relative) if the tool touches the filesystem. Validate the **resolved**
   path, not just the supplied name.
4. Register it in `src/tool_registry.rs`.
5. **If the tool can read or write outside the sandbox, do not add it to
   `DEFAULT_PEER_TOOLS` in `src/a2a/policy.rs`.** That list is the A2A default
   allowlist; adding to it widens what a remote peer can reach.

### Adding a new bot command

Add a branch inside `handle_message` in `src/platform/telegram.rs` (the existing
`/clear`, `/start`, `/tools` branches are the pattern), before the LLM
processing section.

### Changing the default LLM model

Update `default_model()` in `src/config.rs`. Users can override it in
`config.toml`.

### Adding a new MCP server

Add a `[[mcp_servers]]` block to `config.toml` with `name` and either `command`
+ `args` (stdio) or `url` (streamable HTTP), plus optional `env` / `auth_token`.
See `config.example.toml`.

### Adding a new bot skill

Skills are natural-language instructions loaded at startup and injected into the
system prompt. Each lives in its own folder:

```
skills/
  skill-name/
    SKILL.md           # Required: YAML frontmatter + instruction body
    supporting-file.*  # Optional: templates, examples, reference docs
```

```yaml
---
name: skill-name       # lowercase letters, numbers, hyphens only
description: Brief description of what this skill does
tags: [tag1, tag2]     # optional
---
```

1. Create `skills/<skill-name>/SKILL.md`.
2. It is auto-loaded at startup — no code changes needed.
3. Configure the directory with `[skills] directory` in `config.toml`.

Skills appear in the system prompt as **metadata only** (name + description).
**Instruction skills** (no `model` in frontmatter) have their content loaded via
`read_skill_file(skill_name="...", relative_path="SKILL.md")` when relevant.
**Subagent skills** (`model` set) are invoked via
`invoke_agent(agent="name", prompt="...")`.

**Subagent tool whitelist:** the frontmatter `tools:` list must use the **exact**
tool names as seen by the agent. MCP tools are named
`mcp_{server_name}_{tool_name}`. Names are logged at startup when MCP servers
connect. A mismatch (e.g. `search_gmail_messages` when the server exposes
`query_gmail_emails`) silently leaves the subagent without that tool.

**Note:** `invoke_agent` and `spawn_agents` are **not** registry tools — a
circular dependency prevents registering them (see `src/agent.rs:1306`); they
dispatch through a `special_tool_handler` closure instead.

## A2A (Agent2Agent) protocol

Optional and **disabled by default**. When `[a2a].enabled = true`, `main.rs` starts an axum listener alongside the Telegram bot. The server provides:
- Server phases 1–4: Agent Card (`/.well-known/agent-card.json`), Bearer + IP authentication, per-peer tool policy, real `AgentExecutor`/task store, JSON-RPC operations (`SendMessage`, `GetTask`, `CancelTask`), concurrency control via `TaskGate`, and SSE streaming (`SendStreamingMessage` emitting lifecycle transitions).
- Client & tool (Phase 5): Outbound A2A client (`src/a2a/client.rs`) and `call_a2a_agent` tool (`src/a2a/tool.rs`) allowing HaosGreen to delegate tasks to remote A2A peers.

### Endpoints
- `GET /.well-known/agent-card.json` — **public**, no auth. Lists skills by
  name/description/tags only; instruction bodies are never included.
- `POST /jsonrpc` — requires a per-peer bearer token **and** a source IP matching
  the same peer. 401 (bad/absent token), 403 (IP not allowed), 500 (duplicate
  tokens), and JSON-RPC task-method responses for authenticated requests.

### Configuration
- Server config lives in `[a2a]`, `[a2a.card]` and `[a2a.peers.<name>]`.
- Outbound client peers are configured under `[a2a.outbound.peers.<name>]` with keys `url`, `token`, `timeout_secs`, `send_timeout_secs`, `poll_interval_ms`, and `poll_timeout_secs`. See `config.example.toml`.
- `send_timeout_secs` bounds a **complete synchronous `SendMessage`**, and is validated to `1..=300` at load; omitted, it falls back to `timeout_secs`. The HTTP transport timeout is set to `max(send_timeout_secs, timeout_secs) + 1`, so the typed `A2aTimeoutError::SendMessage` always wins the race and a transport error can never mask it. Only `SendMessage` is bounded this way — `GetTask` polling keeps its own `poll_timeout_secs`.

`A2aConfig::validate()` runs at startup and refuses to start the listener on duplicate tokens, an empty token, an empty `ip` list, an unparseable IP/CIDR, or any request for TLS (not implemented — rejected rather than silently served as plaintext). A listener failure never prevents the Telegram bot from starting.

Design spec: `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
Implementation plans: `docs/superpowers/plans/2026-09-16-a2a-phase1-card-auth-policy.md`,
`docs/superpowers/plans/2026-09-16-a2a-phase2-task-store-executor.md`,
`docs/superpowers/plans/2026-09-16-a2a-phase3-concurrency-get-cancel.md`, and
`docs/superpowers/plans/2026-09-16-a2a-phase5-client-tool.md`.

> **Security invariants — do not weaken without a written reason:**
> - `DEFAULT_PEER_TOOLS` (`src/a2a/policy.rs`) is an **allowlist**. A tool added
>   to HaosGreen is *not* granted to peers until it is named there.
> - **Anti-recursion invariant**: `call_a2a_agent` is **NEVER** in `DEFAULT_PEER_TOOLS`. An inbound peer cannot call outbound A2A peers through HaosGreen unless explicitly granted by operator policy, preventing unbounded peer-to-peer amplification loops.
> - `read_soul_file` and `plan_view` are deliberately excluded: `read_soul_file`
>   can reach `~/.haos-green/config.toml`, which holds the API key and every peer
>   token. Do not add them back.
> - `["*"]` expands to the **registry's** tool set, never a hand-written list.
> - An empty configured token never authenticates, and duplicate tokens are
>   refused rather than resolved by `HashMap` iteration order.
> - The card's advertised URL must come from the address actually bound (or
>   `public_url`), never the raw `bind` string.
> - **Redacted tokens**: Outbound peer tokens are never printed in debug representations (`A2aOutboundPeerConfig` redacts tokens), and error messages returned by `call_a2a_agent` sanitize configured tokens and bearer patterns before returning to the model or logs.
> - **No automatic POST retries**: Outbound `SendMessage` calls are never automatically retried to avoid duplicate remote task creation; only `GetTask` polling retries up to `poll_timeout_secs`.

## Web Dashboard

Optional and **disabled by default** (`src/web/`). When `[web].enabled = true`,
`main.rs` starts an embedded axum dashboard next to the Telegram bot — chat,
supervisor, live logs, settings and an A2A manager — served from three
compile-time assets embedded with `include_str!`. A listener failure is logged
and the bot keeps running, exactly as for the A2A listener.

```toml
[web]
enabled = false            # default. A dashboard that can run shell commands
                           #   must never appear because a key was omitted.
bind = "127.0.0.1:8787"    # default: loopback only
# public_url = "https://haos.example.com"
session_ttl_hours = 12     # default
allow_ips = []             # default: EMPTY MEANS ANY SOURCE — see below
```

`WebConfig::validate()` runs before the bind and refuses to start the
**listener** — never the bot — on an unparseable `bind`, `session_ttl_hours = 0`,
a `public_url` without an `http://`/`https://` scheme, or an `allow_ips` entry
that is neither an IP nor a CIDR range.

### Endpoints

| Route | Notes |
|---|---|
| `GET /`, `/app.js`, `/style.css` | Static shell. No session, no CSRF; the IP gate still applies. |
| `POST /api/auth/login` | The only session-less API route. IP gate + CSRF, then the rate limiter. |
| `POST /api/auth/logout` | Requires a session. |
| `GET /api/settings`, `POST /api/settings/password`, `POST /api/settings/bearer`, `PUT /api/settings/allow-ips` | Credentials and the live allowlist. |
| `POST`, `GET /api/chat/sessions`; `GET`, `POST /api/chat/sessions/{id}/messages`; `POST /api/chat/sessions/{id}/cancel` | The chat surface. The `POST` on messages is `text/event-stream`. |
| `GET`, `POST /api/supervisor/tasks`; `GET /api/supervisor/tasks/{id}`; `POST /api/supervisor/tasks/{id}/{pause,resume,cancel,approve}` | Supervisor surface. |
| `GET /api/supervisor/grants`; `POST /api/supervisor/grants/{allow,deny}` | Grant surface. The body is `{"path": "..."}` or `{"network": true}` — exactly one — and a refusal is **400** carrying the reason, because it is about the path, not about task state. |
| `GET /api/logs`, `GET /api/logs/stream` | Log history, and a live tail that is not a replay. |
| `GET /api/a2a/status`, `/peers`, `/outbound`; `PUT /api/a2a/outbound`; `POST /api/a2a/test` | A2A manager. |

Everything except the three static assets and login is mounted **inside** the
`guard` layer; `host_and_headers` wraps every response, including the rejected
ones.

### Authentication

- **Session cookie.** `POST /api/auth/login` mints a 256-bit id in an
  `HttpOnly; SameSite=Strict` cookie named `haos_session`. The `Secure` flag is
  added only when `public_url` is `https://` — an https deployment that omits
  `public_url` gets a cookie without it.
- **CSRF header.** Every `POST`/`PUT`/`PATCH`/`DELETE`, login included, requires
  `x-haos-green-csrf: 1`. `SameSite=Strict` is a browser behaviour; the header is
  the server-side guarantee, and it is checked before the session.
- **Optional bearer token.** `Authorization: Bearer <token>` authenticates
  without a session. It is **off by default** and stored only as a lowercase-hex
  SHA-256 digest: the token is returned exactly once, by the call that mints it,
  and afterwards only a 6-character fingerprint of the digest is readable.
  Enabling again rotates the token, which is the only recovery path.
- **IP allowlist.** Enforced as a middleware layer *before* axum's extractors, so
  a denied source is refused before a request body is parsed — and before the
  login handler can spend Argon2 work on it.

> **`[web].allow_ips` has the opposite semantics to an A2A peer's `ip` list.**
> An empty `[web].allow_ips` permits **any** source; a non-empty list is a strict
> allowlist. An empty `[a2a.peers.<name>].ip` list permits **no** source. The
> dashboard can afford the permissive default because it has a password and A2A
> does not; the UI states the asymmetry so an empty list is never misread as a
> restriction.

### Credentials file

Passwords and bearer state live in `<home>/web-auth.toml`, **never** in
`config.toml` — `config.toml` is the file users copy, share, and paste into
issues. The file is created mode 0600 before any content is written, an existing
file found wider is tightened (with a warning), and the name is in `.gitignore`.
Editing the allowlist from the UI is **in-memory only**; it does not rewrite
`config.toml`.

### The accepted risk: `admin`/`admin`, no forced change

A fresh install starts with `admin`/`admin` and there is deliberately **no forced
password change**. This is an operator decision, not an oversight. The
compensating controls are what make it tolerable:

- loopback bind by default (`127.0.0.1:8787`);
- a startup warning whenever the stored password is still the default;
- a persistent, **non-dismissible** UI banner on every view;
- per-source login rate limiting — five failures, then exponential backoff from
  5 s doubling to a 300 s cap, with the counter deliberately *not* reset when a
  lockout is served: only a successful login, or the stale-entry pruning that
  runs once a source has been quiet for the full lockout window, clears it;
- a settings page to change the password, and a process-wide gate that keeps at
  most four Argon2 operations in flight so a login burst cannot starve the bot.

**A non-loopback bind without changing the password is unsafe.** Anyone who can
reach the port can sign in and run commands on the host.

> **Web dashboard security invariants — do not weaken without a written reason:**
> - **Any authenticated user has host shell execution.** The web chat runs the
>   same agent as Telegram, with a tool policy derived from the live tool registry
>   and MCP manager — `execute_command` included. This is intentional: the
>   dashboard is a single-operator surface, not a multi-user one. Subagent
>   dispatch is not reachable from it, because `invoke_agent` and `spawn_agents`
>   are not registry tools and the web chat path passes
>   `special_tool_handler: None`.
> - **The chat tool policy is derived from those live sources, never
>   hand-written, and must never be `["*"]`.** The loop filters with a literal
>   membership test (`whitelist.contains(&d.function.name)`), so a wildcard
>   policy offers it **no tool at all** — the chat would look functional and
>   silently lose every tool, with no error anywhere.
> - **The bearer token is never readable after generation.** Only the SHA-256
>   digest is persisted, and only a 6-character fingerprint is ever returned.
> - **Host checking is fail-closed.** A non-loopback bind with no `public_url`
>   refuses every request whose `Host` is not the bound address, `localhost`,
>   `127.0.0.1` or `[::1]` — so a browser reaching it by name gets 403. The `Host`
>   header is the whole defence against DNS rebinding.
> - **Sessions are in-memory only** and deliberately do not survive a restart: a
>   restart is a cheap, complete revocation of every session.
> - **The log ring redacts at capture**, before truncation, and `main.rs`
>   registers every configured secret (Telegram token, OpenRouter key, A2A peer
>   tokens, MCP tokens) as an exact value at startup — a shape rule cannot catch
>   a credential that has no recognisable shape.
> - **`PUT /api/a2a/outbound` can redirect a stored peer token to a new host**: an
>   omitted `token` keeps the stored one, so changing a peer's `url` points the
>   existing token at a new host without ever reading it. It is CSRF-guarded and
>   reachable only with an operator session or the operator's bearer token.

### Non-goals

No dark mode. No WebSocket transport — SSE covers streaming. No multiple users,
roles, or per-user permissions: one operator identity. No TLS termination inside
the process; use a reverse proxy or Tailscale. No self-upgrade or binary reload
from the UI. No chat persistence across restarts. `PUT /api/a2a/outbound` is the
**only** route that writes `config.toml`, and only its `[a2a.outbound.peers]`
table.

### Supervisor lifecycle from the dashboard

`pause`, `resume`, `cancel` and `approve` each pre-check the task's state through
`supervisor::state::transition_allowed` and answer **409** without calling the
supervisor at all. `resume` is deliberately stricter than the state table:
`Paused -> Execute` is a legal edge, but only a task that is actually `Paused`
may be resumed, or a task parked in `Route` awaiting approval would run without
one. `Supervisor::pause` refuses the same way, because `record_transition`'s
`debug_assert!` is compiled out of release builds.

The pre-check cannot cover a task that moves between it and the call.
`TaskStore::record_transition` is therefore a **compare-and-swap**: it inserts the
audit row and updates `sup_tasks` in one transaction, conditioned on
`WHERE id=?2 AND state=?3`, so whichever request arrives second finds the row no
longer in `from` and is refused — the audit row rolls back with it and the route
answers 409. A concurrent lifecycle request is **refused, never applied twice**.
The same hazard is closed one level up by `Supervisor`'s per-task in-flight
guard, which answers `AlreadyRunning` for a second `execute_now`: the
compare-and-swap alone cannot catch it, because two `Execute -> Plan`
transitions are both legal edges.

Design spec: `docs/superpowers/specs/2026-09-16-haos-green-web-dashboard-design.md`.

## Files Not to Commit

- `config.toml` - Contains API keys and tokens
- `.env` - Environment variables
- `/target/` - Build artifacts
- `.measure/` - Local benchmark artifacts

## Supervisor (Autopilot v2)

The supervisor is a generic autonomous task runner that lives alongside the
existing chat agent. It accepts a free-form request, classifies it, picks a
plan, dispatches work to one or more **backends** (reasoning, shell, MCP,
Claude Code CLI, Codex CLI, scripts), verifies the result, and persists
artifacts + audit transitions to SQLite.

### Module tree (`src/supervisor/`)

```
src/supervisor/
 mod.rs              — Supervisor facade: submit / execute_now / pause / resume / state / artifacts
 task.rs             — Task, TaskType, RiskLevel, ExecutionMode, TaskStatus enums
 job.rs              — Job, JobType, JobStatus, JobOutput, Evidence
 state.rs            — transition_allowed() — single source of truth for the state machine
 store.rs            — TaskStore: CRUD over sup_tasks / sup_jobs / sup_transitions
 intake.rs           — IntakeRouter::normalize() → Task from raw text
 classifier.rs       — Classifier trait + HeuristicClassifier / LlmBackedClassifier / SkillAwareClassifier
 policy.rs           — PolicyEngine: AutoExecute | Clarify | RequireApproval | UseFallbackBackend | StopAndReport
 planner.rs          — Planner: Task → Plan { jobs, parallel_groups }
 workflow.rs         — Fast / Standard / Rigorous workflow stage templates
 orchestrator.rs     — Orchestrator: executes Plan with fallback + parallel groups + subjob spawning
 verification.rs     — VerificationEngine: ≥1 evidence per job gate
 artifact.rs         — ArtifactManager: write_text() (redacts) + list()
 workspace.rs        — WorkspaceManager: per-task git branch / optional worktree
 reporter.rs         — Human-readable per-job summary
 redact.rs           — Secret scrubber for api_key / password / secret / token / bearer values
 backend/
  mod.rs            — Backend trait + BackendCapabilities + Registry + RunContext
  reasoning.rs      — Wraps the chat Agent
  shell.rs          — Sandboxed shell commands
  mcp.rs            — Calls tools on a connected MCP server
  claude_code.rs    — Spawns the `claude` CLI as a backend
  codex.rs          — Spawns the `codex` CLI as a backend
  script.rs         — Runs a script file from the sandbox
```

### Lifecycle

```
INTAKE → CLASSIFY → ROUTE
              ↓
       (CLARIFY) | (PREPARE_WORKSPACE)? → PLAN → EXECUTE
              ↓                                    ↓
              (Paused ⇄ Execute)         REVIEW (rigorous mode)
                                                   ↓
                                              VERIFY
                                                   ↓
                              REPORT → ARCHIVE → DONE
                                  ↘ Failed   ↘ Cancelled
```

`state.rs::transition_allowed(from, to)` enumerates every legal edge. Add a
new arm there before introducing a new state — the rest of the supervisor
treats unknown transitions as bugs.

### Backend trait + adding a new backend

Every backend implements `Backend` from `src/supervisor/backend/mod.rs`. The
defaults from spec §10 (`prepare`, `collect_result`, `verify_result`,
`cancel`, `resume`) are already provided; most backends only override
`name`, `capabilities`, `can_handle`, and `run`. Register an `Arc<MyBackend>`
into the `Registry` at startup.

```rust
struct EchoBackend;
#[async_trait::async_trait]
impl haos_green::supervisor::backend::Backend for EchoBackend {
    fn name(&self) -> &str { "echo" }
    fn capabilities(&self) -> haos_green::supervisor::backend::BackendCapabilities {
        haos_green::supervisor::backend::BackendCapabilities { reasoning: true, ..Default::default() }
    }
    fn can_handle(&self, _: &haos_green::supervisor::job::JobType) -> bool { true }
    async fn run(&self, job: &mut haos_green::supervisor::job::Job, _: &haos_green::supervisor::backend::RunContext)
        -> anyhow::Result<haos_green::supervisor::job::JobOutput> { /* ... */ todo!() }
}
let mut reg = haos_green::supervisor::backend::Registry::new();
reg.register(std::sync::Arc::new(EchoBackend));
```

### Adding a workflow skill pack

Drop a `skills/sup-<name>/SKILL.md` with frontmatter:

```yaml
---
name: sup-<name>
description: One-line summary
supervisor:
  workflow: research          # or: writing | refactor | research | ops | review
  required_capabilities: [research, reasoning]
---
```

Skill packs are auto-loaded by the existing `SkillRegistry` at startup; the
`SkillAwareClassifier` consults them and overrides the default
`required_capabilities` when the request keyword matches the skill name
(prefix `sup-` is stripped before matching).

### TOML config keys

```toml
[supervisor]
default_autonomy_mode = "standard"   # "fast" | "standard" | "rigorous"
artifacts_dir         = "supervisor/artifacts"

[supervisor.shell]
sandbox = "bwrap"                    # "bwrap" (default) | "none"

[supervisor.risk]
require_approval_for_low    = false
require_approval_for_medium = false
auto_execute_only_low       = false   # when true, Medium escalates to RequireApproval
```

Defaults preserve M1–M6 behavior (Medium-risk auto-executes). Flip individual
fields to tighten the gate.

### Bot commands

| Command | Behaviour |
|---------|-----------|
| `/supervise <text>` | Submit a new supervisor task |
| `/tasks`            | List active / recent tasks |
| `/resume <id>`      | Resume a paused task |
| `/cancel <id>`      | Cancel a task |
| `/approve <id>`     | Approve a task that hit `RequireApproval` |
| `/clarify <id> <text>` | Reply to a `Clarify` prompt |
| `/allow <abs-path>` | Grant shell jobs write access to one host path |
| `/deny <abs-path>`  | Revoke a write grant |
| `/allow_net`        | Share the host network namespace with sandboxed jobs |
| `/deny_net`         | Stop sharing the host network namespace |
| `/grants`           | Show the grants currently held |

All eleven commands are routed by `dispatch_supervisor_command` in
`src/platform/telegram.rs`, reachable only from users in
`telegram.allowed_user_ids` — checked by the dispatcher's filter **and** again
as the first statement of the handler, before any argument parsing, store read
or send, so an unauthorized user gets no action, no data and no reply.

Argument handling is bounded and fails closed: a missing argument answers with
a usage line, a malformed task id is refused rather than echoed (ids are
UUID-shaped and at most `MAX_TASK_ID_CHARS`), and task text is capped at
`MAX_TASK_TEXT_CHARS` (2000). Every reply is redacted and passed through
`bounded_reply` before it is sent.

`/supervise` deliberately does **not** run the pipeline — it creates and routes
the task, exactly like `POST /api/supervisor/tasks`, which leaves it parked in
`Route` or `Clarify`. Running it there would be a second execution path beside
`/approve` and `/resume`, and would block the bot's message handler for the
length of a plan. The reply therefore names the command that moves the task on:
`/approve <id>`, or `/clarify <id> <text>` for a clarification prompt.

`/clarify` calls `Supervisor::clarify`, which takes `Clarify -> Execute` only
for a task actually in `Clarify` (stricter than the state table, mirroring
`resume`) and then delegates to the existing `execute_now`.

### Shell sandbox

`ShellBackend` (`src/supervisor/backend/shell.rs`) runs a command either inside
a real bubblewrap sandbox or, only on explicit consent, unconfined. The argv is
built by `src/supervisor/backend/sandbox.rs`.

`[supervisor.shell].sandbox` accepts exactly two values, and **only the literal
`"none"` is consent**: every other value — including a typo, and including the
default — resolves to the sandboxed mode, and `validate()` refuses an unknown
value at load rather than letting it fail open. `Isolation::resolve` probes the
host (`bwrap --version` against a **0.12.0** floor, then a smoke test that builds
the production argv), so a host without a usable bubblewrap yields
`Isolation::Unavailable(cause)` naming the cause, never a silent downgrade.

Two layers enforce this, and they hold the **same** `Isolation` value so they
cannot disagree:

- **Layer 1 (route time)** — `Supervisor::submit` parks a task that would select
  the shell backend with `RequireApproval` when the boundary is absent, so the
  operator is asked before anything runs rather than learning from a failed job.
- **Layer 2 (run time)** — `ShellBackend::run` refuses to spawn at all and
  returns a `Failed` job naming the cause.

The base set is bound **read-only**, but it is not six host binds: **only `/usr`
is a `--ro-bind` of the host**. `/bin`, `/lib` and `/lib64` are `--symlink`s into
it, and `/proc` and `/dev` are bubblewrap's own fresh mounts (`--proc`, `--dev`),
not the host's. With them come three resolver files and both certificate paths,
all read-only — and `/etc/ssl/certs` **plus**
`/etc/ca-certificates` are both required for TLS: on Arch/CachyOS the bundle is a
symlink into the latter, so binding the first alone leaves it dangling and `curl`
fails with `(77) error adding trust anchors`. A network namespace is shared only
under a network grant, and `--share-net` is emitted **after** `--unshare-all` —
the reverse order is a silent no-op, measured.

Resource bounds are deliberately modest and are documented as best-effort: a
256 KiB cap per output pipe (which stops the *producer*, via `SIGPIPE`, not just
the reading) and an `RLIMIT_NPROC` sized from a live measurement of the real
uid's thread count plus headroom, never a constant — Linux counts that limit per
**real uid** and in **threads**, so a flat value below the uid's current count
makes every `fork` fail with `EAGAIN`. As root the whole limit is a no-op, which
is why it is a brake and not a boundary.

### Grants

A shell job's boundary can be widened by naming a capability, never by asking
for one. `Grants` holds a set of writable host paths and a network flag, and the
operator releases them one at a time with `/allow`, `/deny`, `/allow_net`,
`/deny_net` and reads them back with `/grants` — or, without the Telegram
surface, through `GET /api/supervisor/grants` and
`POST /api/supervisor/grants/{allow,deny}` on the dashboard, which audit as the
fixed actor `"dashboard"`.

> **A grant is standing, not per-job consent, and there is no per-job mechanism
> at all.** `/allow /var/lib` is bound into *every later shell job* until it is
> revoked, rather than being released for one job that asked. Nothing derives a
> job's needs from its command, and nothing compares what a job wants against
> what is held: a `Task::declared_grants` field once existed for exactly that,
> with both layers reading it and the planner copying it onto every job — but
> **no production code ever wrote it**, so the park could never fire and the
> Layer-2 refusal in `ShellBackend::run` was unreachable. The field, the copy,
> `Grants::missing`, `Grants::covers` and `supervisor::park_reason` are
> **deleted**, not merely unused. What remains is the gate an operator can
> actually reach: a task that would select the shell backend is parked for
> approval when there is no usable boundary to run it in, and refuses at run
> time for the same reason. The spec's §3 describes this, and records what it
> used to claim.

**The command names use underscores, not hyphens.** Telegram `BotCommand` names
must match `[a-z0-9_]{1,32}`, so `/allow-net` is not a command Telegram will
accept or publish. The design documents name it with a hyphen; the assertion in
`test_supported_commands_lists_user_visible_commands` is what caught that.

`Grants::resolve_path` refuses four things at **issue** time rather than when a
job later fails to start: `/`, a relative path, a path that does not exist, and
the sandbox root **or any ancestor of it** — the last because an ancestor hands
back the ability to replace the root itself. Containment is component-wise, so
`/…/ws-evil` is grantable while `/…/ws` is the root. A grant covers the path
**named** and not its children, and `revoke_write` is deliberately lenient about
a path that no longer exists, so a grant cannot outlive the operator's ability
to take it back.

Every grant change is written to `sup_transitions` as an audit row with a
**NULL `task_id`**: a grant is process-wide, not a transition of any task. That
row was impossible to write before — the column was `NOT NULL` with a foreign key
to `sup_tasks` — so `run_migrations` rebuilds the table to make it nullable, and
`TaskStore::record_grant_audit` inserts it directly. A grant that takes effect but
whose audit row cannot be written says so in the reply rather than reporting
success.

> **`notnull` is a reserved SQLite keyword.** The check that gates that rebuild
> reads `pragma_table_info`, and the unquoted form — `SELECT notnull FROM
> pragma_table_info(...)` — is a **syntax error**, not a false answer. Wrapped in
> `.unwrap_or(false)` it reads as "no rebuild needed", so the migration becomes
> dead code that looks alive, and the only symptom is a `NOT NULL constraint
> failed` at the first audit write, far from the cause. The identifier is quoted
> and a real error is propagated instead of collapsed into `false`.

**Known limitation: a grant is in-memory only.** There is no `sup_grants` table
and nothing restores grants at startup, so every grant is lost on restart and
must be re-issued — the audit log records that it *was* issued, not that it still
holds. The
`Supervisor` also refuses to grant at all when it was never told its sandbox
root (`with_sandbox_root`), because the ancestor check is what stops a grant
from handing back the sandbox — a guessed root would be a guessed containment
check.

**`/allow_net` is the grant that widens the boundary most**, and the reply says
so. Once it is held, a sandboxed job can reach any service the host can,
including loopback — and a local service that can run commands on the host is
then reachable from inside the sandbox. The reply names that explicitly rather
than reporting a bare success.

### Artifacts

Per-task artifacts are written to `<supervisor.artifacts_dir>/<task_id>/<filename>`
and indexed in `sup_artifacts` (`kind`, `path`, `sha256`, `bytes`). Every
artifact write goes through `redact::redact()`, which scrubs values that
follow `api_key`, `password`, `secret`, `token`, or `bearer` (case-insensitive)
and replaces them with `***` while preserving the key + separator so the
file stays human-readable. Standard kinds emitted by the pipeline: `intake`,
`classification`, `policy`, `plan`, `workspace` (when workspace prepared),
and `result` (Reporter Markdown summary).

### Database tables added

| Table | Purpose |
|-------|---------|
| `sup_tasks`       | One row per submitted task — title, user_request, classification (`task_type` / `risk_level` / `execution_mode`), current `state`, platform / user / chat origin |
| `sup_jobs`        | One row per job dispatched within a task — backend, goal, prompt, status, result_summary, error, optional `parent_job_id` for spawned subjobs |
| `sup_transitions` | Append-only audit log of every state change (`from_state`, `to_state`, `actor`, `reason`, `occurred_at`) |
| `sup_artifacts`   | Index of files written under `artifacts_dir` (`task_id`, `job_id`, `kind`, `path`, `sha256`, `bytes`) |
| `sup_execution_leases` | One row per running task — `owner_id`, `expires_at`, `renewed_at`. The cross-process execution fence; see below |

All five tables are created idempotently in `MemoryStore` at startup.

### Cross-process execution lease

`Supervisor`'s in-flight guard (`InFlight`) only covers one process, so two
supervisors over the same database — a restart racing a still-running instance,
or two hosts on one home — could execute the same task at once. `execute_now`
therefore takes a row in `sup_execution_leases` before it does anything else.

- **Acquire** is one conditional statement:
  `INSERT ... ON CONFLICT(task_id) DO UPDATE ... WHERE expires_at <= ?now`,
  so it is atomic without an explicit transaction. `changed == 1` is the only
  success. The plan's `OR owner_id = ?owner` term is deliberately **omitted**: a
  second claim by the same owner is a second run of the same task, which is
  exactly what the lease exists to refuse.
- **Renew** is owner-checked and refuses an expired row
  (`expires_at > ?now`), so a lapsed lease is never resurrected — it must be
  taken over by a fresh claim. **Release** deletes only a row this owner holds.
- The owner id is minted **per run** (`new_lease_owner_id()`), not per
  `Supervisor`, so a detached release from a cancelled run cannot free a later
  run's lease.
- A heartbeat renews every 60 s against a 300 s TTL, with bounded backoff
  (worst case ~20.7 s, well inside the TTL). It owns the **only**
  `watch::Sender`, so a heartbeat that returns, is aborted or **panics** all
  read as a lost lease.
- Losing the lease aborts the in-progress pipeline: the `execute_now` future is
  dropped, which drops the backends' subprocesses. `SupervisorError::LeaseLost`
  maps to **409** through `lifecycle_failure_status`; its message is
  cause-neutral, because a store outage produces the same variant as a takeover.

Known bounds — documented, not hidden:

- takeover is noticed at the next heartbeat, so up to ~60–80 s of two-owner
  overlap is possible;
- committed side effects (job rows, artifacts, workspace branches, sent LLM/MCP
  calls) are **not** rolled back;
- `kill_on_drop` kills only the **direct** child — a backgrounded grandchild of
  a compound `sh -c` can survive, and an in-flight MCP tool call is abandoned
  rather than stopped (`McpBackend` has no timeout or cancellation). A `shell`
  job is the **exception, but only when it is sandboxed**: its argv then carries
  `--die-with-parent`, so its descendants die with the sandbox instead of being
  reparented. Under `sandbox = "none"` there is no argv — the job is a plain
  `sh -c` with `kill_on_drop`, so a backgrounded grandchild is reparented and
  survives exactly like every other backend. Proven by
  `tests/shell_sandbox_live.rs::killing_the_supervisor_leaves_no_descendant`,
  which fails only after its 20 s deadline when that flag is removed — the
  flag is load-bearing, not decorative;
- a stale row from a crashed process makes its task unresumable for up to
  `LEASE_TTL_SECS` (300 s); there is no liveness probe or operator override;
- the TTL is wall-clock, so a backward clock step larger than the TTL can expire
  a live lease early;
- the heartbeat is an ordinary task, so all-worker starvation stops renewals and
  the row lapses with no signal;
- the lease table is write-only from the app's point of view — no UI or route
  shows who holds a lease or when it expires.

## Agent skills

### Issue tracker

GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context. See `docs/agents/domain.md`.
