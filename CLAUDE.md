# CLAUDE.md - RustFox Development Guide

## Project Overview

RustFox is a Telegram AI assistant written in Rust. It connects to Telegram as a
bot, uses OpenRouter for inference (default model `moonshotai/kimi-k2.6`, see
`default_model()` in `src/config.rs`), provides built-in sandboxed tools plus
MCP (Model Context Protocol) servers for extensible tool integration, and runs
an agentic loop that iterates tool calls until a final text response is produced
(`[agent] max_iterations`, default **25**).

It also carries an autonomous supervisor (see [Supervisor](#supervisor-autopilot-v2))
and an optional Agent2Agent listener (see [A2A](#a2a-agent2agent-protocol)).

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

RustFox stores all state under a single home directory (default `~/.rustfox`),
resolved as: `RUSTFOX_HOME` env (absolute) → `[general].home` config → `~/.rustfox`.
Layout: `config.toml`, `rustfox.db`, `skills/`, `agents/`, `workspace/` (the
sandbox), `artifacts/`, `user_model.md`. Each path can be pinned to an absolute
location in `config.toml`; unset paths fall back to the home default. Run
isolated instances with `RUSTFOX_HOME=...`. See
`docs/persistent-home-directory.md`. Path resolution lives in `src/home.rs`
(`Config::resolve` writes the resolved absolute paths back into the config).
Bundled skills/agents are seed-copied on first run; `/update-skills` re-syncs
them using `<home>/skills-lock.json`.

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
- **Logging**: `tracing` (`RUST_LOG`, default `info,rustfox=debug`)
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
> `read_soul_file` could return `~/.rustfox/config.toml` (API key + every peer
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
| `rmcp` | Official MCP Rust SDK |
| `axum` / `tower-http` | A2A listener; setup wizard's OAuth callback |
| `a2a` (`a2a-lf`) | A2A protocol types |
| `ipnet` | CIDR matching for the A2A peer IP allowlist |
| `subtle` | Constant-time bearer-token comparison |
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

The suite is large and must stay green (~560 unit tests in `src/**` plus 11
integration files in `tests/`). When adding tests:

- Unit tests go in `#[cfg(test)] mod tests` blocks in the file under test.
- Integration tests go in `tests/`.
- Prefer testing through the public API. For HTTP surfaces, bind an ephemeral
  port (`127.0.0.1:0`) and make real requests — see `tests/a2a_endpoint.rs`.
- A test that passes for the wrong reason is worse than no test. When a test
  guards a security property, **prove it has teeth** by mutating the
  implementation and confirming the test fails.

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
- Client & tool (Phase 5): Outbound A2A client (`src/a2a/client.rs`) and `call_a2a_agent` tool (`src/a2a/tool.rs`) allowing RustFox to delegate tasks to remote A2A peers.

### Endpoints
- `GET /.well-known/agent-card.json` — **public**, no auth. Lists skills by
  name/description/tags only; instruction bodies are never included.
- `POST /jsonrpc` — requires a per-peer bearer token **and** a source IP matching
  the same peer. 401 (bad/absent token), 403 (IP not allowed), 500 (duplicate
  tokens), and JSON-RPC task-method responses for authenticated requests.

### Configuration
- Server config lives in `[a2a]`, `[a2a.card]` and `[a2a.peers.<name>]`.
- Outbound client peers are configured under `[a2a.outbound.peers.<name>]` with keys `url`, `token`, `timeout_secs`, `poll_interval_ms`, and `poll_timeout_secs`. See `config.example.toml`.

`A2aConfig::validate()` runs at startup and refuses to start the listener on duplicate tokens, an empty token, an empty `ip` list, an unparseable IP/CIDR, or any request for TLS (not implemented — rejected rather than silently served as plaintext). A listener failure never prevents the Telegram bot from starting.

Design spec: `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
Implementation plans: `docs/superpowers/plans/2026-09-16-a2a-phase1-card-auth-policy.md`,
`docs/superpowers/plans/2026-09-16-a2a-phase2-task-store-executor.md`,
`docs/superpowers/plans/2026-09-16-a2a-phase3-concurrency-get-cancel.md`, and
`docs/superpowers/plans/2026-09-16-a2a-phase5-client-tool.md`.

> **Security invariants — do not weaken without a written reason:**
> - `DEFAULT_PEER_TOOLS` (`src/a2a/policy.rs`) is an **allowlist**. A tool added
>   to RustFox is *not* granted to peers until it is named there.
> - **Anti-recursion invariant**: `call_a2a_agent` is **NEVER** in `DEFAULT_PEER_TOOLS`. An inbound peer cannot call outbound A2A peers through RustFox unless explicitly granted by operator policy, preventing unbounded peer-to-peer amplification loops.
> - `read_soul_file` and `plan_view` are deliberately excluded: `read_soul_file`
>   can reach `~/.rustfox/config.toml`, which holds the API key and every peer
>   token. Do not add them back.
> - `["*"]` expands to the **registry's** tool set, never a hand-written list.
> - An empty configured token never authenticates, and duplicate tokens are
>   refused rather than resolved by `HashMap` iteration order.
> - The card's advertised URL must come from the address actually bound (or
>   `public_url`), never the raw `bind` string.
> - **Redacted tokens**: Outbound peer tokens are never printed in debug representations (`A2aOutboundPeerConfig` redacts tokens), and error messages returned by `call_a2a_agent` sanitize configured tokens and bearer patterns before returning to the model or logs.
> - **No automatic POST retries**: Outbound `SendMessage` calls are never automatically retried to avoid duplicate remote task creation; only `GetTask` polling retries up to `poll_timeout_secs`.

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
impl rustfox::supervisor::backend::Backend for EchoBackend {
    fn name(&self) -> &str { "echo" }
    fn capabilities(&self) -> rustfox::supervisor::backend::BackendCapabilities {
        rustfox::supervisor::backend::BackendCapabilities { reasoning: true, ..Default::default() }
    }
    fn can_handle(&self, _: &rustfox::supervisor::job::JobType) -> bool { true }
    async fn run(&self, job: &mut rustfox::supervisor::job::Job, _: &rustfox::supervisor::backend::RunContext)
        -> anyhow::Result<rustfox::supervisor::job::JobOutput> { /* ... */ todo!() }
}
let mut reg = rustfox::supervisor::backend::Registry::new();
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

The command **parser** is wired and emits a startup log line in `main.rs`;
routing user commands into supervisor handlers in the live Telegram dispatcher
is a minimum-viable integration (M3.8 / M7.3) and the full handler surface is
a follow-up task.

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

All four tables are created idempotently in `MemoryStore` at startup.

## Agent skills

### Issue tracker

GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context. See `docs/agents/domain.md`.
