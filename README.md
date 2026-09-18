<p align="center">
  <img src="assets/logo.jpeg" alt="HaosGreen Logo" width="200"/>
</p>

# HaosGreen — Telegram AI Assistant

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**What is HaosGreen?**

An open-source, self-hosted Telegram AI assistant written in Rust. It solves a simple problem: most AI assistants are locked inside proprietary chat UIs with no access to your files, tools, or schedule. HaosGreen lives in Telegram — your everyday messaging app — and acts as a full agentic AI teammate.

**Why HaosGreen?**

Drop a file, ask a question, schedule a task — HaosGreen handles it. Powered by OpenRouter LLM (Kimi K2.6), it runs an agentic loop: receive your message, call sandboxed tools (file I/O, command execution, web search via MCP), and loop until done. It remembers context via SQLite + vector RAG, runs skills and sub-agents, and even verifies its own work.

**Self-hosted, no cloud dependency.** Single binary. Setup wizard. Runs as systemd/launchd service. `cargo install` and you're running in 2 minutes.

Star the repo ⭐, fork to contribute, or open an issue for feedback.

**docs:** [README.md](README.md) · [GUIDE.md](docs/GUIDE.md) · [ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Features

| | |
|---|---|
| 🤖 **AI Agent** | OpenRouter LLM (default: `moonshotai/kimi-k2.6`), agentic loop with tool calling, configurable max iterations |
| 🔧 **Built-in Tools** | File read/write, command execution, file sending, task scheduling — all sandboxed |
| 🧩 **MCP Servers** | Connect any MCP-compatible server (Git, Brave Search, GitHub, Filesystem, Threads…) |
| 🧠 **Persistent Memory** | SQLite-backed conversation history, vector embedding search (hybrid + FTS5), RAG |
| 🧬 **Skills & Agents** | Folder-based skill instructions auto-loaded at startup; subagent skills with own model and tool whitelist |
| 🤝 **Agent Layer** | Isolated agentic mini-loops in `agents/` with own model/tools; `invoke_agent`, `spawn_agents`, zero-trust verifier |
| 🔄 **Task Scheduling** | Cron and one-shot task scheduler with SQLite persistence |
| 🧭 **Supervisor** | Autonomous task runner: classify → plan → execute → verify, driven from Telegram (`/supervise`, `/tasks`, `/approve`, `/clarify`) or the dashboard |
| 🖥️ **Web Dashboard** | Optional embedded dashboard (off by default): chat with the same agent, supervisor tasks, live logs, A2A peers, settings |
| 📦 **Self-Hosting** | Single binary, 2-min setup wizard, background service (systemd/launchd/Windows Service) |

→ Full feature reference: [docs/GUIDE.md](docs/GUIDE.md#advanced-features)

### Agent Lifecycle & Runtime

| Capability | Description |
|------------|-------------|
| **Self-Upgrade** | Trigger an in-place upgrade: pulls from git source or downloads the latest GitHub release binary. Auto-restarts after upgrade — no SSH, no manual steps. |
| **Model Switching** | Switch OpenRouter models at runtime via `/models`. Interactive picker lets you choose the best model per task: fast/cheap for simple queries, powerful for complex reasoning. |
| **Soul Files** | SOUL.md (persona), AGENTS.md (behaviour), USER.md (preferences) — persistent identity files auto-injected into every system prompt. Session-end self-reflection with `.bak` backups. |

---

### 💭 Multi-Session & Multi-Model (Brainstorming)

> ⚠️ **Planning phase** — not yet implemented. This section captures ideas explored in the `feat/readme-improve-multi-session-brainstorm` branch.

The vision: run multiple concurrent chat sessions, each with its own model and isolated context.

| Use Case | Description |
|----------|-------------|
| **Parallel execution** | Run a cheap model for quick tasks while a powerful model tackles deep analysis — concurrently, not sequentially |
| **Per-user isolation** | Each Telegram user gets their own session with independent conversation context and model preference |
| **Sub-agent delegation** | Spawn sub-agents with different models (e.g., GPT-4o for code review, Claude for writing) without polluting the main session |

**Topics to explore:**

- Session lifecycle — create, switch, merge, archive
- Per-session model binding vs global default model
- Context isolation between sessions (independent or shared RAG?)
- Telegram UX for multi-session management (inline buttons? slash commands?)
- Persistence and RAG across session boundaries

See [docs/roadmap/multi-session.md](docs/roadmap/multi-session.md) for detailed design notes.

## Quick Start

### 1. Install

**Option A — Download a release (recommended)**

Download from the [Releases page](../../releases):

```bash
tar xzf haos-green-*.tar.gz
```

**Option B — Build from source**

```bash
cargo install --path . --locked
```

### 2. Configure

```bash
# Browser wizard
./haos-green --setup

# Or terminal wizard
./haos-green --setup --cli
```

The wizard guides you through: Telegram bot token, allowed user IDs, OpenRouter API key, model, and optional MCP tools.

### 3. Run

```bash
haos-green
# or with a custom config:
haos-green --config /path/to/config.toml
```

### 4. (Optional) Background service

```bash
haos-green --service install   # Linux (systemd), macOS (launchd), or Windows
haos-green --service status
```

---

## Configuration

| Setting | Description |
|---------|-------------|
| `telegram.bot_token` | Telegram Bot API token (from [@BotFather](https://t.me/BotFather)) |
| `telegram.allowed_user_ids` | Comma-separated user IDs allowed to use the bot |
| `openrouter.api_key` | OpenRouter API key ([openrouter.ai/keys](https://openrouter.ai/keys)) |
| `openrouter.model` | LLM model ID (default: `moonshotai/kimi-k2.6`) |
| `sandbox.allowed_directory` | Directory for sandboxed file/command operations |
| `mcp_servers` | List of MCP servers to connect (see [GUIDE.md](docs/GUIDE.md#mcp-server-integration)) |
| `web.enabled` | Enable the embedded web dashboard (default: `false`) — see below |

### Web Dashboard (optional)

HaosGreen ships an embedded web dashboard: chat with the same agent, submit and
track supervisor tasks, tail the live log, manage A2A peers, and change the
dashboard password. It is **off by default**.

```toml
[web]
enabled = true
bind = "127.0.0.1:8787"   # default; keep it on loopback unless you mean it
```

Then open <http://127.0.0.1:8787> and sign in with `admin` / `admin`.

> ⚠️ **Change the password in Settings before exposing the port.** Anyone who can
> sign in runs the same agent as the Telegram operator, shell execution included.
> The dashboard binds to loopback by default, warns at startup and shows a
> persistent banner while the default password is in use — but a non-loopback
> bind without changing it is unsafe.

Dashboard credentials live in `<home>/web-auth.toml` (mode 0600), never in
`config.toml`. For the full security model — the auth flow, the IP allowlist, the
bearer token, and the invariants that must not be weakened — see
[CLAUDE.md → Web Dashboard](CLAUDE.md#web-dashboard).

→ Full configuration reference: [docs/GUIDE.md](docs/GUIDE.md#configuration)

### Supervisor (optional)

The supervisor runs tasks on its own: it classifies a free-form request, picks a
plan, dispatches the work to backends (reasoning, shell, MCP, Claude Code, Codex,
scripts), verifies the result, and keeps an audit trail in SQLite. Drive it from
Telegram — only users in `telegram.allowed_user_ids` get an answer:

| Command | What it does |
|---------|--------------|
| `/supervise <text>` | Create a task. It is **not** started — the reply names the command that runs it |
| `/tasks` | List recent tasks with their state |
| `/approve <id>` | Approve a task waiting for approval, and run it |
| `/clarify <id> <text>` | Answer a clarification prompt, and run it |
| `/resume <id>` | Resume a paused task |
| `/cancel <id>` | Cancel a task |

`/supervise` deliberately stops at `Route`/`Clarify` rather than executing, so a
long plan never blocks the bot; `/approve` and `/clarify` are what start it.

```toml
[supervisor]
default_autonomy_mode = "standard"   # "fast" | "standard" | "rigorous"
artifacts_dir         = "supervisor/artifacts"

[supervisor.risk]
auto_execute_only_low = true         # escalate anything above Low to approval
```

A running task holds a **lease** row in `haos-green.db`, so two HaosGreen
processes sharing one home cannot execute the same task at once. The lease
expires after 300 s and is renewed every 60 s while the task runs; if a process
dies, its task becomes runnable again once the lease lapses. Takeover is noticed
at the next heartbeat, so a brief overlap is possible, and side effects already
committed are not rolled back — see
[CLAUDE.md → Cross-process execution lease](CLAUDE.md#cross-process-execution-lease)
for the exact bounds.

---

## Quick Tool Overview

| Tool | Description |
|------|-------------|
| `read_file` / `write_file` | Read and write files within the sandbox |
| `send_file` | Send a file from the sandbox to the current chat |
| `self_upgrade` | Trigger self-upgrade from git source or GitHub release, auto-restart |
| `read_soul_file` | Read SOUL.md, AGENTS.md, or USER.md soul files |
| `update_soul_file` | Append or replace content in a soul file with `.bak` backup |
| `revert_soul_file` | Restore a soul file from its most recent `.bak` backup |
| `try_new_tech` | Sandboxed experiment — run Rust/JS code and check results |
| `execute_command` | Run shell commands within the sandbox |
| `schedule_task` | Schedule recurring (cron) or one-shot tasks |
| `invoke_agent` | Run a predefined agent from the `agents/` directory |

→ Full tool reference: [docs/GUIDE.md](docs/GUIDE.md#built-in-tools)

---

## Architecture

HaosGreen runs an agentic loop: user message → LLM (OpenRouter) → tool calls → execute → loop until final response. Tools dispatch to built-in functions, MCP servers, or skill/agent directories.

→ Full architecture with source tree and data flow: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Contributing

MIT License. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to open issues and submit PRs.
