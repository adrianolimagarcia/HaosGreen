# README Update — Models, Schedule Tools, Roadmap, License, Sponsorship Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Update README with scheduling tools docs, switch default models, add roadmap/todo list, MIT license, contributing section, and sponsorship links.

**Architecture:** Pure documentation + config-default changes. No logic changes. Four files touched: `README.md` (full rewrite), `src/config.rs` (two default value changes), `config.example.toml` (one model string update), plus a new `LICENSE` file.

**Tech Stack:** Rust (config.rs), TOML (config.example.toml), Markdown (README.md, LICENSE)

**Branch:** `claude/update-readme-models-JMkVu`

---

### Task 1: Ensure correct branch

**Files:**
- Git branch

**Step 1: Check current branch**

```bash
git branch --show-current
```

Expected: `claude/update-readme-models-JMkVu` (or create it if missing)

**Step 2: Create/switch to the branch if needed**

```bash
git checkout -b claude/update-readme-models-JMkVu 2>/dev/null || git checkout claude/update-readme-models-JMkVu
```

---

### Task 2: Update default inference model in `src/config.rs`

**Files:**
- Modify: `src/config.rs:78-80`

**Step 1: Change `default_model()`**

In `src/config.rs`, replace:
```rust
fn default_model() -> String {
    "qwen/qwen3-235b-a22b".to_string()
}
```
with:
```rust
fn default_model() -> String {
    "moonshotai/kimi-k2.5".to_string()
}
```

**Step 2: Change `default_embedding_model()`**

In `src/config.rs`, replace:
```rust
fn default_embedding_model() -> String {
    "openai/text-embedding-3-small".to_string()
}
```
with:
```rust
fn default_embedding_model() -> String {
    "qwen/qwen3-embedding-8b".to_string()
}
```

**Step 3: Verify compilation**

```bash
cargo check 2>&1
```
Expected: no errors

**Step 4: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): update default model to moonshotai/kimi-k2.5 and embedding to qwen/qwen3-embedding-8b"
```

---

### Task 3: Update `config.example.toml`

**Files:**
- Modify: `config.example.toml:14`

**Step 1: Update the model line**

Replace:
```toml
model = "qwen/qwen3-235b-a22b"
```
with:
```toml
model = "moonshotai/kimi-k2.5"
```

**Step 2: Update the commented embedding example**

The embedding section comment already shows `qwen/qwen3-embedding-8b` — verify it matches, update `dimensions` if needed (qwen3-embedding-8b default is 1536, no change needed).

**Step 3: Commit**

```bash
git add config.example.toml
git commit -m "docs(config): update example config to use new default models"
```

---

### Task 4: Create `LICENSE` (MIT)

**Files:**
- Create: `LICENSE`

**Step 1: Write the MIT license file**

```
MIT License

Copyright (c) 2026 chinkan.ai

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Step 2: Commit**

```bash
git add LICENSE
git commit -m "docs: add MIT license"
```

---

### Task 5: Rewrite `README.md`

**Files:**
- Modify: `README.md`

**Step 1: Full README replacement**

Write the complete new README with these sections (in order):

1. **Header** — title, badges (MIT license badge, buymeacoffee badge), one-line description
2. **Features** — updated feature list including scheduling and embedding
3. **Quick Start** — build, configure, run (unchanged structure)
4. **Configuration** — key settings table with updated model defaults
5. **Built-in Tools** — table split into two: Core Tools + Scheduling Tools
6. **Bot Commands** — unchanged
7. **Architecture** — unchanged
8. **Roadmap** — ✅ Done + 🔲 Planned (with all items from the design doc)
9. **Contributing** — MIT license, "feel free to open a PR" text
10. **Support / Sponsorship** — Buy Me a Coffee + GitHub Sponsors

Full content:

```markdown
# HaosGreen — Telegram AI Assistant

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Buy Me a Coffee](https://img.shields.io/badge/buy%20me%20a%20coffee-☕-yellow)](https://buymeacoffee.com/chinkan.ai)

A Rust-based Telegram AI assistant powered by OpenRouter LLM (default: `moonshotai/kimi-k2.5`) with built-in sandboxed tools, scheduling, persistent memory, and MCP server integration.

## Features

- **Telegram Bot** — Responds only to configured user IDs
- **OpenRouter LLM** — Configurable model (default: `moonshotai/kimi-k2.5`)
- **Built-in Tools** — File read/write, directory listing, command execution (sandboxed)
- **Scheduling Tools** — Schedule, list, and cancel recurring or one-shot tasks
- **Persistent Memory** — SQLite-backed conversation history and knowledge base
- **Vector Embedding Search** — Hybrid vector + FTS5 search using `qwen/qwen3-embedding-8b`
- **MCP Integration** — Connect any MCP-compatible server to extend capabilities
- **Bot Skills** — Folder-based natural-language skill instructions auto-loaded at startup
- **Agentic Loop** — Automatic multi-step tool calling until task completion (max 10 iterations)
- **Per-user Conversations** — Independent conversation history per user

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Configure

Copy the example config and fill in your credentials:

```bash
cp config.example.toml config.toml
```

Edit `config.toml`:
- Set your Telegram bot token (from [@BotFather](https://t.me/BotFather))
- Set your OpenRouter API key (from [openrouter.ai/keys](https://openrouter.ai/keys))
- Add your Telegram user ID to `allowed_user_ids`
- Set the sandbox directory for file/command operations
- Optionally configure MCP servers and embedding API

### 3. Run

```bash
cargo run
# or with a custom config path:
cargo run -- /path/to/config.toml
```

## Configuration

See [`config.example.toml`](config.example.toml) for all options.

### Key Settings

| Setting | Description |
|---------|-------------|
| `telegram.bot_token` | Telegram Bot API token |
| `telegram.allowed_user_ids` | List of user IDs allowed to use the bot |
| `openrouter.api_key` | OpenRouter API key |
| `openrouter.model` | LLM model ID (default: `moonshotai/kimi-k2.5`) |
| `sandbox.allowed_directory` | Directory for file/command operations |
| `memory.database_path` | SQLite DB path (default: `haos-green.db`) |
| `embedding` (optional) | Vector search API config (default model: `qwen/qwen3-embedding-8b`) |
| `skills.directory` | Folder of bot skill files (default: `skills/`) |
| `mcp_servers` | List of MCP servers to connect |
| `location` | Your location string, injected into system prompt |

### MCP Server Configuration

```toml
[[mcp_servers]]
name = "git"
command = "uvx"
args = ["mcp-server-git"]

[[mcp_servers]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/dir"]
```

## Built-in Tools

### Core Tools

| Tool | Description |
|------|-------------|
| `read_file` | Read file contents within sandbox |
| `write_file` | Write/create files within sandbox |
| `list_files` | List directory contents within sandbox |
| `execute_command` | Run shell commands within sandbox directory |

### Scheduling Tools

| Tool | Description |
|------|-------------|
| `schedule_task` | Schedule a recurring (cron) or one-shot task with a message |
| `list_scheduled_tasks` | List all active scheduled tasks |
| `cancel_scheduled_task` | Cancel a scheduled task by ID |

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Show welcome message |
| `/clear` | Clear conversation history |
| `/tools` | List all available tools |

## Architecture

```
src/
├── main.rs           # Entry point, config loading, initialization
├── config.rs         # TOML configuration parsing
├── llm.rs            # OpenRouter API client with tool calling
├── agent.rs          # Agentic loop, tool dispatch, scheduling tools
├── tools.rs          # Built-in tools (file I/O, command execution)
├── mcp.rs            # MCP client manager for external tool servers
├── memory/           # SQLite persistence, vector embeddings
├── scheduler/        # Cron/one-shot task scheduler with DB persistence
├── skills/           # Skill loader (auto-loads from skills/ directory)
└── platform/         # Telegram bot handler
```

## Roadmap

### ✅ Done

- [x] Telegram bot with user allowlist
- [x] OpenRouter LLM integration with tool calling (agentic loop)
- [x] Built-in sandboxed tools (file read/write, directory listing, command execution)
- [x] MCP server integration for extensible tooling
- [x] Per-user conversation history
- [x] Persistent memory with SQLite
- [x] Vector embedding search (`qwen/qwen3-embedding-8b`)
- [x] Scheduling tools (`schedule_task`, `list_scheduled_tasks`, `cancel_scheduled_task`)
- [x] Bot skills (folder-based, auto-loaded at startup)

### 🔲 Planned

- [ ] Image upload support
- [ ] Google integration tools (Calendar, Email, Drive)
- [ ] Event trigger framework (e.g., on email receive)
- [ ] Web portal for setup and configuration
- [ ] WhatsApp support
- [ ] Webhook mode (in addition to polling)
- [ ] And more…

## Contributing

This project is open source under the [MIT License](LICENSE). Contributions are very welcome!

Feel free to:
- Open an issue for bugs or feature requests
- Submit a pull request — all PRs are appreciated

## Support

If you find HaosGreen useful, consider supporting the project:

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-☕-yellow?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/chinkan.ai)

[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-❤-pink?style=for-the-badge&logo=github)](https://github.com/sponsors/chinkan)

## Dependencies

- [teloxide](https://github.com/teloxide/teloxide) — Telegram bot framework
- [rmcp](https://github.com/modelcontextprotocol/rust-sdk) — Official MCP Rust SDK
- [reqwest](https://github.com/seanmonstar/reqwest) — HTTP client for OpenRouter
- [tokio](https://tokio.rs/) — Async runtime
- [tokio-cron-scheduler](https://github.com/mvniekerk/tokio-cron-scheduler) — Task scheduling
```

**Step 2: Verify markdown renders correctly** (visual check only — no tool needed)

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README with scheduling tools, new models, roadmap, MIT license, sponsorship links"
```

---

### Task 6: Commit design doc and push

**Step 1: Stage and commit the design doc**

```bash
git add docs/plans/2026-02-19-readme-update-models-and-features.md docs/plans/2026-02-19-readme-update-models-and-features-plan.md
git commit -m "docs: add design and implementation plan for README + model update"
```

**Step 2: Push to remote**

```bash
git push -u origin claude/update-readme-models-JMkVu
```

Expected: branch pushed successfully

---

### Task 7: Verify

**Step 1: Run cargo check to ensure config changes compile**

```bash
cargo check 2>&1
```
Expected: no errors

**Step 2: Run clippy**

```bash
cargo clippy -- -D warnings 2>&1
```
Expected: no warnings
