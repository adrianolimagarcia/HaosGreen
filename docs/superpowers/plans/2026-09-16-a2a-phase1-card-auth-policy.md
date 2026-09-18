# A2A Phase 1 — Card, Auth, Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up an A2A endpoint that serves an Agent Card and rejects every unauthenticated or non-allowlisted request, before any code path exists that can execute an agent turn.

**Architecture:** A new `src/a2a/` module holds four focused units — config, tool policy, authentication, and the axum listener. The server is spawned as a tokio task inside the bot process when `[a2a].enabled` is true. Authentication is a pure function over (bearer token, source IP, config) so it is testable without HTTP.

**Tech Stack:** Rust 2021, `a2a-lf` 0.3.1 (imported as `a2a`), `axum` 0.8.9, `ipnet` 2.12.1, `subtle` 2.6.1, `tokio`, `serde`, `tracing`.

**Spec:** `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`

---

## Scope

This plan records the original Phase 1 implementation. The subsequent Phase 2–3
plans have since added `TaskStore`, `AgentExecutor`, `SendMessage`, `GetTask`,
`CancelTask`, and the concurrency gate. Remaining work is Phase 4 SSE streaming
and Phase 5 A2A client support.

Deliverable: success criteria 1 and 3 from the spec —

1. A remote A2A client can fetch `/.well-known/agent-card.json` and see HaosGreen's skills.
3. An unauthenticated or non-allowlisted peer receives 401/403 and no agent work is performed.

Criterion 3 was only half-testable during this phase: agent work was not yet
available through A2A. Task 7 asserted the 401/403 half; later phases now cover
execution and lifecycle behavior.

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `Cargo.toml` | Modify | Add `a2a-lf`, `ipnet`, `subtle`; promote `tower-http` |
| `src/config.rs` | Modify | `A2aConfig`, `A2aCardConfig`, `A2aPeerConfig` |
| `src/a2a/mod.rs` | Create | Module facade, `A2aState` |
| `src/a2a/policy.rs` | Create | Peer → allowed tool names, with `*` expansion |
| `src/a2a/auth.rs` | Create | Bearer + IP allowlist → `PeerIdentity`, fail-closed |
| `src/a2a/card.rs` | Create | `SkillRegistry` + config → `AgentCard` |
| `src/a2a/server.rs` | Create | axum router, listeners |
| `src/lib.rs` | Modify | `pub mod a2a;` |
| `src/main.rs` | Modify | Spawn the server when enabled |

`policy.rs` and `auth.rs` are pure functions with no axum dependency, so they are unit-testable without a running server. That separation is the point: the security-critical logic is testable in isolation.

---

### Task 1: Add dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add the dependencies**

In `Cargo.toml`, under `[dependencies]`, add:

```toml
# A2A protocol (Phase 1: Agent Card types only)
a2a = { package = "a2a-lf", version = "0.3.1" }
# CIDR matching for the A2A peer IP allowlist
ipnet = "2"
# Constant-time comparison for bearer tokens
subtle = "2"
# Middleware for the A2A listener
tower-http = { version = "0.6", features = ["trace"] }
```

The crate is published as `a2a-lf` but imported in Rust as `a2a`. The `package =` key performs that rename.

- [ ] **Step 2: Verify it resolves**

Run: `cargo check`
Expected: `Finished` with no error. `Cargo.lock` gains direct entries for `a2a-lf`, `ipnet`, `subtle`, `tower-http`.

If this fails with a version conflict on `base64`, note that HaosGreen pins `base64 0.22` while `a2a-lf` requires `^0.23`. Both may coexist; cargo resolves them as separate major versions. Do not attempt to unify them.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(a2a): add a2a-lf, ipnet and subtle deps"
```

---

### Task 2: A2A configuration types

**Files:**
- Modify: `src/config.rs`
- Test: `src/config.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` block in `src/config.rs`:

```rust
    /// Minimal config that parses. `Config` has **no `Default` impl**, and
    /// `telegram.bot_token`, `telegram.allowed_user_ids` and
    /// `openrouter.api_key` are required fields with no serde default.
    fn minimal_config() -> Config {
        toml::from_str(
            r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"
"#,
        )
        .expect("minimal config must parse")
    }

    #[test]
    fn a2a_disabled_by_default() {
        let cfg = minimal_config();
        assert!(!cfg.a2a.enabled, "A2A must be opt-in");
    }

    #[test]
    fn a2a_binds_localhost_by_default() {
        let cfg = minimal_config();
        assert_eq!(cfg.a2a.bind, "127.0.0.1:8443");
    }

    #[test]
    fn a2a_max_concurrent_tasks_defaults_to_four() {
        let cfg = minimal_config();
        assert_eq!(cfg.a2a.max_concurrent_tasks, 4);
    }

    #[test]
    fn a2a_peer_without_tools_parses_as_none() {
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a.peers.laptop]
token = "s3cret"
ip = ["192.168.1.0/24"]
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        let peer = cfg.a2a.peers.get("laptop").expect("peer must parse");
        assert_eq!(peer.token, "s3cret");
        assert_eq!(peer.ip, vec!["192.168.1.0/24".to_string()]);
        assert!(
            peer.tools.is_none(),
            "absent tools key must be None, not an empty vec — None means \
             'apply the conservative default', Some(vec![]) means 'no tools'"
        );
    }

    #[test]
    fn a2a_peer_with_wildcard_parses() {
        let raw = r#"
[telegram]
bot_token = "x"
allowed_user_ids = [1]

[openrouter]
api_key = "x"

[a2a.peers.buildbox]
token = "t"
ip = ["10.8.0.4"]
tools = ["*"]
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        let peer = cfg.a2a.peers.get("buildbox").unwrap();
        assert_eq!(peer.tools.as_ref().unwrap(), &vec!["*".to_string()]);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib a2a_ 2>&1 | tail -20`
Expected: FAIL — compile error, `no field 'a2a' on type 'Config'`.

- [ ] **Step 3: Write the config types**

In `src/config.rs`, add near the other section structs (e.g. after `SupervisorConfig`):

```rust
/// A2A (Agent2Agent) protocol settings.
///
/// Disabled by default. Enabling this opens a network listener; read
/// `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md` §2 and §6
/// before turning it on.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct A2aConfig {
    /// Master switch. `false` means no listener is started at all.
    pub enabled: bool,
    /// Listen address. Defaults to loopback; raising this to a LAN address is
    /// a deliberate act.
    pub bind: String,
    /// Maximum A2A tasks executing concurrently. Excess tasks queue.
    pub max_concurrent_tasks: usize,
    /// Agent Card metadata.
    pub card: A2aCardConfig,
    /// Known peers, keyed by peer name. A request whose token matches no entry
    /// here is rejected. An empty map means nobody can connect.
    pub peers: HashMap<String, A2aPeerConfig>,
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8443".to_string(),
            max_concurrent_tasks: 4,
            card: A2aCardConfig::default(),
            peers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct A2aCardConfig {
    pub name: String,
    pub description: String,
    pub version: String,
}

impl Default for A2aCardConfig {
    fn default() -> Self {
        Self {
            name: "HaosGreen".to_string(),
            description: "Self-hosted Telegram AI assistant".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct A2aPeerConfig {
    /// Bearer token this peer must present.
    pub token: String,
    /// Allowed source addresses: exact IPs (`10.0.0.5`) or CIDR blocks
    /// (`192.168.1.0/24`). Empty means no address is allowed.
    #[serde(default)]
    pub ip: Vec<String>,
    /// Tool allowlist for this peer. `None` applies `DEFAULT_PEER_TOOLS`.
    /// `Some(["*"])` grants every tool, including shell. An explicit list is
    /// used verbatim.
    #[serde(default)]
    pub tools: Option<Vec<String>>,
}
```

Ensure `use std::collections::HashMap;` is present at the top of `src/config.rs`.

- [ ] **Step 4: Add the field to `Config`**

In the `Config` struct, after the `subagents` field:

```rust
    #[serde(default)]
    pub a2a: A2aConfig,
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib a2a_ 2>&1 | tail -20`
Expected: PASS, 8 tests.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs
git commit -m "feat(a2a): add A2A config types, disabled by default"
```

---

### Task 3: Per-peer tool policy

**Files:**
- Create: `src/a2a/mod.rs`
- Create: `src/a2a/policy.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create the module facade**

Create `src/a2a/mod.rs`:

```rust
//! A2A (Agent2Agent) protocol support.
//!
//! Phase 1 covers the Agent Card, authentication and the per-peer tool policy.
//! See `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
//!
//! Each module is declared by the task that creates it: `auth` in Task 4,
//! `card` in Task 5, `server` in Task 6. Declaring them here now would not
//! compile, because those files do not exist yet.

pub mod policy;

pub use policy::{resolve_allowed_tools, DEFAULT_PEER_TOOLS};
```

> **Note for Tasks 4, 5 and 6:** each must add its own `pub mod <name>;` line and
> any re-exports to `src/a2a/mod.rs` as part of its work. Task 4 adds
> `pub mod auth;` plus `pub use auth::{authenticate, AuthError, PeerIdentity};`,
> Task 5 adds `pub mod card;`, Task 6 adds `pub mod server;`. They are not
> declared up front because the files do not exist yet.

- [ ] **Step 2: Add the module to the crate root**

In `src/lib.rs`, add alongside the other `pub mod` declarations:

```rust
pub mod a2a;
```

- [ ] **Step 3: Write the failing tests**

Create `src/a2a/policy.rs` with only the tests, so it compiles as a failing test:

```rust
//! Per-peer tool policy resolution.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::A2aPeerConfig;

    fn peer(tools: Option<Vec<&str>>) -> A2aPeerConfig {
        A2aPeerConfig {
            token: "t".to_string(),
            ip: vec!["127.0.0.1".to_string()],
            tools: tools.map(|v| v.into_iter().map(String::from).collect()),
        }
    }

    #[test]
    fn default_excludes_execute_command() {
        let resolved = resolve_allowed_tools("p", &peer(None), &all_tool_names());
        assert!(
            !resolved.contains(&"execute_command".to_string()),
            "a peer with no explicit tools list must never receive shell access"
        );
    }

    #[test]
    fn default_excludes_every_privileged_tool() {
        let resolved = resolve_allowed_tools("p", &peer(None), &all_tool_names());
        for forbidden in [
            "execute_command",
            "write_file",
            "send_file",
            "self_upgrade",
            "schedule_task",
            "cancel_scheduled_task",
            "rerun_scheduled_task",
            "try_new_tech",
            "write_skill_file",
            "write_agent_file",
            "update_soul_file",
            "revert_soul_file",
            "patch_skill",
            "invoke_agent",
        ] {
            assert!(
                !resolved.contains(&forbidden.to_string()),
                "{forbidden} must not be in the default peer policy"
            );
        }
    }

    #[test]
    fn default_contains_read_only_tools() {
        let resolved = resolve_allowed_tools("p", &peer(None), &all_tool_names());
        for expected in ["read_file", "list_files", "search_memory", "recall"] {
            assert!(
                resolved.contains(&expected.to_string()),
                "{expected} should be in the default peer policy"
            );
        }
    }

    #[test]
    fn wildcard_alone_expands_to_every_available_tool() {
        let available = all_tool_names();
        let resolved = resolve_allowed_tools("p", &peer(Some(vec!["*"])), &available);
        assert_eq!(resolved.len(), available.len());
        assert!(resolved.contains(&"execute_command".to_string()));
    }

    #[test]
    fn mixed_wildcard_is_not_a_grant_of_every_tool() {
        // Before the wildcard arm required a sole element, this list granted
        // every tool including shell. An operator writing this expects to
        // narrow, so it must not widen.
        let resolved = resolve_allowed_tools("p", &peer(Some(vec!["read_file", "*"])), &all_tool_names());
        assert!(
            !resolved.contains(&"execute_command".to_string()),
            "a mixed wildcard must not grant shell"
        );
    }

    #[test]
    fn default_peer_tools_all_exist_in_the_real_handlers() {
        // The regression guard for renames. DEFAULT_PEER_TOOLS is a
        // hand-maintained list in a different module from the tool
        // definitions, so a rename in `builtin_tools.rs` would silently make
        // an entry inert — no compile error, no test failure, the peer just
        // loses access. This test links the two.
        use crate::builtin_tools::BuiltinTools;
        use crate::memory::MemoryStore;
        use crate::memory_tools::MemoryTools;
        use crate::skill_tools::SkillTools;
        use crate::skills::SkillRegistry;
        use crate::tool_registry::ToolHandler;
        use std::path::PathBuf;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let skills: Arc<RwLock<SkillRegistry>> = Arc::new(RwLock::new(SkillRegistry::new()));
        let agents: Arc<RwLock<SkillRegistry>> = Arc::new(RwLock::new(SkillRegistry::new()));

        let builtin = BuiltinTools::new(
            PathBuf::from("/tmp/haos-green-test/skills"),
            Arc::clone(&skills),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let skill_tools = SkillTools::new(
            PathBuf::from("/tmp/haos-green-test/skills"),
            PathBuf::from("/tmp/haos-green-test/agents"),
            Arc::clone(&skills),
            agents,
        );
        let memory_tools = MemoryTools::new(
            MemoryStore::open_in_memory().expect("in-memory memory store should open"),
        );

        let handlers: [&dyn ToolHandler; 3] = [&builtin, &skill_tools, &memory_tools];
        let mut real_names: Vec<String> = Vec::new();
        for handler in handlers {
            real_names.extend(handler.define().into_iter().map(|d| d.function.name));
        }

        assert!(
            !real_names.is_empty(),
            "collected no tool definitions — the test is not exercising real handlers"
        );

        for expected in DEFAULT_PEER_TOOLS {
            assert!(
                real_names.iter().any(|n| n == expected),
                "DEFAULT_PEER_TOOLS entry `{expected}` is not a tool any real handler defines; \
                 it was probably renamed or removed, which would silently strip the peer's \
                 access to it. Real tool names: {real_names:?}"
            );
        }
    }

    #[test]
    fn explicit_list_is_used_verbatim() {
        let resolved = resolve_allowed_tools("p", &peer(Some(vec!["read_file", "recall"])), &all_tool_names());
        assert_eq!(resolved, vec!["read_file".to_string(), "recall".to_string()]);
    }

    #[test]
    fn explicit_empty_list_grants_nothing() {
        let resolved = resolve_allowed_tools("p", &peer(Some(vec![])), &all_tool_names());
        assert!(
            resolved.is_empty(),
            "Some(vec![]) is an explicit denial, distinct from None"
        );
    }

    #[test]
    fn default_is_an_allowlist_not_a_denylist() {
        // A tool that does not exist today must not be granted to peers by
        // default when it is added later. Resolving against a larger tool set
        // must not leak the new tool into the default policy.
        let mut available = all_tool_names();
        available.push("some_future_dangerous_tool".to_string());
        let resolved = resolve_allowed_tools("p", &peer(None), &available);
        assert!(!resolved.contains(&"some_future_dangerous_tool".to_string()));
    }

    fn all_tool_names() -> Vec<String> {
        vec![
            "execute_command",
            "try_new_tech",
            "self_upgrade",
            "schedule_task",
            "cancel_scheduled_task",
            "list_scheduled_tasks",
            "get_scheduled_task_history",
            "rerun_scheduled_task",
            "read_file",
            "write_file",
            "list_files",
            "send_file",
            "read_soul_file",
            "update_soul_file",
            "revert_soul_file",
            "read_skill_file",
            "write_skill_file",
            "patch_skill",
            "read_agent_file",
            "write_agent_file",
            "reload_skills",
            "reload_agents",
            "remember",
            "recall",
            "search_memory",
            "plan_create",
            "plan_update",
            "plan_view",
            "mock_tool",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test --lib a2a::policy 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'resolve_allowed_tools'` and `cannot find value 'DEFAULT_PEER_TOOLS'`.

- [ ] **Step 5: Write the implementation**

Prepend to `src/a2a/policy.rs`, above the `#[cfg(test)]` block:

```rust
use crate::config::A2aPeerConfig;

/// Tools granted to a peer that declares no `tools` key.
///
/// This is an **allowlist**, deliberately. A tool added to HaosGreen in future is
/// not reachable by any peer until it is added here. A denylist would silently
/// grant every new tool to every peer, which is the failure mode this list
/// exists to prevent.
///
/// # What these entries can actually reach
///
/// None of them executes a process or mutates the agent's own configuration,
/// but "read-only" is not the same as "confined":
///
/// - `read_file` and `list_files` are confined to the sandbox: both route the
///   requested path through `validate_sandbox_path`, which canonicalises the
///   sandbox root and rejects anything that escapes it.
/// - `read_skill_file` and `read_agent_file` read the configured skills and
///   agents directories.
/// - `search_memory` searches the **entire** conversation database — every
///   user, every chat — not a peer-scoped subset.
/// - `recall` reads the global `knowledge` table with no per-peer scoping.
/// - `remember` **writes** to the `knowledge` table in `haos-green.db`. This is
///   the one mutating entry here; it is granted because it is memory-scoped
///   and cannot reach the filesystem, but it is a write.
///
/// # Deliberate exclusions
///
/// `read_soul_file` and `plan_view` are excluded even though both have since
/// been hardened (commits `fe7fe2c` and `e667ccb`): `read_soul_file` now
/// validates `file_name` against a fixed allowlist and refuses symlinks, and
/// the `plan_*` handlers route their resolved path through
/// `validate_sandbox_path`.
///
/// The exclusion is kept as defence in depth, because both remain the most
/// powerful read primitives in the set:
///
/// - `read_soul_file` reads from the HaosGreen **home**, not the sandbox. Its
///   containment rests on a hand-written allowlist plus an `O_NOFOLLOW` open,
///   and anything that regresses either one re-exposes `config.toml` — which
///   holds the OpenRouter API key and every A2A peer bearer token.
/// - `plan_view` reads a path derived from an LLM-supplied `title`. It is
///   contained by validation, but it is a second, weaker path to the same
///   filesystem that `read_file` already covers properly.
///
/// Neither is needed for a peer to do useful work: `read_file` and
/// `list_files` cover the sandbox with a single, well-tested containment
/// check. Keeping the wider primitives out means a future regression in
/// either cannot become a remote credential disclosure.
pub const DEFAULT_PEER_TOOLS: &[&str] = &[
    "read_file",
    "list_files",
    "read_skill_file",
    "read_agent_file",
    "search_memory",
    "recall",
    "remember",
];

/// The wildcard entry meaning "every tool available".
const WILDCARD: &str = "*";

/// Resolve the tool names a peer may invoke.
///
/// - `None` → [`DEFAULT_PEER_TOOLS`]
/// - `Some(["*"])` → every name in `available`, with a warning naming the peer
/// - `Some(list)` → `list` verbatim, including `Some([])` meaning no tools
///
/// `available` is the full set of tool names the runtime exposes. It is
/// consulted for the wildcard case and for reporting requested-but-unknown
/// names; an explicit list is returned as written, so a name that no handler
/// defines simply resolves to a tool the peer can never call.
///
/// # The wildcard must be the sole entry
///
/// `"*"` is honoured only when it is the *only* element of the list. A list
/// that mixes `"*"` with other names — `["read_file", "*"]` — is a
/// configuration error and is treated as an explicit list: the wildcard is
/// ignored and the peer receives only the literal names given. A warning is
/// emitted naming the peer.
///
/// Rationale: the wildcard branch is the most dangerous one, because it grants
/// `execute_command`. Ambiguity there must resolve toward refusing rather than
/// toward granting shell. Silently letting the wildcard win would also mean an
/// explicit narrowing such as `["read_file", "*"]` reads as a restriction while
/// actually being a full grant.
///
/// `peer_name` is used for logging only; it never affects the result.
pub fn resolve_allowed_tools(
    peer_name: &str,
    peer: &A2aPeerConfig,
    available: &[String],
) -> Vec<String> {
    match &peer.tools {
        None => DEFAULT_PEER_TOOLS.iter().map(|s| s.to_string()).collect(),
        Some(list) if list.len() == 1 && list[0].as_str() == WILDCARD => {
            warn!(
                peer = %peer_name,
                tool_count = available.len(),
                "A2A peer declared the \"*\" wildcard as its sole tool entry: granting every \
                 available tool, including shell execution via execute_command"
            );
            available.to_vec()
        }
        Some(list) => {
            if list.iter().any(|t| t.as_str() == WILDCARD) {
                warn!(
                    peer = %peer_name,
                    "\"*\" was listed together with other entries; ignoring the wildcard and \
                     treating the entry as an explicit list, because a mixed wildcard is a \
                     configuration error and must not grant every tool"
                );
            }
            for requested in list {
                if !available.iter().any(|a| a == requested) {
                    warn!(
                        peer = %peer_name,
                        tool = %requested,
                        "A2A peer requested a tool that is not available in this runtime; it \
                         will be ignored"
                    );
                }
            }
            list.clone()
        }
    }
}
```

This block requires `use tracing::warn;` alongside `use crate::config::A2aPeerConfig;` at the
top of the file.

> **Amended during review.** This step originally shipped a 9-entry list including
> `read_soul_file` and `plan_view`, a 2-argument signature, and a wildcard arm
> matching on `any()`. A code-quality review proved that `read_soul_file` returns
> `~/.haos-green/config.toml` (API keys plus every peer token) and that
> `["read_file", "*"]` silently granted shell. The block above is the corrected,
> committed form.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --lib a2a::policy 2>&1 | tail -20`
Expected: PASS, 9 tests.

- [ ] **Step 7: Commit**

```bash
git add src/a2a/mod.rs src/a2a/policy.rs src/lib.rs
git commit -m "feat(a2a): add per-peer tool policy with allowlist default"
```

---

### Task 4: Authentication

**Files:**
- Create: `src/a2a/auth.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/a2a/auth.rs` containing only the tests:

```rust
//! Peer authentication for the A2A listener.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{A2aConfig, A2aPeerConfig};
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn cfg_with(peers: Vec<(&str, &str, Vec<&str>)>) -> A2aConfig {
        let mut map = HashMap::new();
        for (name, token, ips) in peers {
            map.insert(
                name.to_string(),
                A2aPeerConfig {
                    token: token.to_string(),
                    ip: ips.into_iter().map(String::from).collect(),
                    tools: None,
                },
            );
        }
        A2aConfig {
            enabled: true,
            peers: map,
            ..A2aConfig::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn valid_token_and_ip_authenticates() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["192.168.1.0/24"])]);
        let id = authenticate(&cfg, Some("s3cret"), ip("192.168.1.10")).unwrap();
        assert_eq!(id.name, "laptop");
    }

    #[test]
    fn missing_token_is_rejected() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["192.168.1.0/24"])]);
        assert_eq!(
            authenticate(&cfg, None, ip("192.168.1.10")),
            Err(AuthError::MissingToken)
        );
    }

    #[test]
    fn wrong_token_is_rejected() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["192.168.1.0/24"])]);
        assert_eq!(
            authenticate(&cfg, Some("wrong"), ip("192.168.1.10")),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn token_prefix_is_rejected() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["192.168.1.0/24"])]);
        assert_eq!(
            authenticate(&cfg, Some("s3cre"), ip("192.168.1.10")),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn correct_token_from_wrong_ip_is_rejected() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["192.168.1.0/24"])]);
        assert_eq!(
            authenticate(&cfg, Some("s3cret"), ip("10.0.0.1")),
            Err(AuthError::IpNotAllowed)
        );
    }

    #[test]
    fn exact_ip_match_works() {
        let cfg = cfg_with(vec![("buildbox", "t", vec!["10.8.0.4"])]);
        let id = authenticate(&cfg, Some("t"), ip("10.8.0.4")).unwrap();
        assert_eq!(id.name, "buildbox");
    }

    #[test]
    fn empty_peer_map_rejects_everyone() {
        let cfg = cfg_with(vec![]);
        assert_eq!(
            authenticate(&cfg, Some("anything"), ip("127.0.0.1")),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn peer_with_empty_ip_list_rejects_everyone() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec![])]);
        assert_eq!(
            authenticate(&cfg, Some("s3cret"), ip("192.168.1.10")),
            Err(AuthError::IpNotAllowed)
        );
    }

    #[test]
    fn empty_configured_token_never_authenticates() {
        // `parse_bearer` trims, so `Authorization: Bearer ` yields `Some("")`.
        // Were an empty configured token accepted, that would authenticate any
        // client from an allowlisted address — the guard in `authenticate`
        // exists precisely to prevent this.
        let cfg = cfg_with(vec![("laptop", "", vec!["192.168.1.0/24"])]);
        assert_eq!(
            authenticate(&cfg, Some(""), ip("192.168.1.10")),
            Err(AuthError::InvalidToken)
        );
    }

    #[test]
    fn duplicate_tokens_are_rejected_as_ambiguous() {
        // Two peers sharing a token would make the applied `ip` allowlist and
        // `tools` policy depend on `HashMap` iteration order, which is
        // randomized per process. One peer could silently inherit the other's
        // policy — potentially `["*"]`, which includes shell.
        let cfg = cfg_with(vec![
            ("laptop", "shared", vec!["192.168.1.0/24"]),
            ("buildbox", "shared", vec!["10.0.0.0/8"]),
        ]);
        assert_eq!(
            authenticate(&cfg, Some("shared"), ip("192.168.1.10")),
            Err(AuthError::AmbiguousToken)
        );
    }

    #[test]
    fn unparseable_ip_entry_does_not_grant_access() {
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["not-an-ip"])]);
        assert_eq!(
            authenticate(&cfg, Some("s3cret"), ip("192.168.1.10")),
            Err(AuthError::IpNotAllowed)
        );
    }

    #[test]
    fn ipv6_cidr_matches() {
        let cfg = cfg_with(vec![("laptop", "t", vec!["fd00::/8"])]);
        let id = authenticate(&cfg, Some("t"), ip("fd00::1")).unwrap();
        assert_eq!(id.name, "laptop");
    }

    #[test]
    fn ipv4_mapped_ipv6_does_not_match_an_ipv4_allowlist() {
        // `ipnet`'s `Contains<&IpAddr> for IpNet` only compares same-family
        // addresses (ipnet-2.12.1/src/ipnet.rs:1418): an `Ipv4Net` never
        // matches an `IpAddr::V6`, even for a v4-mapped address. This fails
        // CLOSED, so it is not a bypass — but on a dual-stack listener an
        // otherwise-allowed peer is refused with a bare 403 and no obvious
        // cause.
        //
        // This test pins the current behaviour deliberately. If dual-stack
        // support becomes a requirement, the fix is to normalise
        // `IpAddr::V6` v4-mapped addresses (`::ffff:a.b.c.d`) to `IpAddr::V4`
        // before matching, and this test must be inverted.
        let cfg = cfg_with(vec![("laptop", "s3cret", vec!["192.168.1.0/24"])]);
        assert_eq!(
            authenticate(&cfg, Some("s3cret"), ip("::ffff:192.168.1.10")),
            Err(AuthError::IpNotAllowed)
        );
    }

    #[test]
    fn identity_carries_resolved_tools() {
        let cfg = cfg_with(vec![("laptop", "t", vec!["10.0.0.1"])]);
        let id = authenticate(&cfg, Some("t"), ip("10.0.0.1")).unwrap();
        assert!(
            !id.allowed_tools.contains(&"execute_command".to_string()),
            "a default peer must not get shell"
        );
        assert!(id.allowed_tools.contains(&"read_file".to_string()));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib a2a::auth 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'authenticate'`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/a2a/auth.rs`:

```rust
use crate::config::A2aConfig;
use ipnet::IpNet;
use std::net::IpAddr;
use subtle::ConstantTimeEq;

/// Why a request was refused. Every variant is a denial — there is no
/// "allowed" variant, because success is represented by `Ok(PeerIdentity)`.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization: Bearer <token>` header was present.
    MissingToken,
    /// The token matched no configured peer, or matched a peer whose
    /// configured token is empty.
    InvalidToken,
    /// More than one peer entry carries the same token.
    ///
    /// `peers` is a `HashMap`, whose iteration order is randomized per
    /// process. With a duplicate token, which peer's `ip` allowlist and
    /// `tools` policy apply would vary between runs — so one peer could
    /// silently inherit another's policy, potentially `["*"]`. Denying is the
    /// only safe response.
    AmbiguousToken,
    /// The token matched a peer, but the source address is not in that peer's
    /// allowlist.
    IpNotAllowed,
}

/// An authenticated peer and the policy resolved for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub name: String,
    pub allowed_tools: Vec<String>,
}

/// Authenticate a request against the configured peers.
///
/// Both the token and the source address must match the *same* peer entry.
/// A valid token from an address outside that peer's allowlist is refused
/// rather than downgraded.
///
/// This function is fail-closed: any condition not explicitly satisfied —
/// absent header, unknown token, unparseable allowlist entry, empty peer map —
/// results in an error.
pub fn authenticate(
    cfg: &A2aConfig,
    bearer: Option<&str>,
    source_ip: IpAddr,
) -> Result<PeerIdentity, AuthError> {
    let token = bearer.ok_or(AuthError::MissingToken)?;

    // Compare against every peer without early exit so the number of
    // comparisons does not reveal which peer matched.
    //
    // An empty configured token is never accepted. `parse_bearer` trims, so
    // `Authorization: Bearer ` reduces to `Some("")`; without this guard an
    // empty configured token would authenticate any client from an
    // allowlisted address.
    let mut matched: Option<(&str, &crate::config::A2aPeerConfig)> = None;
    let mut matches = 0usize;
    for (name, peer) in &cfg.peers {
        if !peer.token.is_empty() && constant_time_eq(token, &peer.token) {
            matches += 1;
            matched = Some((name.as_str(), peer));
        }
    }

    // Two peers sharing a token would make the applied `ip` allowlist and
    // `tools` policy depend on `HashMap` iteration order, which is randomized
    // per process. Refuse rather than pick one arbitrarily.
    if matches > 1 {
        return Err(AuthError::AmbiguousToken);
    }

    let (matched_name, peer) = matched.ok_or(AuthError::InvalidToken)?;

    if !ip_allowed(source_ip, &peer.ip) {
        return Err(AuthError::IpNotAllowed);
    }

    // Resolved here against an EMPTY `available` set; the caller MUST
    // re-resolve against the live tool registry before using it.
    //
    // With `available = &[]` the three cases collapse to: `None` → the default
    // allowlist (the case we want for the identity record); `Some(list)` →
    // `list` verbatim; `Some(["*"])` → `[]`, NOT every tool. So this provisional
    // `allowed_tools` is only correct for the default peer — for a wildcard
    // peer it under-reports and must be recomputed by the caller. Treat it as a
    // placeholder, never as the final policy.
    let allowed_tools = crate::a2a::policy::resolve_allowed_tools(matched_name, peer, &[]);

    Ok(PeerIdentity {
        name: matched_name.to_string(),
        allowed_tools,
    })
}

/// Constant-time string comparison.
///
/// Length is compared first, which leaks the token length through timing. That
/// is accepted here: the token length is a fixed configuration property, not a
/// secret, and an attacker learning it gains no advantage over guessing the
/// contents.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// True when `ip` matches any entry, each either an exact address
/// (`10.0.0.5`) or a CIDR block (`192.168.1.0/24`, `fd00::/8`).
///
/// An entry that parses as neither is ignored rather than treated as a
/// wildcard, so a typo in `config.toml` cannot accidentally open the endpoint.
fn ip_allowed(ip: IpAddr, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        if let Ok(net) = p.parse::<IpNet>() {
            net.contains(&ip)
        } else if let Ok(single) = p.parse::<IpAddr>() {
            single == ip
        } else {
            false
        }
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib a2a::auth 2>&1 | tail -20`
Expected: PASS, 14 tests.

- [ ] **Step 5: Commit**

```bash
git add src/a2a/auth.rs
git commit -m "feat(a2a): add fail-closed peer authentication"
```

---

### Task 5: Agent Card generation

**Files:**
- Create: `src/a2a/card.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/a2a/card.rs` with tests only:

```rust
//! Agent Card generation from the loaded skill registry.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::A2aCardConfig;
    use crate::skills::{Skill, SkillRegistry};
    use std::path::PathBuf;

    fn skill(name: &str, description: &str, tags: &[&str]) -> Skill {
        Skill {
            name: name.to_string(),
            description: description.to_string(),
            content: String::new(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            model: None,
            tools: Vec::new(),
            max_iterations: None,
            skip_bootstrap: false,
            supervisor_workflow: None,
            supervisor_required_caps: Vec::new(),
        }
    }

    fn registry(skills: Vec<Skill>) -> SkillRegistry {
        let mut reg = SkillRegistry::new();
        for s in skills {
            reg.register(s, PathBuf::from("/tmp"));
        }
        reg
    }

    fn cfg() -> A2aCardConfig {
        A2aCardConfig {
            name: "HaosGreen".to_string(),
            description: "Self-hosted assistant".to_string(),
            version: "1.0.2".to_string(),
        }
    }

    #[test]
    fn card_carries_configured_identity() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        assert_eq!(card.name, "HaosGreen");
        assert_eq!(card.description, "Self-hosted assistant");
        assert_eq!(card.version, "1.0.2");
    }

    #[test]
    fn card_declares_the_jsonrpc_interface() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        assert_eq!(card.supported_interfaces.len(), 1);
        let iface = &card.supported_interfaces[0];
        assert_eq!(iface.url, "http://localhost:8443");
        assert_eq!(iface.protocol_binding, "JSONRPC");
        assert!(!iface.protocol_version.is_empty());
    }

    #[test]
    fn skills_are_mapped_from_the_registry() {
        let reg = registry(vec![
            skill("news-fetcher", "Fetches AI news", &["news", "gmail"]),
            skill("thread-writer", "Writes threads", &["writing"]),
        ]);
        let card = build_agent_card(&cfg(), &reg, "http://localhost:8443");
        assert_eq!(card.skills.len(), 2);
        let ids: Vec<&str> = card.skills.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"news-fetcher"));
        assert!(ids.contains(&"thread-writer"));
    }

    #[test]
    fn skill_fields_are_copied() {
        let reg = registry(vec![skill("news-fetcher", "Fetches AI news", &["news"])]);
        let card = build_agent_card(&cfg(), &reg, "http://localhost:8443");
        let s = &card.skills[0];
        assert_eq!(s.id, "news-fetcher");
        assert_eq!(s.name, "news-fetcher");
        assert_eq!(s.description, "Fetches AI news");
        assert_eq!(s.tags, vec!["news".to_string()]);
    }

    #[test]
    fn skill_without_tags_is_not_dropped() {
        let reg = registry(vec![skill("bare", "No tags here", &[])]);
        let card = build_agent_card(&cfg(), &reg, "http://localhost:8443");
        assert_eq!(card.skills.len(), 1, "a tagless skill must still be advertised");
        assert!(card.skills[0].tags.is_empty());
    }

    #[test]
    fn empty_registry_yields_empty_skills_not_an_error() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        assert!(card.skills.is_empty());
    }

    #[test]
    fn card_declares_bearer_security_scheme() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        let schemes = card.security_schemes.as_ref().expect("schemes required");
        assert!(
            schemes.contains_key("bearer"),
            "clients must be told the endpoint requires a bearer token"
        );
    }

    #[test]
    fn card_serialises_with_camel_case_keys() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        let json = serde_json::to_value(&card).unwrap();
        assert!(json.get("supportedInterfaces").is_some());
        assert!(json.get("defaultInputModes").is_some());
        assert!(json.get("supported_interfaces").is_none());
    }

    #[test]
    fn card_round_trips_through_serde() {
        let card = build_agent_card(
            &cfg(),
            &registry(vec![skill("a", "desc", &["t"])]),
            "http://localhost:8443",
        );
        let json = serde_json::to_string(&card).unwrap();
        let back: a2a::agent_card::AgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, back);
    }
}
```

The `Skill` struct has exactly these 10 fields, verified at `src/skills/mod.rs:27-50`: `name`, `description`, `content`, `tags`, `model`, `tools`, `max_iterations`, `skip_bootstrap`, `supervisor_workflow`, `supervisor_required_caps`. The helper above constructs all of them.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib a2a::card 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'build_agent_card'`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/a2a/card.rs`:

```rust
use crate::config::A2aCardConfig;
use crate::skills::SkillRegistry;
use a2a::agent_card::{
    AgentCapabilities, AgentCard, AgentInterface, AgentSkill, HttpAuthSecurityScheme,
    SecurityScheme,
};
use std::collections::HashMap;

/// The protocol binding string for the JSON-RPC transport.
const BINDING_JSONRPC: &str = "JSONRPC";

/// Build the Agent Card advertised at `/.well-known/agent-card.json`.
///
/// Every skill in `registry` becomes an advertised skill. Skills are advertised
/// by metadata only — the instruction body is never included, so the card does
/// not leak prompt content to an unauthenticated caller. The card endpoint is
/// intentionally public: A2A clients fetch it before they authenticate.
pub fn build_agent_card(
    cfg: &A2aCardConfig,
    registry: &SkillRegistry,
    endpoint_url: &str,
) -> AgentCard {
    let mut schemes = HashMap::new();
    schemes.insert(
        "bearer".to_string(),
        SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
            scheme: "Bearer".to_string(),
            description: Some("Static per-peer bearer token".to_string()),
            bearer_format: None,
        }),
    );

    AgentCard {
        name: cfg.name.clone(),
        description: cfg.description.clone(),
        version: cfg.version.clone(),
        supported_interfaces: vec![AgentInterface::new(endpoint_url, BINDING_JSONRPC)],
        capabilities: AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            ..AgentCapabilities::default()
        },
        default_input_modes: vec!["text/plain".to_string()],
        default_output_modes: vec!["text/plain".to_string()],
        skills: registry
            .list()
            .into_iter()
            .map(|s| AgentSkill {
                id: s.name.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
                tags: s.tags.clone(),
                examples: None,
                input_modes: None,
                output_modes: None,
                security_requirements: None,
            })
            .collect(),
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: Some(schemes),
        security_requirements: None,
        signatures: None,
    }
}
```

`streaming: Some(false)` is deliberate for Phase 1 — SSE arrives in Phase 4, and advertising a capability that is not implemented would mislead clients.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib a2a::card 2>&1 | tail -20`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add src/a2a/card.rs
git commit -m "feat(a2a): generate Agent Card from skill registry"
```

---

### Task 6: The HTTP listener

**Files:**
- Create: `src/a2a/server.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/a2a/server.rs` with tests only:

```rust
//! A2A HTTP listener.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{A2aCardConfig, A2aConfig, A2aPeerConfig};
    use crate::skills::SkillRegistry;
    use std::collections::HashMap;

    fn test_config() -> A2aConfig {
        let mut peers = HashMap::new();
        peers.insert(
            "laptop".to_string(),
            A2aPeerConfig {
                token: "s3cret".to_string(),
                ip: vec!["127.0.0.0/8".to_string()],
                tools: None,
            },
        );
        A2aConfig {
            enabled: true,
            bind: "127.0.0.1:0".to_string(),
            card: A2aCardConfig::default(),
            peers,
            ..A2aConfig::default()
        }
    }

    #[test]
    fn parse_bearer_extracts_the_token() {
        assert_eq!(parse_bearer(Some("Bearer s3cret")), Some("s3cret"));
    }

    #[test]
    fn parse_bearer_is_case_insensitive_on_the_scheme() {
        assert_eq!(parse_bearer(Some("bearer s3cret")), Some("s3cret"));
    }

    #[test]
    fn parse_bearer_rejects_a_missing_scheme() {
        assert_eq!(parse_bearer(Some("s3cret")), None);
    }

    #[test]
    fn parse_bearer_rejects_a_different_scheme() {
        assert_eq!(parse_bearer(Some("Basic s3cret")), None);
    }

    #[test]
    fn parse_bearer_handles_absence() {
        assert_eq!(parse_bearer(None), None);
    }

    #[test]
    fn parse_bearer_trims_surrounding_whitespace() {
        assert_eq!(parse_bearer(Some("Bearer  s3cret ")), Some("s3cret"));
    }

    #[test]
    fn router_builds_without_panicking() {
        let state = build_state(test_config(), SkillRegistry::new(), "http://localhost:8443");
        let _router = router(state);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib a2a::server 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'parse_bearer'`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/a2a/server.rs`:

```rust
use crate::a2a::auth::{authenticate, AuthError};
use crate::a2a::card::build_agent_card;
use crate::config::A2aConfig;
use crate::skills::SkillRegistry;
use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

/// Shared state for the A2A listener.
pub struct A2aState {
    pub config: A2aConfig,
    pub skills: SkillRegistry,
    pub endpoint_url: String,
}

/// Build the shared listener state.
pub fn build_state(
    config: A2aConfig,
    skills: SkillRegistry,
    endpoint_url: &str,
) -> Arc<A2aState> {
    Arc::new(A2aState {
        config,
        skills,
        endpoint_url: endpoint_url.to_string(),
    })
}

/// Build the A2A router.
///
/// `/.well-known/agent-card.json` is public by design — A2A clients fetch the
/// card before authenticating. Every other route requires a valid peer.
pub fn router(state: Arc<A2aState>) -> Router {
    Router::new()
        .route("/.well-known/agent-card.json", get(agent_card_handler))
        .route("/jsonrpc", post(jsonrpc_handler))
        .with_state(state)
}

/// Serve the Agent Card. Public, unauthenticated.
async fn agent_card_handler(State(state): State<Arc<A2aState>>) -> impl IntoResponse {
    let card = build_agent_card(&state.config.card, &state.skills, &state.endpoint_url);
    Json(card)
}

/// JSON-RPC endpoint. Phase 1 authenticates and then refuses, because no
/// executor exists yet. Returning 501 rather than 200 is deliberate: a client
/// must not believe a task was accepted.
async fn jsonrpc_handler(
    State(state): State<Arc<A2aState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_bearer(Some(v)));

    match authenticate(&state.config, bearer, addr.ip()) {
        Ok(identity) => {
            info!(
                peer = %identity.name,
                tools = identity.allowed_tools.len(),
                "A2A peer authenticated; no executor implemented yet (Phase 2)"
            );
            (
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": "No A2A method is implemented yet"
                    }
                })),
            )
        }
        Err(AuthError::MissingToken) => {
            warn!(peer_ip = %addr.ip(), "A2A request without a bearer token");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
        }
        Err(AuthError::InvalidToken) => {
            warn!(peer_ip = %addr.ip(), "A2A request with an unknown token");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
        }
        Err(AuthError::AmbiguousToken) => {
            // Misconfiguration, not a client error: two peers share a token.
            // 500 is deliberate so it shows up as a server-side fault rather
            // than being mistaken for a bad credential.
            warn!(
                peer_ip = %addr.ip(),
                "A2A request refused: two peers share the same token"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({})))
        }
        Err(AuthError::IpNotAllowed) => {
            warn!(peer_ip = %addr.ip(), "A2A peer authenticated from a disallowed address");
            (StatusCode::FORBIDDEN, Json(serde_json::json!({})))
        }
    }
}

/// Extract the token from an `Authorization: Bearer <token>` header value.
fn parse_bearer(header: Option<&str>) -> Option<&str> {
    let value = header?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Start the A2A listener. Returns once the listener is bound; the serving
/// task runs in the background.
///
/// The bind address is resolved before spawning so a configuration error
/// surfaces at startup rather than silently inside a detached task.
pub async fn spawn(state: Arc<A2aState>) -> Result<()> {
    let addr = state.config.bind.clone();
    let app = router(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("A2A: failed to bind {addr}"))?;

    let local = listener
        .local_addr()
        .context("A2A: could not read the bound address")?;

    info!(address = %local, "A2A listener started");

    tokio::spawn(async move {
        // `into_make_service_with_connect_info` is required for the
        // `ConnectInfo<SocketAddr>` extractor the auth path depends on.
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            warn!(error = %e, "A2A listener stopped with an error");
        }
    });

    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib a2a::server 2>&1 | tail -20`
Expected: PASS, 7 tests.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -- -D warnings 2>&1 | tail -20`
Expected: no warnings. The project treats warnings as errors in CI.

- [ ] **Step 6: Commit**

```bash
git add src/a2a/server.rs
git commit -m "feat(a2a): add authenticated HTTP listener"
```

---

### Task 7: Wire into startup

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Spawn the listener when enabled**

In `src/main.rs`, locate where the supervisor backends and scheduler are wired (before `platform::telegram::run`). Add:

```rust
    // A2A listener (Phase 1: Agent Card + authentication only).
    if config.a2a.enabled {
        let endpoint_url = format!("http://{}", config.a2a.bind);
        let a2a_state = haos-green::a2a::server::build_state(
            config.a2a.clone(),
            a2a_skills,
            &endpoint_url,
        );
        if let Err(e) = haos-green::a2a::server::spawn(a2a_state).await {
            // A misconfigured A2A listener must not prevent the Telegram bot
            // from starting; log loudly and continue.
            tracing::error!(error = %e, "A2A listener failed to start");
        }
    } else {
        tracing::debug!("A2A disabled");
    }
```

**As implemented:** `main.rs` owns the loaded registry as `skills` (line 185) and moves it
into `Agent::new(...)` (line 253), so the listener takes a clone captured before that
move — `let a2a_skills = skills.clone();` next to the other `skills.clone()` calls around
line 213. The block above sits after the supervisor wiring and before
`info!("Bot is starting...")`.

> **Known limitation (found in final review).** `format!("http://{}", config.a2a.bind)`
> advertises the raw bind string. With `bind = "0.0.0.0:8443"` — the obvious LAN
> setting — the card tells a remote peer to connect to `http://0.0.0.0:8443`, which
> resolves to *that peer's own loopback*. With port `0` it advertises port `0` even
> though `spawn()` knows the real bound port and discards it. A `[a2a].public_url`
> config key and using `listener.local_addr()` are the fix; see the final review
> follow-up commit.

`endpoint_url` uses `http://` because Phase 1 has no TLS. Phase 3 (TLS) must update this to `https://` when `[a2a].tls` is enabled, otherwise the advertised interface will not match the actual transport.

- [ ] **Step 2: Verify it compiles**

Run: `cargo check 2>&1 | tail -20`
Expected: `Finished`.

- [ ] **Step 3: Verify the full test suite still passes**

Run: `cargo test 2>&1 | tail -30`
Expected: all tests pass, including the pre-existing ones. No regressions.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(a2a): start the listener when a2a is enabled"
```

---

### Task 8: End-to-end verification against a live listener

**Files:**
- Test: `tests/a2a_endpoint.rs`

This is the only task that exercises real HTTP. It proves success criteria 1 and 3.

- [ ] **Step 1: Write the integration test**

Create `tests/a2a_endpoint.rs`:

```rust
//! End-to-end checks for the A2A listener: the card is public, everything
//! else is refused without a valid peer.

use haos-green::a2a::server::{build_state, router};
use haos-green::config::{A2aCardConfig, A2aConfig, A2aPeerConfig};
use haos-green::skills::SkillRegistry;
use std::collections::HashMap;

fn config() -> A2aConfig {
    let mut peers = HashMap::new();
    peers.insert(
        "laptop".to_string(),
        A2aPeerConfig {
            token: "s3cret".to_string(),
            ip: vec!["127.0.0.0/8".to_string()],
            tools: None,
        },
    );
    A2aConfig {
        enabled: true,
        bind: "127.0.0.1:0".to_string(),
        card: A2aCardConfig {
            name: "HaosGreen".to_string(),
            description: "test".to_string(),
            version: "1.0.2".to_string(),
        },
        peers,
        ..A2aConfig::default()
    }
}

/// Bind an ephemeral port and return its base URL plus a shutdown handle.
async fn start() -> (String, tokio::task::JoinHandle<()>) {
    let state = build_state(config(), SkillRegistry::new(), "http://placeholder");
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn agent_card_is_public() {
    let (base, handle) = start().await;
    let resp = reqwest::get(format!("{base}/.well-known/agent-card.json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the card must be fetchable without auth");

    let card: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(card["name"], "HaosGreen");
    assert!(card["supportedInterfaces"].is_array());
    assert!(card["securitySchemes"]["bearer"].is_object());
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_without_token_is_401() {
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_with_bad_token_is_401() {
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("wrong")
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    handle.abort();
}

#[tokio::test]
async fn jsonrpc_with_valid_token_reaches_the_handler() {
    let (base, handle) = start().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/jsonrpc"))
        .bearer_auth("s3cret")
        .json(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "message/send"}))
        .send()
        .await
        .unwrap();
    // 501, not 200: authenticated, but no executor exists in Phase 1. A 200
    // here would mean a client believes a task was accepted when it was not.
    assert_eq!(resp.status(), 501);
    handle.abort();
}
```

`reqwest` is already a dependency; if it is not available to integration tests, add it under `[dev-dependencies]`.

- [ ] **Step 2: Run the integration test**

Run: `cargo test --test a2a_endpoint 2>&1 | tail -30`
Expected: PASS, 4 tests.

- [ ] **Step 3: Confirm the fail-closed behaviour by hand**

Run the bot with A2A enabled and an empty peer map, then:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/.well-known/agent-card.json
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8443/jsonrpc
```

Expected: `200` then `401`. The card is public; the RPC endpoint refuses everyone when no peers are configured.

- [ ] **Step 4: Commit**

```bash
git add tests/a2a_endpoint.rs
git commit -m "test(a2a): verify card is public and rpc is fail-closed"
```

---

## Self-Review

**Spec coverage.** Mapping each Phase 1 spec item to a task:

| Spec item | Task |
|---|---|
| §4 `card.rs` — `AgentCardProducer` from skills | 5 |
| §4 `auth.rs` — bearer + IP allowlist, fail-closed | 4 |
| §4 `policy.rs` — peer → `allowed_tools`, `*` | 3 |
| §4 `server.rs` — axum listener, bind | 6 |
| §4 `mod.rs` — facade, wiring | 3, 7 |
| §6 bind default `127.0.0.1` | 2 |
| §6 bearer per peer, 401/403 | 4, 6, 8 |
| §6 IP allowlist per peer | 4 |
| §6 tool policy, conservative default | 3 |
| §5 `PRAGMA busy_timeout` | **not covered — deferred to Phase 2**, where the task store is written |
| §8 config schema | 2 |
| §Implementation Phases row 1 | all |
| Success criterion 1 | 8 |
| Success criterion 3 | 4, 6, 8 |

Deliberately deferred to later phases: `max_concurrent_tasks` is parsed in Task 2 but unused until Phase 3, where the semaphore is built. Parsing it now keeps the config schema stable so operators do not have to edit `config.toml` twice.

**Placeholder scan.** No `TBD`, `TODO`, or "handle edge cases" steps. Every code step contains the full code.

Two defects were found and fixed during this review, both of which would have failed to compile:

1. **`Config::default()` did not exist.** Task 2's tests originally called it. `src/config.rs` has no `impl Default for Config`. Replaced with a `minimal_config()` helper that parses a TOML containing the three required fields — `telegram.bot_token`, `telegram.allowed_user_ids`, `openrouter.api_key`. The two peer tests were also parsing TOML fragments that lacked those required sections, so they would have failed at `toml::from_str`; both now include them.
2. **Wrong `Skill` field name.** Task 5's `skill()` helper set `supervisor: None`. The struct has no such field — the real ones are `supervisor_workflow: Option<String>` and `supervisor_required_caps: Vec<String>` (`src/skills/mod.rs:45-48`). Fixed, and the count is now stated as 10 fields.

One adaptation note remains, in Task 7 Step 1: the name of the in-scope `SkillRegistry` binding in `main.rs` depends on the surrounding code. The step names the exact `grep` command to find it.

**Lint constraint.** `src/lib.rs` begins with `#![deny(dead_code)]`, so unused items are hard errors, not warnings. Everything added by this plan is either `pub` (reachable by definition) or a private helper called by a `pub` function, so the lint is satisfied. Worth knowing because `max_concurrent_tasks` is parsed in Task 2 but not read until Phase 3 — this is safe only because it is a `pub` field of a `pub` struct. If it were private, `deny(dead_code)` would reject it.

**Type consistency.** Verified across tasks:

- `resolve_allowed_tools(&str, &A2aPeerConfig, &[String]) -> Vec<String>` — defined Task 3, called Task 4 Step 3.
- `DEFAULT_PEER_TOOLS: &[&str]` — defined Task 3, re-exported in `mod.rs`.
- `authenticate(&A2aConfig, Option<&str>, IpAddr) -> Result<PeerIdentity, AuthError>` — defined Task 4, called Task 6 Step 3.
- `AuthError` variants `MissingToken` / `InvalidToken` / `AmbiguousToken` / `IpNotAllowed` — defined Task 4, matched exhaustively in Task 6 Step 3.
- `PeerIdentity { name, allowed_tools }` — defined Task 4, read in Task 6.
- `build_agent_card(&A2aCardConfig, &SkillRegistry, &str) -> AgentCard` — defined Task 5, called Task 6 Step 3.
- `build_state(A2aConfig, SkillRegistry, &str) -> Arc<A2aState>` — defined Task 6, called Tasks 7 and 8.
- `router(Arc<A2aState>) -> Router` — defined Task 6, called Tasks 6 and 8.
- `parse_bearer(Option<&str>) -> Option<&str>` — defined Task 6, tested Task 6.
- `spawn(Arc<A2aState>) -> Result<()>` — defined Task 6, called Task 7.

All `a2a` crate types used (`AgentCard`, `AgentSkill`, `AgentInterface`, `AgentCapabilities`, `HttpAuthSecurityScheme`, `SecurityScheme`) were confirmed against the published `a2a-lf` 0.3.1 source, including `AgentInterface::new(url, binding)` and `AgentCapabilities: Default`.

**Known gap.** `A2aConfig` derives `Deserialize` but not `Clone`, while Task 7 calls `config.a2a.clone()`. Task 2 must add `Clone` to the derive list on `A2aConfig`, `A2aCardConfig` and `A2aPeerConfig`. Corrected in the Task 2 code above — all three derive `Debug, Clone, Deserialize`.
