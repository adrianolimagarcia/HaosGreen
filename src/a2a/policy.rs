//! Per-peer tool policy resolution.

use crate::config::A2aPeerConfig;
use tracing::warn;

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
///
/// A peer that authenticates over A2A can drive an agent holding
/// `execute_command`, so this default must never widen the blast radius beyond
/// the sandbox and the shared memory store.
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
                        "A2A peer requested a tool that is not available in this runtime; the \
                         peer will not be able to call it"
                    );
                }
            }
            list.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::A2aPeerConfig;

    /// Peer name used by every test below; the function only logs it.
    const PEER: &str = "test-peer";

    fn peer(tools: Option<Vec<&str>>) -> A2aPeerConfig {
        A2aPeerConfig {
            token: "t".to_string(),
            ip: vec!["127.0.0.1".to_string()],
            tools: tools.map(|v| v.into_iter().map(String::from).collect()),
        }
    }

    #[test]
    fn default_excludes_execute_command() {
        let resolved = resolve_allowed_tools(PEER, &peer(None), &all_tool_names());
        assert!(
            !resolved.contains(&"execute_command".to_string()),
            "a peer with no explicit tools list must never receive shell access"
        );
    }

    #[test]
    fn default_excludes_every_privileged_tool() {
        let resolved = resolve_allowed_tools(PEER, &peer(None), &all_tool_names());
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
            "call_a2a_agent",
            // Both of these can read outside the sandbox: read_soul_file
            // reaches the HaosGreen home (config.toml holds the API key and the
            // peer tokens) and accepts an unvalidated file name; plan_view
            // joins an unvalidated title onto the plans directory, and an
            // absolute title discards the prefix.
            "read_soul_file",
            "plan_view",
        ] {
            assert!(
                !resolved.contains(&forbidden.to_string()),
                "{forbidden} must not be in the default peer policy"
            );
        }
    }

    #[test]
    fn default_contains_read_only_tools() {
        let resolved = resolve_allowed_tools(PEER, &peer(None), &all_tool_names());
        for expected in ["read_file", "list_files", "search_memory", "recall"] {
            assert!(
                resolved.contains(&expected.to_string()),
                "{expected} should be in the default peer policy"
            );
        }

        // These two are available in the runtime (see `all_tool_names`) but
        // must not be reachable by default: both read outside the sandbox.
        for out_of_sandbox in ["read_soul_file", "plan_view"] {
            assert!(
                !resolved.contains(&out_of_sandbox.to_string()),
                "{out_of_sandbox} can read outside the sandbox and must not be granted by default"
            );
        }
    }

    #[test]
    fn wildcard_alone_expands_to_every_available_tool() {
        let available = all_tool_names();
        let resolved = resolve_allowed_tools(PEER, &peer(Some(vec!["*"])), &available);
        assert_eq!(resolved.len(), available.len());
        assert!(resolved.contains(&"execute_command".to_string()));
    }

    #[test]
    fn mixed_wildcard_is_not_a_grant_of_every_tool() {
        // `["read_file", "*"]` reads as a narrowing but must never behave as a
        // full grant: the wildcard is ignored because it is not the sole entry.
        let available = all_tool_names();
        let resolved = resolve_allowed_tools(PEER, &peer(Some(vec!["read_file", "*"])), &available);
        assert!(
            !resolved.contains(&"execute_command".to_string()),
            "a wildcard mixed with other names must not grant shell access"
        );
        assert!(
            resolved.len() < available.len(),
            "a mixed wildcard must not expand to the whole tool set"
        );
        assert_eq!(resolved, vec!["read_file".to_string(), "*".to_string()]);
    }

    #[test]
    fn explicit_list_is_used_verbatim() {
        let resolved = resolve_allowed_tools(
            PEER,
            &peer(Some(vec!["read_file", "recall"])),
            &all_tool_names(),
        );
        assert_eq!(
            resolved,
            vec!["read_file".to_string(), "recall".to_string()]
        );
    }

    #[test]
    fn explicit_empty_list_grants_nothing() {
        let resolved = resolve_allowed_tools(PEER, &peer(Some(vec![])), &all_tool_names());
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
        let resolved = resolve_allowed_tools(PEER, &peer(None), &available);
        assert!(!resolved.contains(&"some_future_dangerous_tool".to_string()));
    }

    /// Regression guard against silent renames.
    ///
    /// `DEFAULT_PEER_TOOLS` is a list of strings matched against tool names at
    /// dispatch time. Renaming a tool (in its `define()` and its dispatch arm)
    /// leaves this list compiling and every other test green, while the peer
    /// silently loses — or, worse, keeps — access depending on the direction of
    /// the rename. So the list is checked against the names the real handlers
    /// actually advertise.
    ///
    /// Scope, stated precisely: this asserts `DEFAULT_PEER_TOOLS ⊆ real_names`.
    /// It therefore fires when a *handler* renames or drops a tool that the
    /// default still names. It cannot fire when an entry is deleted from
    /// `DEFAULT_PEER_TOOLS` itself — that shrinks the left-hand set and keeps
    /// the assertion true — which is why the entries that must stay granted are
    /// also pinned by `default_contains_read_only_tools` and
    /// `default_excludes_every_privileged_tool`. Deleting an entry here is a
    /// deliberate edit to this file, visible in review, not a silent rename.
    #[test]
    fn default_peer_tools_all_exist_in_the_real_handlers() {
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
            "call_a2a_agent",
            "mock_tool",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
}
