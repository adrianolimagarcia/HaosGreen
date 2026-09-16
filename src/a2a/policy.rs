//! Per-peer tool policy resolution.

use crate::config::A2aPeerConfig;

/// Tools granted to a peer that declares no `tools` key.
///
/// This is an **allowlist**, deliberately. A tool added to RustFox in future is
/// not reachable by any peer until it is added here. A denylist would silently
/// grant every new tool to every peer, which is the failure mode this list
/// exists to prevent.
///
/// Every entry is read-only or memory-scoped. Nothing here writes to disk,
/// executes a process, or mutates the agent's own configuration.
pub const DEFAULT_PEER_TOOLS: &[&str] = &[
    "read_file",
    "list_files",
    "read_soul_file",
    "read_skill_file",
    "read_agent_file",
    "search_memory",
    "recall",
    "remember",
    "plan_view",
];

/// The wildcard entry meaning "every tool available".
const WILDCARD: &str = "*";

/// Resolve the tool names a peer may invoke.
///
/// - `None` → [`DEFAULT_PEER_TOOLS`]
/// - `Some(["*"])` → every name in `available`
/// - `Some(list)` → `list` verbatim, including `Some([])` meaning no tools
///
/// `available` is the full set of tool names the runtime exposes; it is only
/// consulted for the wildcard case.
pub fn resolve_allowed_tools(peer: &A2aPeerConfig, available: &[String]) -> Vec<String> {
    match &peer.tools {
        None => DEFAULT_PEER_TOOLS.iter().map(|s| s.to_string()).collect(),
        Some(list) if list.iter().any(|t| t == WILDCARD) => available.to_vec(),
        Some(list) => list.clone(),
    }
}

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
        let resolved = resolve_allowed_tools(&peer(None), &all_tool_names());
        assert!(
            !resolved.contains(&"execute_command".to_string()),
            "a peer with no explicit tools list must never receive shell access"
        );
    }

    #[test]
    fn default_excludes_every_privileged_tool() {
        let resolved = resolve_allowed_tools(&peer(None), &all_tool_names());
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
        let resolved = resolve_allowed_tools(&peer(None), &all_tool_names());
        for expected in ["read_file", "list_files", "search_memory", "recall"] {
            assert!(
                resolved.contains(&expected.to_string()),
                "{expected} should be in the default peer policy"
            );
        }
    }

    #[test]
    fn wildcard_expands_to_every_available_tool() {
        let available = all_tool_names();
        let resolved = resolve_allowed_tools(&peer(Some(vec!["*"])), &available);
        assert_eq!(resolved.len(), available.len());
        assert!(resolved.contains(&"execute_command".to_string()));
    }

    #[test]
    fn explicit_list_is_used_verbatim() {
        let resolved =
            resolve_allowed_tools(&peer(Some(vec!["read_file", "recall"])), &all_tool_names());
        assert_eq!(
            resolved,
            vec!["read_file".to_string(), "recall".to_string()]
        );
    }

    #[test]
    fn explicit_empty_list_grants_nothing() {
        let resolved = resolve_allowed_tools(&peer(Some(vec![])), &all_tool_names());
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
        let resolved = resolve_allowed_tools(&peer(None), &available);
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
