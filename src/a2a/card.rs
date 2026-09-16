//! Agent Card generation from the loaded skill registry.

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
            scheme: "bearer".to_string(),
            description: Some("Static per-peer bearer token".to_string()),
            bearer_format: None,
        }),
    );

    let mut sec_req = HashMap::new();
    sec_req.insert("bearer".to_string(), Vec::new());

    let mut skills: Vec<AgentSkill> = registry
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
        .collect();
    skills.sort_by(|a, b| a.id.cmp(&b.id));

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
        skills,
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: Some(schemes),
        security_requirements: Some(vec![sec_req]),
        signatures: None,
    }
}

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
            name: "RustFox".to_string(),
            description: "Self-hosted assistant".to_string(),
            version: "1.0.2".to_string(),
        }
    }

    #[test]
    fn card_carries_configured_identity() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        assert_eq!(card.name, "RustFox");
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
        assert_eq!(
            card.skills.len(),
            1,
            "a tagless skill must still be advertised"
        );
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

    #[test]
    fn card_declares_security_requirements() {
        let card = build_agent_card(&cfg(), &registry(vec![]), "http://localhost:8443");
        let reqs = card
            .security_requirements
            .as_ref()
            .expect("requirements required");
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].contains_key("bearer"));
    }

    #[test]
    fn skills_are_sorted_deterministically_by_id() {
        let reg = registry(vec![
            skill("zeta", "z", &[]),
            skill("alpha", "a", &[]),
            skill("mid", "m", &[]),
        ]);
        let card = build_agent_card(&cfg(), &reg, "http://localhost:8443");
        let ids: Vec<&str> = card.skills.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "mid", "zeta"]);
    }
}
