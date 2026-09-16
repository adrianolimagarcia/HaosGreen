//! Peer authentication for the A2A listener.

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

    // Resolved against a fixed set here; the caller re-resolves against the
    // live tool registry. An empty `available` still yields the default list,
    // which is what we want for the identity record.
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
