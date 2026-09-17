//! A2A routes (design spec §5.4).
//!
//! ```text
//! GET  /api/a2a/status    -> what actually happened to the listener
//! GET  /api/a2a/peers     -> inbound peers, tokens replaced by a fingerprint
//! GET  /api/a2a/outbound  -> outbound peers, tokens replaced by a fingerprint
//! PUT  /api/a2a/outbound  -> replace the outbound peers, live and persisted
//! POST /api/a2a/test      -> Agent Card discovery against a *named* peer
//! ```
//!
//! All five are on the **guarded** router, never the public one. The A2A
//! surface names every peer, its allowed source addresses and its tool policy;
//! the test route makes the server issue an outbound request. Nothing about it
//! is reachable without a session, and the two mutating routes additionally
//! require the CSRF header. When the dashboard was started without A2A wiring
//! every route answers **503**, the same contract as the supervisor and log
//! routes.
//!
//! # The five properties this module exists to keep
//!
//! 1. **`POST /api/a2a/test` takes a peer *name*, never a URL.**
//!    [`A2aClient::discover`] attaches `bearer_auth(&config.token)` to the
//!    request it makes. If the caller could choose the URL, an authenticated
//!    caller could make this process send the operator's A2A peer token to an
//!    arbitrary host: SSRF plus token exfiltration. The name is looked up in
//!    the configured outbound peers and an unknown name is a **404** with no
//!    outbound request at all. The request body is `{"peer": "..."}` with
//!    `deny_unknown_fields`, so a body that also carries a `url` is rejected
//!    before any lookup happens — a URL-shaped value in the `peer` field is
//!    simply a name that does not exist.
//!
//! 2. **Tokens are never returned, in either direction.** The responses are
//!    built from structs that have no field able to carry a token; each peer
//!    carries a `token_fingerprint` instead — the first six hex characters of
//!    the SHA-256 digest of the configured token, the same shape
//!    `Credentials::bearer_fingerprint` uses for the dashboard's own bearer
//!    token. It identifies a token the operator already holds and does not
//!    narrow a search for the token. `A2aOutboundPeerConfig`'s redacting
//!    `Debug` is not used here at all, and must not be replaced by a
//!    `json!({...})` literal that could grow a token field by accident.
//!
//! 3. **A peer's Agent Card is untrusted remote data.** It arrives over the
//!    network from another host, so the test route echoes four bounded fields
//!    (name, protocol binding, protocol version, skill count) rather than the
//!    card. Nothing from the card reaches a path, a command, or a log line
//!    unredacted, and nothing is rendered as markup here — this module emits
//!    JSON only.
//!
//! 4. **`allowed_ips` is fail-closed and the web allowlist is not.** An empty
//!    `[a2a.peers.<name>].ip` list means *no address is allowed*; an empty
//!    `[web].allow_ips` means *any address is allowed*. Both are reported, and
//!    the asymmetry is stated in the body so a reader cannot carry the web
//!    semantics over to A2A.
//!
//! 5. **`["*"]` means opposite things in the two tool policies.** For a peer,
//!    an absent `tools` key means the conservative `DEFAULT_PEER_TOOLS` and
//!    `["*"]` as the sole entry means *every* tool, `execute_command`
//!    included. For `LoopConfig.allowed_tools` a literal `["*"]` grants
//!    nothing. The peers response reports the raw `tools` value, which
//!    convention applies, and the concrete list
//!    [`resolve_allowed_tools`] actually produces — resolved through that
//!    function rather than re-derived, so neither convention is translated
//!    into the other.
//!
//! # `PUT /api/a2a/outbound` is live **and** persistent
//!
//! The operator overrode the dashboard's original "no `config.toml` editing
//! from the UI" non-goal, so this route now does three things, in this order,
//! and reports success only when all three happened:
//!
//! 1. It rewrites **only** the `[a2a.outbound.peers]` table of the file this
//!    process was started from — the same path
//!    [`crate::home::resolve_config_path`] resolved in `main.rs`, so the file
//!    written is the file read. The edit goes through `toml_edit`, which leaves
//!    every comment, blank line, key order and formatting choice elsewhere in
//!    the file byte-identical. The `Config` struct is never round-tripped
//!    through serde: that would silently delete the operator's comments and
//!    reorder the file that holds their secrets.
//! 2. The write is **atomic**. A temporary file is created *in the same
//!    directory*, never world-readable even for an instant, given the original
//!    file's mode, fsynced, and only then renamed over `config.toml`. A crash
//!    or a full disk therefore leaves the old file or the new one, never a
//!    truncated one — a truncated `config.toml` means the operator's bot does
//!    not start.
//!
//!    The target is resolved through any symlink **first** ([`resolve_target`]),
//!    so a `config.toml` that is a link into a dotfiles repository keeps its
//!    link and the real file is the one replaced. `rename(2)` replaces the link
//!    itself, not what it points at, so writing to the path as given would turn
//!    the operator's symlink into a regular file, leave the real configuration
//!    stale and copy every secret into a new inode without the target's
//!    ownership or ACLs.
//! 3. Only then is the shared configuration handle replaced — the same handle
//!    `call_a2a_agent` reads, so the running agent uses the new peers on its
//!    next invocation.
//!
//! The change survives a restart. It is lost only if the operator edits
//! `config.toml` externally and restarts, at which point the file is the
//! authority again, as it is for every other setting.
//!
//! Failure is reported as failure. If the file cannot be read, parsed or
//! replaced, the route answers **500**, the in-memory configuration is left
//! exactly as it was, and the file is left exactly as it was. A "saved"
//! response that did not save is worse than an error. A **missing**
//! `config.toml` is one of those failures: the route refuses to create one,
//! because a fresh file holding only `[a2a.outbound.peers]` is a configuration
//! the process could not start from.
//!
//! Concurrency: the whole read-modify-write is serialised by a mutex held on
//! the state, so two concurrent `PUT`s cannot interleave into a corrupt file.
//! One of them wins outright, and the file and the in-memory configuration
//! always agree once a `PUT` has answered.
//!
//! # This route can redirect a stored peer token
//!
//! An omitted `token` keeps the stored one, so a `PUT` that changes a peer's
//! `url` points the *existing* token at a new host without ever knowing the
//! token. That is a real capability and the reason this route is CSRF-guarded
//! like every other mutating route, and reachable only with an operator session
//! or the operator's bearer token. Nothing here is reachable unauthenticated.
//!
//! # "The stored one" means the file's, not the handle's
//!
//! Every "keep what the peer already has" default — the token and the three
//! timeouts — comes from the document **just parsed from `config.toml`**, never
//! from the in-memory handle. The two agree at startup and after every `PUT`,
//! but an operator who rotates a token by editing `config.toml` without
//! restarting leaves the handle stale, and the UI's promise is "empty keeps the
//! stored token". Taking that default from the handle would have the route
//! compose the *old* token and write it back over the new one — silently
//! reverting an out-of-band rotation, while the running agent kept using the old
//! token and its calls failed with no diagnosable cause. The file wins because
//! the file is what the next start reads.
//!
//! Reading the token from the file is safe: it stays in this process, and the
//! response carries only a fingerprint.
//!
//! The file is read **once**, before the candidate is built, and the same parsed
//! document is what the write edits — so there is no window in which the
//! defaults and the rewrite could come from two different versions of the file.
//!
//! # A rejected `PUT` changes nothing
//!
//! The whole candidate configuration is built and validated *before* the live
//! one is replaced, so a bad entry is a 400 that leaves the previous
//! configuration exactly as it was — no half-applied peer set. Validation goes
//! through [`A2aOutboundPeerConfig::validate`], the same function
//! `A2aConfig::validate` calls for each outbound peer at startup, rather than a
//! second hand-written copy of those rules.
//!
//! Peer **names** are checked before the file is read at all, so an invalid name
//! is a 400 whatever the state of `config.toml`. Everything else is validated
//! after the read, because the defaults it validates against come from the file;
//! a request whose peers are all individually well-formed but whose
//! `config.toml` cannot be read is therefore a 500 rather than a 400.
//!
//! # A connection test is bounded
//!
//! `A2aClient::discover` builds its HTTP client with the peer's own
//! `timeout_secs`, which the operator can set to a day. The route therefore
//! wraps the call in its own timeout capped by
//! [`A2aWebState::connection_test_timeout`], so a black-holed peer cannot pin a
//! dashboard request for longer than that cap.

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a2a::types::TRANSPORT_PROTOCOL_JSONRPC;
use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, Table};

use crate::a2a::client::A2aClient;
use crate::a2a::policy::resolve_allowed_tools;
use crate::a2a::tool::SharedOutboundConfig;
use crate::agent::Agent;
use crate::config::{A2aConfig, A2aOutboundConfig, A2aOutboundPeerConfig, A2aPeerConfig};
use crate::skills::SkillRegistry;
use crate::web::state::WebState;

/// Routes for the A2A surface. Guarded router only.
pub fn router() -> Router<WebState> {
    Router::new()
        .route("/api/a2a/status", get(read_status))
        .route("/api/a2a/peers", get(read_inbound_peers))
        .route(
            "/api/a2a/outbound",
            get(read_outbound).put(replace_outbound),
        )
        .route("/api/a2a/test", post(test_peer))
}

/// Hard ceiling on one `POST /api/a2a/test`.
///
/// Ten seconds is far longer than a card fetch on a reachable peer and far
/// shorter than the day an operator could legitimately configure for a slow
/// peer's *tasks*. It bounds the dashboard request, not the peer.
const DEFAULT_CONNECTION_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest peer name a `PUT` accepts.
const MAX_PEER_NAME_CHARS: usize = 64;

/// Longest string echoed from a remote Agent Card.
const MAX_ECHOED_CHARS: usize = 200;

/// Longest failure reason reported to the dashboard.
///
/// A config-validation message is written by this crate and is allowed to be a
/// full sentence; a network failure reason is classified down to one short
/// phrase before it ever reaches here.
const MAX_REASON_CHARS: usize = 400;

/// Largest numeric peer setting a `PUT` accepts.
///
/// TOML's only integer type is signed 64-bit, so a larger `u64` would be
/// written as a negative number and the file would not load on the next start.
const MAX_TOML_INTEGER: u64 = i64::MAX as u64;

// ── State ───────────────────────────────────────────────────────────────────

/// What `main.rs` observed about the A2A listener.
///
/// The listener's outcome used to be discarded (`a2a::server::spawn` returns
/// the address it bound, and `main.rs` threw it away), so nothing could say
/// whether A2A was up. This type is the observation, and the status route
/// reports it verbatim — it never infers a state it did not see.
#[derive(Debug, Clone)]
pub enum A2aListenerOutcome {
    /// `[a2a].enabled = false`: no listener was started, by configuration.
    Disabled,
    /// The listener bound `bound` and its serve task was spawned. The Agent
    /// Card advertises `advertised_url`, which is what
    /// `a2a::server::resolve_endpoint_url` produced from the address actually
    /// bound (or `[a2a].public_url` when set).
    Started {
        bound: SocketAddr,
        advertised_url: String,
    },
    /// `[a2a].enabled = true` but no listener is serving: either
    /// `A2aConfig::validate` refused the configuration or the bind failed.
    /// `reason` is the short, single-line explanation. A listener that bound
    /// successfully and died later is **not** represented here: its error is
    /// logged by the serve task and is visible in the log view.
    Failed { reason: String },
}

/// The A2A half of the dashboard state.
///
/// Holds the inbound peers as configured at startup (tokens included, because
/// fingerprints are derived from them) and the **live** outbound peers.
pub struct A2aWebState {
    config: A2aConfig,
    outcome: A2aListenerOutcome,
    /// The same handle `main.rs` hands to `call_a2a_agent`.
    ///
    /// This is what makes a `PUT` reach the running agent: there is one
    /// configuration value, and both the route and the tool read it. Behind a
    /// `tokio::sync::RwLock` because the readers are async and the rest of the
    /// codebase uses tokio locks for shared async state; a write is a
    /// whole-struct swap, so a reader can never observe a half-updated peer set.
    outbound: SharedOutboundConfig,
    /// The file the process was started from, as `main.rs` resolved it.
    ///
    /// `main.rs` passes the very `PathBuf` it loaded `Config` from, rather than
    /// re-resolving here: writing to a different file than the process read
    /// would be a silent and very confusing bug.
    outbound_config_path: PathBuf,
    /// Serialises the whole read-modify-write of the configuration file.
    ///
    /// Two concurrent `PUT`s would otherwise both read the file, both edit
    /// their own in-memory copy and both rename: the second rename wins and the
    /// first operator's change is silently gone. Held for the duration of the
    /// persist **and** the in-memory swap, so the file and memory cannot
    /// disagree when a request answers.
    write_lock: tokio::sync::Mutex<()>,
    connection_test_timeout: Duration,
}

impl A2aWebState {
    /// Build the dashboard's A2A view from the startup configuration, the
    /// listener outcome [`start_listener`] returned, the shared outbound handle
    /// `main.rs` created, and the path that handle's file lives at.
    pub fn new(
        config: A2aConfig,
        outcome: A2aListenerOutcome,
        outbound: SharedOutboundConfig,
        outbound_config_path: PathBuf,
    ) -> Self {
        Self {
            config,
            outcome,
            outbound,
            outbound_config_path,
            write_lock: tokio::sync::Mutex::new(()),
            connection_test_timeout: DEFAULT_CONNECTION_TEST_TIMEOUT,
        }
    }

    /// Shorten the connection-test cap. Tests only: the cap is what makes a
    /// black-holed peer survivable, and a test that had to wait the production
    /// ten seconds to observe it would not be run.
    #[doc(hidden)]
    pub fn with_connection_test_timeout(mut self, timeout: Duration) -> Self {
        self.connection_test_timeout = timeout;
        self
    }

    /// The effective timeout for one connection test: the peer's own setting,
    /// clamped to at least a second and at most the configured cap.
    fn test_timeout(&self, peer: &A2aOutboundPeerConfig) -> Duration {
        Duration::from_secs(
            peer.timeout_secs
                .clamp(1, self.connection_test_timeout.as_secs().max(1)),
        )
    }
}

/// Start the A2A listener and return what actually happened.
///
/// This is the *only* place the listener outcome is observed, and `main.rs`
/// calls it, so the status route and the startup log cannot disagree. The
/// Telegram bot keeps running on every failure path: an A2A misconfiguration
/// must not take the bot down.
///
/// A failure is returned, never swallowed: a caller that ignores the value
/// still leaves the dashboard able to say "the listener is not running".
pub async fn start_listener(
    config: &A2aConfig,
    skills: SkillRegistry,
    executor: impl a2a_server::AgentExecutor,
    store: impl a2a_server::TaskStore,
) -> A2aListenerOutcome {
    let (_tx, rx) = tokio::sync::broadcast::channel(1);
    start_listener_with_shutdown(config, skills, executor, store, rx).await
}

pub async fn start_listener_with_shutdown(
    config: &A2aConfig,
    skills: SkillRegistry,
    executor: impl a2a_server::AgentExecutor,
    store: impl a2a_server::TaskStore,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> A2aListenerOutcome {
    if !config.enabled {
        tracing::debug!("A2A disabled");
        return A2aListenerOutcome::Disabled;
    }

    // Validate first. Every rule checked here already fails closed at request
    // time; validating up front turns a silent per-request denial (or a 500
    // from duplicate tokens) into one loud startup error. The listener is not
    // started on failure — but the Telegram bot still is.
    if let Err(e) = config.validate() {
        tracing::error!(
            error = %e,
            "A2A configuration is invalid; the A2A listener was NOT started"
        );
        return A2aListenerOutcome::Failed {
            reason: bounded_reason(&e.to_string(), &configured_tokens(config)),
        };
    }

    match crate::a2a::server::spawn_with_shutdown(config.clone(), skills, executor, store, shutdown)
        .await
    {
        Ok(bound) => {
            // The same function the Agent Card is built from, so the URL
            // reported here is the URL peers are told to use. `spawn` calls it
            // too; for an unspecified bind that means its warning is emitted
            // twice at startup, which is noise rather than a disagreement.
            let advertised_url = crate::a2a::server::resolve_endpoint_url(config, bound);
            A2aListenerOutcome::Started {
                bound,
                advertised_url,
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "A2A listener failed to start");
            A2aListenerOutcome::Failed {
                reason: bounded_reason(&e.to_string(), &configured_tokens(config)),
            }
        }
    }
}

/// Every token in the configuration, for redaction of text that might carry
/// one. Errors from this module do not contain tokens; this is defence in
/// depth, not a workaround for a known leak.
fn configured_tokens(config: &A2aConfig) -> Vec<String> {
    config
        .peers
        .values()
        .map(|peer| peer.token.clone())
        .chain(
            config
                .outbound
                .peers
                .values()
                .map(|peer| peer.token.clone()),
        )
        .filter(|token| !token.is_empty())
        .collect()
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// What the listener did, as observed at startup.
#[derive(Serialize)]
struct StatusResponse {
    /// `[a2a].enabled`. `false` with `state: "disabled"` is the honest
    /// "switched off" answer, not an error.
    enabled: bool,
    /// `"disabled"`, `"started"` or `"failed"`.
    state: &'static str,
    /// The address the listener actually bound. Absent unless `state` is
    /// `"started"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    bound: Option<String>,
    /// The base URL the Agent Card advertises. Absent unless `state` is
    /// `"started"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    advertised_url: Option<String>,
    /// Why the listener is not running. Present only when `state` is
    /// `"failed"` — the failure is reported, never smoothed over into
    /// "disabled".
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<String>,
    /// The card's own name, from `[a2a.card].name`.
    card_name: String,
    inbound_peers: usize,
    outbound_peers: usize,
}

async fn read_status(State(state): State<WebState>) -> Response {
    let a2a = match state.a2a_or_unavailable() {
        Ok(a2a) => a2a,
        Err(rejection) => return rejection.into_response(),
    };

    let (status, bound, advertised_url, failure) = match &a2a.outcome {
        A2aListenerOutcome::Disabled => ("disabled", None, None, None),
        A2aListenerOutcome::Started {
            bound,
            advertised_url,
        } => (
            "started",
            Some(bound.to_string()),
            Some(advertised_url.clone()),
            None,
        ),
        A2aListenerOutcome::Failed { reason } => {
            ("failed", None, None, Some(bounded_reason(reason, &[])))
        }
    };

    // Derived from the observation, not read back from `[a2a].enabled`: a
    // listener can only have started — or failed to start — if it was enabled,
    // so the two can never contradict each other in a response.
    let enabled = !matches!(a2a.outcome, A2aListenerOutcome::Disabled);

    // The live handle, not a copy taken at startup: after a `PUT` this is what
    // the running agent is actually using. Cloned out of the guard before the
    // response is built, so no guard outlives this statement.
    let outbound_peers = a2a.outbound.read().await.peers.len();

    Json(StatusResponse {
        enabled,
        state: status,
        bound,
        advertised_url,
        failure,
        card_name: truncate(&a2a.config.card.name, MAX_ECHOED_CHARS),
        inbound_peers: a2a.config.peers.len(),
        outbound_peers,
    })
    .into_response()
}

/// One inbound peer, with its token replaced by a fingerprint.
#[derive(Serialize)]
struct InboundPeerView {
    name: String,
    /// First six hex characters of the SHA-256 digest of the peer's configured
    /// token, or `null` when no token is configured (which is a configuration
    /// error `A2aConfig::validate` refuses at startup, so it only appears on a
    /// dashboard wired by a test).
    token_fingerprint: Option<String>,
    allowed_ips: Vec<String>,
    /// True when `allowed_ips` is empty, i.e. when this peer can authenticate
    /// from nowhere at all. The flag exists because the opposite list in the
    /// same process means the opposite thing.
    allows_no_address: bool,
    tools: ToolPolicyView,
}

/// A peer's tool policy, in both the form it was written and the form that
/// applies.
#[derive(Serialize)]
struct ToolPolicyView {
    /// The literal `[a2a.peers.<name>].tools` value, or `null` when the key is
    /// absent.
    configured: Option<Vec<String>>,
    /// Which reading of `configured` applies: `"default"` (key absent →
    /// `DEFAULT_PEER_TOOLS`), `"wildcard"` (`["*"]` as the sole entry → every
    /// tool), `"explicit"`, or `"explicit_wildcard_ignored"` (`"*"` mixed with
    /// other names is a configuration error and is treated as the literal list,
    /// never as a full grant).
    source: &'static str,
    /// The concrete allowlist a request from this peer is filtered against.
    /// `null` when it cannot be computed — see `effective_unavailable`.
    effective: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_unavailable: Option<&'static str>,
}

/// The body of `GET /api/a2a/peers`.
#[derive(Serialize)]
struct InboundPeersResponse {
    peers: Vec<InboundPeerView>,
    /// The fail-closed semantics, stated so the `[web].allow_ips` reading is
    /// not carried over.
    ip_allowlist_semantics: &'static str,
    /// The `["*"]` asymmetry, stated for the same reason.
    tool_policy_semantics: &'static str,
    /// Why a fingerprint and not a token.
    token_semantics: &'static str,
}

const IP_ALLOWLIST_SEMANTICS: &str = "An inbound peer's allowed_ips is a fail-closed allowlist: an empty list allows no address at all. This is the opposite of [web].allow_ips, where an empty list allows any source.";

const TOOL_POLICY_SEMANTICS: &str = "A peer with no `tools` key gets the conservative default allowlist (DEFAULT_PEER_TOOLS). `[\"*\"]` as the sole entry grants every tool, including execute_command. This is the opposite of the agent loop's allowed_tools, where a literal \"*\" grants nothing. `tools.effective` is the list actually applied.";

const TOKEN_SEMANTICS: &str = "Tokens are never returned by any route, not even to an authenticated operator. token_fingerprint is the first six hex characters of the SHA-256 digest of the configured token: it identifies a token you already hold and cannot be reversed.";

const OUTBOUND_SEMANTICS: &str = "Saved and live. A PUT replaces [a2a.outbound.peers] in config.toml and hands the new peers to the running call_a2a_agent tool, which uses them on its next invocation. The write is atomic (a temporary file in the same directory is renamed over config.toml), keeps the file's existing permissions, and touches nothing else in the file: comments, formatting and key order are preserved. The change survives a restart and is lost only if config.toml is edited elsewhere and the process restarted.";

const OUTBOUND_TOKEN_SEMANTICS: &str = "Tokens are never returned by any route, not even to an authenticated operator. token_fingerprint is the first six hex characters of the SHA-256 digest of the configured token: it identifies a token you already hold and cannot be reversed. A PUT that omits a peer's token keeps the token already stored for that peer, so changing only a url redirects the existing token to the new host; an explicitly empty token is not \"keep the existing one\" but an empty credential, and the whole update is refused with 400. Removing a peer is how its token is cleared.";

async fn read_inbound_peers(State(state): State<WebState>) -> Response {
    let a2a = match state.a2a_or_unavailable() {
        Ok(a2a) => a2a,
        Err(rejection) => return rejection.into_response(),
    };

    let available = available_tool_names(state.agent.as_deref());

    // Sorted so the response is stable across runs: `peers` is a `HashMap`,
    // whose iteration order is randomized per process.
    let mut names: Vec<&String> = a2a.config.peers.keys().collect();
    names.sort();

    let peers = names
        .into_iter()
        .map(|name| {
            let peer = &a2a.config.peers[name];
            InboundPeerView {
                name: name.clone(),
                token_fingerprint: fingerprint(&peer.token),
                allowed_ips: peer.ip.clone(),
                allows_no_address: peer.ip.is_empty(),
                tools: peer_tool_policy(name, peer, &available),
            }
        })
        .collect();

    Json(InboundPeersResponse {
        peers,
        ip_allowlist_semantics: IP_ALLOWLIST_SEMANTICS,
        tool_policy_semantics: TOOL_POLICY_SEMANTICS,
        token_semantics: TOKEN_SEMANTICS,
    })
    .into_response()
}

/// One outbound peer, with its token replaced by a fingerprint.
#[derive(Serialize)]
struct OutboundPeerView {
    name: String,
    url: String,
    token_fingerprint: Option<String>,
    timeout_secs: u64,
    poll_interval_ms: u64,
    poll_timeout_secs: u64,
}

/// The body of `GET`/`PUT /api/a2a/outbound`.
#[derive(Serialize)]
struct OutboundResponse {
    peers: Vec<OutboundPeerView>,
    /// `true`: the peers listed here are in `config.toml` as well as in memory.
    /// See [`outbound_view`] for what this rests on.
    persistent: bool,
    /// `false`: the change survives a restart. Only an external edit of
    /// `config.toml` followed by a restart discards it.
    restart_reverts: bool,
    /// `true`: the running `call_a2a_agent` tool reads this configuration, so
    /// the next invocation uses these peers.
    affects_running_agent: bool,
    semantics: &'static str,
    token_semantics: &'static str,
}

/// Describe the live outbound peers, with the three persistence flags.
///
/// # The flags are claims about the write path, not observations made here
///
/// `persistent`, `restart_reverts` and `affects_running_agent` are **not**
/// derived from anything this function can see, and that is deliberate:
///
/// * `GET` cannot observe the file without reading and parsing `config.toml` on
///   every poll, and the dashboard polls this route.
/// * `PUT` *could* observe it — it just wrote it — but the two halves of the
///   route must not disagree, and the contract is that they report the same
///   three values.
///
/// What the flags rest on is an invariant of [`replace_outbound`]: it writes
/// `config.toml` **before** it swaps the live handle, and answers **500**
/// *without* swapping when the write fails. The handle can therefore only ever
/// hold peers that are also on disk, and a restart — which reads exactly that
/// file — keeps them. `main.rs` hands the same handle to `call_a2a_agent`, which
/// is what makes `affects_running_agent` true.
///
/// The values are true today, so this is not a lie to the operator. It is a
/// dependency, and it is named here rather than left implicit because the UI's
/// save-honesty rests on it: a future path that swapped the handle **without**
/// writing the file — a read-only-filesystem fallback, a dry-run mode — would
/// leave the dashboard confidently announcing a save that did not happen, with
/// the copy driven by a constant.
/// `tests/web_endpoint.rs`'s
/// `the_persistence_flags_are_measured_against_the_file_and_the_handle` ties
/// these three values to the file on disk and to the shared handle, so such a
/// change fails there instead of in an operator's browser.
fn outbound_view(outbound: &A2aOutboundConfig) -> OutboundResponse {
    let mut names: Vec<&String> = outbound.peers.keys().collect();
    names.sort();

    let peers = names
        .into_iter()
        .map(|name| {
            let peer = &outbound.peers[name];
            OutboundPeerView {
                name: name.clone(),
                url: peer.url.clone(),
                token_fingerprint: fingerprint(&peer.token),
                timeout_secs: peer.timeout_secs,
                poll_interval_ms: peer.poll_interval_ms,
                poll_timeout_secs: peer.poll_timeout_secs,
            }
        })
        .collect();

    OutboundResponse {
        peers,
        persistent: true,
        restart_reverts: false,
        affects_running_agent: true,
        semantics: OUTBOUND_SEMANTICS,
        token_semantics: OUTBOUND_TOKEN_SEMANTICS,
    }
}

async fn read_outbound(State(state): State<WebState>) -> Response {
    let a2a = match state.a2a_or_unavailable() {
        Ok(a2a) => a2a,
        Err(rejection) => return rejection.into_response(),
    };

    // The guard is scoped to the block: `outbound_view` returns an owned value,
    // so nothing borrows the lock past this point.
    let view = {
        let outbound = a2a.outbound.read().await;
        outbound_view(&outbound)
    };
    Json(view).into_response()
}

/// One peer in a `PUT /api/a2a/outbound` body.
///
/// Every field except `url` is optional and means "keep what the peer already
/// has", falling back to [`A2aOutboundPeerConfig::default`] for a peer that
/// does not exist yet. In particular an omitted `token` keeps the stored one:
/// the dashboard never reads a token back, so a UI that re-sent an empty string
/// would silently clear a working credential.
///
/// An *explicitly* empty token is not "keep the existing one" — it is an empty
/// credential, which `validate` refuses with a 400 and the whole update is
/// rejected. Clearing a token is done by removing the peer.
///
/// A `PUT` that changes a peer's `url` while omitting its `token` therefore
/// points the *existing* token at a new host. That is the plan's stated
/// semantics ("an omitted token keeps the existing one rather than clearing
/// it") and it is also why this route is CSRF-guarded and operator-only: it is
/// the one place a token can be redirected without being known. Supply the
/// token explicitly when changing a URL.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundPeerInput {
    url: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    poll_interval_ms: Option<u64>,
    #[serde(default)]
    poll_timeout_secs: Option<u64>,
}

/// The body of `PUT /api/a2a/outbound`: the complete replacement peer set.
///
/// `deny_unknown_fields` is deliberate. An unrecognised key is a client bug,
/// and silently ignoring it would let a UI that misspelled `peers` wipe the
/// whole configuration with an empty map.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundUpdate {
    peers: HashMap<String, OutboundPeerInput>,
}

async fn replace_outbound(
    State(state): State<WebState>,
    Json(body): Json<OutboundUpdate>,
) -> Response {
    let a2a = match state.a2a_or_unavailable() {
        Ok(a2a) => a2a,
        Err(rejection) => return rejection.into_response(),
    };

    // Everything from here to the response is serialised. Two concurrent PUTs
    // must not both read the file, both edit their own copy and both rename:
    // the second rename would silently discard the first operator's change, and
    // the file and the running agent could disagree.
    let _serialised = a2a.write_lock.lock().await;

    // Sorted so the error reported for a body with several bad peers is stable
    // across runs, matching `A2aConfig::validate`.
    let mut names: Vec<&String> = body.peers.keys().collect();
    names.sort();

    // Peer names first, before the file is read at all: an invalid name is a
    // property of the request body and must not depend on what is on disk.
    for name in &names {
        if !valid_peer_name(name) {
            tracing::warn!("web: rejected an A2A outbound update with an invalid peer name");
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "peer name must be 1-{MAX_PEER_NAME_CHARS} characters of ASCII letters, \
                     digits, '-', '_' or '.'"
                ),
            )
                .into_response();
        }
    }

    // The configuration file is read **once**, here, and supplies both the
    // "keep what the peer already has" defaults and the document the write
    // edits. Reading it is blocking work (`read_to_string`), so it runs on the
    // blocking pool rather than stalling a tokio worker.
    let config_path = a2a.outbound_config_path.clone();
    let file = match tokio::task::spawn_blocking(move || ConfigFile::load(&config_path)).await {
        Ok(Ok(file)) => file,
        Ok(Err(failure)) => {
            return persist_failure(&failure, &a2a.outbound_config_path);
        }
        Err(join) => {
            let failure = PersistError::Failed(anyhow::anyhow!(
                "the configuration file could not be read: {join}"
            ));
            return persist_failure(&failure, &a2a.outbound_config_path);
        }
    };

    // The file, never the in-memory handle: see `ConfigFile::outbound_peers`.
    let on_disk = file.outbound_peers();

    let mut candidate = A2aOutboundConfig::default();
    for name in names {
        let input = &body.peers[name];
        let existing = on_disk.peers.get(name);
        let defaults = A2aOutboundPeerConfig::default();

        let peer = A2aOutboundPeerConfig {
            url: input.url.trim().to_string(),
            token: input
                .token
                .clone()
                .or_else(|| existing.map(|peer| peer.token.clone()))
                .unwrap_or(defaults.token),
            timeout_secs: input
                .timeout_secs
                .or_else(|| existing.map(|peer| peer.timeout_secs))
                .unwrap_or(defaults.timeout_secs),
            poll_interval_ms: input
                .poll_interval_ms
                .or_else(|| existing.map(|peer| peer.poll_interval_ms))
                .unwrap_or(defaults.poll_interval_ms),
            poll_timeout_secs: input
                .poll_timeout_secs
                .or_else(|| existing.map(|peer| peer.poll_timeout_secs))
                .unwrap_or(defaults.poll_timeout_secs),
        };

        // The same check `A2aConfig::validate` runs for every outbound peer at
        // startup, so a `PUT` cannot install a configuration that would have
        // been refused there.
        if let Err(e) = peer.validate(name) {
            tracing::warn!(peer = %name, "web: rejected an A2A outbound update");
            return (StatusCode::BAD_REQUEST, bounded_reason(&e.to_string(), &[])).into_response();
        }

        // TOML has one integer type and `toml_edit` writes it as `i64`. A value
        // above `i64::MAX` would be written as a negative number, and the
        // operator's next start would fail to parse the file this route wrote.
        // Refused here rather than truncated.
        for (field, value) in [
            ("timeout_secs", peer.timeout_secs),
            ("poll_interval_ms", peer.poll_interval_ms),
            ("poll_timeout_secs", peer.poll_timeout_secs),
        ] {
            if value > MAX_TOML_INTEGER {
                tracing::warn!(peer = %name, field, "web: rejected an out-of-range A2A outbound value");
                return (
                    StatusCode::BAD_REQUEST,
                    format!("{field} must be at most {MAX_TOML_INTEGER}"),
                )
                    .into_response();
            }
        }

        candidate.peers.insert(name.clone(), peer);
    }

    // The document edit, the render and the create/write/fsync/chmod/rename
    // sequence are all blocking work — `sync_all` on a slow volume can take
    // hundreds of milliseconds, and on a tokio worker thread that is hundreds of
    // milliseconds in which every other task on that worker is stalled, the
    // Telegram bot's polling included. The whole read-modify-write therefore
    // runs on the blocking pool, with the document that was already parsed and
    // the candidate that was already validated.
    //
    // Persist first, then apply. The file is the authority: if the write fails,
    // both the file and the running agent must be left exactly as they were, and
    // the caller must be told it failed rather than told "saved".
    let to_persist = candidate.clone();
    let written = tokio::task::spawn_blocking(move || {
        let mut file = file;
        file.write(&to_persist)
    })
    .await;

    let failure = match written {
        Ok(Ok(())) => None,
        Ok(Err(failure)) => Some(failure),
        Err(join) => Some(PersistError::Failed(anyhow::anyhow!(
            "the configuration file could not be replaced: {join}"
        ))),
    };
    if let Some(failure) = failure {
        return persist_failure(&failure, &a2a.outbound_config_path);
    }

    // The file now holds the new peers. The in-memory swap cannot fail, so this
    // point is the first at which the update is guaranteed to have happened in
    // both places.
    *a2a.outbound.write().await = candidate.clone();

    // Defence in depth for the one class of text this route cannot sanitize
    // itself: a token it just installed is a token that may end up inside a
    // `reqwest` URL, a `toml_edit` parse error or an artifact, and the registry
    // is what catches a value with no recognisable shape wherever it appears.
    // `register_secret` dedupes and refuses a needle too short to be a
    // credential, so this is idempotent and cannot over-redact.
    //
    // Only the count is logged. Logging the values would be the bug.
    let registered = crate::supervisor::redact::register_secrets(
        candidate.peers.values().map(|peer| peer.token.as_str()),
    );
    tracing::debug!(
        peers = candidate.peers.len(),
        registered,
        "web: A2A outbound tokens armed in the redaction registry"
    );

    // Names and counts only: this route accepts tokens, and a log line is not
    // the place for one.
    tracing::info!(
        peers = body.peers.len(),
        "web: A2A outbound peers replaced in config.toml and applied to the running agent"
    );

    let view = {
        let outbound = a2a.outbound.read().await;
        outbound_view(&outbound)
    };
    Json(view).into_response()
}

/// The single failure path of a `PUT`: log the detail, answer the caller.
///
/// The detail (which carries the path, never a token) goes to the log; the
/// response body carries no path, like every other route here. The detail goes
/// through [`log_safe`] as well, because a `toml_edit` parse error renders the
/// offending source line and a hand-edited `config.toml` can put a newline in
/// it.
fn persist_failure(failure: &PersistError, path: &Path) -> Response {
    tracing::error!(
        error = %log_safe(&failure.log_detail(path)),
        "web: the A2A outbound peers could not be written to the configuration file; \
         nothing was changed"
    );
    (StatusCode::INTERNAL_SERVER_ERROR, failure.client_message()).into_response()
}

/// The body of `POST /api/a2a/test`: a peer **name**, never a URL.
///
/// `deny_unknown_fields` means a body carrying a `url` alongside the name is
/// rejected before the handler runs. The field is a name that is looked up in
/// the configured outbound peers; it is never parsed as an address.
///
/// The name is caller-controlled text. It is only ever *compared*, logged
/// through [`log_safe`], and echoed through [`echo_safe`] — bounded and stripped
/// of control characters, so one request produces one bounded log line and one
/// bounded response field. It is never allowed to carry a newline into either.
/// The **404** branch does not echo it at all, and says only "unknown outbound
/// peer": there the caller gets nothing back that they did not already send.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestPeerRequest {
    peer: String,
}

/// The discovered card, bounded to the four fields the dashboard shows.
///
/// The card is remote, attacker-controlled data. Echoing it whole would put an
/// arbitrary payload into the dashboard's JSON; every string here is truncated,
/// and no field is used for anything but display.
#[derive(Serialize)]
struct DiscoveredCard {
    name: String,
    protocol_binding: String,
    protocol_version: String,
    skill_count: usize,
}

#[derive(Serialize)]
struct TestResponse {
    ok: bool,
    /// The peer name as it was given, bounded and stripped of control
    /// characters by [`echo_safe`]. See [`TestPeerRequest`].
    peer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<DiscoveredCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn test_peer(State(state): State<WebState>, Json(body): Json<TestPeerRequest>) -> Response {
    let a2a = match state.a2a_or_unavailable() {
        Ok(a2a) => a2a,
        Err(rejection) => return rejection.into_response(),
    };

    // The lookup, and the whole SSRF defence: the URL comes from the operator's
    // own configuration, never from the request. An unknown name is a 404 and
    // no request leaves this process.
    //
    // The peer is cloned out of the guard here rather than inside the match, so
    // the lock is released before the request below is awaited.
    let peer_config = a2a.outbound.read().await.peers.get(&body.peer).cloned();

    let peer_config = match peer_config {
        Some(peer) => peer,
        // The name is not echoed: it is caller-controlled text and there is
        // nothing the caller does not already know.
        None => return (StatusCode::NOT_FOUND, "unknown outbound peer").into_response(),
    };
    let timeout = a2a.test_timeout(&peer_config);

    // `discover` builds its own client with the peer's `timeout_secs`, which
    // the operator can set arbitrarily high; this outer bound is what keeps a
    // black-holed peer from pinning the request. Dropping the future cancels
    // the request.
    let outcome =
        tokio::time::timeout(timeout, A2aClient::discover(&body.peer, &peer_config)).await;

    match outcome {
        Err(_elapsed) => Json(TestResponse {
            ok: false,
            peer: echo_safe(&body.peer),
            card: None,
            error: Some("the connection test timed out".to_string()),
        })
        .into_response(),
        Ok(Err(e)) => {
            let reason = test_failure_reason(&e, &peer_config.token);
            tracing::warn!(
                peer = %log_safe(&body.peer),
                reason = %reason,
                "web: A2A connection test failed"
            );
            Json(TestResponse {
                ok: false,
                peer: echo_safe(&body.peer),
                card: None,
                error: Some(reason),
            })
            .into_response()
        }
        Ok(Ok(card)) => {
            // Prefer the JSON-RPC interface `discover` validated the card
            // against; fall back to the first one so the report is never empty
            // for a card that somehow has none.
            let interface = card
                .supported_interfaces
                .iter()
                .find(|i| i.protocol_binding == TRANSPORT_PROTOCOL_JSONRPC)
                .or_else(|| card.supported_interfaces.first());

            let (protocol_binding, protocol_version) = match interface {
                Some(interface) => (
                    truncate(&interface.protocol_binding, MAX_ECHOED_CHARS),
                    truncate(&interface.protocol_version, MAX_ECHOED_CHARS),
                ),
                None => (String::new(), String::new()),
            };

            Json(TestResponse {
                ok: true,
                peer: echo_safe(&body.peer),
                card: Some(DiscoveredCard {
                    name: truncate(&card.name, MAX_ECHOED_CHARS),
                    protocol_binding,
                    protocol_version,
                    skill_count: card.skills.len(),
                }),
                error: None,
            })
            .into_response()
        }
    }
}

// ── Persisting the outbound peers ───────────────────────────────────────────

/// Why a persist attempt changed nothing.
///
/// Two variants rather than one string because the two cases are told apart in
/// the response: a missing configuration file is a different operator problem
/// from a file that cannot be replaced.
///
/// `Debug` carries the inner `anyhow` chain, which names paths and never a
/// token; nothing here derives `Serialize`, so this cannot reach a response.
#[derive(Debug)]
enum PersistError {
    /// There is no `config.toml` at the resolved path.
    MissingFile,
    /// The file could not be read, parsed or replaced.
    Failed(anyhow::Error),
}

impl PersistError {
    /// The detail for the log line. Carries the path (an operator's own server
    /// log already names it at startup) and never a token.
    fn log_detail(&self, path: &Path) -> String {
        match self {
            PersistError::MissingFile => format!("{} does not exist", path.display()),
            PersistError::Failed(error) => format!("{error:#}"),
        }
    }

    /// The message the dashboard returns.
    ///
    /// Deliberately free of any filesystem path: this module's responses do not
    /// leak paths, and the caller cannot act on one anyway.
    fn client_message(&self) -> &'static str {
        match self {
            PersistError::MissingFile => {
                "the configuration file does not exist, so the outbound peers could not be \
                 saved; nothing was changed"
            }
            PersistError::Failed(_) => {
                "the configuration file could not be updated; nothing was changed"
            }
        }
    }
}

/// Rewrite `[a2a.outbound.peers]` in `path` to exactly `outbound`, atomically.
///
/// The **synchronous** form of the route's read-modify-write, kept for the tests
/// that exercise the file handling directly; the route itself interleaves the
/// read with the request body and runs both halves on the blocking pool. Only
/// the tests call it, so it is compiled only for them.
///
/// Three properties, each of which the module documentation states in full:
///
/// * **Surgical.** The file is parsed with `toml_edit` and only that one table
///   is replaced. Comments, blank lines, key order and the formatting of every
///   other section come out byte-identical, because `toml_edit` keeps the
///   original text of everything it does not change. The whole `Config` is
///   never re-serialized: that would delete the operator's comments and reorder
///   the file that holds their secrets.
/// * **Atomic.** The new text is written to a temporary file in the same
///   directory, fsynced, given the original file's permissions, and renamed
///   over the target. A crash or a full disk leaves the old file or the new
///   one, never a truncated one.
/// * **Fail-closed.** Every failure leaves the file untouched, including a
///   missing file: this route does not create one, because a fresh file holding
///   only `[a2a.outbound.peers]` is a configuration the process cannot start
///   from.
#[cfg(test)]
fn persist_outbound(path: &Path, outbound: &A2aOutboundConfig) -> Result<(), PersistError> {
    ConfigFile::load(path)?.write(outbound)
}

/// The configuration file as it is on disk: the resolved target, its metadata,
/// and the parsed document.
///
/// One value rather than three separate reads, because the route needs all
/// three of them: the document supplies the "keep what the peer already has"
/// defaults, the target is what the rename lands on, and the metadata is the
/// mode the replacement has to carry. Reading it once also removes the window in
/// which the file could change between the defaults being read and the file
/// being rewritten.
struct ConfigFile {
    /// Where the write actually goes, with every symlink resolved. See
    /// [`resolve_target`].
    target: PathBuf,
    /// The target's own metadata, for its permissions.
    metadata: std::fs::Metadata,
    /// The parsed file, kept as a document so the edit stays surgical.
    document: DocumentMut,
}

impl ConfigFile {
    /// Read, resolve and parse the configuration file.
    ///
    /// **Blocking.** `read_to_string` is a syscall; the route calls this through
    /// [`tokio::task::spawn_blocking`].
    fn load(path: &Path) -> Result<Self, PersistError> {
        let target = resolve_target(path)?;

        let metadata = std::fs::metadata(&target).map_err(|error| {
            PersistError::Failed(
                anyhow::Error::new(error)
                    .context(format!("{} could not be read", target.display())),
            )
        })?;

        let original = std::fs::read_to_string(&target).map_err(|error| {
            PersistError::Failed(anyhow::Error::new(error).context(format!(
                "{} could not be read as UTF-8 text",
                target.display()
            )))
        })?;

        // A file this crate cannot parse is a file this route must not rewrite:
        // the edit is defined in terms of the document that is already there.
        let document: DocumentMut = original.parse().map_err(|error| {
            PersistError::Failed(anyhow::anyhow!(
                "{} is not valid TOML: {error}",
                target.display()
            ))
        })?;

        Ok(Self {
            target,
            metadata,
            document,
        })
    }

    /// The outbound peers the **file** currently holds.
    ///
    /// This is the authority for a `PUT` that omits a peer's token or timeouts,
    /// not the in-memory handle. The two agree at startup and after every `PUT`,
    /// but an operator who rotates a token by editing `config.toml` and does not
    /// restart leaves the handle stale; taking the default from the handle would
    /// then have the route compose the *old* token and write it back over the
    /// new one, while the process carried on using the old one — a silent revert
    /// with no diagnosable cause. The file wins because the file is what the
    /// next start reads.
    ///
    /// A peer the document does not hold, and a key it does not set, fall back
    /// to [`A2aOutboundPeerConfig::default`] — the same fallback the route used
    /// before, so a peer the operator removed from the file is treated as new.
    fn outbound_peers(&self) -> A2aOutboundConfig {
        let defaults = A2aOutboundPeerConfig::default();
        let mut peers = HashMap::new();

        let Some(table) = self
            .document
            .get("a2a")
            .and_then(Item::as_table)
            .and_then(|a2a| a2a.get("outbound"))
            .and_then(Item::as_table)
            .and_then(|outbound| outbound.get("peers"))
            .and_then(Item::as_table)
        else {
            return A2aOutboundConfig::default();
        };

        for (name, item) in table.iter() {
            // A `peers` entry that is not a table (`peers = 5`) carries no peer
            // settings; skipping it leaves it to the default fallback rather
            // than inventing a peer out of nothing.
            let Some(peer) = item.as_table() else {
                continue;
            };

            let string = |key: &str| peer.get(key).and_then(Item::as_str).map(str::to_string);
            let integer = |key: &str| {
                peer.get(key)
                    .and_then(Item::as_integer)
                    .and_then(|value| u64::try_from(value).ok())
            };

            peers.insert(
                name.to_string(),
                A2aOutboundPeerConfig {
                    url: string("url").unwrap_or_default(),
                    token: string("token").unwrap_or_else(|| defaults.token.clone()),
                    timeout_secs: integer("timeout_secs").unwrap_or(defaults.timeout_secs),
                    poll_interval_ms: integer("poll_interval_ms")
                        .unwrap_or(defaults.poll_interval_ms),
                    poll_timeout_secs: integer("poll_timeout_secs")
                        .unwrap_or(defaults.poll_timeout_secs),
                },
            );
        }

        A2aOutboundConfig { peers }
    }

    /// Replace `[a2a.outbound.peers]` in the document and publish it.
    ///
    /// **Blocking**: the route calls this through
    /// [`tokio::task::spawn_blocking`] with the whole [`ConfigFile`], because
    /// `write_all`, `sync_all`, `set_permissions` and `rename` are all syscalls
    /// and `sync_all` on a slow volume can take hundreds of milliseconds.
    fn write(&mut self, outbound: &A2aOutboundConfig) -> Result<(), PersistError> {
        set_outbound_peers(&mut self.document, outbound).map_err(PersistError::Failed)?;

        let rendered = self.document.to_string();

        write_replacing(&self.target, rendered.as_bytes(), &self.metadata)
            .map_err(PersistError::Failed)
    }
}

/// The path a write should actually target: `path` with every symlink resolved.
///
/// `rename(2)` replaces the **link**, not what it points at. Writing to the path
/// as given would therefore silently turn a symlinked `config.toml` into a
/// regular file, leave the real configuration holding its old bytes, and copy
/// every secret into a new inode without the target's ownership or ACLs.
/// Symlinking a gitignored credentials file into a dotfiles repository is a
/// normal setup, and destroying it on the first dashboard save is not something
/// an operator would expect from a "saved" response.
///
/// Resolving the link and operating on the real file keeps the link intact and
/// the write atomic: the temporary file is created in the *real* target's
/// directory, so the rename that publishes it stays within one filesystem, and
/// the link simply points at the updated file afterwards.
///
/// Writing *through* the link instead (`File::create(path)` and truncate) is the
/// alternative that must not be taken: it is not atomic, and a crash halfway
/// through leaves the operator with a truncated `config.toml` — a bot that does
/// not start.
///
/// `symlink_metadata` rather than `metadata` for the existence check, because a
/// **dangling** symlink has to be refused exactly like a missing file: this
/// route must not create a `config.toml`, and writing to the link's target would
/// create one.
fn resolve_target(path: &Path) -> Result<PathBuf, PersistError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PersistError::MissingFile)
        }
        Err(error) => {
            return Err(PersistError::Failed(
                anyhow::Error::new(error).context(format!("{} could not be read", path.display())),
            ))
        }
    }

    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        // A dangling link: the path exists, what it names does not.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(PersistError::MissingFile)
        }
        Err(error) => Err(PersistError::Failed(anyhow::Error::new(error).context(
            format!("{} could not be resolved to a real file", path.display()),
        ))),
    }
}

/// Replace the `[a2a.outbound.peers]` table of `document`, and nothing else.
///
/// An empty peer set removes the table rather than writing an empty one, and
/// does not create an `[a2a]` section in a file that has none.
fn set_outbound_peers(
    document: &mut DocumentMut,
    outbound: &A2aOutboundConfig,
) -> anyhow::Result<()> {
    // Sorted so the written file is stable: `peers` is a `HashMap`, whose
    // iteration order is randomized per process, and a file whose peer order
    // changed on every save would produce meaningless diffs.
    let mut names: Vec<&String> = outbound.peers.keys().collect();
    names.sort();

    if names.is_empty() {
        if let Some(table) = document
            .get_mut("a2a")
            .and_then(Item::as_table_mut)
            .and_then(|a2a| a2a.get_mut("outbound"))
            .and_then(Item::as_table_mut)
        {
            table.remove("peers");
        }
        return Ok(());
    }

    let a2a = table_entry(document.as_table_mut(), "a2a").ok_or_else(|| {
        anyhow::anyhow!("the [a2a] entry in the configuration file is not a table")
    })?;
    let outbound_table = table_entry(a2a, "outbound").ok_or_else(|| {
        anyhow::anyhow!("the [a2a.outbound] entry in the configuration file is not a table")
    })?;

    // Implicit so the file gains `[a2a.outbound.peers.<name>]` headers and no
    // bare `[a2a.outbound.peers]` line that was not there before.
    let mut peers = Table::new();
    peers.set_implicit(true);

    for name in names {
        let peer = &outbound.peers[name];
        let mut entry = Table::new();
        entry.insert("url", toml_edit::value(peer.url.clone()));
        entry.insert("token", toml_edit::value(peer.token.clone()));
        entry.insert(
            "timeout_secs",
            toml_edit::value(toml_integer(peer.timeout_secs, "timeout_secs", name)?),
        );
        entry.insert(
            "poll_interval_ms",
            toml_edit::value(toml_integer(
                peer.poll_interval_ms,
                "poll_interval_ms",
                name,
            )?),
        );
        entry.insert(
            "poll_timeout_secs",
            toml_edit::value(toml_integer(
                peer.poll_timeout_secs,
                "poll_timeout_secs",
                name,
            )?),
        );
        peers.insert(name, Item::Table(entry));
    }

    // Replacing the key wholesale is what removes every sub-table of the old
    // value: a peer dropped from the set must not survive in the file.
    outbound_table.insert("peers", Item::Table(peers));
    Ok(())
}

/// A `u64` as a TOML integer, which is signed 64-bit.
///
/// The route refuses an out-of-range value before it gets here; this is the
/// belt to that pair of braces, so no path through this module can write a
/// negative timeout into the operator's configuration file.
fn toml_integer(value: u64, field: &str, peer: &str) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| {
        anyhow::anyhow!(
            "A2A outbound peer '{peer}' {field} is too large to write to the configuration file"
        )
    })
}

/// The `key` table inside `parent`, created implicit when it is absent.
///
/// Implicit so a file that never had an `[a2a]` header does not gain one: the
/// only thing this module writes is the peers table the operator asked for.
///
/// `None` when the entry exists but is not a table (`a2a = 5`). That is a file
/// this route cannot edit surgically, so it fails rather than replacing it.
fn table_entry<'a>(parent: &'a mut Table, key: &str) -> Option<&'a mut Table> {
    if !parent.contains_key(key) {
        let mut table = Table::new();
        table.set_implicit(true);
        parent.insert(key, Item::Table(table));
    }
    parent.get_mut(key).and_then(Item::as_table_mut)
}

/// Write `contents` over `path` atomically, keeping `metadata`'s permissions.
///
/// The temporary file is created in the target's own directory, because
/// `rename` is only atomic within one filesystem — a temporary in `/tmp` would
/// turn the rename into a copy. It is created owner-only and then given the
/// original file's mode, so the replacement is never briefly world-readable:
/// `config.toml` holds the Telegram token, the OpenRouter key and every peer
/// token, and an owner-only file must stay owner-only.
///
/// A failure leaves no temporary file behind.
fn write_replacing(
    path: &Path,
    contents: &[u8],
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("the configuration path has no file name"))?
        .to_string_lossy()
        .into_owned();

    // Unique per attempt: the process id keeps two instances apart, the
    // timestamp keeps two writes in one process apart (they are already
    // serialised by the state's mutex).
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let temporary = directory.join(format!(".{file_name}.{}.{unique}.tmp", std::process::id()));

    match write_and_rename(&temporary, path, contents, metadata, directory) {
        Ok(()) => Ok(()),
        Err(error) => {
            // Leave the operator's configuration directory as it was found.
            match std::fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => {}
                Err(cleanup) => {
                    tracing::warn!(error = %cleanup, "web: a temporary config file could not be removed")
                }
            }
            Err(error)
        }
    }
}

/// The body of [`write_replacing`]: create, fill, fsync, chmod, rename.
fn write_and_rename(
    temporary: &Path,
    target: &Path,
    contents: &[u8],
    metadata: &std::fs::Metadata,
    directory: &Path,
) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Owner-only from the instant it exists, so the credentials it is about
        // to hold are never exposed even between create and chmod.
        options.mode(0o600);
    }

    let mut file = options
        .open(temporary)
        .with_context(|| format!("{} could not be created", temporary.display()))?;
    file.write_all(contents)
        .with_context(|| format!("{} could not be written", temporary.display()))?;
    // On disk before the rename: a full disk must fail here, while the old
    // `config.toml` is still the one in place.
    file.sync_all()
        .with_context(|| format!("{} could not be flushed to disk", temporary.display()))?;
    drop(file);

    // The original file's mode, copied onto the replacement before it is
    // published.
    std::fs::set_permissions(temporary, metadata.permissions()).with_context(|| {
        format!(
            "{} could not be given the permissions of the file it replaces",
            temporary.display()
        )
    })?;

    std::fs::rename(temporary, target)
        .with_context(|| format!("{} could not be replaced", target.display()))?;

    // Flush the directory entry too, so the rename itself survives a power
    // loss. Reported but not fatal: the rename has already happened, and
    // reporting a failed write here would tell the caller nothing changed when
    // the file on disk has changed.
    if let Err(error) = sync_directory(directory) {
        tracing::warn!(
            error = %error,
            "web: the configuration file was replaced but its directory could not be flushed"
        );
    }

    Ok(())
}

/// Flush a directory entry. A no-op where opening a directory is not a thing.
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// A short, redacted, bounded explanation of a failed connection test.
///
/// The anyhow chain is never returned: it carries a URL, an OS error and
/// sometimes a header value. A `reqwest` error anywhere in the chain is
/// classified into one phrase; anything else is the outermost message
/// `A2aClient::discover` wrote itself ("agent card request returned HTTP 404",
/// "invalid agent card response", "agent card has no compatible JSON-RPC 1.0
/// interface with a valid URL").
fn test_failure_reason(err: &anyhow::Error, token: &str) -> String {
    let reason = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<reqwest_client::Error>())
        .map(|error| {
            if error.is_timeout() {
                "the request timed out".to_string()
            } else if error.is_connect() {
                "the connection could not be established".to_string()
            } else if let Some(status) = error.status() {
                format!("the peer answered HTTP {status}")
            } else {
                err.to_string()
            }
        })
        .unwrap_or_else(|| err.to_string());

    bounded_reason(&reason, &[token.to_string()])
}

/// Redact `secrets` out of `reason`, strip control characters, and bound its
/// length.
///
/// The control-character pass is not cosmetic. The reason is logged
/// (`tracing::warn!(reason = %reason, …)` in [`test_peer`] and the `tracing::error!`
/// in [`start_listener`]), and part of it is derived from the operator's own
/// `config.toml`: `A2aOutboundPeerConfig::validate` and `A2aConfig::validate`
/// both name the offending peer, and a peer name in a hand-edited file may
/// contain a newline. A newline in a log message forges a second log line —
/// exactly what [`log_safe`] exists to prevent for the caller-supplied name, and
/// the config-derived path needs the same treatment.
///
/// `truncate` cuts on a character boundary, so a multi-byte name cannot be
/// split into invalid UTF-8.
fn bounded_reason(reason: &str, secrets: &[String]) -> String {
    let mut redacted = reason.to_string();
    for secret in secrets {
        if !secret.is_empty() && redacted.contains(secret.as_str()) {
            redacted = redacted.replace(secret.as_str(), "[REDACTED]");
        }
    }
    sanitize(&redacted, MAX_REASON_CHARS)
}

/// First six hex characters of the SHA-256 digest of `token`.
///
/// The same shape as `Credentials::bearer_fingerprint`: six hex characters of
/// a digest identify a value the operator already holds and do not narrow a
/// search for it in any useful way. The token itself is never returned, and an
/// empty token has no fingerprint.
fn fingerprint(token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let digest = Sha256::digest(token.as_bytes());
    Some(format!("{digest:x}").chars().take(6).collect())
}

/// Truncate to `max` characters, marking that it happened.
fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut truncated: String = value.chars().take(max).collect();
    truncated.push('…');
    truncated
}

/// Peer names a `PUT` accepts.
///
/// Restricted so that a name cannot carry a newline into a log line, cannot be
/// empty, and cannot make a response or an error message unbounded. Names in
/// `config.toml` are not restricted this way — a hand-written file is the
/// operator's own business, and this route fails closed on anything it would
/// have to echo into a log.
fn valid_peer_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_PEER_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// A caller-supplied string made safe to put in a log line.
///
/// `POST /api/a2a/test` logs the peer name it was given, and that name comes
/// straight from the request body: a newline in it would forge a second line
/// in the dashboard's log view. Control characters are replaced and the result
/// is bounded, so one request can produce exactly one log line.
fn log_safe(value: &str) -> String {
    sanitize(value, MAX_PEER_NAME_CHARS)
}

/// A caller-supplied string made safe to echo into a response body.
///
/// `POST /api/a2a/test` echoes the name it was given back to the caller, and
/// the name is arbitrary request text: unbounded, it would let one request
/// return a body of any size. Bounded to [`MAX_ECHOED_CHARS`] — the same bound
/// every remote-card string gets — and stripped of control characters, so the
/// echoed value cannot carry a newline into a terminal that prints it.
///
/// This is what the "the name is never echoed" claim in the module's earlier
/// documentation got wrong: it is echoed, in three of the four branches, so it
/// has to be bounded rather than asserted away.
fn echo_safe(value: &str) -> String {
    sanitize(value, MAX_ECHOED_CHARS)
}

/// Replace every control character with `?` and bound the result to `max`
/// characters.
///
/// The single implementation behind [`log_safe`], [`echo_safe`] and the
/// config-derived path in [`bounded_reason`], so the three cannot drift apart.
fn sanitize(value: &str, max: usize) -> String {
    let printable: String = value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    truncate(&printable, max)
}

/// The tool names the live registry exposes, for expanding a peer's `["*"]`.
///
/// `None` — a dashboard started without an agent — yields an empty list, which
/// [`peer_tool_policy`] treats as "cannot be expanded" rather than as "no
/// tools".
fn available_tool_names(agent: Option<&Agent>) -> Vec<String> {
    match agent {
        Some(agent) => agent
            .all_tool_definitions()
            .into_iter()
            .map(|definition| definition.function.name)
            .collect(),
        None => Vec::new(),
    }
}

/// Report a peer's tool policy as configured and as applied.
///
/// The resolution is [`resolve_allowed_tools`] itself, so the two conventions
/// (`None` = conservative default here, `["*"]` = nothing there) cannot be
/// translated into one another by a second implementation.
fn peer_tool_policy(name: &str, peer: &A2aPeerConfig, available: &[String]) -> ToolPolicyView {
    let source = match &peer.tools {
        None => "default",
        Some(list) if list.len() == 1 && list[0] == "*" => "wildcard",
        Some(list) if list.iter().any(|tool| tool == "*") => "explicit_wildcard_ignored",
        Some(_) => "explicit",
    };

    // The wildcard is the one case whose result depends on the live registry.
    // `resolve_allowed_tools` returns an empty list for it when `available` is
    // empty — the trap `PeerIdentity::allowed_tools` documents — and reporting
    // that empty list as "what applies" would be exactly the lie this view
    // exists to prevent.
    if source == "wildcard" && available.is_empty() {
        return ToolPolicyView {
            configured: peer.tools.clone(),
            source,
            effective: None,
            effective_unavailable: Some(
                "the dashboard was started without an agent, so the live tool registry cannot \
                 be consulted and \"*\" cannot be expanded",
            ),
        };
    }

    ToolPolicyView {
        configured: peer.tools.clone(),
        source,
        effective: Some(resolve_allowed_tools(name, peer, available)),
        effective_unavailable: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{FunctionDefinition, ToolDefinition};
    use crate::tool_registry::{ToolContext, ToolHandler, ToolResult};

    /// A handler that exists only to put names in the registry.
    struct NamedTools(Vec<&'static str>);

    #[async_trait::async_trait]
    impl ToolHandler for NamedTools {
        fn define(&self) -> Vec<ToolDefinition> {
            self.0
                .iter()
                .map(|name| ToolDefinition {
                    tool_type: "function".to_string(),
                    function: FunctionDefinition {
                        name: (*name).to_string(),
                        description: "test tool".to_string(),
                        parameters: serde_json::json!({ "type": "object", "properties": {} }),
                    },
                })
                .collect()
        }

        async fn execute(
            &self,
            name: &str,
            _args: serde_json::Value,
            _ctx: ToolContext,
        ) -> ToolResult {
            Ok(format!("executed {name}"))
        }
    }

    /// The registry names a wildcard peer would receive, built the way
    /// `A2aExecutor::policy_for` builds them.
    fn registry_names() -> Vec<String> {
        let mut registry = crate::tool_registry::ToolRegistry::new();
        registry.register(Box::new(NamedTools(vec!["read_file", "execute_command"])));
        registry
            .all_definitions()
            .into_iter()
            .map(|definition| definition.function.name)
            .collect()
    }

    fn peer(tools: Option<Vec<&str>>) -> A2aPeerConfig {
        A2aPeerConfig {
            token: "peer-token".to_string(),
            ip: vec!["10.0.0.5".to_string()],
            tools: tools.map(|list| list.into_iter().map(str::to_string).collect()),
        }
    }

    #[test]
    fn an_absent_tools_key_reports_the_conservative_default() {
        let available = registry_names();
        let view = peer_tool_policy("p", &peer(None), &available);

        assert_eq!(view.source, "default");
        assert_eq!(view.configured, None);
        let effective = view.effective.expect("the default is always computable");
        assert_eq!(
            effective,
            resolve_allowed_tools("p", &peer(None), &available)
        );
        assert!(
            !effective.contains(&"execute_command".to_string()),
            "an absent `tools` key must never grant shell, got {effective:?}"
        );
    }

    #[test]
    fn a_lone_wildcard_reports_every_registry_tool_not_an_empty_list() {
        // The trap: `["*"]` here grants *every* tool, including
        // `execute_command`, while the same literal in `LoopConfig.allowed_tools`
        // grants nothing. Reporting the loop's reading would be a dangerous lie.
        let available = registry_names();
        assert!(
            available.contains(&"execute_command".to_string()),
            "the test registry must hold a shell tool for this to mean anything"
        );

        let view = peer_tool_policy("p", &peer(Some(vec!["*"])), &available);

        assert_eq!(view.source, "wildcard");
        let effective = view.effective.expect("the registry is available");
        assert_eq!(effective, available);
        assert!(
            effective.contains(&"execute_command".to_string()),
            "the wildcard grants shell and the view must say so, got {effective:?}"
        );
        assert!(!effective.is_empty(), "the wildcard is not an empty grant");
    }

    #[test]
    fn a_mixed_wildcard_is_reported_as_the_literal_list() {
        // `resolve_allowed_tools` returns a mixed list verbatim — including the
        // `"*"` entry, which matches no handler — so the wildcard is *not*
        // expanded. The property that matters is that the peer does not receive
        // every tool.
        let available = registry_names();
        let view = peer_tool_policy("p", &peer(Some(vec!["read_file", "*"])), &available);

        assert_eq!(view.source, "explicit_wildcard_ignored");
        assert_eq!(
            view.effective,
            Some(vec!["read_file".to_string(), "*".to_string()])
        );
        let effective = view
            .effective
            .expect("an explicit list is always computable");
        assert!(
            !effective.contains(&"execute_command".to_string()),
            "a mixed wildcard must never be a full grant, got {effective:?}"
        );
    }

    #[test]
    fn an_explicit_empty_list_reports_no_tools() {
        let available = registry_names();
        let view = peer_tool_policy("p", &peer(Some(vec![])), &available);

        assert_eq!(view.source, "explicit");
        assert_eq!(view.effective, Some(Vec::new()));
    }

    #[test]
    fn a_wildcard_without_a_registry_is_unavailable_rather_than_empty() {
        // `resolve_allowed_tools` returns an empty list for a wildcard against
        // an empty registry. Reporting that as "what applies" would tell an
        // operator their full-grant peer has no tools at all.
        let view = peer_tool_policy("p", &peer(Some(vec!["*"])), &[]);

        assert_eq!(view.source, "wildcard");
        assert_eq!(view.effective, None);
        assert!(
            view.effective_unavailable.is_some(),
            "an unavailable expansion must say why"
        );
    }

    #[test]
    fn fingerprints_are_short_digests_and_never_the_token() {
        let token = "super-secret-peer-token";
        let print = fingerprint(token).expect("a non-empty token has a fingerprint");

        assert_eq!(print.len(), 6);
        assert!(print.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!token.contains(&print), "the fingerprint is not a prefix");
        assert_eq!(fingerprint(token).as_deref(), Some(print.as_str()));
        assert_ne!(fingerprint(token), fingerprint("another-token"));
        assert_eq!(fingerprint(""), None, "an empty token has no fingerprint");
    }

    #[test]
    fn a_failure_reason_is_bounded_and_redacted() {
        let token = "peer-token-abcdef";
        let err = anyhow::anyhow!("request failed with header bearer {token}");

        let reason = test_failure_reason(&err, token);

        assert!(
            !reason.contains(token),
            "the token must be redacted: {reason}"
        );
        assert!(reason.contains("[REDACTED]"));

        let long = anyhow::anyhow!("x".repeat(MAX_REASON_CHARS * 2));
        let bounded = test_failure_reason(&long, token);
        assert!(bounded.chars().count() <= MAX_REASON_CHARS + 1);
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let value = "é".repeat(10);
        let truncated = truncate(&value, 3);
        assert_eq!(truncated.chars().count(), 4);
        assert!(truncated.starts_with("ééé"));
    }

    #[test]
    fn peer_names_that_could_carry_a_newline_are_refused() {
        assert!(valid_peer_name("laptop"));
        assert!(valid_peer_name("lab-2.eu_1"));
        assert!(!valid_peer_name(""));
        assert!(!valid_peer_name("bad\nname"));
        assert!(!valid_peer_name("bad name"));
        assert!(!valid_peer_name(&"n".repeat(MAX_PEER_NAME_CHARS + 1)));
    }

    #[test]
    fn a_caller_supplied_name_cannot_forge_a_log_line() {
        let forged = log_safe("beta\nweb: A2A listener started");

        assert!(
            !forged.contains('\n'),
            "a newline would forge a second log line: {forged:?}"
        );
        assert!(log_safe("beta") == "beta");
        assert!(log_safe(&"n".repeat(500)).chars().count() <= MAX_PEER_NAME_CHARS + 1);
    }

    #[test]
    fn the_connection_test_timeout_is_capped_below_the_peer_setting() {
        // No file is ever written by this test; the path only has to exist as a
        // value. Nothing here may point at a real configuration file.
        let state = A2aWebState::new(
            A2aConfig::default(),
            A2aListenerOutcome::Disabled,
            std::sync::Arc::new(tokio::sync::RwLock::new(A2aOutboundConfig::default())),
            std::path::PathBuf::from("/nonexistent/config.toml"),
        );

        let patient = A2aOutboundPeerConfig {
            timeout_secs: 86_400,
            ..A2aOutboundPeerConfig::default()
        };
        assert_eq!(
            state.test_timeout(&patient),
            DEFAULT_CONNECTION_TEST_TIMEOUT
        );

        let quick = A2aOutboundPeerConfig {
            timeout_secs: 3,
            ..A2aOutboundPeerConfig::default()
        };
        assert_eq!(state.test_timeout(&quick), Duration::from_secs(3));

        // `validate` refuses 0, but a state built by hand must not produce a
        // zero-length timeout that would fail every test.
        let zero = A2aOutboundPeerConfig {
            timeout_secs: 0,
            ..A2aOutboundPeerConfig::default()
        };
        assert_eq!(state.test_timeout(&zero), Duration::from_secs(1));

        let impatient = state.with_connection_test_timeout(Duration::from_millis(200));
        assert_eq!(impatient.test_timeout(&patient), Duration::from_secs(1));
    }

    // ── Persisting [a2a.outbound.peers] ─────────────────────────────────────

    /// A configuration file with the properties that matter: comments of every
    /// kind (whole-line, inline, a box-drawing separator), unrelated sections
    /// before and after the outbound peers, and two peers inside the table the
    /// route rewrites.
    const FIXTURE: &str = r#"# HaosGreen configuration.
# The comments in this file belong to the operator; the dashboard must not eat them.
[telegram]
bot_token = "telegram-secret-token"   # inline comment, kept
allowed_user_ids = [1, 2]

# ── A2A ──────────────────────────────────────────────────────────────
[a2a]
enabled = true

[a2a.card]
name = "HaosGreen"
version = "1.0.2"

[a2a.outbound.peers.beta]
url = "http://127.0.0.1:9001"    # the old url
token = "beta-old-token"
timeout_secs = 2

[a2a.outbound.peers.gamma]
url = "http://127.0.0.1:9002"
token = "gamma-old-token"

# The web dashboard.
[web]
enabled = true
bind = "127.0.0.1:8787"
"#;

    /// An outbound configuration holding one peer per name.
    fn peers(names: &[&str]) -> A2aOutboundConfig {
        let mut outbound = A2aOutboundConfig::default();
        for name in names {
            outbound.peers.insert(
                (*name).to_string(),
                A2aOutboundPeerConfig {
                    url: format!("http://127.0.0.1:9/{name}"),
                    token: format!("{name}-token"),
                    timeout_secs: 5,
                    poll_interval_ms: 25,
                    poll_timeout_secs: 5,
                },
            );
        }
        outbound
    }

    /// `text` with its `[a2a.outbound.peers]` table removed.
    ///
    /// `toml_edit` round-trips a document it has not changed byte-for-byte, so
    /// comparing these two strings compares every *other* byte of the file.
    fn without_outbound_peers(text: &str) -> String {
        let mut document: DocumentMut = text.parse().expect("valid TOML");
        if let Some(table) = document
            .get_mut("a2a")
            .and_then(Item::as_table_mut)
            .and_then(|a2a| a2a.get_mut("outbound"))
            .and_then(Item::as_table_mut)
        {
            table.remove("peers");
        }
        document.to_string()
    }

    /// The names of the files in `directory`, sorted.
    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .expect("the directory should be readable")
            .map(|entry| {
                entry
                    .expect("a directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_edit_touches_only_the_outbound_peers_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, FIXTURE).unwrap();

        persist_outbound(&path, &peers(&["beta"])).expect("the write should succeed");
        let after = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            without_outbound_peers(FIXTURE),
            without_outbound_peers(&after),
            "the edit must change nothing but [a2a.outbound.peers]\n--- after ---\n{after}"
        );

        // Every comment outside the replaced table survives, including the
        // inline one on a line this route never touches and the one directly
        // above the section it rewrites.
        for comment in [
            "# HaosGreen configuration.",
            "# The comments in this file belong to the operator; the dashboard must not eat them.",
            "# inline comment, kept",
            "# ── A2A ──",
            "# The web dashboard.",
        ] {
            assert!(
                after.contains(comment),
                "the comment {comment:?} was lost:\n{after}"
            );
        }

        // The boundary of that guarantee: a comment *inside* the replaced table
        // annotates an entry that was replaced, so it goes with it. Pinned here
        // so that a future change which starts preserving such comments is a
        // deliberate one rather than an accident.
        assert!(
            !after.contains("# the old url"),
            "a comment attached to a replaced peer entry is not preserved:\n{after}"
        );

        // The replacement is complete: the rewritten peer's new values are in,
        // and a peer dropped from the set is gone rather than merged.
        assert!(after.contains("beta-token"));
        assert!(!after.contains("beta-old-token"), "{after}");
        assert!(!after.contains("gamma-old-token"), "{after}");
        assert!(
            !after.contains("[a2a.outbound.peers.gamma]"),
            "a peer removed from the set must not survive in the file:\n{after}"
        );
    }

    #[test]
    fn a_successful_write_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, FIXTURE).unwrap();

        persist_outbound(&path, &peers(&["beta"])).expect("the write should succeed");

        assert_eq!(
            entries(dir.path()),
            vec!["config.toml".to_string()],
            "the temporary file must have been renamed, not left behind"
        );
    }

    #[test]
    fn a_failed_rename_leaves_the_target_alone_and_no_temporary_file_behind() {
        // The failure is injected at the last step of the atomic write: `rename`
        // cannot replace a directory. That is the step where a half-written file
        // could otherwise be published, and it is also where the cleanup of the
        // temporary file has to work.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep-me"), b"x").unwrap();
        let metadata = std::fs::metadata(&target).unwrap();

        let error = write_replacing(&target, b"new contents", &metadata).unwrap_err();

        assert!(
            format!("{error:#}").contains("could not be replaced"),
            "{error:#}"
        );
        assert!(target.is_dir(), "the target must be untouched");
        assert_eq!(
            std::fs::read_dir(&target).unwrap().count(),
            1,
            "the target's contents must be untouched"
        );
        assert_eq!(
            entries(dir.path()),
            vec!["config.toml".to_string()],
            "a failed write must not leave its temporary file behind"
        );
    }

    #[test]
    fn a_missing_configuration_file_is_refused_rather_than_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let error = persist_outbound(&path, &peers(&["delta"])).unwrap_err();

        assert!(matches!(error, PersistError::MissingFile));
        assert!(
            !path.exists(),
            "a file holding only [a2a.outbound.peers] is a config the process cannot start from, \
             so this route must not create one"
        );
        assert!(
            entries(dir.path()).is_empty(),
            "nothing may be written at all"
        );
        // The message the dashboard returns names no path.
        assert!(!error.client_message().contains('/'));
        assert!(error.client_message().contains("does not exist"));
    }

    #[test]
    fn an_unparseable_configuration_file_is_left_exactly_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let broken = "this is not = = toml\n";
        std::fs::write(&path, broken).unwrap();

        let error = persist_outbound(&path, &peers(&["delta"])).unwrap_err();

        assert!(matches!(error, PersistError::Failed(_)));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            broken,
            "a file this route cannot parse must not be rewritten"
        );
        assert_eq!(entries(dir.path()), vec!["config.toml".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn the_replacement_keeps_the_original_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        // Deliberately **not** `0o600`. The temporary file is created `0o600`, so
        // a fixture in that mode would make this assertion pass whether or not
        // `set_permissions` ever runs — it would be measuring the creation mode,
        // not the preservation. `0o640` is a mode the creation cannot produce, so
        // the only way to observe it afterwards is to have copied it across.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        persist_outbound(&path, &peers(&["delta"])).expect("the write should succeed");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o640,
            "config.toml holds the Telegram token and every peer token; the replacement must \
             carry the original file's mode, got {mode:o}"
        );
    }

    /// The write publishes by `rename`, and nothing else observed that.
    ///
    /// Every other test here asserts the *end state* — the target's contents, no
    /// leftover temporary, the error text on failure — and an in-place
    /// truncate-and-write satisfies all of them. Dropping the `rename` therefore
    /// left the whole suite green while silently giving up atomicity, which is
    /// the property that stops a crash or a full disk from leaving a truncated
    /// `config.toml` behind. A `rename` replaces the directory entry, so the
    /// inode changes; an in-place write keeps it. That is the difference this
    /// test measures, and it is the only thing that distinguishes the two.
    #[cfg(unix)]
    #[test]
    fn the_write_publishes_by_rename_rather_than_writing_in_place() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        let before = std::fs::metadata(&path).unwrap().ino();

        persist_outbound(&path, &peers(&["delta"])).expect("the write should succeed");

        let after = std::fs::metadata(&path).unwrap().ino();
        assert_ne!(
            before, after,
            "the target must be replaced, not written in place: a crash part-way through an \
             in-place write leaves a truncated config.toml, which is exactly what the temporary \
             file and the rename exist to prevent"
        );
        assert_eq!(entries(dir.path()), vec!["config.toml".to_string()]);
    }

    /// A symlinked `config.toml` is written **through**, not replaced.
    ///
    /// `rename` replaces the directory entry it is given, so writing to the path
    /// as given would turn a symlink into a regular file: the link is destroyed,
    /// the operator's real configuration keeps the old bytes, and the secrets are
    /// copied into a new inode without the target's ownership or ACLs. Pointing a
    /// gitignored credentials file at a dotfiles repository is an ordinary thing
    /// to do, so this is the case the route has to get right.
    ///
    /// The mode is `0o640` for the same reason as the test above: `0o600` is the
    /// temporary file's creation mode and would prove nothing.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_configuration_file_is_written_through_not_replaced() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-config.toml");
        let link = dir.path().join("config.toml");
        std::fs::write(&real, FIXTURE).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&real, &link).unwrap();

        persist_outbound(&link, &peers(&["delta"])).expect("the write should succeed");

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the operator's symlink must survive a save; replacing it with a regular file would \
             silently leave the real configuration stale"
        );
        let written = std::fs::read_to_string(&real).unwrap();
        assert!(
            written.contains("[a2a.outbound.peers.delta]"),
            "the write must land in the file the symlink names, not in the link: {written}"
        );
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o640,
            "the real file's mode must be carried onto the replacement"
        );
        // The temporary is created beside the real file, so the link's directory
        // holds the link and nothing else.
        assert_eq!(
            entries(dir.path())
                .iter()
                .filter(|n| n.ends_with(".tmp"))
                .count(),
            0,
            "no temporary file may be left behind"
        );
    }

    #[test]
    fn an_empty_peer_set_removes_the_table_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, FIXTURE).unwrap();

        persist_outbound(&path, &A2aOutboundConfig::default()).expect("the write should succeed");
        let after = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            without_outbound_peers(FIXTURE),
            without_outbound_peers(&after)
        );
        assert!(!after.contains("beta-old-token"), "{after}");
        assert!(!after.contains("a2a.outbound.peers"), "{after}");
        assert!(after.contains("[a2a.card]"), "{after}");
    }

    #[test]
    fn a_file_with_no_a2a_section_gains_only_the_peers_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let minimal = "# keep me\n[telegram]\nbot_token = \"t\"\n";
        std::fs::write(&path, minimal).unwrap();

        persist_outbound(&path, &peers(&["delta"])).expect("the write should succeed");
        let after = std::fs::read_to_string(&path).unwrap();

        assert!(
            after.starts_with(minimal),
            "the original bytes are a prefix:\n{after}"
        );
        assert!(after.contains("[a2a.outbound.peers.delta]"), "{after}");
        assert!(
            !after.contains("[a2a]\n") && !after.contains("[a2a.outbound]\n"),
            "no bare parent header may be invented:\n{after}"
        );
    }

    #[test]
    fn an_out_of_range_setting_is_refused_rather_than_written_as_a_negative_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, FIXTURE).unwrap();

        let mut outbound = peers(&["delta"]);
        outbound
            .peers
            .get_mut("delta")
            .expect("the delta peer")
            .timeout_secs = u64::MAX;

        let error = persist_outbound(&path, &outbound).unwrap_err();

        assert!(matches!(error, PersistError::Failed(_)));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            FIXTURE,
            "TOML integers are signed; writing u64::MAX would produce a negative timeout the \
             operator's next start could not load"
        );
    }
}
