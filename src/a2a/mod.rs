//! A2A (Agent2Agent) protocol support.
//!
//! Phase 1 covers the Agent Card, authentication and the per-peer tool policy.
//! See `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
//!
//! - [`card`] builds the public Agent Card served at
//!   `/.well-known/agent-card.json`.
//! - [`auth`] authenticates a peer from its bearer token and source address.
//! - [`policy`] resolves a peer's tool allowlist.
//! - [`server`] wires those into the axum listener that `main` starts when
//!   `[a2a].enabled` is set.

pub mod auth;
pub mod card;
pub mod policy;
pub mod server;

pub use auth::{authenticate, AuthError, PeerIdentity};
pub use policy::{resolve_allowed_tools, DEFAULT_PEER_TOOLS};
