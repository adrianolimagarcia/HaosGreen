//! A2A (Agent2Agent) protocol support.
//!
//! Phase 1 covers the Agent Card, authentication and the per-peer tool policy.
//! See `docs/superpowers/specs/2026-09-16-a2a-client-server-design.md`.
//!
//! Each module is declared by the task that creates it: `auth` in Task 4,
//! `card` in Task 5, `server` in Task 6. Declaring them here now would not
//! compile, because those files do not exist yet.

pub mod auth;
pub mod card;
pub mod policy;
pub mod server;

pub use auth::{authenticate, AuthError, PeerIdentity};
pub use policy::{resolve_allowed_tools, DEFAULT_PEER_TOOLS};
