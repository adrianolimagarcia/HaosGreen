//! Embedded web dashboard.
//!
//! Phase 1 (foundation) lives here: the `[web]` configuration, credential
//! storage, sessions, and the source-IP/login gates. The listener, router,
//! and route modules are added by the later phases of
//! `docs/superpowers/plans/2026-09-16-haos-green-web-dashboard.md`.

pub mod auth;
