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
pub mod client;
pub mod executor;
pub mod policy;
pub mod server;
pub mod task_store;
pub mod tool;

pub use auth::{authenticate, AuthError, PeerIdentity};
pub use executor::{A2aExecutor, NoopExecutor};
pub use policy::{resolve_allowed_tools, DEFAULT_PEER_TOOLS};
pub use task_store::SqliteTaskStore;
pub use tool::{CallA2aAgent, SharedOutboundConfig};

#[cfg(test)]
mod dependency_probe {
    use std::sync::Arc;

    use a2a_client::agent_card::AgentCardResolver;
    use a2a_client::auth::AuthInterceptor;
    use a2a_client::{A2AClient, A2AClientFactory, Transport};

    /// Type-level only: proves `a2a-server-lf` is wired under the expected
    /// crate name and that the three items Phase 2 depends on exist with the
    /// expected bounds. Phase 1 added `a2a-lf` for the types; this is the
    /// server half.
    #[test]
    fn sdk_server_items_are_reachable() {
        fn _assert_handler<H: a2a_server::RequestHandler>() {}
        fn _assert_executor<E: a2a_server::AgentExecutor>() {}
        fn _assert_store<S: a2a_server::TaskStore>() {}
        // `DefaultRequestHandler::new` takes (executor, task_store); only the
        // bounds are asserted here, since Phase 2 supplies the executor later.
        fn _assert_constructible<E: a2a_server::AgentExecutor, S: a2a_server::TaskStore>() {
            let _ = |e: E, s: S| a2a_server::DefaultRequestHandler::new(e, s);
        }
        let _ = a2a_server::jsonrpc::jsonrpc_router::<a2a_server::DefaultRequestHandler>;
    }

    /// Type-level only: proves the Phase 5 client SDK's public APIs are
    /// reachable under the expected crate name and module paths. The SDK's
    /// transport trait is sealed behind its public factory API, so this probe
    /// intentionally verifies factory/interceptor construction rather than
    /// inventing a concrete transport implementation.
    #[test]
    fn sdk_client_items_are_reachable() {
        fn _assert_client<T: Transport>() {
            let _: Option<A2AClient<T>> = None;
        }

        let auth = Arc::new(AuthInterceptor::bearer("probe-token"));
        let _factory: A2AClientFactory = A2AClientFactory::builder().with_interceptor(auth).build();
        let _ = AgentCardResolver::new(None);
    }
}
