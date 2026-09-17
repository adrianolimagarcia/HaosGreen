//! Route modules for the dashboard.
//!
//! Two routers are exposed, and the split is a security boundary:
//!
//! * [`router`] holds everything that requires an authenticated session. It is
//!   mounted **inside** the `guard` layer.
//! * [`public_router`] holds everything that must be reachable without a
//!   session. It takes the `WebState` because it wraps itself in
//!   `middleware::public_guard` — the source-IP gate and the CSRF check — before
//!   returning. That guard is a layer, not a call inside each handler, so it
//!   runs *before* axum's extractors: a denied source is refused without the
//!   request body being parsed at all.
//!
//! The only route on the public router is `/api/auth/login`: it mints sessions
//! and therefore cannot require one. The layering lives in this module rather
//! than at the call site so that adding a route here cannot accidentally skip
//! the gate — a handler mounted on the public router is covered the moment it
//! is added.

pub mod auth_routes;
pub mod chat;
pub mod settings;

use axum::Router;

use crate::web::middleware;
use crate::web::state::WebState;

/// Guarded routes: everything that requires a session or a bearer token.
///
/// The `/api/ping` placeholder from Task 6 is gone: `/api/settings` is a real
/// protected route, and the guard is covered by the integration tests against
/// it.
pub fn router() -> Router<WebState> {
    Router::new()
        .merge(auth_routes::router())
        .merge(chat::router())
        .merge(settings::router())
}

/// Routes reachable without a session, already wrapped in the IP and CSRF
/// gates.
pub fn public_router(state: WebState) -> Router<WebState> {
    auth_routes::public_router().layer(axum::middleware::from_fn_with_state(
        state,
        middleware::public_guard,
    ))
}
