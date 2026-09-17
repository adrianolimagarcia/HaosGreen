//! Route modules for the dashboard.
//!
//! Two routers are exposed, and the split is a security boundary:
//!
//! * [`router`] holds everything that requires an authenticated session. It is
//!   mounted **inside** the `guard` layer.
//! * [`public_router`] holds everything that must be reachable without a
//!   session. It is mounted **outside** the `guard` layer, which means a
//!   handler mounted there is responsible for its own CSRF check.
//!
//! The only route on the public router is `/api/auth/login`: it mints sessions
//! and therefore cannot require one. Adding a route to `public_router` without
//! its own `middleware::csrf_ok` check silently reopens CSRF on a route that
//! hands out credentials.

pub mod auth_routes;
pub mod settings;

use axum::Router;

use crate::web::state::WebState;

/// Guarded routes: everything that requires a session or a bearer token.
///
/// The `/api/ping` placeholder from Task 6 is gone: `/api/settings` is a real
/// protected route, and the guard is covered by the integration tests against
/// it.
pub fn router() -> Router<WebState> {
    Router::new()
        .merge(auth_routes::router())
        .merge(settings::router())
}

/// Routes reachable without a session.
pub fn public_router() -> Router<WebState> {
    auth_routes::public_router()
}
