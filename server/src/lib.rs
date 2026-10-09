//! Library surface for `mint-server`: state, configuration, and the Axum
//! handlers in `api`. `mintd` serves them over HTTP, and the PSP, ESP and
//! FSP repos reuse them and add their own routes.

pub mod api;
pub mod config;
pub mod state;
