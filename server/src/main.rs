//! `mintd`: one process, one key, a plain HTTP API.
//! Just `mint-core` (issuance/redemption logic) wired to Axum routes.

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use mint_server::api;
use mint_server::config::Settings;
use mint_server::state::AppState;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let settings = Settings::from_env()?;
    let bind_addr = settings.bind_addr.clone();
    let state: Arc<AppState> = Arc::new(AppState::init(&settings).await?);

    let app = Router::new()
        .route("/keys", get(api::get_keys))
        .route("/admin/issue", post(api::admin_issue))
        .route("/swap", post(api::swap))
        .route("/melt", post(api::melt))
        .route("/check-state", post(api::check_state))
        .route("/audit", get(api::audit))
        .with_state(state);

    info!(%bind_addr, "mintd listening");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
