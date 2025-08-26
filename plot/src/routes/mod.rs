use crate::state::AppState;
use axum::Router;

pub mod entries;
pub mod metrics;
pub mod peers;

pub fn app(state: AppState) -> Router {
    Router::new()
        .nest("/peers", peers::router(state.clone()))
        .nest("/entries", entries::router(state.clone()))
        .nest("/metrics", metrics::router(state.clone()))
}
