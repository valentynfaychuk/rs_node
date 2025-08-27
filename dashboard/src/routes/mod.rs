use ama_core::Context;
use axum::Router;
use std::sync::Arc;

//pub mod entries;
pub mod metrics;
pub mod peers;

pub fn app(ctx: Arc<Context>) -> Router {
    Router::new().nest("/peers", peers::router(ctx.clone())).nest("/metrics", metrics::router(ctx.clone()))
}
