use crate::views;
use ama_core::Context;
use axum::{
    Router,
    extract::State,
    response::{Html, Json},
    routing::get,
};
use serde_json::Value;
use std::sync::Arc;

pub fn router(ctx: Arc<Context>) -> Router {
    Router::new().route("/", get(index)).route("/json", get(metrics_json)).with_state(ctx)
}

async fn index(State(ctx): State<Arc<Context>>) -> Html<String> {
    Html(views::metrics::page(ctx.get_json_metrics()))
}

async fn metrics_json(State(ctx): State<Arc<Context>>) -> Json<Value> {
    Json(ctx.get_json_metrics())
}
