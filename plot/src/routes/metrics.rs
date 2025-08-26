use axum::{
    Router,
    extract::State,
    response::{
        Html,
        Json,
    },
    routing::get,
};

use crate::{state::AppState, views, views::layout};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/json", get(metrics_json))
        .with_state(state)
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let metrics = state.get_metrics().await;
    Html(layout::page("Metrics", &views::metrics::page(&metrics)))
}

async fn metrics_json(State(state): State<AppState>) -> Json<crate::state::Metrics> {
    Json(state.get_metrics().await)
}