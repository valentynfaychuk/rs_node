pub mod models;
mod routes;
mod views {
    pub mod metrics;
    pub mod peers;
}

use ama_core::Context;
use axum::{response::Html, routing::get};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

pub async fn serve(socket: TcpListener, ctx: Arc<Context>) -> anyhow::Result<()> {
    let app = routes::app(ctx.clone())
        .route(
            "/",
            get(|| async {
                // Try to serve the simple dashboard first
                let simple_paths = [
                    "dashboard/static/simple-dashboard.html",
                    "../dashboard/static/simple-dashboard.html",
                    "./dashboard/static/simple-dashboard.html",
                    "static/simple-dashboard.html",
                ];

                for path in &simple_paths {
                    if let Ok(content) = tokio::fs::read_to_string(path).await {
                        return Html(content);
                    }
                }

                // Fallback: serve embedded simple dashboard HTML
                Html(get_embedded_simple_dashboard())
            }),
        )
        .route(
            "/advanced",
            get(|| async {
                // Try to serve the advanced React dashboard
                let advanced_paths = [
                    "dashboard/static/dashboard.html",
                    "../dashboard/static/dashboard.html",
                    "./dashboard/static/dashboard.html",
                    "static/dashboard.html",
                ];

                for path in &advanced_paths {
                    if let Ok(content) = tokio::fs::read_to_string(path).await {
                        return Html(content);
                    }
                }

                // Fallback: serve embedded advanced dashboard HTML
                Html(get_embedded_dashboard())
            }),
        )
        .nest_service("/static", ServeDir::new("dashboard/static"));

    axum::serve(socket, app).await.unwrap();
    Ok(())
}

fn get_embedded_simple_dashboard() -> String {
    // Embedded simple dashboard HTML - this ensures it always works
    include_str!("../static/simple-dashboard.html").to_string()
}

fn get_embedded_dashboard() -> String {
    // Embedded advanced dashboard HTML
    include_str!("../static/dashboard.html").to_string()
}
