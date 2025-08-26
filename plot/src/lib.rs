pub mod models;
mod routes;
pub mod state;
mod views {
    pub mod entries;
    pub mod entry;
    pub mod layout;
    pub mod metrics;
    pub mod peers;
}

use axum::{response::Html, routing::get};
use state::AppState;

pub async fn serve(_addr: &str, state: &AppState) -> anyhow::Result<()> {
    // demo data
    let app = routes::app(state.clone())
        // simple home page that links to sections
        .route(
            "/",
            get(|| async {
                Html(views::layout::page(
                    "Home",
                    r#"
            <h1>Node Overview</h1>
            <ul>
              <li><a href="/entries">Entries</a></li>
              <li><a href="/peers">Peers</a></li>
              <li><a href="/metrics">Metrics</a></li>
            </ul>
        "#,
                ))
            }),
        );

    let port: u16 = std::env::var("HTTP_PORT").ok().and_then(|s| s.parse::<u16>().ok()).unwrap_or(3000);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    println!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

#[allow(dead_code)]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
