pub mod models;
mod routes;
pub mod state;
mod views {
    pub mod entries;
    pub mod entry;
    pub mod layout;
    pub mod peers;
}

use axum::{response::Html, routing::get};
use state::AppState;

pub async fn serve(addr: &str, state: &AppState) -> anyhow::Result<()> {
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
            </ul>
        "#,
                ))
            }),
        );

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
