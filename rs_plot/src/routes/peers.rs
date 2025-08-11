use async_stream::stream;
use axum::{
    Json, Router,
    extract::State,
    response::{
        Html,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use futures_core::Stream;
use std::{convert::Infallible, time::Duration};
use tokio::time::interval;

use crate::{models::Peer, state::AppState, views, views::layout};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/stream", get(stream_peers))
        .route("/", post(add_peer))
        .with_state(state)
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let peers = state.peers.read().await.clone();
    Html(layout::page("Peers", &views::peers::page(&peers)))
}

async fn stream_peers(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let st = state.clone();
    let stream = stream! {
        let mut ticker = interval(Duration::from_millis(100));
        loop {
            ticker.tick().await;
            let snapshot = { st.peers.read().await.clone() };
            let json = serde_json::to_string(&snapshot).unwrap();
            yield Ok(Event::default().data(json));
        }
    };
    Sse::new(stream)
}

#[derive(serde::Deserialize)]
struct NewPeer {
    id: String,
    addr: String,
    kind: String,
    last_msg: Option<String>,
    sk: Option<String>,
}

async fn add_peer(State(state): State<AppState>, Json(np): Json<NewPeer>) -> Json<&'static str> {
    let mut peers = state.peers.write().await;
    //peers.push(Peer {
    //    id: np.id,
    //    addr: np.addr,
    //    kind: np.kind,
    //    last_msg: np.last_msg,
    //    sk: np.sk,
    //    last_seen_ms: now_ms(),
    //});
    Json("ok")
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
