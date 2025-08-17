use async_stream::stream;
use axum::{
    Router,
    extract::State,
    response::{
        Html,
        sse::{Event, Sse},
    },
    routing::get,
};
use futures_core::Stream;
use std::{convert::Infallible, time::Duration};
use tokio::time::interval;

use crate::{state::AppState, views, views::layout};

pub fn router(state: AppState) -> Router {
    Router::new().route("/", get(index)).route("/stream", get(stream_peers)).with_state(state)
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let peers = state.peers.read().await.clone();
    Html(layout::page("Peers", &views::peers::page(&peers)))
}

async fn stream_peers(State(state): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
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
