use crate::{
    state::AppState,
    views::{entries as entries_view, entry as entry_view, layout},
};
use axum::{
    Router,
    extract::{Path, State},
    response::Html,
    routing::get,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(list_entries))
        .route("/:id", get(show_entry))
        .with_state(state)
}

async fn list_entries(State(state): State<AppState>) -> Html<String> {
    let entries = state.entries.read().await.clone();
    Html(layout::page("Entries", &entries_view::page(&entries)))
}

async fn show_entry(State(state): State<AppState>, Path(id): Path<String>) -> Html<String> {
    let entries = state.entries.read().await;
    let Some(e) = entries.iter().find(|e| e.id == id).cloned() else {
        return Html(layout::page("Not found", "<h1>Entry not found</h1>"));
    };
    Html(layout::page(
        &format!("Entry {}", id),
        &entry_view::page(&e),
    ))
}
