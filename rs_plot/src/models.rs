use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub addr: String,
    pub last_seen_ms: u64,
    pub kind: String,
    pub last_msg: Option<String>,
    pub sk: Option<String>, // short public key / session key display
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub ts_ms: u64,
    pub author: String,
    pub kind: String,
    pub summary: String, // short text for list view
}
