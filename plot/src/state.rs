use crate::models::Entry;
use std::sync::Arc;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub last_seen_ms: u64,
    pub sk: Option<String>,       // "full", "light", etc. If you can infer.
    pub last_msg: Option<String>, // e.g. "Ping", "Pong", "AttestationBulk"
}

#[derive(Clone)]
pub struct AppState {
    pub peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    pub entries: Arc<RwLock<Vec<Entry>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self { peers: Arc::new(RwLock::new(HashMap::new())), entries: Arc::new(RwLock::new(vec![])) }
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    /// Upsert a peer record whenever we see a packet from them.
    pub async fn seen_peer<S1: Into<Option<String>>, S2: Into<Option<String>>>(
        &self,
        addr: SocketAddr,
        sk: S1,
        last_msg: S2,
    ) {
        let mut map = self.peers.write().await;
        let entry = map.entry(addr).or_insert_with(|| PeerInfo {
            addr,
            last_seen_ms: Self::now_ms(),
            sk: None,
            last_msg: None,
        });
        entry.last_seen_ms = Self::now_ms();
        if let Some(k) = sk.into() {
            if !k.is_empty() {
                entry.sk = Some(k);
            }
        }
        if let Some(m) = last_msg.into() {
            if !m.is_empty() {
                entry.last_msg = Some(m);
            }
        }
    }

    /// For HTTP: return a snapshot list, newest first.
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let map = self.peers.read().await;
        let mut v: Vec<_> = map.values().cloned().collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.last_seen_ms));
        v
    }
}
