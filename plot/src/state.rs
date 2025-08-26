use crate::models::Entry;
use std::sync::Arc;
use tokio::sync::RwLock;

use ama_core::metrics::METRICS;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub total_messages: u64,
    pub total_bytes_received: u64,
    pub total_peers: u64,
    pub active_peers: u64,
    pub total_entries: u64,
    pub messages_per_second: f64,
    pub bytes_per_second: f64,
    pub start_time_ms: u64,
    pub uptime_seconds: u64,
    pub total_udp_packets: u64,
    pub total_errors: u64,

    // Protocol message breakdown
    pub ping_count: u64,
    pub pong_count: u64,
    pub entry_count: u64,
    pub attestation_bulk_count: u64,
    pub txpool_count: u64,
}

#[derive(Clone)]
pub struct AppState {
    pub peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    pub entries: Arc<RwLock<Vec<Entry>>>,
    pub start_time_ms: u64,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            entries: Arc::new(RwLock::new(vec![])),
            start_time_ms: Self::now_ms(),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
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
        if let Some(k) = sk.into()
            && !k.is_empty()
        {
            entry.sk = Some(k);
        }
        if let Some(m) = last_msg.into()
            && !m.is_empty()
        {
            entry.last_msg = Some(m);
        }
    }

    /// For HTTP: return a snapshot list, newest first.
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let map = self.peers.read().await;
        let mut v: Vec<_> = map.values().cloned().collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.last_seen_ms));
        v
    }

    /// Get current metrics snapshot combining core metrics with plot-specific data
    pub async fn get_metrics(&self) -> Metrics {
        // Get core metrics from ama_core as JSON
        let core_json = METRICS.get_json();

        let now = Self::now_ms();
        // Use uptime from core metrics if available, otherwise calculate
        let uptime_seconds = core_json["uptime"].as_u64().unwrap_or_else(|| (now - self.start_time_ms) / 1000);

        // Extract protocol counts from JSON (now under "handled_protos")
        let empty_protocols = serde_json::Map::new();
        let protocols = core_json["handled_protos"].as_object().unwrap_or(&empty_protocols);
        let ping_count = protocols.get("ping").and_then(|v| v.as_u64()).unwrap_or(0);
        let pong_count = protocols.get("pong").and_then(|v| v.as_u64()).unwrap_or(0);
        let entry_count = protocols.get("entry").and_then(|v| v.as_u64()).unwrap_or(0);
        let attestation_bulk_count = protocols.get("attestation_bulk").and_then(|v| v.as_u64()).unwrap_or(0);
        let txpool_count = protocols.get("txpool").and_then(|v| v.as_u64()).unwrap_or(0);

        // Calculate total messages
        let total_messages: u64 = protocols.values().filter_map(|v| v.as_u64()).sum();

        // Extract error counts
        let empty_errors = serde_json::Map::new();
        let errors = core_json["errors"].as_object().unwrap_or(&empty_errors);
        let total_errors: u64 = errors.values().filter_map(|v| v.as_u64()).sum();

        // Extract packet info
        let packets = &core_json["packets"];
        let total_udp_packets = packets["total_incoming_packets"].as_u64().unwrap_or(0);
        let total_bytes_received = packets["total_incoming_bytes"].as_u64().unwrap_or(0);

        // Use rate metrics from core if available, otherwise calculate
        let messages_per_second = packets["packets_per_second"].as_u64().map(|v| v as f64)
            .unwrap_or_else(|| if uptime_seconds > 0 { total_messages as f64 / uptime_seconds as f64 } else { 0.0 });

        let bytes_per_second = packets["bytes_per_second"].as_u64().map(|v| v as f64)
            .unwrap_or_else(|| if uptime_seconds > 0 { total_bytes_received as f64 / uptime_seconds as f64 } else { 0.0 });

        // Get plot-specific data
        let peers = self.peers.read().await;
        let total_peers = peers.len() as u64;
        let active_threshold_ms = 30000;
        let active_peers = peers.values().filter(|p| now - p.last_seen_ms < active_threshold_ms).count() as u64;

        let total_entries = self.entries.read().await.len() as u64;

        Metrics {
            total_messages,
            total_bytes_received,
            total_peers,
            active_peers,
            total_entries,
            messages_per_second,
            bytes_per_second,
            start_time_ms: self.start_time_ms,
            uptime_seconds,
            total_udp_packets,
            total_errors,
            ping_count,
            pong_count,
            entry_count,
            attestation_bulk_count,
            txpool_count,
        }
    }
}
