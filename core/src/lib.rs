#![allow(dead_code)]

use crate::node::protocol::Protocol;
use crate::utils::misc::get_unix_secs_now;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod bic;
pub mod config;
pub mod consensus;
pub mod genesis;
pub mod metrics;
pub mod node;
pub mod utils;
pub mod wasm;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Fabric(#[from] consensus::fabric::Error),
    #[error(transparent)]
    Archiver(#[from] utils::archiver::Error),
}

/// Reads UDP datagram and silently does parsing, validation and reassembly
/// If the protocol message is complete, returns Some(Protocol)
pub async fn read_udp_packet(ctx: &Context, src: SocketAddr, buf: &[u8]) -> Option<Box<dyn Protocol>> {
    use node::protocol::from_etf_bin;
    ctx.metrics.add_v2_udp_packet(buf.len());

    match ctx.reassembler.add_shard(buf) {
        Ok(Some(packet)) => match from_etf_bin(&packet) {
            Ok(proto) => {
                let last_ts = get_unix_secs_now();
                let last_msg = proto.typename().to_string();
                ctx.add_peer(src.to_string(), PeerInfo { last_ts, last_msg }).await;
                return Some(proto);
            }
            Err(e) => ctx.metrics.add_error(&e),
        },
        Ok(None) => {} // waiting for more shards, not an error
        Err(e) => ctx.metrics.add_error(&e),
    }

    None
}

pub struct Context {
    config: config::Config,
    metrics: metrics::Metrics,
    reassembler: Arc<node::ReedSolomonReassembler>,
    peers: Mutex<HashMap<String, PeerInfo>>, // TODO: replace with a proper peer management system
    // handle for the periodic task
    pub periodic_handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub last_ts: u64,
    pub last_msg: String,
}

impl Context {
    pub async fn new() -> Result<Self, Error> {
        let config = config::Config::generate_new(None).await;
        Self::with_config(config).await
    }

    pub async fn with_config(config: config::Config) -> Result<Self, Error> {
        use consensus::fabric::init_kvdb;
        use metrics::Metrics;
        use node::reassembler::ReedSolomonReassembler as Reassembler;
        use tokio::spawn;
        use tokio::time::{Duration, interval};
        use utils::archiver::init_storage;

        // initialize the global state or perform any necessary setup
        // this function can be used to set up logging, metrics, etc
        // currently, it does nothing but can be extended in the future
        init_kvdb(config.get_root()).await?;
        init_storage(config.get_root()).await?;

        const CLEANUP_SECS: u64 = 8;
        let reassembler = Arc::new(Reassembler::new());
        let reassembler_ref = reassembler.clone();
        let periodic_handle = spawn(async move {
            let mut ticker = interval(Duration::from_secs(CLEANUP_SECS));
            loop {
                ticker.tick().await;
                reassembler_ref.clear_stale(CLEANUP_SECS);
            }
        });

        let metrics = Metrics::new();
        let peers = Mutex::new(HashMap::new());
        Ok(Self { config, metrics, reassembler, peers, periodic_handle })
    }

    pub fn get_prometheus_metrics(&self) -> String {
        self.metrics.get_prometheus()
    }

    pub fn get_json_metrics(&self) -> Value {
        self.metrics.get_json()
    }

    pub async fn add_peer(&self, addr: String, info: PeerInfo) {
        let mut map = self.peers.lock().await;
        let _ = map.insert(addr, info); // just replace is fine
    }

    pub async fn get_peers(&self) -> HashMap<String, PeerInfo> {
        let map = self.peers.lock().await;
        map.clone()
    }

    pub async fn get_entries(&self) -> Vec<String> {
        vec![]
    }
}
