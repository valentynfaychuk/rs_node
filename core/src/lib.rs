#![allow(dead_code)]

use crate::node::protocol::Protocol;
use crate::node::{NodePeers, NodeState, anr, peers};
use crate::utils::misc::get_unix_secs_now;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

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
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error(transparent)]
    Peers(#[from] peers::Error),
}

/// Reads UDP datagram and silently does parsing, validation and reassembly
/// If the protocol message is complete, returns Some(Protocol)
pub async fn read_udp_packet(ctx: &Context, src: SocketAddr, buf: &[u8]) -> Option<Box<dyn Protocol>> {
    use node::protocol::from_etf_bin;
    ctx.metrics.add_v2_udp_packet(buf.len());

    match ctx.reassembler.add_shard(buf) {
        Ok(Some(packet)) => match from_etf_bin(&packet) {
            Ok(proto) => {
                let _last_ts = get_unix_secs_now();
                let last_msg = proto.typename().to_string();

                // Extract IP from SocketAddr and update peer info
                if let std::net::IpAddr::V4(ipv4) = src.ip() {
                    let _ = ctx.update_peer_activity(ipv4, &last_msg).await;
                }

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
    node_peers: Arc<NodePeers>,
    node_state: Arc<RwLock<NodeState>>,
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
        let config = config::Config::from_fs(None, None).await?;
        Self::with_config(config).await
    }

    pub async fn with_config(config: config::Config) -> Result<Self, Error> {
        use consensus::fabric::init_kvdb;
        use metrics::Metrics;
        use node::reassembler::ReedSolomonReassembler as Reassembler;
        use tokio::spawn;
        use tokio::time::{Duration, interval};
        use utils::archiver::init_storage;

        let root = config.get_root()?;
        init_kvdb(root).await?;
        init_storage(root).await?;

        // Initialize ANR and peer systems
        let node_ip = Ipv4Addr::new(127, 0, 0, 1); // TODO: Get from config
        let seed_anrs = vec![];
        let my_sk = vec![0u8; 32]; // TODO: Get from config/environment
        let my_pk = vec![0u8; 48]; // TODO: Get from config/environment  
        let my_pop = vec![0u8; 96]; // TODO: Get from config/environment
        let version = "1.0.0".to_string(); // TODO: Get from config

        anr::seed(seed_anrs, &my_sk, my_pk, my_pop, version)?;
        peers::seed(node_ip)?;

        let node_peers = Arc::new(NodePeers::new(1000)); // TODO: Get max_peers from config
        let node_state = Arc::new(RwLock::new(NodeState::init()));

        const CLEANUP_SECS: u64 = 8;
        let reassembler = Arc::new(Reassembler::new());
        let reassembler_ref = reassembler.clone();
        let periodic_handle = spawn(async move {
            let mut ticker = interval(Duration::from_secs(CLEANUP_SECS));
            loop {
                ticker.tick().await;
                reassembler_ref.clear_stale(CLEANUP_SECS);
                // Also clear stale peers
                let _ = peers::clear_stale();
            }
        });

        let metrics = Metrics::new();
        Ok(Self { config, metrics, reassembler, node_peers, node_state, periodic_handle })
    }

    pub fn get_prometheus_metrics(&self) -> String {
        self.metrics.get_prometheus()
    }

    pub fn get_json_metrics(&self) -> Value {
        self.metrics.get_json()
    }

    pub async fn update_peer_activity(&self, ip: Ipv4Addr, last_msg: &str) -> Result<(), Error> {
        // Update peer activity using the proper peer management system
        peers::update_activity(ip, last_msg)?;
        Ok(())
    }

    pub async fn get_peers(&self) -> HashMap<String, PeerInfo> {
        // Get peers from the new system and convert to the expected format
        let mut result = HashMap::new();
        if let Ok(peer_ips) = peers::get_all_ips() {
            for ip_str in peer_ips {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if let Some(peer) = peers::get_by_ip(ip) {
                        let peer_info = PeerInfo {
                            last_ts: peer.last_seen,
                            last_msg: peer.last_msg_type.unwrap_or_else(|| "unknown".to_string()),
                        };
                        result.insert(ip_str, peer_info);
                    }
                }
            }
        }
        result
    }

    pub fn get_node_state(&self) -> Arc<RwLock<NodeState>> {
        Arc::clone(&self.node_state)
    }

    pub fn get_node_peers(&self) -> Arc<NodePeers> {
        Arc::clone(&self.node_peers)
    }

    pub async fn get_entries(&self) -> Vec<String> {
        vec![]
    }
}
