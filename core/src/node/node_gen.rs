use crate::node::state::NodeState;
use crate::node::{
    anr, peers,
    socket_gen::{NodeGenSocketGen, SocketGenConfig},
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Socket error: {0}")]
    SocketError(String),
    #[error("ANR error: {0}")]
    AnrError(#[from] anr::Error),
    #[error("Peers error: {0}")]
    PeersError(#[from] peers::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Main node generator managing node state and broadcasting
pub struct NodeGen {
    ip: Ipv4Addr,
    port: u16,
    node_state: Arc<RwLock<NodeState>>,
    socket_gens: Vec<Arc<NodeGenSocketGen>>,
}

impl NodeGen {
    pub async fn new(ip: Ipv4Addr, port: u16) -> Result<Self, Error> {
        // seed peers and ANR with placeholder values for now
        // TODO: Get actual values from config/environment
        let seed_anrs = vec![];
        let my_sk = vec![0u8; 32];
        let my_pk = vec![0u8; 48];
        let my_pop = vec![0u8; 96];
        let version = "1.0.0".to_string();
        anr::seed(seed_anrs, &my_sk, my_pk, my_pop, version)?;
        peers::seed(ip)?;

        // create multiple socket generators (8 as in Elixir)
        let mut socket_gens = Vec::new();
        for i in 0..8 {
            let config = SocketGenConfig {
                ip,
                port: port + i as u16, // slightly different ports for each socket gen
                name: format!("NodeGenSocketGen{}", i),
                ..Default::default()
            };

            let socket_gen = NodeGenSocketGen::new(config).await.map_err(|e| Error::SocketError(e.to_string()))?;
            socket_gens.push(Arc::new(socket_gen));
        }

        Ok(Self { ip, port, node_state: Arc::new(RwLock::new(NodeState::init())), socket_gens })
    }

    pub async fn start(&self) -> Result<(), Error> {
        info!("Starting NodeGen on {}:{}", self.ip, self.port);

        // start all socket generators
        for socket_gen in &self.socket_gens {
            let socket_gen_clone = Arc::clone(socket_gen);
            tokio::spawn(async move {
                if let Err(e) = socket_gen_clone.run().await {
                    warn!("Socket generator error: {}", e);
                }
            });
        }

        // start periodic tasks
        self.start_tick_tasks().await;

        Ok(())
    }

    async fn start_tick_tasks(&self) {
        // main tick every 1 second
        let node_gen_clone = self.clone_for_task();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Err(e) = node_gen_clone.tick().await {
                    warn!("Tick error: {}", e);
                }
            }
        });

        // ping tick every 500ms
        let node_gen_clone = self.clone_for_task();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                if let Err(e) = node_gen_clone.broadcast_ping().await {
                    warn!("Ping broadcast error: {}", e);
                }
            }
        });

        // ANR check tick every 1 second
        let node_gen_clone = self.clone_for_task();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Err(e) = node_gen_clone.broadcast_check_anr().await {
                    warn!("ANR check error: {}", e);
                }
            }
        });
    }

    fn clone_for_task(&self) -> NodeGenClone {
        NodeGenClone {
            ip: self.ip,
            port: self.port,
            node_state: Arc::clone(&self.node_state),
            socket_gens: self.socket_gens.clone(),
        }
    }

    /// Get socket generator by index
    pub fn get_socket_gen(&self) -> Arc<NodeGenSocketGen> {
        let idx = rand::random::<usize>() % self.socket_gens.len();
        Arc::clone(&self.socket_gens[idx])
    }

    /// Get reassembly generator index for a given pk and timestamp
    pub fn get_reassembly_gen_index(pk: &[u8], ts_nano: u64) -> u32 {
        let mut hasher = DefaultHasher::new();
        pk.hash(&mut hasher);
        ts_nano.hash(&mut hasher);
        (hasher.finish() % 32) as u32
    }

    pub async fn broadcast_ping(&self) -> Result<(), Error> {
        debug!("Broadcasting ping to all peers");

        // TODO: create ping message using protocol module
        let msg_compressed = vec![]; // placeholder

        let all_ips = peers::get_all_ips()?;
        let socket_gen = self.get_socket_gen();

        socket_gen.send_to_some(all_ips, msg_compressed).await.map_err(|e| Error::SocketError(e.to_string()))?;

        Ok(())
    }

    pub async fn broadcast_check_anr(&self) -> Result<(), Error> {
        debug!("Broadcasting ANR checks");

        // get my trainer pk from environment or config
        let my_pk = std::env::var("TRAINER_PK").unwrap_or_else(|_| "".to_string()).as_bytes().to_vec();

        let random_unverified = anr::get_random_unverified(3)?;

        for (pk, ip) in random_unverified {
            if pk != my_pk {
                debug!("ANR request to {}", ip);

                let _challenge =
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
                        as u64;

                // TODO: create new_phone_who_dis message using protocol module
                let msg_compressed = vec![]; // placeholder

                let socket_gen = self.get_socket_gen();
                socket_gen
                    .send_to_some(vec![ip.to_string()], msg_compressed)
                    .await
                    .map_err(|e| Error::SocketError(e.to_string()))?;
            }
        }

        Ok(())
    }

    pub async fn broadcast(
        &self,
        msg_type: BroadcastType,
        who: PeerSelector,
        _args: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        debug!("Broadcasting {:?} to {:?}", msg_type, who);

        // TODO: create message using protocol module based on msg_type
        let msg_compressed = vec![]; // placeholder

        let ips = match who {
            PeerSelector::All => peers::get_all_ips()?,
            PeerSelector::ByWho(_who_type) => {
                // TODO: convert who_type string to appropriate Who enum variant
                // For now, just return all IPs
                peers::get_all_ips()?
            }
        };

        let socket_gen = self.get_socket_gen();
        socket_gen.send_to_some(ips, msg_compressed).await.map_err(|e| Error::SocketError(e.to_string()))?;

        Ok(())
    }

    async fn tick(&self) -> Result<(), Error> {
        debug!("Node tick - clearing stale peers");
        peers::clear_stale()?;
        Ok(())
    }
}

// Clone-like struct for async tasks (avoids Clone trait complexity)
#[derive(Clone)]
struct NodeGenClone {
    ip: Ipv4Addr,
    port: u16,
    node_state: Arc<RwLock<NodeState>>,
    socket_gens: Vec<Arc<NodeGenSocketGen>>,
}

impl NodeGenClone {
    fn get_socket_gen(&self) -> Arc<NodeGenSocketGen> {
        let idx = rand::random::<usize>() % self.socket_gens.len();
        Arc::clone(&self.socket_gens[idx])
    }

    async fn broadcast_ping(&self) -> Result<(), Error> {
        debug!("Broadcasting ping to all peers");

        // TODO: create ping message using protocol module
        let msg_compressed = vec![]; // placeholder

        let all_ips = peers::get_all_ips()?;
        let socket_gen = self.get_socket_gen();

        socket_gen.send_to_some(all_ips, msg_compressed).await.map_err(|e| Error::SocketError(e.to_string()))?;

        Ok(())
    }

    async fn broadcast_check_anr(&self) -> Result<(), Error> {
        debug!("Broadcasting ANR checks");

        let my_pk = std::env::var("TRAINER_PK").unwrap_or_else(|_| "".to_string()).as_bytes().to_vec();

        let random_unverified = anr::get_random_unverified(3)?;

        for (pk, ip) in random_unverified {
            if pk != my_pk {
                debug!("ANR request to {}", ip);

                let _challenge =
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
                        as u64;

                // TODO: create new_phone_who_dis message using protocol module
                let msg_compressed = vec![]; // placeholder

                let socket_gen = self.get_socket_gen();
                socket_gen
                    .send_to_some(vec![ip.to_string()], msg_compressed)
                    .await
                    .map_err(|e| Error::SocketError(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn tick(&self) -> Result<(), Error> {
        debug!("Node tick - clearing stale peers");
        peers::clear_stale()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum BroadcastType {
    TxPool,
    Entry,
    AttestationBulk,
    Sol,
    SpecialBusiness,
}

#[derive(Debug, Clone)]
pub enum PeerSelector {
    All,
    ByWho(String),
}
