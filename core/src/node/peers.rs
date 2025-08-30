use crate::consensus;
use crate::node::anr;
use crate::utils::misc::get_unix_millis_now;
use scc::HashMap;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("ANR error: {0}")]
    AnrError(#[from] anr::Error),
    #[error("Consensus error: {0}")]
    ConsensusError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub pk: Option<Vec<u8>>,
    pub version: Option<String>,
    pub latency: Option<u64>,
    pub last_msg: u64,
    pub last_ping: Option<u64>,
    pub last_pong: Option<u64>,
    pub shared_secret: Option<Vec<u8>>,
    pub temporal: Option<TemporalInfo>,
    pub rooted: Option<RootedInfo>,
    pub last_seen: u64,
    pub last_msg_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalInfo {
    pub header_unpacked: HeaderInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootedInfo {
    pub header_unpacked: HeaderInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderInfo {
    pub height: u64,
    pub prev_hash: Option<Vec<u8>>,
}

/// NodePeers structure managing the peer database
#[derive(Debug, Clone)]
pub struct NodePeers {
    peers: Arc<HashMap<Ipv4Addr, Peer>>,
    max_peers: usize,
}

impl NodePeers {
    /// Create a new NodePeers instance
    pub fn new(max_peers: usize) -> Self {
        Self { peers: Arc::new(HashMap::new()), max_peers }
    }

    /// Create with default max_peers of 100
    pub fn default() -> Self {
        Self::new(100)
    }

    /// Clear stale peers and add missing validators/handshaked nodes
    pub fn clear_stale(&self) -> Result<(), Error> {
        let ts_m = get_unix_millis_now() as u64;

        // Get validators for current height + 1
        let height = consensus::chain_height();
        let validators = consensus::trainers_for_height(height + 1).unwrap_or_default();
        let validators: Vec<Vec<u8>> = validators.iter().map(|pk| pk.to_vec()).collect();

        let validator_anr_ips = anr::by_pks_ip(&validators)?;
        let validators_map: std::collections::HashSet<Vec<u8>> = validators.into_iter().collect();

        let handshaked_ips = anr::handshaked_pk_ip4()?;

        let mut cur_ips = Vec::new();
        let mut cur_val_ips = Vec::new();

        // Clean stale peers and collect current IPs
        self.peers.scan(|ip, peer| {
            // Remove peers that haven't sent messages in 60 seconds (60*1000 ms)
            if ts_m > (peer.last_msg + 60_000) {
                let _ = self.peers.remove(ip);
                return;
            }

            if let Some(ref pk) = peer.pk {
                if validators_map.contains(pk) {
                    cur_val_ips.push(*ip);
                } else {
                    cur_ips.push(*ip);
                }
            } else {
                cur_ips.push(*ip);
            }
        });

        // Find missing validators and handshaked peers
        let missing_vals: Vec<_> = validator_anr_ips.iter().filter(|ip| !cur_val_ips.contains(ip)).cloned().collect();

        let missing_ips: Vec<_> = handshaked_ips.iter().map(|(_, ip)| *ip).filter(|ip| !cur_ips.contains(ip)).collect();

        // Get max_peers config
        let add_size = self
            .max_peers
            .saturating_sub(self.size())
            .saturating_sub(cur_val_ips.len())
            .saturating_sub(missing_vals.len());

        // Shuffle and take limited missing IPs
        let mut missing_ips = missing_ips;
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        missing_ips.shuffle(&mut rng);
        missing_ips.truncate(add_size);

        // Add missing validators and peers
        for ip in missing_vals.iter().chain(missing_ips.iter()) {
            let _ = self.insert_new_peer(Peer {
                ip: *ip,
                pk: None,
                version: None,
                latency: None,
                last_msg: ts_m,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen: ts_m,
                last_msg_type: None,
            });
        }

        Ok(())
    }

    /// Insert a new peer if it doesn't already exist
    pub fn insert_new_peer(&self, mut peer: Peer) -> Result<bool, Error> {
        if peer.last_msg == 0 {
            peer.last_msg = get_unix_millis_now() as u64;
        }

        Ok(self.peers.insert(peer.ip, peer).is_ok())
    }

    /// Seed initial peers with validators
    pub fn seed(&self, my_ip: Ipv4Addr) -> Result<(), Error> {
        let height = consensus::chain_height();
        let validators = consensus::trainers_for_height(height + 1).unwrap_or_default();
        let validators: Vec<Vec<u8>> = validators.iter().map(|pk| pk.to_vec()).collect();

        let validator_ips: Vec<_> = anr::by_pks_ip(&validators)?.into_iter().filter(|ip| *ip != my_ip).collect();

        for ip in validator_ips {
            let _ = self.insert_new_peer(Peer {
                ip,
                pk: None,
                version: None,
                latency: None,
                last_msg: get_unix_millis_now() as u64,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen: get_unix_millis_now() as u64,
                last_msg_type: None,
            });
        }

        Ok(())
    }

    /// Get number of peers
    pub fn size(&self) -> usize {
        self.peers.len()
    }

    /// Get random online peers
    pub fn random(&self, no: usize) -> Result<Vec<Peer>, Error> {
        let online_peers = self.online()?;
        if online_peers.is_empty() {
            return Ok(vec![]);
        }

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut peers = online_peers;
        peers.shuffle(&mut rng);
        peers.truncate(no);

        Ok(peers)
    }

    /// Get all peers
    pub fn all(&self) -> Result<Vec<Peer>, Error> {
        let mut peers = Vec::new();
        self.peers.scan(|_, peer| {
            peers.push(peer.clone());
        });
        Ok(peers)
    }

    /// Get all online peers
    pub fn online(&self) -> Result<Vec<Peer>, Error> {
        let mut online_peers = Vec::new();

        self.peers.scan(|_, peer| {
            if Self::is_online(peer, None) {
                online_peers.push(peer.clone());
            }
        });

        Ok(online_peers)
    }

    /// Check if a peer is online
    pub fn is_online(peer: &Peer, trainer_pk: Option<&[u8]>) -> bool {
        let ts_m = get_unix_millis_now() as u64;

        match (&peer.pk, peer.last_ping) {
            (None, _) => false,
            (Some(_), None) => false,
            (Some(pk), Some(last_ping)) => {
                // Check if this is our own trainer PK (always online)
                if let Some(my_trainer_pk) = trainer_pk {
                    if pk == my_trainer_pk {
                        return true;
                    }
                }

                // Peer is online if last ping was within 6 seconds (6000 ms)
                (ts_m - last_ping) <= 6_000
            }
        }
    }

    /// Get all trainer peers for given height
    pub fn all_trainers(&self, height: Option<u64>) -> Result<Vec<Peer>, Error> {
        let height = height.unwrap_or_else(|| consensus::chain_height());
        let pks = consensus::trainers_for_height(height + 1).unwrap_or_default();
        let pks: Vec<Vec<u8>> = pks.iter().map(|pk| pk.to_vec()).collect();

        let mut trainers = Vec::new();
        for pk in pks {
            self.peers.scan(|_, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    if *peer_pk == pk {
                        trainers.push(peer.clone());
                    }
                }
            });
        }

        Ok(trainers)
    }

    /// Get summary of all peers
    pub fn summary(&self) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let mut summary = Vec::new();

        self.peers.scan(|_, peer| {
            let temporal_height = peer.temporal.as_ref().map(|t| t.header_unpacked.height);
            let rooted_height = peer.rooted.as_ref().map(|r| r.header_unpacked.height);

            summary.push((peer.ip, peer.latency, temporal_height, rooted_height));
        });

        // Sort by IP
        summary.sort_by_key(|(ip, _, _, _)| ip.octets());

        Ok(summary)
    }

    /// Get summary of online peers only
    pub fn summary_online(&self) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let online_peers = self.online()?;
        let mut summary = Vec::new();

        for peer in online_peers {
            let temporal_height = peer.temporal.as_ref().map(|t| t.header_unpacked.height);
            let rooted_height = peer.rooted.as_ref().map(|r| r.header_unpacked.height);

            summary.push((peer.ip, peer.latency, temporal_height, rooted_height));
        }

        Ok(summary)
    }

    /// Get shared secret for a peer by public key
    pub fn get_shared_secret(&self, pk: &[u8]) -> Result<Vec<u8>, Error> {
        if pk.is_empty() {
            return Ok(vec![]);
        }

        let mut found_secret = None;
        self.peers.scan(|_, peer| {
            if let Some(ref peer_pk) = peer.pk {
                if peer_pk == pk {
                    found_secret = peer.shared_secret.clone();
                }
            }
        });

        if let Some(secret) = found_secret {
            return Ok(secret);
        }

        // TODO: Generate shared secret using BLS
        // For now, return empty vector as placeholder
        Ok(vec![])
    }

    /// Get peer by IP address
    pub fn by_ip(&self, ip: Ipv4Addr) -> Result<Option<Peer>, Error> {
        Ok(self.peers.read(&ip, |_, peer| peer.clone()))
    }

    /// Get IP addresses for a given public key
    pub fn ips_by_pk(&self, pk: &[u8]) -> Result<Vec<Ipv4Addr>, Error> {
        let mut ips = Vec::new();

        self.peers.scan(|ip, peer| {
            if let Some(ref peer_pk) = peer.pk {
                if peer_pk == pk {
                    ips.push(*ip);
                }
            }
        });

        Ok(ips)
    }

    /// Get first peer by public key
    pub fn by_pk(&self, pk: &[u8]) -> Result<Option<Peer>, Error> {
        let mut found_peer = None;

        self.peers.scan(|_, peer| {
            if let Some(ref peer_pk) = peer.pk {
                if peer_pk == pk && found_peer.is_none() {
                    found_peer = Some(peer.clone());
                }
            }
        });

        Ok(found_peer)
    }

    /// Get peers by multiple public keys
    pub fn by_pks(&self, pks: &[Vec<u8>]) -> Result<Vec<Peer>, Error> {
        let pks_set: std::collections::HashSet<_> = pks.iter().collect();
        let mut peers = Vec::new();

        self.peers.scan(|_, peer| {
            if let Some(ref peer_pk) = peer.pk {
                if pks_set.contains(peer_pk) {
                    peers.push(peer.clone());
                }
            }
        });

        Ok(peers)
    }

    /// Get peers for a specific height (trainers)
    pub fn for_height(&self, height: u64) -> Result<Vec<Peer>, Error> {
        let trainers = consensus::trainers_for_height(height).unwrap_or_default();
        let trainers: Vec<Vec<u8>> = trainers.iter().map(|pk| pk.to_vec()).collect();

        let trainers_set: std::collections::HashSet<_> = trainers.iter().collect();
        let mut peers = Vec::new();

        self.peers.scan(|_, peer| {
            if let Some(ref pk) = peer.pk {
                if trainers_set.contains(pk) {
                    peers.push(peer.clone());
                }
            }
        });

        Ok(peers)
    }

    /// Get all peer IPs as strings
    pub fn get_all_ips(&self) -> Result<Vec<String>, Error> {
        let mut ips = Vec::new();
        self.peers.scan(|_key, peer| {
            ips.push(peer.ip.to_string());
        });
        Ok(ips)
    }

    /// Get peer IPs by who specification
    pub fn by_who(&self, who: Who) -> Result<Vec<Ipv4Addr>, Error> {
        match who {
            Who::Some(peer_ips) => Ok(peer_ips),
            Who::Trainers => {
                let height = consensus::chain_height();
                let trainer_peers = self.for_height(height + 1)?;
                let mut ips: Vec<_> = trainer_peers.iter().map(|p| p.ip).collect();

                if ips.is_empty() {
                    return Ok(vec![]);
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                ips.shuffle(&mut rng);
                Ok(ips)
            }
            Who::NotTrainers(cnt) => {
                let height = consensus::chain_height();
                let trainer_peers = self.for_height(height + 1)?;
                let trainer_ips: std::collections::HashSet<_> = trainer_peers.iter().map(|p| p.ip).collect();

                let all_peers = self.all()?;
                let not_trainer_ips: Vec<_> =
                    all_peers.iter().map(|p| p.ip).filter(|ip| !trainer_ips.contains(ip)).collect();

                if not_trainer_ips.is_empty() {
                    return Ok(vec![]);
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                let mut ips = not_trainer_ips;
                ips.shuffle(&mut rng);
                ips.truncate(cnt);
                Ok(ips)
            }
            Who::Random(no) => {
                let random_peers = self.random(no)?;
                Ok(random_peers.iter().map(|p| p.ip).collect())
            }
        }
    }

    /// Get highest heights from online peers with filtering
    pub fn highest_height(&self, filter: HeightFilter) -> Result<Vec<u64>, Error> {
        let summary = self.summary_online()?;

        let min_temporal = filter.min_temporal.unwrap_or(0);
        let min_rooted = filter.min_rooted.unwrap_or(0);

        let mut filtered: Vec<_> = summary
            .into_iter()
            .filter(|(_, _, temp, rooted)| temp.unwrap_or(0) >= min_temporal && rooted.unwrap_or(0) >= min_rooted)
            .collect();

        // Sort by temporal or rooted height
        let sort_by_temporal = filter.sort.as_deref() != Some("rooted");

        filtered.sort_by(|(_, _, temp1, rooted1), (_, _, temp2, rooted2)| {
            let height1 = if sort_by_temporal { temp1.unwrap_or(0) } else { rooted1.unwrap_or(0) };
            let height2 = if sort_by_temporal { temp2.unwrap_or(0) } else { rooted2.unwrap_or(0) };
            height2.cmp(&height1) // descending order
        });

        // Apply latency filtering if specified
        filtered = Self::highest_height_filter(filtered, filter)?;

        let heights = filtered
            .into_iter()
            .map(|(_, _, temp, rooted)| if sort_by_temporal { temp.unwrap_or(0) } else { rooted.unwrap_or(0) })
            .collect();

        Ok(heights)
    }

    fn highest_height_filter(
        mut filtered: Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>,
        filter: HeightFilter,
    ) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let take = filter.take.unwrap_or(3);

        // Apply latency2 filter first
        if let Some(latency2) = filter.latency2 {
            let new_filtered: Vec<_> =
                filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency2).cloned().collect();

            if new_filtered.len() >= take {
                let mut new_filter = filter;
                new_filter.latency2 = None;
                return Self::highest_height_filter(new_filtered, new_filter);
            }
            // Continue with current filtered list
        }

        // Apply latency1 filter
        if let Some(latency1) = filter.latency1 {
            let new_filtered: Vec<_> =
                filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency1).cloned().collect();

            if new_filtered.len() >= take {
                let mut new_filter = filter;
                new_filter.latency1 = None;
                return Self::highest_height_filter(new_filtered, new_filter);
            }
            // Continue with current filtered list
        }

        // Apply main latency filter
        if let Some(latency) = filter.latency {
            let new_filtered: Vec<_> =
                filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency).cloned().collect();

            if new_filtered.len() >= take {
                filtered = new_filtered;
            }
            // Continue with filtered list (either new or original)
        }

        // Truncate to requested size
        filtered.truncate(take);
        Ok(filtered)
    }

    /// Update peer activity and last message type
    pub fn update_peer_activity(&self, ip: Ipv4Addr, last_msg_type: &str) -> Result<(), Error> {
        let current_time = get_unix_millis_now() as u64;

        // Try to update existing peer first
        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.last_seen = current_time;
                peer.last_msg = current_time;
                peer.last_msg_type = Some(last_msg_type.to_string());
            })
            .is_some();

        if !updated {
            // Create new peer if it doesn't exist
            let new_peer = Peer {
                ip,
                pk: None,
                version: None,
                latency: None,
                last_msg: current_time,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen: current_time,
                last_msg_type: Some(last_msg_type.to_string()),
            };
            self.insert_new_peer(new_peer)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum Who {
    Some(Vec<Ipv4Addr>),
    Trainers,
    NotTrainers(usize),
    Random(usize),
}

#[derive(Debug, Clone)]
pub struct HeightFilter {
    pub min_temporal: Option<u64>,
    pub min_rooted: Option<u64>,
    pub take: Option<usize>,
    pub sort: Option<String>,
    pub latency: Option<u64>,
    pub latency1: Option<u64>,
    pub latency2: Option<u64>,
}

// Compatibility layer: Global functions that use a default instance
use once_cell::sync::Lazy;

static DEFAULT_NODE_PEERS: Lazy<NodePeers> = Lazy::new(NodePeers::default);

/// Clear stale peers using default instance
pub fn clear_stale() -> Result<(), Error> {
    DEFAULT_NODE_PEERS.clear_stale()
}

/// Insert a new peer using default instance
pub fn insert_new_peer(peer: Peer) -> Result<bool, Error> {
    DEFAULT_NODE_PEERS.insert_new_peer(peer)
}

/// Seed initial peers using default instance
pub fn seed(my_ip: Ipv4Addr) -> Result<(), Error> {
    DEFAULT_NODE_PEERS.seed(my_ip)
}

/// Get number of peers using default instance
pub fn size() -> usize {
    DEFAULT_NODE_PEERS.size()
}

/// Get random online peers using default instance
pub fn random(no: usize) -> Result<Vec<Peer>, Error> {
    DEFAULT_NODE_PEERS.random(no)
}

/// Get all peers using default instance
pub fn all() -> Result<Vec<Peer>, Error> {
    DEFAULT_NODE_PEERS.all()
}

/// Get all online peers using default instance
pub fn online() -> Result<Vec<Peer>, Error> {
    DEFAULT_NODE_PEERS.online()
}

/// Check if a peer is online using default instance
pub fn is_online(peer: &Peer) -> bool {
    NodePeers::is_online(peer, None)
}

/// Get all trainer peers using default instance
pub fn all_trainers(height: Option<u64>) -> Result<Vec<Peer>, Error> {
    DEFAULT_NODE_PEERS.all_trainers(height)
}

/// Get summary of all peers using default instance
pub fn summary() -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
    DEFAULT_NODE_PEERS.summary()
}

/// Get summary of online peers using default instance
pub fn summary_online() -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
    DEFAULT_NODE_PEERS.summary_online()
}

/// Get shared secret for a peer using default instance
pub fn get_shared_secret(pk: &[u8]) -> Result<Vec<u8>, Error> {
    DEFAULT_NODE_PEERS.get_shared_secret(pk)
}

/// Get peer by IP using default instance
pub fn by_ip(ip: Ipv4Addr) -> Result<Option<Peer>, Error> {
    DEFAULT_NODE_PEERS.by_ip(ip)
}

/// Get IP addresses for a given public key using default instance
pub fn ips_by_pk(pk: &[u8]) -> Result<Vec<Ipv4Addr>, Error> {
    DEFAULT_NODE_PEERS.ips_by_pk(pk)
}

/// Get first peer by public key using default instance
pub fn by_pk(pk: &[u8]) -> Result<Option<Peer>, Error> {
    DEFAULT_NODE_PEERS.by_pk(pk)
}

/// Get peers by multiple public keys using default instance
pub fn by_pks(pks: &[Vec<u8>]) -> Result<Vec<Peer>, Error> {
    DEFAULT_NODE_PEERS.by_pks(pks)
}

/// Get peers for a specific height using default instance
pub fn for_height(height: u64) -> Result<Vec<Peer>, Error> {
    DEFAULT_NODE_PEERS.for_height(height)
}

/// Get all peer IPs as strings using default instance
pub fn get_all_ips() -> Result<Vec<String>, Error> {
    DEFAULT_NODE_PEERS.get_all_ips()
}

/// Get peer IPs by who specification using default instance
pub fn by_who(who: Who) -> Result<Vec<Ipv4Addr>, Error> {
    DEFAULT_NODE_PEERS.by_who(who)
}

/// Get highest heights from online peers using default instance
pub fn highest_height(filter: HeightFilter) -> Result<Vec<u64>, Error> {
    DEFAULT_NODE_PEERS.highest_height(filter)
}

/// Update peer activity using default instance
pub fn update_activity(ip: Ipv4Addr, last_msg_type: &str) -> Result<(), Error> {
    DEFAULT_NODE_PEERS.update_peer_activity(ip, last_msg_type)
}

/// Get peer by IP using default instance
pub fn get_by_ip(ip: Ipv4Addr) -> Option<Peer> {
    DEFAULT_NODE_PEERS.by_ip(ip).unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_operations() {
        let node_peers = NodePeers::new(100);
        let ip = Ipv4Addr::new(127, 0, 0, 1);

        let peer = Peer {
            ip,
            pk: Some(vec![1, 2, 3]),
            version: Some("1.0.0".to_string()),
            latency: Some(100),
            last_msg: get_unix_millis_now() as u64,
            last_ping: Some(get_unix_millis_now() as u64),
            last_pong: None,
            shared_secret: None,
            temporal: None,
            rooted: None,
            last_seen: get_unix_millis_now() as u64,
            last_msg_type: Some("ping".to_string()),
        };

        // Test insert
        assert!(node_peers.insert_new_peer(peer.clone()).unwrap());

        // Test size
        assert_eq!(node_peers.size(), 1);

        // Test by_ip
        let retrieved = node_peers.by_ip(ip).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ip, ip);

        // Test is_online
        let retrieved = node_peers.by_ip(ip).unwrap().unwrap();
        assert!(NodePeers::is_online(&retrieved, None));
    }

    #[tokio::test]
    async fn test_default_instance_compatibility() {
        // Test that the default instance functions still work
        let ip = Ipv4Addr::new(192, 168, 1, 1);

        let peer = Peer {
            ip,
            pk: Some(vec![4, 5, 6]),
            version: Some("1.0.1".to_string()),
            latency: Some(50),
            last_msg: get_unix_millis_now() as u64,
            last_ping: Some(get_unix_millis_now() as u64),
            last_pong: None,
            shared_secret: None,
            temporal: None,
            rooted: None,
            last_seen: get_unix_millis_now() as u64,
            last_msg_type: Some("pong".to_string()),
        };

        // Use global functions
        assert!(insert_new_peer(peer.clone()).unwrap());
        assert!(size() >= 1);

        let retrieved = by_ip(ip).unwrap();
        assert!(retrieved.is_some());
    }
}
