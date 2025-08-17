use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::shards::{create_resource, decode_shards};
use crate::bls;
use crate::misc::blake3 as b3;
use crate::proto::{MessageV2, NodeProto};
use crate::proto_enc::parse_nodeproto;

pub struct ReedSolomonReassembler {
    reorg: Arc<Mutex<HashMap<ReassemblyKey, EntryState>>>,
}

#[derive(Clone, Debug, Eq)]
struct ReassemblyKey {
    pk: Vec<u8>,
    ts_nano: u64,
    shard_total: u16,
}

impl From<&MessageV2> for ReassemblyKey {
    fn from(msg: &MessageV2) -> Self {
        Self { pk: msg.pk.clone(), ts_nano: msg.ts_nano, shard_total: msg.shard_total }
    }
}

impl PartialEq for ReassemblyKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk && self.ts_nano == other.ts_nano && self.shard_total == other.shard_total
    }
}

impl Hash for ReassemblyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk.hash(state);
        self.ts_nano.hash(state);
        self.shard_total.hash(state);
    }
}

#[derive(Debug)]
enum EntryState {
    Collecting(HashMap<u16, Vec<u8>>), // shard_index -> shard bytes
    Spent,
}

impl ReedSolomonReassembler {
    pub fn new() -> Self {
        Self { reorg: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn start_periodic_cleanup(&self) {
        let reorg = self.reorg.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(8));
            loop {
                interval.tick().await;
                Self::clear_stale(reorg.clone());
            }
        });
    }

    fn clear_stale(reorg: Arc<Mutex<HashMap<ReassemblyKey, EntryState>>>) {
        let now_nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let threshold = now_nanos.saturating_sub(8_000_000_000u128);
        let size_before = reorg.lock().unwrap().len();
        reorg.lock().unwrap().retain(|k, _| (k.ts_nano as u128) > threshold);
        let size_after = reorg.lock().unwrap().len();
        println!("cleared {}", size_before - size_after);
    }

    // Adds a shard to the reassembly buffer
    // When enough shards collected, reconstructs
    pub fn add_shard(&self, message: &MessageV2) -> anyhow::Result<Option<NodeProto>> {
        let key = ReassemblyKey::from(message);
        let shard = &message.payload;

        // Some messages are single-shard only, so we can skip the reorg logic
        if key.shard_total == 1 {
            return Self::verify_msg_sig(&key, &message.signature, &shard);
        }

        let data_shards = (key.shard_total / 2) as usize;
        let parity_shards = data_shards;

        let mut reorg = self.reorg.lock().map_err(|_| anyhow::anyhow!("reorg lock poisoned"))?;
        match reorg.get_mut(&key) {
            None => {
                let mut m = HashMap::new();
                m.insert(message.shard_index, shard.clone());
                reorg.insert(key, EntryState::Collecting(m));
            }
            Some(EntryState::Spent) => {
                // do nothing
            }
            Some(EntryState::Collecting(m)) => {
                // If we still have fewer than data_shards-1 before adding this shard, keep collecting
                if m.len() < data_shards.saturating_sub(1) {
                    m.insert(message.shard_index, shard.clone());
                    return Ok(None);
                }
                // Otherwise, we can attempt reassembly with existing m + this shard
                // Build shard list first (while borrow is active), then drop borrow before mutating self.reorg
                let shards: Vec<(usize, Vec<u8>)> = {
                    let mut v: Vec<(usize, Vec<u8>)> =
                        m.iter().map(|(idx, bytes)| (*idx as usize, bytes.clone())).collect();
                    v.push((message.shard_index as usize, shard.clone()));
                    v
                };

                // Now mark as spent
                reorg.insert(key.clone(), EntryState::Spent);

                let resource = create_resource(data_shards, parity_shards)?;
                let payload =
                    decode_shards(resource, shards, data_shards + parity_shards, message.original_size as usize)?;

                return Self::verify_msg_sig(&key, &message.signature, &payload);
            }
        }
        Ok(None)
    }

    fn verify_msg_sig(key: &ReassemblyKey, signature: &[u8], payload: &[u8]) -> anyhow::Result<Option<NodeProto>> {
        if !signature.is_empty() {
            let mut hasher = b3::Hasher::new();
            hasher.update(&key.pk);
            hasher.update(payload);
            let msg_hash = hasher.finalize();

            match bls::verify(&key.pk, signature, &msg_hash, bls::DST_NODE) {
                Ok(()) => {
                    if let Ok(msg) = parse_nodeproto(payload) {
                        return Ok(Some(msg));
                    }
                    Err(anyhow::anyhow!("can't parse payload after signature verification"))?
                }
                Err(_) => Err(anyhow::anyhow!("invalid bls signature"))?,
            }
        }
        // All messages must have signature
        Err(anyhow::anyhow!("message has no signature"))
    }
}
