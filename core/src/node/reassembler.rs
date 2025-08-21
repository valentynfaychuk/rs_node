use crate::consensus::DST_NODE;
use crate::misc;
use misc::utils::get_unix_nanos_now;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::Mutex;
// does not poison mutex on panic

use super::msg_v2::MessageV2;
use crate::misc::reed_solomon;
use crate::misc::reed_solomon::ReedSolomonResource;
use crate::misc::{blake3, bls12_381};

type ReassemblySyncMap = Arc<Mutex<HashMap<ReassemblyKey, EntryState>>>;

pub struct ReedSolomonReassembler {
    reorg: ReassemblySyncMap,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ReedSolomon(#[from] reed_solomon::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error("message has no signature")]
    NoSignature,
}

#[derive(Clone, Debug, Eq)]
struct ReassemblyKey {
    pk: [u8; 48],
    ts_nano: u64,
    shard_total: u16,
}

impl From<&MessageV2> for ReassemblyKey {
    fn from(&MessageV2 { pk, ts_nano, shard_total, .. }: &MessageV2) -> Self {
        Self { pk, ts_nano, shard_total }
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

impl Default for ReedSolomonReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl ReedSolomonReassembler {
    pub fn new() -> Self {
        Self { reorg: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Create a signed MessageV2 from given payload and header fields.
    ///
    /// Reference: node.local/ex encrypt_message_v2 signs Blake3(pk || payload) with DST_NODE.
    pub fn build_message_v2(
        payload: Vec<u8>,
        shard_index: u16,
        shard_total: u16,
        original_size: u32,
        ts_nano: u64,
        version: &str,
    ) -> Result<MessageV2, Error> {
        let pk = crate::config::trainer_pk();
        let sk_seed = crate::config::trainer_sk_seed();

        // sign Blake3(pk || payload) per reference implementation
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&payload);
        let msg_hash = hasher.finalize();

        let signature = bls12_381::sign(&sk_seed, &msg_hash, DST_NODE)?;

        Ok(MessageV2 {
            version: version.to_string(),
            pk,
            signature,
            shard_index,
            shard_total,
            ts_nano,
            original_size,
            payload,
        })
    }

    /// Convenience: build a single-shard MessageV2 (shard_total=2) using current time and payload length
    pub fn build_single_shard_message_v2(payload: Vec<u8>, version: &str) -> Result<MessageV2, Error> {
        let ts_nano = get_unix_nanos_now() as u64;
        let original_size = payload.len() as u32;
        Self::build_message_v2(payload, 0, 2, original_size, ts_nano, version)
    }

    /// This starts a timer that clears outdated reassemblies
    pub fn start_periodic_cleanup(&self) {
        tokio::spawn(Self::periodic_cleanup(self.reorg.clone()));
    }

    async fn periodic_cleanup(reorg: ReassemblySyncMap) -> ! {
        use tokio::time::{Duration, interval};
        let mut int = interval(Duration::from_secs(8));
        loop {
            int.tick().await;
            Self::clear_stale(reorg.clone()).await;
        }
    }

    async fn clear_stale(reorg: ReassemblySyncMap) {
        let threshold = get_unix_nanos_now().saturating_sub(8_000_000_000u128);
        let mut reorg = reorg.lock().await;
        let size_before = reorg.len();
        reorg.retain(|k, _| (k.ts_nano as u128) > threshold);
        println!("cleared {}", size_before - reorg.len());
    }

    pub async fn add_shard(&self, message: &MessageV2) -> Result<Option<Vec<u8>>, Error> {
        self.add_shard_inner(message).await.inspect_err(|_| crate::metrics::inc_reassembly_errors())
    }

    // adds a shard to the reassembly buffer
    // when enough shards collected, reconstructs
    pub async fn add_shard_inner(&self, message: &MessageV2) -> Result<Option<Vec<u8>>, Error> {
        let key = ReassemblyKey::from(message);
        let shard = &message.payload;

        // some messages are single-shard only, so we can skip the reorg logic
        if key.shard_total == 1 {
            Self::verify_msg_sig(&key, &message.signature, message.payload.as_slice())?;
            return Ok(Some(message.payload.clone()));
        }

        let data_shards = (key.shard_total / 2) as usize;
        let parity_shards = data_shards;

        let mut reorg = self.reorg.lock().await;
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
                // if we still have fewer than data_shards-1 before adding this shard, keep collecting
                if m.len() < data_shards.saturating_sub(1) {
                    m.insert(message.shard_index, shard.clone());
                    return Ok(None);
                }
                // otherwise, we can attempt reassembly with existing m + this shard
                // build shard list first (while borrow is active), then drop borrow before mutating self.reorg
                let shards: Vec<(usize, Vec<u8>)> = {
                    let mut v: Vec<(usize, Vec<u8>)> =
                        m.iter().map(|(idx, bytes)| (*idx as usize, bytes.clone())).collect();
                    v.push((message.shard_index as usize, shard.clone()));
                    v
                };

                // now mark as spent
                reorg.insert(key.clone(), EntryState::Spent);

                let msg_size = message.original_size as usize;
                let mut rs_res = ReedSolomonResource::new(data_shards, parity_shards)?;
                let payload = rs_res.decode_shards(shards, data_shards + parity_shards, msg_size)?;

                Self::verify_msg_sig(&key, &message.signature, payload.as_slice())?;
                return Ok(Some(payload));
            }
        }
        Ok(None)
    }

    fn verify_msg_sig(key: &ReassemblyKey, signature: &[u8], payload: &[u8]) -> Result<(), Error> {
        if signature.is_empty() {
            return Err(Error::NoSignature);
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&key.pk);
        hasher.update(payload);
        let msg_hash = hasher.finalize();

        bls12_381::verify(&key.pk, signature, &msg_hash, DST_NODE)?;

        Ok(())
    }
}
