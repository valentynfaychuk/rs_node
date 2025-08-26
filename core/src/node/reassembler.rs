use crate::consensus::DST_NODE;
use crate::utils::misc::get_unix_nanos_now;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::Mutex;
// does not poison mutex on panic

use super::msg_v2::MessageV2;
use crate::utils::reed_solomon;
use crate::utils::reed_solomon::ReedSolomonResource;
use crate::utils::{blake3, bls12_381};

type ReassemblySyncMap = Arc<Mutex<HashMap<ReassemblyKey, EntryState>>>;

pub struct ReedSolomonReassembler {
    reorg: ReassemblySyncMap,
}

#[derive(thiserror::Error, Debug, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error(transparent)]
    ReedSolomon(#[from] reed_solomon::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error("message has no signature")]
    NoSignature,
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
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

    /// Create signed MessageV2 shards from payload, implementing symmetric sharding to add_shard.
    ///
    /// Reference: node.local/ex encrypt_message_v2 logic:
    /// - Small messages (< 1300 bytes): single shard with shard_total=1  
    /// - Large messages: Reed-Solomon encode with data_shards = parity_shards = (total_bytes + 1023) / 1024
    /// - Sign Blake3(pk || original_payload) once, use same signature for all shards
    pub fn build_shards(config: &crate::config::Config, payload: Vec<u8>, version: &str) -> Result<Vec<MessageV2>, Error> {
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();
        let ts_nano = get_unix_nanos_now() as u64;
        let original_size = payload.len() as u32;

        // sign Blake3(pk || payload) once for the entire message
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&payload);
        let msg_hash = hasher.finalize();
        let signature = bls12_381::sign(&trainer_sk, &msg_hash, DST_NODE)?;

        // reference: if byte_size(msg_compressed) < 1300, single shard
        if payload.len() < 1300 {
            return Ok(vec![MessageV2 {
                version: version.to_string(),
                pk,
                signature,
                shard_index: 0,
                shard_total: 1,
                ts_nano,
                original_size,
                payload,
            }]);
        }

        // large message: Reed-Solomon sharding
        // reference: shards = div(byte_size(msg_compressed)+1023, 1024)
        let data_shards = payload.len().div_ceil(1024);
        let parity_shards = data_shards;
        let total_shards = (data_shards + parity_shards) as u16;

        let mut rs_resource = ReedSolomonResource::new(data_shards, parity_shards)?;
        let encoded_shards = rs_resource.encode_shards(&payload)?;

        // reference: |> Enum.take(shards+1+div(shards,4))
        // take data shards + some parity shards (not all)
        let shards_to_send = data_shards + 1 + (data_shards / 4);
        let limited_shards: Vec<_> = encoded_shards.into_iter().take(shards_to_send).collect();

        let mut messages = Vec::new();
        for (shard_index, shard_payload) in limited_shards {
            messages.push(MessageV2 {
                version: version.to_string(),
                pk,
                signature,
                shard_index: shard_index as u16,
                shard_total: total_shards,
                ts_nano,
                original_size,
                payload: shard_payload,
            });
        }

        Ok(messages)
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
        self.add_shard_inner(message).await.inspect_err(|e| crate::metrics::METRICS.add_error(e))
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

#[cfg(test)]
mod tests {
    use super::*;

    // test-specific functions that use consistent keypair
    fn test_trainer_sk() -> [u8; 64] {
        // fixed test secret key for deterministic results
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
            30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63, 64,
        ]
    }

    fn test_trainer_pk() -> [u8; 48] {
        // derive public key from the test secret key
        bls12_381::get_public_key(&test_trainer_sk()).unwrap()
    }

    // test version of build_message_v2 that uses consistent test keys
    fn test_build_message_v2(payload: Vec<u8>, version: &str) -> Result<Vec<MessageV2>, Error> {
        let pk = test_trainer_pk();
        let trainer_sk = test_trainer_sk();
        let ts_nano = get_unix_nanos_now() as u64;
        let original_size = payload.len() as u32;

        // sign Blake3(pk || payload) once for the entire message
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&payload);
        let msg_hash = hasher.finalize();
        let signature = bls12_381::sign(&trainer_sk, &msg_hash, DST_NODE)?;

        // reference: if byte_size(msg_compressed) < 1300, single shard
        if payload.len() < 1300 {
            return Ok(vec![MessageV2 {
                version: version.to_string(),
                pk,
                signature,
                shard_index: 0,
                shard_total: 1,
                ts_nano,
                original_size,
                payload,
            }]);
        }

        // large message: Reed-Solomon sharding
        let data_shards = payload.len().div_ceil(1024);
        let parity_shards = data_shards;
        let total_shards = (data_shards + parity_shards) as u16;

        let mut rs_resource = ReedSolomonResource::new(data_shards, parity_shards)?;
        let encoded_shards = rs_resource.encode_shards(&payload)?;

        let shards_to_send = data_shards + 1 + (data_shards / 4);
        let limited_shards: Vec<_> = encoded_shards.into_iter().take(shards_to_send).collect();

        let mut messages = Vec::new();
        for (shard_index, shard_payload) in limited_shards {
            messages.push(MessageV2 {
                version: version.to_string(),
                pk,
                signature,
                shard_index: shard_index as u16,
                shard_total: total_shards,
                ts_nano,
                original_size,
                payload: shard_payload,
            });
        }

        Ok(messages)
    }

    #[tokio::test]
    async fn test_message_v2_roundtrip_small() {
        // test small message (single shard)
        let payload = b"hello world".to_vec();
        let version = "test";

        let messages = test_build_message_v2(payload.clone(), version).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].shard_total, 1);
        assert_eq!(messages[0].payload, payload);

        let reassembler = ReedSolomonReassembler::new();
        let result = reassembler.add_shard(&messages[0]).await.unwrap();
        assert_eq!(result, Some(payload));
    }

    #[tokio::test]
    async fn test_message_v2_roundtrip_large() {
        // test large message (multiple shards)
        let payload = vec![42u8; 3000]; // larger than 1300 bytes
        let version = "test";

        let messages = test_build_message_v2(payload.clone(), version).unwrap();
        assert!(messages.len() > 1);
        assert!(messages[0].shard_total > 1);

        // all messages should have same metadata
        for msg in &messages {
            assert_eq!(msg.version, version);
            assert_eq!(msg.pk, messages[0].pk);
            assert_eq!(msg.ts_nano, messages[0].ts_nano);
            assert_eq!(msg.shard_total, messages[0].shard_total);
            assert_eq!(msg.original_size, payload.len() as u32);
            assert_eq!(msg.signature, messages[0].signature);
        }

        let reassembler = ReedSolomonReassembler::new();
        let mut result = None;

        // add shards one by one
        for msg in &messages {
            if let Some(restored) = reassembler.add_shard(msg).await.unwrap() {
                result = Some(restored);
                break;
            }
        }

        assert_eq!(result, Some(payload));
    }

    #[tokio::test]
    async fn test_message_v2_partial_shards() {
        // test that we can recover with missing shards
        let payload = vec![123u8; 4000];
        let version = "test";

        let messages = test_build_message_v2(payload.clone(), version).unwrap();
        assert!(messages.len() > 2);

        // calculate data_shards to know minimum needed for recovery
        let data_shards = payload.len().div_ceil(1024);
        println!("Generated {} messages, data_shards={}", messages.len(), data_shards);

        let reassembler = ReedSolomonReassembler::new();

        // take first data_shards worth of messages to ensure we can recover
        let mut restored = None;
        for (_i, msg) in messages.iter().enumerate().take(data_shards + 1) {
            if let Some(result) = reassembler.add_shard(msg).await.unwrap() {
                restored = Some(result);
                break;
            }
        }

        // should be able to recover with minimum required shards
        assert_eq!(restored, Some(payload));
    }
}
