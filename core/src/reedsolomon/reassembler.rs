use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::shards::{create_resource, decode_shards};
use crate::bls;
use crate::proto::{MessageV2, NodeProto};
use crate::proto_enc::parse_nodeproto;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead, aead::KeyInit};
use blake3;
use sha2::{Digest, Sha256};

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
        Self {
            pk: msg.pk.clone(),
            ts_nano: msg.ts_nano,
            shard_total: msg.shard_total,
        }
    }
}

impl PartialEq for ReassemblyKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
            && self.ts_nano == other.ts_nano
            && self.shard_total == other.shard_total
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
        Self {
            reorg: Arc::new(Mutex::new(HashMap::new())),
        }
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
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let threshold = now_nanos.saturating_sub(8_000_000_000u128);
        let size_before = reorg.lock().unwrap().len();
        reorg
            .lock()
            .unwrap()
            .retain(|k, _| (k.ts_nano as u128) > threshold);
        let size_after = reorg.lock().unwrap().len();
        println!("cleared {}", size_before - size_after);
    }

    // Adds a shard to the reassembly buffer
    // When enough shards collected, reconstructs triggers callback
    pub fn add_shard(&self, message: &MessageV2) -> anyhow::Result<Option<NodeProto>> {
        let key = ReassemblyKey::from(message);
        let shard = &message.payload;

        // Some messages are single-shard only, so we can skip the reorg logic
        if key.shard_total == 1 {
            return Self::proc_msg(&key, &message.signature, &shard);
        }

        let data_shards = (key.shard_total / 2) as usize;
        let parity_shards = data_shards; // same as Elixir: div(total,2), div(total,2)

        let mut reorg = self
            .reorg
            .lock()
            .map_err(|_| anyhow::anyhow!("reorg lock poisoned"))?;
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
                    let mut v: Vec<(usize, Vec<u8>)> = m
                        .iter()
                        .map(|(idx, bytes)| (*idx as usize, bytes.clone()))
                        .collect();
                    v.push((message.shard_index as usize, shard.clone()));
                    v
                };

                // Now mark as spent
                reorg.insert(key.clone(), EntryState::Spent);

                println!(
                    "reassembling from {} shards ({} total)",
                    shards.len(),
                    key.shard_total
                );

                let resource = create_resource(data_shards, parity_shards)?;
                let payload = decode_shards(
                    resource,
                    shards,
                    data_shards + parity_shards,
                    message.original_size as usize,
                )?;

                return Self::proc_msg(&key, &message.signature, &payload);
            }
        }
        Ok(None)
    }

    // TODO: rename this function
    fn proc_msg(
        key: &ReassemblyKey,
        signature: &[u8],
        payload: &[u8],
    ) -> anyhow::Result<Option<NodeProto>> {
        if !signature.is_empty() {
            // Align with Elixir: valid = BlsEx.verify?(pk, signature, Blake3.hash(pk<>payload), BLS12AggSig.dst_node())
            let mut hasher = blake3::Hasher::new();
            hasher.update(&key.pk);
            hasher.update(payload);
            let msg_hash = hasher.finalize();

            match bls::verify(&key.pk, signature, msg_hash.as_bytes(), bls::DST_NODE) {
                Ok(()) => {
                    if let Ok(msg) = parse_nodeproto(payload) {
                        return Ok(Some(msg));
                    }
                    Err(anyhow::anyhow!(
                        "can't parse payload after signature verification"
                    ))?
                }
                Err(_) => Err(anyhow::anyhow!("invalid bls signature"))?,
            }
        } else {
            // Right now, all messages are using signature, so this is for the future
            let shared_secret: Option<Vec<u8>> = None;

            // Encrypted path (AES-256-GCM). Follow Elixir reference.
            // Layout: <<iv::12-binary, tag::16-binary, ciphertext::binary>>
            if let Some(shared) = shared_secret {
                if payload.len() >= 12 + 16 {
                    let iv = &payload[0..12];
                    let tag = &payload[12..28];
                    let ciphertext = &payload[28..];

                    // Derive key = sha256(shared_secret || ts_nano_be || iv)
                    let mut hasher = Sha256::new();
                    hasher.update(shared);
                    hasher.update(key.ts_nano.to_be_bytes());
                    hasher.update(iv);
                    let key_bytes = hasher.finalize();

                    // aes-gcm crate expects tag to be appended to ciphertext. Concatenate accordingly.
                    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
                    ct_with_tag.extend_from_slice(ciphertext);
                    ct_with_tag.extend_from_slice(tag);

                    // Initialize cipher
                    if let Ok(cipher) = Aes256Gcm::new_from_slice(&key_bytes) {
                        let nonce = Nonce::from_slice(iv);
                        if let Ok(plaintext) = cipher.decrypt(nonce, ct_with_tag.as_ref()) {
                            if let Ok(msg) = parse_nodeproto(&plaintext) {
                                return Ok(Some(msg));
                            }
                            Err(anyhow::anyhow!("can't parse decrypted message"))?
                        }
                        Err(anyhow::anyhow!("invalid ciphertext"))?
                    }
                    Err(anyhow::anyhow!("invalid encryption key"))?
                }
                Err(anyhow::anyhow!(format!("payload len is {}", payload.len())))?
            }
            Err(anyhow::anyhow!("no shared_secret in message"))?
        }
    }
}
