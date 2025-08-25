use crate::misc::bls12_381::{sign, verify};
use crate::misc::rocksdb as rdb;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

// ama node record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
pub struct ANR {
    pub ip4: Ipv4Addr,
    pub pk: Vec<u8>,
    pub pop: Vec<u8>,
    pub port: u16,
    pub signature: Vec<u8>,
    pub ts: u64,
    pub version: String,
    // runtime fields
    #[serde(skip)]
    pub handshaked: bool,
    #[serde(skip)]
    pub has_chain_pop: bool,
    #[serde(skip)]
    pub error: Option<String>,
    #[serde(skip)]
    pub error_tries: u32,
    #[serde(skip)]
    pub next_check: u64,
}

impl ANR {
    // build a new anr with signature
    pub fn build(sk: &[u8], pk: Vec<u8>, pop: Vec<u8>, ip4: Ipv4Addr, version: String) -> Result<Self, String> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();

        let mut anr = ANR {
            ip4,
            pk: pk.clone(),
            pop,
            port: 36969,
            ts,
            version,
            signature: vec![],
            handshaked: false,
            has_chain_pop: false,
            error: None,
            error_tries: 0,
            next_check: ts + 3,
        };

        // create signature over deterministic encoding of fields
        let to_sign = anr.to_binary_for_signing()?;
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ANR";
        let sig_array = sign(sk, &to_sign, dst).map_err(|e| e.to_string())?;
        anr.signature = sig_array.to_vec();

        Ok(anr)
    }

    // convert to binary for signing (excludes signature field)
    // uses bincode for deterministic serialization
    fn to_binary_for_signing(&self) -> Result<Vec<u8>, String> {
        // create a map with fields in same order as elixir
        // we'll use bincode to serialize deterministically
        let signing_data = SigningData {
            ip4: self.ip4,
            pk: self.pk.clone(),
            pop: self.pop.clone(),
            port: self.port,
            ts: self.ts,
            version: self.version.clone(),
        };

        bincode::encode_to_vec(&signing_data, bincode::config::standard())
            .map_err(|e| format!("Failed to serialize for signing: {}", e))
    }

    // verify anr signature and proof of possession
    pub fn verify_signature(&self) -> bool {
        if let Ok(to_sign) = self.to_binary_for_signing() {
            let dst_anr = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ANR";
            let dst_pop = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

            // verify main signature
            if verify(&self.pk, &self.signature, &to_sign, dst_anr).is_err() {
                return false;
            }

            // verify proof of possession (pop is signature of pk with pk as key)
            verify(&self.pk, &self.pop, &self.pk, dst_pop).is_ok()
        } else {
            false
        }
    }

    // verify and unpack anr from untrusted source
    pub fn verify_and_unpack(anr: ANR) -> Option<ANR> {
        // check not wound into future (10 min tolerance)
        let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;

        let delta_ms = (now_ms as i64) - (anr.ts as i64 * 1000);
        let min10_ms = 60 * 10 * 1000;
        if delta_ms < -(min10_ms as i64) {
            return None;
        }

        // check size limit (390 bytes in elixir)
        let serialized = bincode::encode_to_vec(&anr, bincode::config::standard()).ok()?;
        if serialized.len() > 390 {
            return None;
        }

        // verify signature
        if !anr.verify_signature() {
            return None;
        }

        Some(anr)
    }

    // pack anr for network transmission
    pub fn pack(&self) -> ANR {
        ANR {
            ip4: self.ip4,
            pk: self.pk.clone(),
            pop: self.pop.clone(),
            port: self.port,
            signature: self.signature.clone(),
            ts: self.ts,
            version: self.version.clone(),
            handshaked: false,
            has_chain_pop: false,
            error: None,
            error_tries: 0,
            next_check: 0,
        }
    }
}

// helper struct for deterministic signing serialization
#[derive(Serialize, Deserialize, bincode::Encode, bincode::Decode)]
struct SigningData {
    ip4: Ipv4Addr,
    pk: Vec<u8>,
    pop: Vec<u8>,
    port: u16,
    ts: u64,
    version: String,
}

// storage functions using rocksdb

// serialize anr for storage
fn serialize_anr(anr: &ANR) -> Result<Vec<u8>, String> {
    bincode::encode_to_vec(anr, bincode::config::standard()).map_err(|e| e.to_string())
}

// deserialize anr from storage
fn deserialize_anr(bytes: &[u8]) -> Result<ANR, String> {
    let (anr, _) = bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| e.to_string())?;
    Ok(anr)
}

// insert or update anr
pub fn insert(anr: ANR) -> Result<(), rdb::Error> {
    // check if we have chain pop for this pk (would need consensus module)
    // let has_chain_pop = consensus::chain_pop(&anr.pk).is_some();
    let mut anr = anr;
    anr.has_chain_pop = false; // placeholder

    // check if anr already exists
    let old_anr = get(&anr.pk)?;

    if let Some(old) = old_anr {
        // only update if newer timestamp
        if anr.ts <= old.ts {
            return Ok(());
        }

        // check if ip4/port changed
        let same_ip4_port = old.ip4 == anr.ip4 && old.port == anr.port;
        if !same_ip4_port {
            // reset handshake status
            anr.handshaked = false;
            anr.error = None;
            anr.error_tries = 0;
            anr.next_check = anr.ts + 3;
        } else {
            // preserve handshake status
            anr.handshaked = old.handshaked;
        }
    } else {
        // new anr
        anr.handshaked = false;
        anr.error = None;
        anr.error_tries = 0;
        anr.next_check = anr.ts + 3;
    }

    // store in db with prefixed key
    let serialized =
        serialize_anr(&anr).map_err(|e| rdb::Error::TokioIo(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    let mut key = b"anr:".to_vec();
    key.extend_from_slice(&anr.pk);
    rdb::put("default", &key, &serialized)?;

    // update indexes
    update_indexes(&anr)?;

    Ok(())
}

// get anr by public key
pub fn get(pk: &[u8]) -> Result<Option<ANR>, rdb::Error> {
    let mut key = b"anr:".to_vec();
    key.extend_from_slice(pk);

    match rdb::get("default", &key)? {
        Some(bytes) => {
            let anr = deserialize_anr(&bytes)
                .map_err(|e| rdb::Error::TokioIo(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
            Ok(Some(anr))
        }
        None => Ok(None),
    }
}

// get all anrs
pub fn get_all() -> Result<Vec<ANR>, rdb::Error> {
    let mut anrs = Vec::new();
    let items = rdb::iter_prefix("default", b"anr:")?;

    for (_key, value) in items {
        if let Ok(anr) = deserialize_anr(&value) {
            anrs.push(anr);
        }
    }

    Ok(anrs)
}

// set handshaked status
pub fn set_handshaked(pk: &[u8]) -> Result<(), rdb::Error> {
    if let Some(mut anr) = get(pk)? {
        anr.handshaked = true;

        let serialized =
            serialize_anr(&anr).map_err(|e| rdb::Error::TokioIo(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        let mut key = b"anr:".to_vec();
        key.extend_from_slice(pk);
        rdb::put("default", &key, &serialized)?;

        update_indexes(&anr)?;
    }
    Ok(())
}

// update secondary indexes for efficient queries
fn update_indexes(anr: &ANR) -> Result<(), rdb::Error> {
    // clean up old indexes first (if any)
    cleanup_indexes_for_pk(&anr.pk)?;

    // create index key for handshaked status and ip4
    // format: "idx:anr:handshaked:<0|1>:ip4:<a.b.c.d>:pk:<base58>"
    let handshaked_byte = if anr.handshaked { b'1' } else { b'0' };
    let ip4_str = anr.ip4.to_string();
    let pk_b58 = bs58::encode(&anr.pk).into_string();

    let index_key = format!("idx:anr:handshaked:{}:ip4:{}:pk:{}", handshaked_byte as char, ip4_str, pk_b58);

    // store pk as value for reverse lookup
    rdb::put("default", index_key.as_bytes(), &anr.pk)?;

    // also store a simpler index for handshaked-only queries
    let simple_index = format!("idx:anr:handshaked:{}:pk:{}", handshaked_byte as char, pk_b58);
    rdb::put("default", simple_index.as_bytes(), &anr.pk)?;

    Ok(())
}

// cleanup old indexes for a given pk
fn cleanup_indexes_for_pk(pk: &[u8]) -> Result<(), rdb::Error> {
    let pk_b58 = bs58::encode(pk).into_string();

    // delete all indexes containing this pk
    let prefixes = vec![format!("idx:anr:handshaked:0:pk:{}", pk_b58), format!("idx:anr:handshaked:1:pk:{}", pk_b58)];

    for prefix in prefixes {
        let items = rdb::iter_prefix("default", prefix.as_bytes())?;
        for (key, _) in items {
            rdb::delete("default", &key)?;
        }
    }

    // also cleanup ip4 indexes
    let ip4_prefixes = vec![b"idx:anr:handshaked:0:ip4:", b"idx:anr:handshaked:1:ip4:"];

    for prefix in ip4_prefixes {
        let items = rdb::iter_prefix("default", prefix)?;
        for (key, value) in items {
            if value == pk {
                rdb::delete("default", &key)?;
            }
        }
    }

    Ok(())
}

// query functions

// get all handshaked node public keys
pub fn handshaked() -> Result<Vec<Vec<u8>>, rdb::Error> {
    let prefix = b"idx:anr:handshaked:1:";
    let items = rdb::iter_prefix("default", prefix)?;

    let mut pks = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (_key, value) in items {
        if seen.insert(value.clone()) {
            pks.push(value);
        }
    }

    Ok(pks)
}

// get all not handshaked (pk, ip4) pairs
pub fn not_handshaked_pk_ip4() -> Result<Vec<(Vec<u8>, Ipv4Addr)>, rdb::Error> {
    let prefix = b"idx:anr:handshaked:0:ip4:";
    let items = rdb::iter_prefix("default", prefix)?;

    let mut results = Vec::new();
    for (key, pk) in items {
        // parse ip4 from key
        if let Ok(key_str) = std::str::from_utf8(&key) {
            if let Some(ip4_part) = key_str.split(":ip4:").nth(1) {
                if let Some(ip4_str) = ip4_part.split(":pk:").next() {
                    if let Ok(ip4) = ip4_str.parse::<Ipv4Addr>() {
                        results.push((pk, ip4));
                    }
                }
            }
        }
    }

    Ok(results)
}

// check if node is handshaked
pub fn is_handshaked(pk: &[u8]) -> Result<bool, rdb::Error> {
    if let Some(anr) = get(pk)? { Ok(anr.handshaked) } else { Ok(false) }
}

// check if node is handshaked with valid ip4
pub fn handshaked_and_valid_ip4(pk: &[u8], ip4: &Ipv4Addr) -> Result<bool, rdb::Error> {
    if let Some(anr) = get(pk)? { Ok(anr.handshaked && anr.ip4 == *ip4) } else { Ok(false) }
}

// get random verified nodes
pub fn get_random_verified(count: usize) -> Result<Vec<ANR>, rdb::Error> {
    use rand::seq::SliceRandom;

    let pks = handshaked()?;
    let mut rng = rand::thread_rng();
    let selected: Vec<_> = pks.choose_multiple(&mut rng, count).cloned().collect();

    let mut anrs = Vec::new();
    for pk in selected {
        if let Some(anr) = get(&pk)? {
            anrs.push(anr.pack());
        }
    }

    Ok(anrs)
}

// get random unverified nodes
pub fn get_random_unverified(count: usize) -> Result<Vec<(Vec<u8>, Ipv4Addr)>, rdb::Error> {
    use rand::seq::SliceRandom;
    use std::collections::HashSet;

    let pairs = not_handshaked_pk_ip4()?;

    // deduplicate by ip4
    let mut seen_ips = HashSet::new();
    let mut unique_pairs = Vec::new();
    for (pk, ip4) in pairs {
        if seen_ips.insert(ip4) {
            unique_pairs.push((pk, ip4));
        }
    }

    let mut rng = rand::thread_rng();
    let selected: Vec<_> = unique_pairs.choose_multiple(&mut rng, count).cloned().collect();

    Ok(selected)
}

// get all validators from handshaked nodes
pub fn all_validators() -> Result<Vec<ANR>, rdb::Error> {
    // this would need integration with consensus module to get validator set
    // for now, return all handshaked nodes
    let pks = handshaked()?;
    let mut anrs = Vec::new();

    for pk in pks {
        if let Some(anr) = get(&pk)? {
            anrs.push(anr);
        }
    }

    Ok(anrs)
}

// seed initial anrs (called on startup)
pub fn seed(
    seed_anrs: Vec<ANR>,
    my_sk: &[u8],
    my_pk: Vec<u8>,
    my_pop: Vec<u8>,
    version: String,
) -> Result<(), rdb::Error> {
    // insert seed anrs
    for anr in seed_anrs {
        insert(anr)?;
    }

    // build and insert our own anr
    // would need stun::get_current_ip4() equivalent
    let my_ip4 = Ipv4Addr::new(0, 0, 0, 0); // placeholder
    if let Ok(my_anr) = ANR::build(my_sk, my_pk.clone(), my_pop, my_ip4, version) {
        insert(my_anr)?;
        set_handshaked(&my_pk)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anr_operations() {
        // initialize db for testing with unique path
        let test_path = format!("target/test_anr_{}", std::process::id());
        let _ = rdb::init(&test_path).await;

        // create test keys with unique pk to avoid conflicts
        let _sk = vec![1; 32];
        let mut pk = vec![2; 48];
        // make pk unique per test run
        let pid_bytes = std::process::id().to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);

        let pop = vec![3; 96];
        let ip4 = Ipv4Addr::new(127, 0, 0, 1);
        let version = "1.0.0".to_string();

        // ensure no existing data for this pk
        let _ = cleanup_test_anr(&pk);

        // manually create ANR without signature verification for testing
        let anr = ANR {
            ip4,
            pk: pk.clone(),
            pop,
            port: 36969,
            signature: vec![0; 96],
            ts: 1234567890,
            version,
            handshaked: false,
            has_chain_pop: false,
            error: None,
            error_tries: 0,
            next_check: 1234567893,
        };

        // test insert
        insert(anr.clone()).unwrap();

        // test get
        let retrieved = get(&pk).unwrap().unwrap();
        assert_eq!(retrieved.pk, pk);
        assert!(!retrieved.handshaked, "Expected handshaked to be false after insert, got true");

        // test set_handshaked
        set_handshaked(&pk).unwrap();
        let retrieved = get(&pk).unwrap().unwrap();
        assert!(retrieved.handshaked);

        // test handshaked query
        let handshaked_pks = handshaked().unwrap();
        assert!(handshaked_pks.iter().any(|p| p == &pk));

        // test is_handshaked
        assert!(is_handshaked(&pk).unwrap());

        // test get_all
        let all = get_all().unwrap();
        assert!(!all.is_empty());
        assert!(all.iter().any(|a| a.pk == pk));

        // cleanup
        let _ = cleanup_test_anr(&pk);
    }

    // helper function to clean up test data
    fn cleanup_test_anr(pk: &[u8]) -> Result<(), rdb::Error> {
        // delete main record
        let mut key = b"anr:".to_vec();
        key.extend_from_slice(pk);
        let _ = rdb::delete("default", &key);

        // cleanup indexes
        let _ = cleanup_indexes_for_pk(pk);

        Ok(())
    }
}
