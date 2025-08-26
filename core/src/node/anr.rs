use crate::utils::bls12_381::{sign, verify};
use once_cell::sync::Lazy;
use scc::HashMap;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// global in-memory storage for anrs
static ANR_STORE: Lazy<Arc<HashMap<Vec<u8>, ANR>>> = Lazy::new(|| Arc::new(HashMap::new()));

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

// storage functions using scc hashmap

// insert or update anr
pub fn insert(anr: ANR) -> Result<(), String> {
    // check if we have chain pop for this pk (would need consensus module)
    // let has_chain_pop = consensus::chain_pop(&anr.pk).is_some();
    let mut anr = anr;
    anr.has_chain_pop = false; // placeholder

    let pk = anr.pk.clone();
    
    // check if anr already exists and update accordingly
    ANR_STORE.entry(pk.clone()).and_modify(|old| {
        // only update if newer timestamp
        if anr.ts > old.ts {
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
            *old = anr.clone();
        }
    }).or_insert_with(|| {
        // new anr
        anr.handshaked = false;
        anr.error = None;
        anr.error_tries = 0;
        anr.next_check = anr.ts + 3;
        anr
    });

    Ok(())
}

// get anr by public key
pub fn get(pk: &[u8]) -> Result<Option<ANR>, String> {
    Ok(ANR_STORE.read(pk, |_, v| v.clone()))
}

// get all anrs
pub fn get_all() -> Result<Vec<ANR>, String> {
    let mut anrs = Vec::new();
    ANR_STORE.scan(|_k, v| {
        anrs.push(v.clone());
    });
    Ok(anrs)
}

// set handshaked status
pub fn set_handshaked(pk: &[u8]) -> Result<(), String> {
    let _ = ANR_STORE.entry(pk.to_vec()).and_modify(|anr| {
        anr.handshaked = true;
    });
    Ok(())
}

// query functions

// get all handshaked node public keys
pub fn handshaked() -> Result<Vec<Vec<u8>>, String> {
    let mut pks = Vec::new();
    ANR_STORE.scan(|k, v| {
        if v.handshaked {
            pks.push(k.clone());
        }
    });
    Ok(pks)
}

// get all not handshaked (pk, ip4) pairs
pub fn not_handshaked_pk_ip4() -> Result<Vec<(Vec<u8>, Ipv4Addr)>, String> {
    let mut results = Vec::new();
    ANR_STORE.scan(|k, v| {
        if !v.handshaked {
            results.push((k.clone(), v.ip4));
        }
    });
    Ok(results)
}

// check if node is handshaked
pub fn is_handshaked(pk: &[u8]) -> Result<bool, String> {
    Ok(ANR_STORE.read(pk, |_, v| v.handshaked).unwrap_or(false))
}

// check if node is handshaked with valid ip4
pub fn handshaked_and_valid_ip4(pk: &[u8], ip4: &Ipv4Addr) -> Result<bool, String> {
    Ok(ANR_STORE.read(pk, |_, v| v.handshaked && v.ip4 == *ip4).unwrap_or(false))
}

// get random verified nodes
pub fn get_random_verified(count: usize) -> Result<Vec<ANR>, String> {
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
pub fn get_random_unverified(count: usize) -> Result<Vec<(Vec<u8>, Ipv4Addr)>, String> {
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
pub fn all_validators() -> Result<Vec<ANR>, String> {
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
) -> Result<(), String> {
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

// clear all anrs (useful for testing)
pub fn clear_all() -> Result<(), String> {
    ANR_STORE.clear();
    Ok(())
}

// get count of anrs
pub fn count() -> usize {
    ANR_STORE.len()
}

// get count of handshaked anrs
pub fn count_handshaked() -> usize {
    let mut count = 0;
    ANR_STORE.scan(|_, v| {
        if v.handshaked {
            count += 1;
        }
    });
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anr_operations() {
        // create test keys with unique pk to avoid conflicts
        let _sk = vec![1; 32];
        let mut pk = vec![2; 48];
        // make pk unique per test run to avoid collision with parallel tests
        let pid_bytes = std::process::id().to_le_bytes();
        let time_bytes = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);
        pk[4..12].copy_from_slice(&time_bytes[..8]);

        let pop = vec![3; 96];
        let ip4 = Ipv4Addr::new(127, 0, 0, 1);
        let version = "1.0.0".to_string();

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
        assert!(retrieved.handshaked, "Expected handshaked to be true after set_handshaked");

        // test handshaked query
        let handshaked_pks = handshaked().unwrap();
        assert!(handshaked_pks.iter().any(|p| p == &pk), "pk should be in handshaked list");

        // test is_handshaked
        assert!(is_handshaked(&pk).unwrap(), "is_handshaked should return true");

        // test get_all
        let all = get_all().unwrap();
        assert!(!all.is_empty());
        assert!(all.iter().any(|a| a.pk == pk));

        // test count functions - since tests run in parallel, we can't assume exact counts
        let total_count = count();
        assert!(total_count >= 1, "Expected at least 1 ANR, got {}", total_count);
        
        // cleanup - remove only our test anr
        let _ = ANR_STORE.remove(&pk);
        
        // verify our pk was removed
        assert!(get(&pk).unwrap().is_none(), "Our pk should be removed");
    }

    #[tokio::test]
    async fn test_anr_update() {
        // create unique pk for this test
        let mut pk = vec![1; 48];
        let pid_bytes = std::process::id().to_le_bytes();
        let time_bytes = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);
        pk[4..12].copy_from_slice(&time_bytes[..8]);
        let pop = vec![2; 96];
        let ip4 = Ipv4Addr::new(192, 168, 1, 1);
        let version = "1.0.0".to_string();

        // insert initial anr
        let anr1 = ANR {
            ip4,
            pk: pk.clone(),
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 1000,
            version: version.clone(),
            handshaked: true,
            has_chain_pop: false,
            error: None,
            error_tries: 0,
            next_check: 1003,
        };
        insert(anr1).unwrap();
        set_handshaked(&pk).unwrap();

        // try to insert older anr (should not update)
        let anr2 = ANR {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: pk.clone(),
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 999,
            version: version.clone(),
            handshaked: false,
            has_chain_pop: false,
            error: None,
            error_tries: 0,
            next_check: 1002,
        };
        insert(anr2).unwrap();

        // verify old anr was not updated
        let retrieved = get(&pk).unwrap().unwrap();
        assert_eq!(retrieved.ip4, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(retrieved.ts, 1000);
        assert!(retrieved.handshaked);

        // insert newer anr with same ip (should preserve handshake)
        let anr3 = ANR {
            ip4,
            pk: pk.clone(),
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 2000,
            version: "2.0.0".to_string(),
            handshaked: false,
            has_chain_pop: false,
            error: None,
            error_tries: 0,
            next_check: 2003,
        };
        insert(anr3).unwrap();

        let retrieved = get(&pk).unwrap().unwrap();
        assert_eq!(retrieved.ts, 2000);
        assert_eq!(retrieved.version, "2.0.0");
        assert!(retrieved.handshaked); // should be preserved

        // insert newer anr with different ip (should reset handshake)
        let anr4 = ANR {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: pk.clone(),
            pop,
            port: 36969,
            signature: vec![0; 96],
            ts: 3000,
            version: "3.0.0".to_string(),
            handshaked: true,
            has_chain_pop: false,
            error: Some("old error".to_string()),
            error_tries: 5,
            next_check: 3003,
        };
        insert(anr4).unwrap();

        let retrieved = get(&pk).unwrap().unwrap();
        assert_eq!(retrieved.ts, 3000);
        assert_eq!(retrieved.ip4, Ipv4Addr::new(10, 0, 0, 1));
        assert!(!retrieved.handshaked); // should be reset
        assert_eq!(retrieved.error, None); // should be reset
        assert_eq!(retrieved.error_tries, 0); // should be reset

        // cleanup - remove only our test anr
        let _ = ANR_STORE.remove(&pk);
    }
}