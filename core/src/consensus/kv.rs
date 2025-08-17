// TODO: must be implemented on top of the RocksDB
// Other options include sled or komora
use blake3;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Put,
    Delete,
    SetBit { bit_idx: u32, bloom_size: u32 },
    ClearBit { bit_idx: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    pub op: Op,
    pub key: String,
    pub value: Option<Vec<u8>>, // for Put original/new values or for revert
}

#[derive(Default, Debug, Clone)]
struct KvCtx {
    // Ordered store to support prefix iteration and next/prev
    store: BTreeMap<String, Vec<u8>>,
    mutations: VecDeque<Mutation>,
    mutations_reverse: VecDeque<Mutation>,
}

thread_local! {
    static CTX: RefCell<KvCtx> = RefCell::new(KvCtx::default());
}

fn get_store_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut KvCtx) -> R,
{
    CTX.with(|c| f(&mut *c.borrow_mut()))
}

fn get_store<F, R>(f: F) -> R
where
    F: FnOnce(&KvCtx) -> R,
{
    CTX.with(|c| f(&*c.borrow()))
}

fn ascii_i64(bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.parse::<i64>().ok()
}

fn i64_ascii(n: i64) -> Vec<u8> {
    n.to_string().into_bytes()
}

pub fn reset() {
    get_store_mut(|ctx| {
        *ctx = KvCtx::default();
    });
}

pub fn kv_put(key: &str, value: &[u8]) {
    get_store_mut(|ctx| {
        let existed = ctx.store.get(key).cloned();
        ctx.store.insert(key.to_string(), value.to_vec());
        // forward mutation tracks new value
        ctx.mutations.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(value.to_vec()) });
        // reverse mutation: if existed put old value, else delete
        match existed {
            Some(old) => {
                ctx.mutations_reverse.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(old) })
            }
            None => ctx.mutations_reverse.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None }),
        }
    });
}

pub fn kv_increment(key: &str, delta: i64) -> i64 {
    get_store_mut(|ctx| {
        let cur = ctx.store.get(key).and_then(|v| ascii_i64(v.as_slice())).unwrap_or(0);
        let newv = cur.saturating_add(delta);
        let new_bytes = i64_ascii(newv);
        let old_bytes = ctx.store.get(key).cloned();
        ctx.store.insert(key.to_string(), new_bytes.clone());
        ctx.mutations.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(new_bytes) });
        match old_bytes {
            Some(old) => {
                ctx.mutations_reverse.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(old) })
            }
            None => ctx.mutations_reverse.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None }),
        }
        newv
    })
}

pub fn kv_delete(key: &str) {
    get_store_mut(|ctx| {
        if let Some(old) = ctx.store.remove(key) {
            ctx.mutations.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None });
            ctx.mutations_reverse.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(old) });
        }
    });
}

pub fn kv_get(key: &str) -> Option<Vec<u8>> {
    get_store(|ctx| ctx.store.get(key).cloned())
}

pub fn kv_get_to_i64(key: &str) -> Option<i64> {
    kv_get(key).and_then(|v| ascii_i64(&v))
}

pub fn kv_exists(key: &str) -> bool {
    get_store(|ctx| ctx.store.contains_key(key))
}

pub fn kv_get_prefix(prefix: &str) -> Vec<(String, Vec<u8>)> {
    get_store(|ctx| {
        ctx.store
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k[prefix.len()..].to_string(), v.clone()))
            .collect()
    })
}

pub fn kv_clear(prefix: &str) -> usize {
    get_store_mut(|ctx| {
        let keys: Vec<String> = ctx
            .store
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, _)| k.clone())
            .collect();
        let mut count = 0usize;
        for k in keys {
            if let Some(v) = ctx.store.remove(&k) {
                ctx.mutations.push_back(Mutation { op: Op::Delete, key: k.clone(), value: None });
                ctx.mutations_reverse.push_back(Mutation { op: Op::Put, key: k, value: Some(v) });
                count += 1;
            }
        }
        count
    })
}

/// Set a bit at bit_idx within a bitstring page. If the bit changes 0->1, returns true;
/// otherwise returns false. Page size defaults to BIC sol bloom size (65_536 bits) when None.
pub fn kv_set_bit(key: &str, bit_idx: u32, bloom_size_opt: Option<u32>) -> bool {
    let bloom_size = bloom_size_opt.unwrap_or(65_536);
    let byte_len = (bloom_size as usize + 7) / 8;
    get_store_mut(|ctx| {
        let mut page = ctx.store.get(key).cloned().unwrap_or_else(|| vec![0u8; byte_len]);
        let byte_i = (bit_idx / 8) as usize;
        let bit_in_byte = (bit_idx % 8) as u8; // LSB first to match Elixir bitstring semantics
        let mask = 1u8 << bit_in_byte;
        let old_set = (page[byte_i] & mask) != 0;
        if old_set {
            return false;
        }
        // Record mutations (forward: set_bit; reverse: clear_bit or delete if not existed)
        let existed = ctx.store.contains_key(key);
        ctx.mutations.push_back(Mutation { op: Op::SetBit { bit_idx, bloom_size }, key: key.to_string(), value: None });
        if existed {
            ctx.mutations_reverse.push_back(Mutation {
                op: Op::ClearBit { bit_idx },
                key: key.to_string(),
                value: None,
            });
        } else {
            ctx.mutations_reverse.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None });
        }
        page[byte_i] |= mask;
        ctx.store.insert(key.to_string(), page);
        true
    })
}

pub fn hash_mutations(muts: &[Mutation]) -> [u8; 32] {
    // Deterministic compact encoding: [op_code,u32(len(key)),key_bytes, ...]
    // op codes: 0=Put,1=Delete,2=SetBit,3=ClearBit; value included only for Put as length+bytes
    let mut buf = Vec::new();
    for m in muts {
        match &m.op {
            Op::Put => buf.push(0u8),
            Op::Delete => buf.push(1u8),
            Op::SetBit { .. } => buf.push(2u8),
            Op::ClearBit { .. } => buf.push(3u8),
        }
        let k = m.key.as_bytes();
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(k);
        match (&m.op, &m.value) {
            (Op::Put, Some(v)) => {
                buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                buf.extend_from_slice(v);
            }
            (Op::SetBit { bit_idx, bloom_size }, _) => {
                buf.extend_from_slice(&bit_idx.to_le_bytes());
                buf.extend_from_slice(&bloom_size.to_le_bytes());
            }
            (Op::ClearBit { bit_idx }, _) => {
                buf.extend_from_slice(&bit_idx.to_le_bytes());
            }
            _ => {}
        }
    }
    let h = blake3::hash(&buf);
    *h.as_bytes()
}

pub fn mutations() -> Vec<Mutation> {
    get_store(|ctx| ctx.mutations.iter().cloned().collect())
}
pub fn mutations_reverse() -> Vec<Mutation> {
    get_store(|ctx| ctx.mutations_reverse.iter().cloned().collect())
}

pub fn revert(m_rev: &[Mutation]) {
    get_store_mut(|ctx| {
        for m in m_rev.iter().rev() {
            match &m.op {
                Op::Put => {
                    if let Some(v) = &m.value {
                        ctx.store.insert(m.key.clone(), v.clone());
                    }
                }
                Op::Delete => {
                    ctx.store.remove(&m.key);
                }
                Op::ClearBit { bit_idx } => {
                    if let Some(mut page) = ctx.store.get(&m.key).cloned() {
                        let byte_i = (*bit_idx / 8) as usize;
                        let bit_in_byte = (*bit_idx % 8) as u8;
                        let mask = 1u8 << bit_in_byte;
                        page[byte_i] &= !mask;
                        ctx.store.insert(m.key.clone(), page);
                    }
                }
                Op::SetBit { bit_idx, .. } => {
                    if let Some(mut page) = ctx.store.get(&m.key).cloned() {
                        let byte_i = (*bit_idx / 8) as usize;
                        let bit_in_byte = (*bit_idx % 8) as u8;
                        let mask = 1u8 << bit_in_byte;
                        page[byte_i] |= mask;
                        ctx.store.insert(m.key.clone(), page);
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_and_get() {
        reset();
        assert_eq!(kv_get_to_i64("a:1"), None);
        let v = kv_increment("a:1", 5);
        assert_eq!(v, 5);
        assert_eq!(kv_get_to_i64("a:1"), Some(5));
        let v2 = kv_increment("a:1", -2);
        assert_eq!(v2, 3);
        assert_eq!(kv_get("a:1").unwrap(), b"3".to_vec());
    }

    #[test]
    fn prefix_and_clear() {
        reset();
        kv_put("p:x", b"1");
        kv_put("p:y", b"2");
        kv_put("q:z", b"3");
        let got = kv_get_prefix("p:");
        assert_eq!(got.len(), 2);
        let cnt = kv_clear("p:");
        assert_eq!(cnt, 2);
        assert!(!kv_exists("p:x"));
        assert!(kv_exists("q:z"));
    }

    #[test]
    fn set_bit() {
        reset();
        let changed = kv_set_bit("bloom:1", 9, Some(16)); // 2 bytes
        assert!(changed);
        let changed2 = kv_set_bit("bloom:1", 9, Some(16));
        assert!(!changed2);
    }
}
