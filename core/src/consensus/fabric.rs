use crate::config;
use crate::consensus;
use crate::consensus::attestation::Attestation;
use crate::consensus::entry::Entry;
use crate::consensus::entry_gen;
use crate::misc::rocksdb;
use crate::misc::utils::{bools_to_bitvec, get_unix_millis_now};
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;
// TODO: make the database trait that the fabric will use

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    Att(#[from] consensus::attestation::Error),
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    #[error("missing dependency: {0}")]
    Missing(&'static str),
}

const CF_DEFAULT: &str = "default";
const CF_ENTRY_BY_HEIGHT: &str = "entry_by_height";
const CF_ENTRY_BY_SLOT: &str = "entry_by_slot";
const CF_MY_SEEN_TIME_FOR_ENTRY: &str = "my_seen_time_for_entry";
const CF_MY_ATTESTATION_FOR_ENTRY: &str = "my_attestation_for_entry";
const CF_CONSENSUS_BY_ENTRYHASH: &str = "consensus_by_entryhash";
const CF_SYSCONF: &str = "sysconf";

/// Initialize Fabric DB area (creates/open RocksDB with the required CFs)
pub async fn init(base: &str) -> Result<(), Error> {
    rocksdb::init(&format!("{}/fabric", base)).await.map_err(Into::into)
}

pub fn close() {
    rocksdb::close();
}

/// Insert an entry into RocksDB: default CF by hash, seen time, and index by height/slot
pub fn insert_entry(hash: &[u8; 32], height: u64, slot: u64, entry_bin: &[u8], seen_millis: u128) -> Result<(), Error> {
    // idempotent: if already present under default CF, do nothing
    if rocksdb::get(CF_DEFAULT, hash)?.is_none() {
        rocksdb::put(CF_DEFAULT, hash, entry_bin)?;
        rocksdb::put(CF_MY_SEEN_TIME_FOR_ENTRY, hash, &seen_millis.to_be_bytes())?;

        // index by height and slot -> value is hash, key is "{height}:{hash_b58_or_bytes}"
        let b58_hash = bs58::encode(hash).into_string();
        rocksdb::put(CF_ENTRY_BY_HEIGHT, format!("{}:{}", height, &b58_hash).as_bytes(), hash)?;
        rocksdb::put(CF_ENTRY_BY_SLOT, format!("{}:{}", slot, &b58_hash).as_bytes(), hash)?;
    }

    Ok(())
}

/// Get all entries (ETF-encoded) for a specific height
pub fn entries_by_height(height: u64) -> Result<Vec<Vec<u8>>, Error> {
    let prefix = format!("{}:", height);
    let kvs = rocksdb::iter_prefix(CF_ENTRY_BY_HEIGHT, prefix.as_bytes())?;
    let mut out = Vec::new();
    for (_k, v) in kvs.into_iter() {
        // v is entry hash
        if let Some(entry_bin) = rocksdb::get(CF_DEFAULT, &v)? {
            out.push(entry_bin);
        }
    }
    Ok(out)
}

/// Insert the genesis entry and initial state markers if not present yet
pub fn insert_genesis() -> Result<(), Error> {
    let genesis_entry = consensus::entry_gen::get();
    if rocksdb::get(CF_DEFAULT, &genesis_entry.hash)?.is_some() {
        return Ok(()); // already inserted, no-op
    }

    println!("🌌  Ahhh... Fresh Fabric. Marking genesis..");

    let hash = genesis_entry.hash;
    let height = genesis_entry.header.height;
    let slot = genesis_entry.header.slot;
    let entry_bin: Vec<u8> = genesis_entry.try_into().map_err(|_| Error::Missing("genesis_entry"))?;
    insert_entry(&hash, height, slot, &entry_bin, get_unix_millis_now())?;

    // insert genesis attestation aggregate (no-op until full trainers implemented)
    let att = entry_gen::attestation();
    aggregate_attestation(&att)?;

    // set rooted_tip = genesis.hash and temporal_height = 0
    set_rooted_tip(&hash)?;
    rocksdb::put(CF_SYSCONF, b"temporal_height", &height.to_be_bytes())?;

    Ok(())
}

/// Read Entry stub (height only) from CF_DEFAULT by entry hash (32 bytes)
pub fn get_entry_by_hash(hash: &[u8; 32]) -> Option<Entry> {
    let bin = rocksdb::get(CF_DEFAULT, hash).ok()??;
    let entry = Entry::try_from(bin.as_slice()).ok()?;
    Some(entry)
}

#[derive(Debug, Clone)]
pub struct EntryStub {
    pub hash: [u8; 32],
    pub header_height: u64,
}

pub fn my_attestation_by_entryhash(hash: &[u8]) -> Result<Option<Attestation>, Error> {
    if let Some(bin) = rocksdb::get(CF_MY_ATTESTATION_FOR_ENTRY, hash)? {
        let a = Attestation::from_etf_bin(&bin)?;
        return Ok(Some(a));
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsensus {
    pub mask: Vec<bool>,
    pub agg_sig: [u8; 96],
}

fn pack_consensus_map(map: &HashMap<[u8; 32], StoredConsensus>) -> Result<Vec<u8>, Error> {
    // Encode as ETF map: key: mutations_hash (binary 32); val: map{mask: bitstring, aggsig: binary}
    let mut outer = HashMap::<Term, Term>::new();
    for (mut_hash, v) in map.iter() {
        let key = Term::from(Binary { bytes: mut_hash.to_vec() });
        // pack mask into bytes (bitstring, MSB first)
        let mask_bytes = bools_to_bitvec(&v.mask);
        let mut inner = HashMap::new();
        inner.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: mask_bytes }));
        inner.insert(Term::Atom(Atom::from("aggsig")), Term::from(Binary { bytes: v.agg_sig.to_vec() }));
        outer.insert(key, Term::from(eetf::Map { map: inner }));
    }
    let term = Term::from(eetf::Map { map: outer });
    let mut out = Vec::new();
    term.encode(&mut out)?;
    Ok(out)
}

fn unpack_consensus_map(_bin: &[u8]) -> Result<HashMap<[u8; 32], StoredConsensus>, Error> {
    unimplemented!();
    // let map = Term::decode(bin)?.get_term_map().unwrap_or_default();
    //
    // let mut out: HashMap<[u8; 32], StoredConsensus> = HashMap::new();
    // for (k, v) in map.into_iter() {
    //     let mh = k.get_binary().ok_or(Error::Missing("mutations_hash"))?;
    //     let mh: [u8; 32] = mh.try_into().map_err(|_| Error::InvalidLength("mutations_hash"))?;
    //     let inner = v.get_term_map().ok_or(Error::Missing("consensus_inner"))?;
    //     let mask = inner.get_binary("mask").map(bitvec_to_bools).ok_or(Error::Missing("mask"))?;
    //     let agg_sig = inner.get_binary("aggsig").ok_or(Error::Missing("aggsig"))?;
    //     out.insert(mh, StoredConsensus { mask, agg_sig });
    // }
    // Ok(out)
}

/// If DB has an attestation for entry_hash signed by a different trainer than current
/// config::trainer_pk, then resign with current keys, update DB and return new attestation.
pub fn get_or_resign_my_attestation(entry_hash: &[u8; 32]) -> Result<Option<Attestation>, Error> {
    let packed = rocksdb::get(CF_MY_ATTESTATION_FOR_ENTRY, entry_hash)?;
    let Some(bin) = packed else { return Ok(None) };
    let att = Attestation::from_etf_bin(&bin)?;
    if att.signer == config::trainer_pk() {
        return Ok(Some(att));
    }
    println!("imported database, resigning attestation {}", bs58::encode(entry_hash).into_string());
    let pk = config::trainer_pk();
    let sk = config::trainer_sk_seed();
    let new_a = Attestation::sign_with(&pk, &sk, entry_hash, &att.mutations_hash)?;
    let packed = new_a.to_etf_bin()?;
    rocksdb::put(CF_MY_ATTESTATION_FOR_ENTRY, entry_hash, packed.as_slice())?;
    Ok(Some(new_a))
}

/// Update aggregate consensus under entry_hash for attestations with matching mutations_hash
pub fn aggregate_attestation(_a: &Attestation) -> Result<(), Error> {
    // Fetch entry if available (not implemented yet)
    // let entry = entry_by_hash(&a.entry_hash);
    // let trainers = entry.as_ref().and_then(|e| consensus::trainers_for_height(e.header_height));
    // if trainers.is_none() { return Ok(()); }
    // let trainers = trainers.unwrap();

    // For now, without trainers we cannot aggregate reliably; exit early.
    // TODO: implement trainers_for_height and entry storage then enable below code.
    if consensus::trainers_for_height(0).is_none() {
        return Ok(());
    }

    // The code below is kept as reference when trainers are implemented.
    // let trainers = trainers;
    // let mut consensuses = match rocksdb::get(CF_CONSENSUS_BY_ENTRYHASH, &a.entry_hash)? {
    //     Some(bin) => unpack_consensus_map(&bin)?,
    //     None => HashMap::new(),
    // };
    // let cur = consensuses.get(&a.mutations_hash).cloned();
    // let mut agg = match cur {
    //     None => AggSig::new(&trainers, &a.signer, &a.signature).map_err(|_| Error::Missing("agg_sig"))?,
    //     Some(sc) => {
    //         if sc.mask.len() < trainers.len() {
    //             AggSig::new(&trainers, &a.signer, &a.signature).map_err(|_| Error::Missing("agg_sig"))?
    //         } else {
    //             let mut ag = AggSig { mask: sc.mask, aggsig: sc.aggsig };
    //             ag.add(&trainers, &a.signer, &a.signature).map_err(|_| Error::Missing("agg_sig_add"))?;
    //             ag
    //         }
    //     }
    // };
    // consensuses.insert(a.mutations_hash, StoredConsensus { mask: agg.mask.clone(), aggsig: agg.aggsig });
    // let packed = pack_consensus_map(&consensuses)?;
    // rocksdb::put(CF_CONSENSUS_BY_ENTRYHASH, &a.entry_hash, &packed)?;

    Ok(())
}

/// Insert externally computed consensus if its score is better than previous and >= 0.67
pub fn insert_consensus(
    entry_hash: [u8; 32],
    mutations_hash: [u8; 32],
    consensus_mask: Vec<bool>,
    consensus_agg_sig: [u8; 96],
    score: f64,
) -> Result<(), Error> {
    if score < 0.67 {
        return Ok(());
    }
    // TODO: trainers and best_by_weight are not implemented, we optimistically accept if threshold is met

    let mut map = match rocksdb::get(CF_CONSENSUS_BY_ENTRYHASH, &entry_hash)? {
        Some(bin) => unpack_consensus_map(&bin)?,
        None => HashMap::new(),
    };
    map.insert(mutations_hash, StoredConsensus { mask: consensus_mask, agg_sig: consensus_agg_sig });
    let packed = pack_consensus_map(&map)?;
    rocksdb::put(CF_CONSENSUS_BY_ENTRYHASH, &entry_hash, &packed)?;
    Ok(())
}

/// Best consensus by weight for a given entry hash and trainers list (weights TODO: all 1.0)
pub fn best_consensus_by_entryhash(
    trainers: &[[u8; 48]],
    entry_hash: &[u8],
) -> Result<(Option<[u8; 32]>, Option<f64>, Option<StoredConsensus>), Error> {
    let Some(bin) = rocksdb::get(CF_CONSENSUS_BY_ENTRYHASH, entry_hash)? else { return Ok((None, None, None)) };
    let map = unpack_consensus_map(&bin)?;
    let max_score = trainers.len() as f64;
    let mut best: Option<([u8; 32], f64, StoredConsensus)> = None;
    for (k, v) in map.into_iter() {
        // Compute score as number of set bits among trainers (unit weight)
        let mut score_units = 0f64;
        for (i, bit) in v.mask.iter().enumerate() {
            if i < trainers.len() && *bit {
                score_units += 1.0;
            }
        }
        let score = if max_score > 0.0 { score_units / max_score } else { 0.0 };
        match &mut best {
            None => best = Some((k, score, v)),
            Some((_bk, bs, _bv)) if score > *bs => best = Some((k, score, v)),
            _ => {}
        }
    }
    if let Some((k, s, v)) = best { Ok((Some(k), Some(s), Some(v))) } else { Ok((None, None, None)) }
}

pub fn set_temporal_height(height: u64) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"temporal_height", &height.to_be_bytes())?)
}

pub fn get_temporal_height() -> Result<Option<u64>, Error> {
    match rocksdb::get(CF_SYSCONF, b"temporal_height")? {
        Some(hb) => Ok(Some(u64::from_be_bytes(hb.try_into().map_err(|_| Error::InvalidLength("temporal_height"))?))),
        None => Ok(None),
    }
}

pub fn set_rooted_tip(hash: &[u8; 32]) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"rooted_tip", hash)?)
}

pub fn get_rooted_tip() -> Result<Option<[u8; 32]>, Error> {
    match rocksdb::get(CF_SYSCONF, b"rooted_tip")? {
        Some(rt) => Ok(Some(rt.try_into().map_err(|_| Error::InvalidLength("rooted_tip"))?)),
        None => Ok(None),
    }
}

pub fn set_temporal_tip(hash: &[u8; 32]) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"rooted_tip", hash)?)
}

pub fn get_temporal_tip() -> Result<Option<[u8; 32]>, Error> {
    match rocksdb::get(CF_SYSCONF, b"temporal_tip")? {
        Some(rt) => Ok(Some(rt.try_into().map_err(|_| Error::InvalidLength("temporal_tip"))?)),
        None => Ok(None),
    }
}
