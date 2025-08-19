use crate::config;
use crate::consensus::attestation::{Attestation, Error as AttError};
use crate::consensus::{self};
use crate::misc::rocksdb;
use crate::misc::utils::TermExt;
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Rocks(#[from] rocksdb::Error),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    Att(#[from] AttError),
    #[error("missing dependency: {0}")]
    Missing(&'static str),
}

const CF_DEFAULT: &str = "default";
const CF_MY_SEEN_TIME_FOR_ENTRY: &str = "my_seen_time_for_entry";
const CF_MY_ATTESTATION_FOR_ENTRY: &str = "my_attestation_for_entry";
const CF_CONSENSUS_BY_ENTRYHASH: &str = "consensus_by_entryhash";
const CF_SYSCONF: &str = "sysconf";

/// Initialize Fabric DB area (creates/open RocksDB with the required CFs)
pub fn init() -> Result<(), Error> {
    let base = config::work_folder();
    let path = format!("{}/db/fabric", base);
    rocksdb::init(&path)?;
    Ok(())
}

pub fn close() {
    rocksdb::close();
}

/// ENTRY STORAGE is not implemented yet in Rust
pub fn entry_by_hash(_hash: &[u8]) -> Option<EntryStub> {
    // TODO: implement Entry pack/unpack and hook
    None
}

#[derive(Debug, Clone)]
pub struct EntryStub {
    pub hash: [u8; 32],
    pub header_height: i64,
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

fn unpack_consensus_map(bin: &[u8]) -> Result<HashMap<[u8; 32], StoredConsensus>, Error> {
    let term = Term::decode(bin)?;
    let map = match term {
        Term::Map(m) => m.map,
        _ => return Ok(HashMap::new()),
    };
    let mut out: HashMap<[u8; 32], StoredConsensus> = HashMap::new();
    for (k, v) in map.into_iter() {
        let mh = k.get_binary().ok_or(Error::Missing("mutations_hash"))?.to_vec();
        let mh: [u8; 32] = mh.try_into().map_err(|_| AttError::InvalidLength("mutations_hash"))?;
        let inner = v.get_map().ok_or(Error::Missing("consensus_inner"))?;
        let mask_bytes = inner
            .get(&Term::Atom(Atom::from("mask")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or(Error::Missing("mask"))?;
        let agg_sig = inner
            .get(&Term::Atom(Atom::from("aggsig")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or(Error::Missing("aggsig"))?;
        let agg_sig: [u8; 96] =
            agg_sig.try_into().map_err(|_| AttError::InvalidLength("aggsig")).map_err(Error::Att)?;
        out.insert(mh, StoredConsensus { mask: bitvec_to_bools(&mask_bytes), agg_sig });
    }
    Ok(out)
}

fn bools_to_bitvec(mask: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; (mask.len() + 7) / 8];
    for (i, &b) in mask.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}
fn bitvec_to_bools(bytes: &[u8]) -> Vec<bool> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for (_, byte) in bytes.iter().enumerate() {
        for bit in 0..8 {
            let val = (byte >> (7 - bit)) & 1;
            out.push(val == 1);
        }
    }
    out
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
    // TODO: trainers and best_by_weight are not implemented; we optimistically accept if threshold is met.

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

/// Rooted tip helpers (partial)
pub fn set_rooted_tip(hash: &[u8]) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"rooted_tip", hash)?)
}

pub fn rooted_tip() -> Result<Option<Vec<u8>>, Error> {
    Ok(rocksdb::get(CF_SYSCONF, b"rooted_tip")?)
}
