use crate::config;
use crate::consensus::agg_sig::DST_ATT;
use crate::consensus::entry::Entry;
use crate::consensus::{self, fabric};
use crate::misc::utils::{TermExt, bitvec_to_bools, bools_to_bitvec};
use crate::misc::{bls12_381 as bls, rocksdb};
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("wrong type: {0}")]
    WrongType(&'static str),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error("invalid entry")]
    InvalidEntry,
    #[error("too far in future")]
    TooFarInFuture,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    Bls(#[from] bls::Error),
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error(transparent)]
    Fabric(#[from] fabric::Error),
}

const CF_SYSCONF: &str = "sysconf";

/// Consensus message holding aggregated attestation for an entry and a particular
/// mutations_hash. Mask denotes which trainers signed the aggregate.
#[derive(Debug, Clone, PartialEq)]
pub struct Consensus {
    pub entry_hash: [u8; 32],
    pub mutations_hash: [u8; 32],
    pub mask: Vec<bool>,
    pub agg_sig: [u8; 96],
    pub score: Option<f64>,
}

impl Consensus {
    /// Decode from ETF map; supported keys: entry_hash, mutations_hash, mask (bitvec), aggsig
    pub fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let map = Term::decode(bin)?.get_term_map().ok_or(Error::WrongType("consensus map"))?;
        let entry_hash = map.get_binary("entry_hash").ok_or(Error::Missing("entry_hash"))?;
        let mutations_hash = map.get_binary("mutations_hash").ok_or(Error::Missing("mutations_hash"))?;
        let mask = map.get_binary("mask").map(bitvec_to_bools).ok_or(Error::Missing("mask"))?;
        let agg_sig = map.get_binary("aggsig").ok_or(Error::Missing("aggsig"))?;
        Ok(Self { entry_hash, mutations_hash, mask, agg_sig, score: None })
    }

    /// Encode into an ETF map with deterministic field set (Elixir Map.take and term_to_binary)
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("entry_hash")), Term::from(Binary { bytes: self.entry_hash.to_vec() }));
        m.insert(Term::Atom(Atom::from("mutations_hash")), Term::from(Binary { bytes: self.mutations_hash.to_vec() }));
        m.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: bools_to_bitvec(&self.mask) }));
        m.insert(Term::Atom(Atom::from("aggsig")), Term::from(Binary { bytes: self.agg_sig.to_vec() }));
        let term = Term::from(eetf::Map { map: m });
        let mut out = Vec::new();
        term.encode(&mut out)?;
        Ok(out)
    }

    /// Validate this consensus vs chain state:
    /// - Entry must exist and not be in the future vs current temporal_height
    /// - Aggregate signature must verify against the set of trainers unmasked by `mask`
    ///
    /// On success, sets self.score = Some(score) and returns Ok(())
    pub fn validate_vs_chain(&mut self) -> Result<(), Error> {
        // Build message to sign: entry_hash || mutations_hash
        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(&self.entry_hash);
        to_sign[32..].copy_from_slice(&self.mutations_hash);

        // Fetch entry stub (height only for now)
        let entry = crate::consensus::fabric::get_entry_by_hash(&self.entry_hash);
        let Some(entry) = entry else { return Err(Error::InvalidEntry) };

        // Ensure entry height is not in the future
        if let Ok(cur_h) = get_chain_height()
            && entry.header.height > cur_h
        {
            return Err(Error::TooFarInFuture);
        }

        // Trainers
        let trainers =
            consensus::trainers_for_height(entry.header.height).ok_or(Error::Missing("trainers_for_height"))?;
        if trainers.is_empty() {
            return Err(Error::Missing("trainers_for_height:empty"));
        }

        // Score by mask weight (unit weights)
        let score = score_mask_unit(&self.mask, trainers.len());

        // Aggregate public keys of signed trainers and verify aggregate signature
        let signed_pks = unmask_trainers(&self.mask, &trainers);
        let agg_pk = bls::aggregate_public_keys(&signed_pks)?;
        bls::verify(&agg_pk, &self.agg_sig, &to_sign, DST_ATT)?;

        self.score = Some(score);
        Ok(())
    }
}

/// Return true if our trainer_pk is included in trainers_for_height(chain_height()+1)
pub fn is_trainer() -> bool {
    let Some(h) = get_chain_height().ok() else { return false };
    let Some(trainers) = consensus::trainers_for_height(h + 1) else { return false };
    trainers.iter().any(|pk| pk == &config::trainer_pk())
}

/// Select trainer for a slot from the roster for the corresponding height
pub fn trainer_for_slot(height: u64, slot: u64) -> Option<[u8; 48]> {
    let trainers = consensus::trainers_for_height(height)?;
    if trainers.is_empty() {
        return None;
    }
    let idx = (slot.rem_euclid(trainers.len() as u64)) as usize;
    trainers.get(idx).copied()
}

pub fn trainer_for_slot_current() -> Option<[u8; 48]> {
    let h = get_chain_height().ok()?;
    trainer_for_slot(h, h)
}

pub fn trainer_for_slot_next() -> Option<[u8; 48]> {
    let h = get_chain_height().ok()?;
    trainer_for_slot(h + 1, h + 1)
}

pub fn trainer_for_slot_next_me() -> bool {
    match trainer_for_slot_next() {
        Some(pk) => pk == config::trainer_pk(),
        None => false,
    }
}

pub fn get_chain_tip_entry() -> Result<Option<Entry>, Error> {
    match fabric::get_temporal_tip()? {
        Some(hash) => Ok(fabric::get_entry_by_hash(&hash)),
        None => Ok(None),
    }
}

pub fn get_chain_rooted_tip_entry() -> Result<Option<Entry>, Error> {
    match fabric::get_rooted_tip()? {
        Some(hash) => Ok(fabric::get_entry_by_hash(&hash)),
        None => Ok(None),
    }
}

pub fn get_chain_height() -> Result<u64, Error> {
    fabric::get_temporal_height()?.ok_or(Error::Missing("temporal_height"))
}

fn unmask_trainers(mask: &[bool], trainers: &[[u8; 48]]) -> Vec<[u8; 48]> {
    mask.iter().zip(trainers.iter()).filter_map(|(&bit, pk)| if bit { Some(*pk) } else { None }).collect()
}

fn score_mask_unit(mask: &[bool], total_trainers: usize) -> f64 {
    if total_trainers == 0 {
        return 0.0;
    }
    let signed = mask.iter().filter(|&&b| b).count();
    (signed as f64) / (total_trainers as f64)
}
