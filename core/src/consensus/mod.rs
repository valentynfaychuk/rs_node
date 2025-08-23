#![allow(clippy::module_inception)]
pub mod agg_sig;
pub mod attestation;
pub mod consensus;
pub mod entry;
pub mod fabric;
pub mod genesis;
pub mod kv;
pub mod tx;

pub use agg_sig::{AggSig, DST, DST_ATT, DST_ENTRY, DST_MOTION, DST_NODE, DST_POP, DST_TX, DST_VRF};

use crate::misc::rocksdb;
use crate::misc::utils::TermExt;
use eetf::Term;

/// Return trainers for the given height, reading from contractstate CF.
/// Keys: "bic:epoch:trainers:height:{:012}" (ASCII), values: ETF list of 48-byte PKs.
/// Special case: heights in 3195570..=3195575 map to fixed key "000000319557".
pub fn trainers_for_height(height: u64) -> Option<Vec<[u8; 48]>> {
    let cf = "contractstate";
    let value: Option<Vec<u8>> = if (3_195_570..=3_195_575).contains(&height) {
        match rocksdb::get(cf, b"bic:epoch:trainers:height:000000319557") {
            Ok(v) => v,
            Err(_) => return None,
        }
    } else {
        let key_suffix = format!("{:012}", height);
        match rocksdb::get_prev_or_first(cf, "bic:epoch:trainers:height:", &key_suffix) {
            Ok(Some((_k, v))) => Some(v),
            Ok(None) => None,
            Err(_) => return None,
        }
    };

    let bytes = value?;
    let term = Term::decode(&bytes[..]).ok()?;
    let list = term.get_list()?;
    let mut out = Vec::with_capacity(list.len());
    for t in list {
        let pk = t.get_binary()?;
        if pk.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(pk);
        out.push(arr);
    }
    Some(out)
}

/// TODO: Chain epoch accessor (Elixir: Consensus.chain_epoch/0)
/// Placeholder returns 0 until chain state is implemented.
pub fn chain_epoch() -> u64 {
    0
}

/// TODO: Latest observed nonce for a signer (Elixir: Consensus.chain_nonce/1)
/// None means no prior nonce is recorded.
pub fn chain_nonce(_signer: &[u8]) -> Option<u128> {
    None
}

/// TODO: Balance accessor (Elixir: Consensus.chain_balance/1)
/// Returns 0 until chain state is implemented.
pub fn chain_balance(_signer: &[u8]) -> u64 {
    0
}
