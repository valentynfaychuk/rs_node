pub mod agg_sig;
pub mod entry;
pub mod kv;
pub mod tx;

pub use agg_sig::{AggSig, DST, DST_ATT, DST_ENTRY, DST_MOTION, DST_NODE, DST_POP, DST_TX, DST_VRF};

/// TODO: return trainers for the given height
pub fn trainers_for_height(_height: i64) -> Option<Vec<[u8; 48]>> {
    None
}

/// TODO: Chain epoch accessor (Elixir: Consensus.chain_epoch/0)
/// Placeholder returns 0 until chain state is implemented.
pub fn chain_epoch() -> i64 {
    0
}

/// TODO: Latest observed nonce for a signer (Elixir: Consensus.chain_nonce/1)
/// None means no prior nonce is recorded.
pub fn chain_nonce(_signer: &[u8]) -> Option<i64> {
    None
}

/// TODO: Balance accessor (Elixir: Consensus.chain_balance/1)
/// Returns 0 until chain state is implemented.
pub fn chain_balance(_signer: &[u8]) -> u64 {
    0
}
