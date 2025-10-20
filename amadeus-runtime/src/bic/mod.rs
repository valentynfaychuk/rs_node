// Root-level bic modules (RocksDB protocol-level types)
pub mod coin;
pub mod protocol;
pub mod sol_bloom;
pub mod sol_difficulty;

// Re-export from rocksdb_runtime::bic for backward compatibility
pub use crate::rocksdb_runtime::bic::{
    contract, epoch, sol,
    chain_balance, chain_balance_symbol, chain_pop, chain_nonce,
    chain_diff_bits, chain_segment_vr_hash, chain_total_sols, is_reserved,
};
