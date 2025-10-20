pub mod apply;
pub mod bic;
pub mod muts;
pub mod utils;
pub mod wasm;
pub mod rocksdb_runtime;

// Create a kv module that combines both implementations for backward compatibility
pub mod kv {
    // Re-export RocksDB-based functions from root kv module
    pub use crate::root_kv::{kv_delete, kv_exists, kv_get, kv_get_next, kv_get_prev, kv_increment, kv_put, kv_set_bit};
    // Re-export ApplyCtx-based types from rocksdb_runtime for backward compatibility
    pub use crate::rocksdb_runtime::kv::{ApplyCtx, Op, Mutation, hash_mutations, mutations_from_etf, mutations_to_etf, revert};
}

// Keep root-level kv module as root_kv internally
mod root_kv;

pub use apply::{ApplyEnv, CallerEnv, make_apply_env, make_caller_env, set_apply_env_tx};
pub use kv::{kv_delete, kv_exists, kv_get, kv_get_next, kv_get_prev, kv_increment, kv_put, kv_set_bit};
pub use muts::Mutation;
pub use utils::bcat;

// Re-export rocksdb_runtime for compatibility
pub use rocksdb_runtime as rdb;

// Re-export old API for backward compatibility (these types moved to rocksdb_runtime)
pub use rocksdb_runtime::{
    apply_entry, ApplyEntryResult, EntryHeader, ApplyEntryError, Tx, TxAction, TxResult, TxU,
};
pub use rocksdb_runtime::kv::{ApplyCtx, Op, hash_mutations, mutations_from_etf, mutations_to_etf, revert};
