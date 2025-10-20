pub const DECIMALS: u32 = 9;
pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn to_cents(coins: u128) -> u128 {
    coins.saturating_mul(10_000_000)
}

// Re-export from rocksdb_runtime::bic::coin for backward compatibility
pub use crate::rocksdb_runtime::bic::coin::{
    burn_address, balance, burn_balance, CallEnv, call, CoinError,
    to_flat, to_tenthousandth, from_flat,
};
