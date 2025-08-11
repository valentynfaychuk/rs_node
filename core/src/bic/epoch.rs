// src/bic/epoch.rs
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use crate::bic::{
    bls::{AggSig, PublicKey},
    coin::{Coin, FlatCoin},
    kv::{KV, KvError},
    sol::{Sol, SolBloom, SolUnpacked},
};

/// All epoch-related state lives behind this struct so it can be injected /
—mocked in tests.
pub struct EpochCtx<K: KV + Clone + Send + Sync + 'static> {
    /// Handle to your (possibly distributed) KV store.
    pub kv: Arc<K>,
    /// Blake3-based hash helper.
    pub hasher: Blake3Hash,
    /// Caches verified solutions for rapid re-checking.
    pub sol_verified_cache: dashmap::DashMap<[u8; 32], bool>,
}

/// Constants lifted 1 : 1 from Elixir
impl<K: KV + Clone + Send + Sync> EpochCtx<K> {
    pub const EPOCH_EMISSION_BASE: FlatCoin = Coin::to_flat(1_000_000);
    pub const EPOCH_EMISSION_FIXED: FlatCoin = Coin::to_flat(100_000);
    pub const EPOCH_INTERVAL: u64 = 100_000;

    const A: f64 = 23_072_960_000.0;
    const C: f64 = 1_110.573_766;
    const START_EPOCH: u64 = 500;
}

/* ---------------------------------------------------------------- *\
 * 1. Pure math helpers                                             *
\* ---------------------------------------------------------------- */

impl<K: KV + Clone + Send + Sync> EpochCtx<K> {
    /// Rust port of `epoch_emission/1` (for epochs ≥ START_EPOCH).
    pub fn epoch_emission_long(epoch: u64) -> FlatCoin {
        assert!(epoch >= Self::START_EPOCH);
        let val =
            (0.5 * Self::A / (f64::powf((epoch - Self::START_EPOCH) as f64 + Self::C, 1.5))).floor();
        Coin::to_flat(val as u64)
    }

    /// Rust port of `epoch_emission/1` (for epochs < START_EPOCH).
    pub fn epoch_emission_short(epoch: u64) -> FlatCoin {
        Self::epoch_emission_1(epoch, Self::EPOCH_EMISSION_BASE) + Self::EPOCH_EMISSION_FIXED
    }

    pub fn epoch_emission(epoch: u64) -> FlatCoin {
        if epoch >= Self::START_EPOCH {
            Self::epoch_emission_long(epoch)
        } else {
            Self::epoch_emission_short(epoch)
        }
    }

    fn epoch_emission_1(epoch: u64, acc: FlatCoin) -> FlatCoin {
        if epoch == 0 {
            acc
        } else {
            let sub = acc * 333 / 1_000_000;
            let emitted = acc - sub;
            Self::epoch_emission_1(epoch - 1, emitted)
        }
    }

    pub fn circulating_without_burn(epoch: u64) -> FlatCoin {
        Self::circulating_without_burn_rec(epoch, 0)
    }

    fn circulating_without_burn_rec(epoch: u64, acc: FlatCoin) -> FlatCoin {
        if epoch == 0 {
            acc
        } else {
            Self::circulating_without_burn_rec(epoch - 1, acc + Self::epoch_emission(epoch))
        }
    }

    pub fn circulating<M: BurnMeter>(epoch: u64, burn_meter: &M) -> FlatCoin {
        Self::circulating_without_burn(epoch) - burn_meter.burn_balance()
    }
}

/* ---------------------------------------------------------------- *\
 * 2. Callable entrypoints (“transactions”)                         *
\* ---------------------------------------------------------------- */

#[derive(Debug)]
pub enum EpochCall {
    /// `:submit_sol`
    SubmitSol { sol: Vec<u8> },
    /// `:set_emission_address`
    SetEmissionAddress { address: [u8; 48] },
    /// `:slash_trainer`
    SlashTrainer {
        epoch: u64,
        malicious_pk: PublicKey,
        signature: Vec<u8>,
        mask_size: usize,
        mask: Vec<u8>,
    },
}

/// Environment info normally passed in by your blockchain runtime.
#[derive(Clone)]
pub struct CallEnv {
    pub entry_epoch: u64,
    pub entry_height: u64,
    pub account_caller: PublicKey,
}

impl<K: KV + Clone + Send + Sync> EpochCtx<K> {
    pub fn call(&self, op: EpochCall, env: &CallEnv) -> Result<(), KvError> {
        match op {
            EpochCall::SubmitSol { sol } => self.submit_sol(env, sol),
            EpochCall::SetEmissionAddress { address } => self.set_emission_address(env, address),
            EpochCall::SlashTrainer {
                epoch,
                malicious_pk,
                signature,
                mask_size,
                mask,
            } => self.slash_trainer(env, epoch, malicious_pk, signature, mask_size, mask),
        }
    }

    /// Port of `call(:submit_sol, …)`.
    fn submit_sol(&self, env: &CallEnv, sol: Vec<u8>) -> Result<(), KvError> {
        todo!("verify solution, update bloom filters, etc.")
    }

    /// Port of `call(:set_emission_address, …)`.
    fn set_emission_address(
        &self,
        env: &CallEnv,
        address: [u8; 48],
    ) -> Result<(), KvError> {
        todo!("persist emission address")
    }

    /// Port of `call(:slash_trainer, …)`.
    fn slash_trainer(
        &self,
        env: &CallEnv,
        epoch: u64,
        malicious_pk: PublicKey,
        signature: Vec<u8>,
        mask_size: usize,
        mask: Vec<u8>,
    ) -> Result<(), KvError> {
        todo!("validate signatures, update trainer set")
    }
}

/* ---------------------------------------------------------------- *\
 * 3. Epoch transition handler (`next/1` in Elixir)                 *
\* ---------------------------------------------------------------- */

impl<K: KV + Clone + Send + Sync> EpochCtx<K> {
    /// Executes end-of-epoch housekeeping and schedules the next trainer set.
    pub fn next(&self, env: &CallEnv) -> Result<(), KvError> {
        todo!("pay emissions, rotate trainers, clear bloom, etc.")
    }
}

/* ---------------------------------------------------------------- *\
 * 4. Helper traits & placeholder types                             *
\* ---------------------------------------------------------------- */

// Something in your codebase that exposes BLS aggregation utilities.
pub trait BlsLib {
    fn verify_pop(pk: &PublicKey, pop: &[u8]) -> bool;
    fn aggregate_pks(pks: &[PublicKey]) -> PublicKey;
    fn verify_signature(pk: &PublicKey, sig: &[u8], msg: &[u8]) -> bool;
}

/// Abstracts the global burn accounting.
pub trait BurnMeter {
    fn burn_balance(&self) -> FlatCoin;
}

/// Wrap whatever Blake3 hash helper you use.
pub struct Blake3Hash;
impl Blake3Hash {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }
}

/* ---------------------------------------------------------------- *\
 * 5. Re-export convenience                                         *
\* ---------------------------------------------------------------- */

pub use super::bls;
pub use crate::bic::coin;
