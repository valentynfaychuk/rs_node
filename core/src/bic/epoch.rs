use crate::consensus::{DST_MOTION, DST_POP};
use crate::misc::blake3;
use crate::misc::bls12_381;

use crate::bic::coin;
use crate::bic::sol;
use crate::bic::sol::Solution;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum EpochError {
    #[error("invalid sol: already exists in bloom or failed verification")]
    InvalidSol,
    #[error("invalid epoch")]
    InvalidEpoch,
    #[error("invalid proof of possession")]
    InvalidPop,
    #[error("invalid emission address pk size")]
    InvalidAddressPk,
    #[error("invalid trainer pk")]
    InvalidTrainerPk,
    #[error("invalid amount of signatures")]
    InvalidAmountOfSignatures,
    #[error("invalid signature")]
    InvalidSignature,
}

pub const EPOCH_EMISSION_BASE: u64 = 1_000_000_000_000_000; // BIC.Coin.to_flat(1_000_000)
pub const EPOCH_EMISSION_FIXED: u64 = 100_000_000_000_000; // BIC.Coin.to_flat(100_000)
pub const EPOCH_INTERVAL: u64 = 100_000;
const A: f64 = 23_072_960_000.0;
const C: f64 = 1_110.573_766;
const START_EPOCH: u64 = 500;

/// Emission schedule, port of epoch_emission/1
pub fn epoch_emission(epoch: u64) -> u64 {
    if epoch >= START_EPOCH {
        let val = (0.5 * A / f64::powf((epoch - START_EPOCH) as f64 + C, 1.5)).floor();
        coin::to_flat(val as u64)
    } else {
        epoch_emission_1(epoch, EPOCH_EMISSION_BASE) + EPOCH_EMISSION_FIXED
    }
}

fn epoch_emission_1(epoch: u64, acc: u64) -> u64 {
    if epoch == 0 {
        acc
    } else {
        let sub = acc.saturating_mul(333) / 1_000_000;
        let emitted = acc.saturating_sub(sub);
        epoch_emission_1(epoch - 1, emitted)
    }
}

/// Sum of emissions up to the given epoch, without burn deduction
pub fn circulating_without_burn(epoch: u64) -> u64 {
    fn rec(n: u64, acc: u64) -> u64 {
        if n == 0 { acc } else { rec(n - 1, acc + epoch_emission(n)) }
    }
    rec(epoch, 0)
}

/// Trait to inject a burn meter
pub trait BurnMeter {
    fn burn_balance(&self) -> u64;
}

pub fn circulating_with_burn(epoch: u64, burn_meter: &impl BurnMeter) -> u64 {
    circulating_without_burn(epoch).saturating_sub(burn_meter.burn_balance())
}

/// Environment for calls
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnv {
    pub entry_epoch: u64,
    pub entry_height: u64,
    pub account_caller: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochCall {
    SubmitSol {
        sol: Vec<u8>,
    },
    SetEmissionAddress {
        address: [u8; 48],
    },
    SlashTrainer {
        epoch: u64,
        malicious_pk: [u8; 48],
        signature: Vec<u8>,
        mask: Vec<bool>,
        // note: in Elixir, trainers are pulled from KV; here we accept them optionally
        trainers: Option<Vec<[u8; 48]>>,
    },
}

#[derive(Default, Debug, Clone)]
pub struct Epoch;

impl Epoch {
    /// Dispatch a call, state mutations are TODO
    pub fn call(&self, op: EpochCall, env: &CallEnv) -> Result<(), EpochError> {
        match op {
            EpochCall::SubmitSol { sol } => self.submit_sol(env, &sol),
            EpochCall::SetEmissionAddress { address } => self.set_emission_address(env, &address),
            EpochCall::SlashTrainer { epoch, malicious_pk, signature, mask, trainers } => {
                self.slash_trainer(env, epoch, &malicious_pk, &signature, &mask, trainers)
            }
        }
    }

    fn submit_sol(&self, env: &CallEnv, sol_bytes: &[u8]) -> Result<(), EpochError> {
        let hash = blake3::hash(sol_bytes);
        let _segments = crate::bic::sol_bloom::segs(&hash);
        // TODO: for each segment: kv_set_bit("bic:epoch:solbloom:{page}", bit_offset)

        // unpack and verify epoch
        let parsed = Solution::unpack(sol_bytes).map_err(|_| EpochError::InvalidSol)?;
        let (epoch, pk, pop) = match parsed {
            sol::Solution::V2(v2) => (v2.epoch as u64, v2.pk, v2.pop),
            sol::Solution::V1(v1) => (v1.epoch as u64, v1.pk, v1.pop),
            sol::Solution::V0(v0) => (v0.epoch as u64, v0.pk, v0.pop),
        };
        if epoch != env.entry_epoch {
            return Err(EpochError::InvalidEpoch);
        }

        // use cached verification
        let valid = sol::verify_with_hash(sol_bytes, &hash).unwrap_or(false);
        if !valid {
            return Err(EpochError::InvalidSol);
        }

        // verify Proof-of-Possession: message is pk bytes
        if bls12_381::verify(&pk, &pop, &pk, DST_POP).is_err() {
            return Err(EpochError::InvalidPop);
        }

        // TODO: bloom filter set bits in KV, ensure uniqueness, increment solutions_count for pk
        Ok(())
    }

    fn set_emission_address(&self, _env: &CallEnv, address: &[u8; 48]) -> Result<(), EpochError> {
        // Elixir checks byte_size(address) == 48
        if address.len() != 48 {
            return Err(EpochError::InvalidAddressPk);
        }
        // TODO: kv_put("bic:epoch:emission_address:{caller}", address)
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn slash_trainer(
        &self,
        env: &CallEnv,
        epoch: u64,
        malicious_pk: &[u8; 48],
        signature: &[u8],
        mask: &Vec<bool>,
        trainers_opt: Option<Vec<[u8; 48]>>,
    ) -> Result<(), EpochError> {
        if env.entry_epoch != epoch {
            return Err(EpochError::InvalidEpoch);
        }

        // TODO: read trainers from kv
        let trainers = match trainers_opt {
            Some(t) => t,
            None => unimplemented!("TODO: read trainers from KV"),
        };

        if !trainers.iter().any(|pk| pk == malicious_pk) {
            return Err(EpochError::InvalidTrainerPk);
        }

        // verify and threshold as in Elixir
        slash_trainer_verify(epoch, malicious_pk, &trainers, mask, signature)?;

        // TODO: persist removal into KV and update trainer set and height index
        Ok(())
    }

    /// Epoch transition (Elixir next/1). Placeholder without KV.
    pub fn next(&self, _env: &CallEnv) -> Result<(), EpochError> {
        // TODO: pay emissions by solutions_count leaders, clear bloom and counters, choose new trainers
        unimplemented!("TODO: implement epoch transition logic")
    }
}

pub fn slash_trainer_verify(
    cur_epoch: u64,
    malicious_pk: &[u8; 48],
    trainers: &[[u8; 48]],
    mask: &Vec<bool>,
    signature: &[u8],
) -> Result<(), EpochError> {
    // unmask trainers according to bit mask
    let signers = unmask_trainers(trainers, mask);
    let consensus_pct = if trainers.is_empty() { 0.0 } else { (signers.len() as f64) / (trainers.len() as f64) };

    if consensus_pct < 0.67 {
        return Err(EpochError::InvalidAmountOfSignatures);
    }

    // aggregate public keys and verify signature on the motion message
    let apk = bls12_381::aggregate_public_keys(signers.iter()).map_err(|_| EpochError::InvalidSignature)?;

    // msg = <<"slash_trainer", cur_epoch::32-little, malicious_pk::binary>>
    let mut msg = Vec::with_capacity("slash_trainer".len() + 4 + 48);
    msg.extend_from_slice(b"slash_trainer");
    msg.extend_from_slice(&(cur_epoch as u32).to_le_bytes());
    msg.extend_from_slice(malicious_pk);

    bls12_381::verify(&apk, signature, &msg, DST_MOTION).map_err(|_| EpochError::InvalidSignature)
}

/// Return the subset of trainers whose corresponding bits are set in the bitmask
pub fn unmask_trainers(trainers: &[[u8; 48]], mask: &Vec<bool>) -> Vec<[u8; 48]> {
    let mut res = Vec::new();
    for i in 0..trainers.len() {
        if let Some(&bit) = mask.get(i)
            && bit
        {
            res.push(trainers[i]);
        }
    }
    res
}

fn bit_is_set(mask: &[u8], idx: usize, mask_bits: usize) -> bool {
    if idx >= mask_bits {
        return false;
    }
    let byte_idx = idx / 8;
    let bit_idx = idx % 8; // LSB-first as in Elixir bitstrings
    if byte_idx >= mask.len() {
        return false;
    }
    let b = mask[byte_idx];
    ((b >> bit_idx) & 1) == 1
}
