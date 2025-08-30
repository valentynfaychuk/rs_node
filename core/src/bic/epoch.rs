use crate::consensus::{DST_MOTION, DST_POP};
use crate::utils::blake3;
use crate::utils::bls12_381;

use crate::bic::coin;
use crate::bic::sol;
use crate::bic::sol::Solution;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct CallEnv {
    pub entry_epoch: u64,
    pub entry_height: u64,
    pub entry_signer: [u8; 48],          // The signer of the current entry
    pub entry_vr: Vec<u8>,               // VR hash for the current entry
    pub tx_hash: Vec<u8>,                // Hash of current transaction
    pub tx_signer: [u8; 48],             // Signer of current transaction
    pub account_caller: [u8; 48],        // Current caller account
    pub account_current: Vec<u8>,        // Current contract account
    pub call_counter: u64,               // Counter for nested calls
    pub call_exec_points: u64,           // Available execution points
    pub call_exec_points_remaining: u64, // Remaining execution points
    pub attached_symbol: Vec<u8>,        // Attached token symbol
    pub attached_amount: Vec<u8>,        // Attached token amount
    pub seed: [u8; 32],                  // Random seed for current call
    pub seedf64: f64,                    // Seed as f64
    pub readonly: bool,                  // Read-only call flag
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

pub const TOP_X: usize = 99;

// Base58-encoded trainer public keys, aka peddlebike67 validator set
const PEDDLEBIKE67_B58: &[&str] = &[
    "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",
];

/// Return the static peddlebike67 validator set
pub fn peddlebike67() -> Vec<[u8; 48]> {
    PEDDLEBIKE67_B58
        .iter()
        .filter_map(|s| bs58::decode(s).into_vec().ok())
        .filter(|v| v.len() == 48)
        .map(|v| {
            let mut a = [0u8; 48];
            a.copy_from_slice(&v);
            a
        })
        .collect()
}

/// Select validators given leaders: prepend peddlebike67, remove duplicates, take TOP_X, shuffle
pub fn select_validators(leaders: &[[u8; 48]]) -> Vec<[u8; 48]> {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    let mut pb = peddlebike67();

    // collect leaders that are not in pb set
    let pb_set: std::collections::HashSet<Vec<u8>> = pb.iter().map(|k| k.to_vec()).collect();
    let mut rest: Vec<[u8; 48]> = Vec::new();
    for pk in leaders {
        if !pb_set.contains(&pk.to_vec()) {
            rest.push(*pk);
        }
    }

    // merge and deduplicate while preserving order (pb first)
    let mut all: Vec<[u8; 48]> = Vec::with_capacity(pb.len() + rest.len());
    all.append(&mut pb);
    all.extend(rest);

    // take TOP_X
    let mut out: Vec<[u8; 48]> = all.into_iter().take(TOP_X).collect();

    // shuffle
    out.as_mut_slice().shuffle(&mut thread_rng());
    out
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

        // Read trainers from KV or use provided ones
        let trainers = match trainers_opt {
            Some(t) => t,
            None => crate::consensus::trainers_for_height(env.entry_height).ok_or(EpochError::InvalidEpoch)?,
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
    for (i, trainer) in trainers.iter().enumerate() {
        if Some(true) == mask.get(i).copied() {
            res.push(*trainer);
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
