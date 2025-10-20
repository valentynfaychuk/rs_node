use rust_rocksdb::{
    TransactionDB, MultiThreaded, TransactionOptions, WriteOptions,
    Transaction, BoundColumnFamily,
};

use super::bic::protocol;
use super::kv as consensus_kv;
use super::muts as consensus_muts;
use std::collections::HashMap;

pub struct CallerEnv {
    pub readonly: bool,
    pub seed: Option<Vec<u8>>,
    pub seedf64: f64,
    pub entry_signer: [u8; 48],
    pub entry_prev_hash: [u8; 32],
    pub entry_slot: u64,
    pub entry_prev_slot: u64,
    pub entry_height: u64,
    pub entry_epoch: u64,
    pub entry_vr: [u8; 96],
    pub entry_vr_b3: [u8; 32],
    pub entry_dr: [u8; 32],
    pub tx_index: u64,
    pub tx_signer: [u8; 48],
    pub tx_nonce: u64,
    pub tx_hash: [u8; 32],
    pub account_origin: Vec<u8>,
    pub account_caller: Vec<u8>,
    pub account_current: Vec<u8>,
    pub attached_symbol: String,
    pub attached_amount: String,
    pub call_counter: u32,
    pub call_exec_points: u64,
    pub call_exec_points_remaining: u64,
}

pub fn make_caller_env(
    entry_signer: &[u8; 48], entry_prev_hash: &[u8; 32],
    entry_slot: u64, entry_prev_slot: u64, entry_height: u64, entry_epoch: u64,
    entry_vr: &[u8; 96], entry_vr_b3: &[u8; 32], entry_dr: &[u8; 32],
) -> CallerEnv {
    CallerEnv {
        readonly: false,
        seed: None,
        seedf64: 1.0,
        entry_signer: *entry_signer,
        entry_prev_hash: *entry_prev_hash,
        entry_slot,
        entry_prev_slot,
        entry_height,
        entry_epoch,
        entry_vr: *entry_vr,
        entry_vr_b3: *entry_vr_b3,
        entry_dr: *entry_dr,
        tx_index: 0,
        tx_signer: [0u8; 48],
        tx_nonce: 0,
        tx_hash: [0u8; 32],
        account_origin: Vec::new(),
        account_caller: Vec::new(),
        account_current: Vec::new(),
        attached_symbol: String::new(),
        attached_amount: String::new(),
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
    }
}

pub struct ApplyEnv<'db> {
    pub caller_env: CallerEnv,
    pub cf: std::sync::Arc<BoundColumnFamily<'db>>,
    pub txn: Transaction<'db, TransactionDB<MultiThreaded>>,
    pub muts: Vec<consensus_muts::Mutation>,
    pub muts_gas: Vec<consensus_muts::Mutation>,
    pub muts_rev: Vec<consensus_muts::Mutation>,
    pub muts_rev_gas: Vec<consensus_muts::Mutation>,
    pub result_log: Vec<HashMap<&'static str, &'static str>>,
}

pub fn make_apply_env<'db>(txn: Transaction<'db, TransactionDB<MultiThreaded>>, cf: std::sync::Arc<BoundColumnFamily<'db>>,
    entry_signer: &[u8; 48], entry_prev_hash: &[u8; 32],
    entry_slot: u64, entry_prev_slot: u64, entry_height: u64, entry_epoch: u64,
    entry_vr: &[u8; 96], entry_vr_b3: &[u8; 32], entry_dr: &[u8; 32],
) -> ApplyEnv<'db> {
    ApplyEnv {
        caller_env: make_caller_env(entry_signer, entry_prev_hash, entry_slot, entry_prev_slot, entry_height, entry_epoch, entry_vr, entry_vr_b3, entry_dr),
        cf,
        txn,
        muts: Vec::new(),
        muts_gas: Vec::new(),
        muts_rev: Vec::new(),
        muts_rev_gas: Vec::new(),
        result_log: Vec::new(),
    }
}

pub fn set_apply_env_tx<'db>(env: &mut ApplyEnv<'db>, tx_hash: &[u8; 32], tx_signer: &[u8; 48], tx_nonce: u64) {
    env.caller_env.tx_hash = *tx_hash;
    env.caller_env.tx_nonce = tx_nonce;
    env.caller_env.tx_signer = *tx_signer;
    env.caller_env.account_origin = tx_signer.to_vec();
}

// NIF-specific functions have been moved to the rdb crate
