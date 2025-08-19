use crate::consensus::kv;
use crate::consensus::kv::Mutation;
use crate::consensus::tx::TxU;
use blake3;
use std::cell::RefCell;
use std::collections::HashMap;

/// Compute execution cost in "cents" identical to Elixir logic:
///
/// We return the integer value directly (assuming the caller treats it as cents).
pub fn exec_cost_from_len(tx_encoded_len: usize) -> u64 {
    let bytes = tx_encoded_len + 32 + 96;
    let cost_units = 3 + (bytes / 256) * 3; // integer division
    // Elixir: BIC.Coin.to_cents(3 + div(bytes, 256) * 3)
    crate::bic::coin::to_cents(cost_units as u64)
}

/// Blake3-based deterministic seed, mirroring:
///
/// Returns the 32-byte seed (little-endian interpretation is up to the caller where needed).
pub fn seed_random(vr: &[u8], txhash: &[u8], action_index: &[u8], call_cnt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(vr);
    hasher.update(txhash);
    hasher.update(action_index);
    hasher.update(call_cnt);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Extract a deterministic f64 from the first 8 bytes of the seed (little-endian),
///
/// Note: Random bytes mapped to f64 may produce NaN or infinities; this mirrors Elixir’s
/// direct binary-to-float interpretation and is intentional.
pub fn seed_to_f64(seed: &[u8; 32]) -> f64 {
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&seed[0..8]);
    f64::from_le_bytes(first8)
}

pub fn exec_cost(txu: &crate::consensus::tx::TxU) -> u64 {
    exec_cost_from_len(txu.tx_encoded.len())
}

/// KV mutations are not implemented yet
pub fn call_txs_pre_parallel_build_sol_cache(
    txus: &[crate::consensus::tx::TxU],
) -> std::collections::HashMap<[u8; 32], bool> {
    use crate::bic::sol;
    use std::collections::HashMap;

    let mut cache: HashMap<[u8; 32], bool> = HashMap::new();

    for txu in txus {
        // Find a.submit_sol with at least one arg (sol binary)
        if let Some(action) = txu.tx.actions.first()
            && action.function == "submit_sol"
            && let Some(first_arg) = action.args.first()
        {
            let hash = blake3::hash(first_arg);
            let hash32: [u8; 32] = *hash.as_bytes();
            let valid = sol::verify_with_hash(first_arg, &hash32).unwrap_or(false);
            cache.insert(hash32, valid);
        }
    }

    cache
}

// TODO: implement following
// - call_exit(env)
// - call_tx_actions(env, txu)

/// Minimal WASM call stub to reflect Elixir BIC.Base.WASM.call/4 cross-dependency.
/// This is a placeholder; real implementation requires a WASM runtime integration.
pub mod wasm {
    #[derive(Default, Debug, Clone)]
    pub struct WasmCallResult {
        /// Optional execution units used; mirrors Elixir using this to charge gas.
        pub exec_used: Option<u64>,
    }

    /// Invoke contract bytecode with the given function and args.
    /// TODO: implement with a WASM runtime and proper ABI for env, bytecode, and args.
    pub fn call(
        _env: &crate::bic::epoch::CallEnv,
        _bytecode: &[u8],
        _function: &str,
        _args: &[Vec<u8>],
    ) -> WasmCallResult {
        unimplemented!("TODO: BIC.Base.WASM.call requires WASM runtime integration");
    }
}

// Thread-local cache similar to Elixir's Process.put(SolVerifiedCache, ...)
thread_local! {
    static SOL_VERIFIED_CACHE: RefCell<HashMap<[u8; 32], bool>> = RefCell::new(HashMap::new());
}

pub fn set_sol_verified_cache(cache: HashMap<[u8; 32], bool>) {
    SOL_VERIFIED_CACHE.with(|c| {
        *c.borrow_mut() = cache;
    });
}

pub fn get_sol_verified_cache() -> HashMap<[u8; 32], bool> {
    SOL_VERIFIED_CACHE.with(|c| c.borrow().clone())
}

fn pk_hex(pk: &[u8]) -> String {
    let mut s = String::with_capacity(pk.len() * 2);
    for b in pk {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn key_balance(pk: &[u8], symbol: &str) -> String {
    format!("bic:coin:balance:{}:{}", pk_hex(pk), symbol)
}

/// Note: This function does not handle VRF/epoch-dependent sol verification flags; the
/// bic::sol::verify_with_hash handles epoch branches internally
pub fn call_txs_pre_parallel(entry_signer: &[u8; 48], txus: &[TxU]) -> (Vec<Mutation>, Vec<Mutation>) {
    // For each txu: set nonce and move exec cost from signer to entry_signer in AMA
    for txu in txus {
        // nonce
        let key_nonce = format!("bic:base:nonce:{}", pk_hex(&txu.tx.signer));
        kv::kv_put(&key_nonce, txu.tx.nonce.to_string().as_bytes());

        // exec cost in cents
        let exec_cost = exec_cost(txu) as i64;
        // charge signer
        let key_signer = key_balance(&txu.tx.signer, "AMA");
        kv::kv_increment(&key_signer, -exec_cost);
        // reward entry signer
        let key_entry = key_balance(entry_signer, "AMA");
        kv::kv_increment(&key_entry, exec_cost);
    }

    // Build and store Sol verification cache
    let cache = call_txs_pre_parallel_build_sol_cache(txus);
    set_sol_verified_cache(cache);

    (kv::mutations(), kv::mutations_reverse())
}

/// TODO: Implement when kv is ready
pub fn call_exit_todo() {
    // TODO: seed randomness, increment AMA by to_flat(1) for entry_signer, update epoch segment VR hash every 1000 heights, handle genesis/next epoch transitions.
    unimplemented!("BIC.Base.call_exit requires complete environment and KV integration");
}

/// TODO: Implement when wasm contract calls are ready
pub fn call_tx_actions_todo() {
    // TODO: implement logic to handle:
    // - WASM bytecode calls for contract public keys
    // - built-in modules: Epoch, Coin, Contract
    // - attachments handling and gas accounting
    unimplemented!("BIC.Base.call_tx_actions requires WASM runtime and contract dispatch integration");
}
