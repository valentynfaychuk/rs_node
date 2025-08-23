use crate::bic::base::wasm::WasmCallResult;
use crate::bic::base_wasm_safe;
use crate::bic::epoch::CallEnv;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

/// Minimal bridge message protocol translated from Elixir's BIC.Base.WASM
#[derive(Debug)]
pub enum WasmBridgeMsg {
    /// Result from the WASM runtime: (error, logs, exec_remaining, return_value)
    /// error: None or Some("return_value") indicates success; other strings indicate abort/system
    Result { error: Option<String>, logs: Vec<String>, exec_remaining: u64, retv: Option<Vec<u8>> },
    // Storage and call messages can be added here in future:
    // StorageKvGet { rpc_id: u64, key: String }, ...
}

/// WASM Runtime Bridge
///
/// Mirrors Elixir BIC.Base.WASM at a minimal viable level: spawns sandboxed
/// execution and listens for a Result message with a timeout, then returns a
/// WasmCallResult. Other messages are reserved for future implementation.
pub fn call(env: &CallEnv, wasmbytes: &[u8], function: &str, args: &[Vec<u8>]) -> WasmCallResult {
    let (tx, rx): (Sender<WasmBridgeMsg>, Receiver<WasmBridgeMsg>) = mpsc::channel();

    // spawn sandboxed execution, pass sender so child can report back
    let handle = base_wasm_safe::spawn(env.clone(), wasmbytes.to_vec(), function.to_string(), args.to_vec(), tx);

    // Process messages; currently we only care about a single Result
    let result = wasm_loop(&rx);

    // join and prefer loop's result if present; otherwise fall back to thread outcome
    match result {
        Some(res) => res,
        None => match handle.join() {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                tracing::warn!(target = "bic::base_wasm", "wasm execution error: {}", e);
                WasmCallResult::default()
            }
            Err(_) => {
                tracing::warn!(target = "bic::base_wasm", "wasm execution thread panicked");
                WasmCallResult::default()
            }
        },
    }
}

fn wasm_loop(rx: &Receiver<WasmBridgeMsg>) -> Option<WasmCallResult> {
    // mimic Elixir after 1000ms timeout
    match rx.recv_timeout(Duration::from_millis(1_000)) {
        Ok(WasmBridgeMsg::Result { error, logs: _logs, exec_remaining: _rem, retv: _retv }) => {
            // When top-level, we don't expose logs or retv in WasmCallResult yet
            match error.as_deref() {
                None => Some(WasmCallResult { exec_used: None }),
                Some("return_value") => Some(WasmCallResult { exec_used: None }),
                Some(other) => {
                    tracing::warn!(target = "bic::base_wasm", "wasm returned error: {}", other);
                    Some(WasmCallResult::default())
                }
            }
        }
        Err(_timeout) => {
            // timeout: consider it a system error
            tracing::warn!(target = "bic::base_wasm", "wasm bridge loop timeout (1s)");
            Some(WasmCallResult::default())
        }
    }
}
