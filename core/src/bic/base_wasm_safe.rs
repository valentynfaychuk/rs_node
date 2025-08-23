use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};

use wasmer::{Module, Store};

use crate::bic::base::wasm::WasmCallResult;
use crate::bic::base_wasm::WasmBridgeMsg;

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("wasm compilation failed: {0}")]
    Compilation(String),
    #[error("panic during wasm execution")]
    Panic,
}

/// Spawn a sandboxed WASM execution in a separate OS thread.
/// For now, we only attempt to compile the module to validate it and notify the bridge
/// via a Result message. This mirrors Elixir's BIC.Base.WASM.Safe.spawn behavior of isolating execution.
pub fn spawn(
    env: crate::bic::epoch::CallEnv,
    wasmbytes: Vec<u8>,
    function: String,
    args: Vec<Vec<u8>>,
    tx: Sender<WasmBridgeMsg>,
) -> JoinHandle<Result<WasmCallResult, WasmError>> {
    thread::spawn(move || {
        let exec = || -> Result<WasmCallResult, WasmError> {
            // compile module to ensure it is valid
            let store = Store::default();
            match Module::new(&store, &wasmbytes) {
                Ok(_module) => {
                    // Successful compile; notify parent of success with no return value
                    let _ = tx.send(WasmBridgeMsg::Result { error: None, logs: vec![], exec_remaining: 0, retv: None });
                    // For now, do nothing else; ABI is undefined in this phase.
                    let _ = (env, function, args);
                    Ok(WasmCallResult::default())
                }
                Err(e) => {
                    // Compilation error; notify parent of error
                    let _ = tx.send(WasmBridgeMsg::Result {
                        error: Some("abort".to_string()),
                        logs: vec![format!("compilation failed: {}", e)],
                        exec_remaining: 0,
                        retv: None,
                    });
                    Err(WasmError::Compilation(e.to_string()))
                }
            }
        };

        match catch_unwind(AssertUnwindSafe(exec)) {
            Ok(res) => res,
            Err(_) => {
                let _ = tx.send(WasmBridgeMsg::Result {
                    error: Some("system".to_string()),
                    logs: vec!["panic".to_string()],
                    exec_remaining: 0,
                    retv: None,
                });
                Err(WasmError::Panic)
            }
        }
    })
}
