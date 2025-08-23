use crate::consensus::kv;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("wasm compilation failed: {0}")]
    Compilation(String),
    #[error("invalid function: {0}")]
    InvalidFunction(String),
    #[error("invalid arguments")]
    InvalidArgs,
}

/// Minimal validation for a contract WASM binary.
/// Mirrors Elixir BIC.Contract.validate/1 behavior at a high level:
/// - Return Ok(()) when the module compiles
/// - Return Err with reason otherwise
pub fn validate(wasm: &[u8]) -> Result<(), ContractError> {
    // Use wasmer to attempt compilation. If it compiles, we accept it.
    // Keep implementation minimal and side-effect free to stay testable.
    let store = wasmer::Store::default();
    match wasmer::Module::new(&store, wasm) {
        Ok(_) => Ok(()),
        Err(e) => Err(ContractError::Compilation(e.to_string())),
    }
}

fn pk_hex(pk: &[u8]) -> String {
    let mut s = String::with_capacity(pk.len() * 2);
    for b in pk {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn key_bytecode(account: &[u8; 48]) -> String {
    format!("bic:contract:account:{}:bytecode", pk_hex(account))
}

/// Read stored bytecode for a given account public key
pub fn bytecode(account: &[u8; 48]) -> Option<Vec<u8>> {
    kv::kv_get(&key_bytecode(account))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnv {
    pub account_caller: [u8; 48],
}

/// Dispatch contract module calls (currently only "deploy")
pub fn call(function: &str, env: &CallEnv, args: &[Vec<u8>]) -> Result<(), ContractError> {
    match function {
        "deploy" => {
            // Expect exactly one argument: wasm bytes
            if args.len() != 1 {
                return Err(ContractError::InvalidArgs);
            }
            let wasmbytes = &args[0];
            // Store bytecode under caller's account key
            let key = key_bytecode(&env.account_caller);
            kv::kv_put(&key, wasmbytes);
            Ok(())
        }
        other => Err(ContractError::InvalidFunction(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytecode_roundtrip_with_deploy_call() {
        // reset KV
        kv::reset();
        let env = CallEnv { account_caller: [7u8; 48] };
        let wasm = vec![0xde, 0xad, 0xbe, 0xef];

        // Wrong usage
        assert!(matches!(call("deploy", &env, &[]), Err(ContractError::InvalidArgs)));
        assert!(matches!(call("unknown", &env, &[wasm.clone()]), Err(ContractError::InvalidFunction(_))));

        // Correct deploy
        call("deploy", &env, &[wasm.clone()]).expect("deploy ok");
        let got = bytecode(&env.account_caller).expect("stored");
        assert_eq!(got, wasm);
    }
}
