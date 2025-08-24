use crate::bic::epoch::CallEnv;
use crate::consensus::kv;
use crate::misc::rocksdb;
use crate::wasm::runtime;
/// Test real smart contracts to identify missing WASM runtime features
use std::sync::Once;

#[cfg(test)]
mod tests {
    use super::*;

    static INIT: Once = Once::new();

    fn setup_test_env() -> CallEnv {
        INIT.call_once(|| {
            let test_db_path = "target/test_real_contracts_db";
            std::fs::create_dir_all(test_db_path).unwrap();
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let _ = rocksdb::init("target/test_real_contracts").await;
            });
        });

        CallEnv {
            entry_epoch: 1000,
            entry_height: 500000,
            entry_signer: [1u8; 48],
            entry_vr: vec![0xde, 0xad, 0xbe, 0xef],
            tx_hash: vec![0xca, 0xfe, 0xba, 0xbe],
            tx_signer: [2u8; 48],
            account_caller: [3u8; 48],
            account_current: vec![4, 5, 6],
            call_counter: 1,
            call_exec_points: 100000,
            call_exec_points_remaining: 95000,
            attached_symbol: vec![],
            attached_amount: vec![],
            seed: [42u8; 32],
            seedf64: 3.14159,
            readonly: false,
        }
    }

    fn load_wasm_file(filename: &str) -> Vec<u8> {
        let path = format!("../wasm/{}", filename);
        match std::fs::read(&path) {
            Ok(data) => data,
            Err(e) => {
                panic!("Failed to load WASM file {}: {}. Make sure to run 'wat2wasm' first.", path, e);
            }
        }
    }

    #[test]
    fn test_simple_counter_contract() {
        let env = setup_test_env();
        kv::reset_for_tests();

        let wasm_bytecode = load_wasm_file("simple_counter.wasm");
        println!("loaded simple_counter.wasm ({} bytes)", wasm_bytecode.len());

        let result = runtime::execute(&env, &wasm_bytecode, "init", &[]);
        match result {
            Ok(execution_result) => {
                println!(
                    "counter init ok: {} points, {} logs",
                    execution_result.exec_used,
                    execution_result.logs.len()
                );
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("counter init failed: {:?}", e),
        }

        let result = runtime::execute(&env, &wasm_bytecode, "increment", &[]);
        match result {
            Ok(execution_result) => {
                println!("counter increment ok: {} points", execution_result.exec_used);
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("counter increment failed: {:?}", e),
        }

        let result = runtime::execute(&env, &wasm_bytecode, "get_counter", &[]);
        match result {
            Ok(execution_result) => {
                println!("counter get ok: {:?}", execution_result.return_value);
            }
            Err(e) => println!("counter get failed: {:?}", e),
        }

        let counter_value = kv::kv_get("counter");
        println!("counter storage: {:?}", counter_value);
    }

    #[test]
    fn test_token_contract() {
        let env = setup_test_env();
        kv::reset_for_tests();

        let wasm_bytecode = load_wasm_file("token_contract.wasm");
        println!("loaded token_contract.wasm ({} bytes)", wasm_bytecode.len());

        let initial_supply = 1000000u64;
        let supply_bytes = initial_supply.to_le_bytes().to_vec();
        let result = runtime::execute(&env, &wasm_bytecode, "init", &[supply_bytes]);
        match result {
            Ok(execution_result) => {
                println!("token init ok: {} points", execution_result.exec_used);
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("token init failed: {:?}", e),
        }

        let result = runtime::execute(&env, &wasm_bytecode, "total_supply", &[]);
        match result {
            Ok(execution_result) => {
                println!("token total_supply ok: {:?}", execution_result.return_value);
            }
            Err(e) => println!("token total_supply failed: {:?}", e),
        }

        let account = b"test_account_123";
        let result = runtime::execute(&env, &wasm_bytecode, "balance_of", &[account.to_vec()]);
        match result {
            Ok(execution_result) => {
                println!("token balance_of ok: {:?}", execution_result.return_value);
            }
            Err(e) => println!("token balance_of failed: {:?}", e),
        }

        let to_account = b"recipient_account";
        let transfer_amount = 100u64;
        let amount_bytes = transfer_amount.to_le_bytes().to_vec();
        let result = runtime::execute(&env, &wasm_bytecode, "transfer", &[to_account.to_vec(), amount_bytes]);
        match result {
            Ok(execution_result) => {
                println!("token transfer ok: {:?}", execution_result.return_value);
                for log in execution_result.logs.iter() {
                    println!("log: {}", log);
                }
            }
            Err(e) => println!("token transfer failed: {:?}", e),
        }
    }

    #[test]
    fn test_host_function_coverage() {
        let _env = setup_test_env();

        let expected_host_functions = vec![
            ("bic", "storage_kv_get"),
            ("bic", "storage_kv_put"),
            ("bic", "storage_kv_increment"),
            ("bic", "coin_get_balance"),
            ("env", "env_get_block_height"),
            ("env", "env_get_tx_signer"),
            ("env", "log_info"),
            ("env", "system_return"),
        ];

        for (module, func) in expected_host_functions {
            println!("required: {}::{}", module, func);
        }

        use crate::wasm::opcodes::generate_host_signatures;
        let signatures = generate_host_signatures();

        println!("implemented host functions: {}", signatures.len());
        let mut missing_functions = Vec::new();

        for (module, func_name) in &[
            ("bic", "storage_kv_get"),
            ("bic", "storage_kv_put"),
            ("bic", "storage_kv_increment"),
            ("env", "env_get_block_height"),
            ("env", "log_info"),
        ] {
            let found = signatures
                .values()
                .any(|sig| sig.opcode.import_name() == *func_name && sig.opcode.module_name() == *module);

            if found {
                println!("{}::{} ok", module, func_name);
            } else {
                println!("{}::{} missing", module, func_name);
                missing_functions.push((*module, *func_name));
            }
        }

        if missing_functions.is_empty() {
            println!("all required host functions implemented");
        } else {
            println!("missing {} host functions", missing_functions.len());
        }
    }

    #[test]
    fn test_memory_management() {
        let env = setup_test_env();

        let memory_test_wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic
            0x01, 0x00, 0x00, 0x00, // Version
            // Type section: function type (i32) -> i32
            0x01, 0x07, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // Import section: memory from env
            0x02, 0x0a, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x01,
            // Function section: 1 function of type 0
            0x03, 0x02, 0x01, 0x00, // Export section: export function 0 as "test_memory"
            0x07, 0x10, 0x01, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x00, 0x00,
            // Code section: function body
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x0b,
        ];

        let result = runtime::execute(&env, &memory_test_wasm, "test_memory", &[vec![42]]);
        match result {
            Ok(_) => println!("wasm memory test ok"),
            Err(e) => println!("wasm memory test failed: {:?}", e),
        }
    }

    #[test]
    fn identify_critical_gaps() {
        let gaps = vec![
            ("abi parameter passing", "contracts expect proper string/binary parameter encoding from wasm memory"),
            ("return value handling", "contracts need to return values through wasm memory or registers"),
            ("memory import/export", "contracts expect 'memory' export and may need memory imports"),
            ("string encoding", "host functions need utf-8 string handling from wasm linear memory"),
            ("error propagation", "wasm errors should propagate properly to transaction results"),
            ("gas metering", "all host function calls should consume appropriate execution points"),
            ("storage integration", "storage operations should persist between contract calls"),
            ("transaction context", "contracts need access to tx_signer, block_height, etc"),
        ];

        for (category, description) in gaps {
            println!("{}: {}", category, description);
        }

        println!("implementation priority:");
        println!("1. fix abi parameter passing (memory read/write)");
        println!("2. implement proper return value handling");
        println!("3. add missing host functions (env_get_tx_signer, etc)");
        println!("4. enhance error handling and logging");
        println!("5. add storage persistence verification");
        println!("6. implement cross-contract calls");
    }
}
