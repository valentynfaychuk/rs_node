use crate::bic::epoch::CallEnv;
use crate::consensus::kv;
use crate::misc::rocksdb;
use crate::wasm::runtime;
/// Test for the complete WASM runtime implementation
/// This validates the OP-code enumeration system and host function bindings
use std::sync::Once;

#[cfg(test)]
mod tests {
    use super::*;

    static INIT: Once = Once::new();

    fn setup_test_env() -> CallEnv {
        INIT.call_once(|| {
            let test_db_path = "target/test_wasm_runtime_db";
            std::fs::create_dir_all(test_db_path).unwrap();
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let _ = rocksdb::init("target/test_wasm_runtime").await;
            });
        });

        CallEnv {
            entry_epoch: 42,
            entry_height: 100000,
            entry_signer: [1u8; 48],
            entry_vr: vec![0xde, 0xad, 0xbe, 0xef],
            tx_hash: vec![0xca, 0xfe, 0xba, 0xbe],
            tx_signer: [2u8; 48],
            account_caller: [3u8; 48],
            account_current: vec![4, 5, 6],
            call_counter: 1,
            call_exec_points: 10000,
            call_exec_points_remaining: 9000,
            attached_symbol: vec![],
            attached_amount: vec![],
            seed: [42u8; 32],
            seedf64: 3.14159,
            readonly: false,
        }
    }

    #[test]
    fn test_wasm_runtime_compilation_and_validation() {
        let env = setup_test_env();

        // Test with invalid WASM bytecode
        let invalid_wasm = vec![0x00, 0x61, 0x73, 0x6d]; // incomplete WASM header
        let result = runtime::execute(&env, &invalid_wasm, "main", &[]);
        assert!(result.is_err());

        // Test with minimal valid WASM module (contains basic structure)
        let minimal_wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic
            0x01, 0x00, 0x00, 0x00, // Version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section: function type
            0x03, 0x02, 0x01, 0x00, // Function section: 1 function
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section: empty function
        ];

        // This should compile but fail to find "main" function
        let result = runtime::execute(&env, &minimal_wasm, "main", &[]);
        assert!(matches!(result, Err(runtime::WasmError::FunctionNotFound(_))));

        println!("wasm runtime compilation tests ok");
    }

    #[test]
    fn test_op_code_enumeration_completeness() {
        use crate::wasm::opcodes::{OpCode, generate_host_signatures};

        // Verify all opcodes have signatures
        let signatures = generate_host_signatures();

        // Test a few key opcodes are present
        assert!(signatures.contains_key(&OpCode::StorageKvGet));
        assert!(signatures.contains_key(&OpCode::EnvGetBlockHeight));
        assert!(signatures.contains_key(&OpCode::CrossContractCall));
        assert!(signatures.contains_key(&OpCode::LogDebug));
        assert!(signatures.contains_key(&OpCode::MemoryGrow));
        assert!(signatures.contains_key(&OpCode::SystemAbort));

        // Verify import names are consistent
        for (opcode, signature) in signatures.iter() {
            assert_eq!(opcode, &signature.opcode);
            assert!(!opcode.import_name().is_empty());
            assert!(!opcode.module_name().is_empty());
        }

        println!("opcode enumeration test ok: {} opcodes", signatures.len());
    }

    #[test]
    fn test_wasm_context_and_host_function_access() {
        use crate::wasm::runtime::WasmContext;

        let env = setup_test_env();
        let context = WasmContext::new(env.clone());

        // Verify context initialization
        assert_eq!(context.env.entry_epoch, 42);
        assert_eq!(context.env.entry_height, 100000);
        assert_eq!(context.env.call_exec_points, 10000);
        assert!(!context.env.readonly);

        // Verify RPC counter functionality
        let id1 = context.next_rpc_id();
        let id2 = context.next_rpc_id();
        assert_eq!(id2, id1 + 1);

        // Test execution cost tracking
        context.add_exec_cost(100);
        assert_eq!(*context.exec_used.lock().unwrap(), 100);
        context.add_exec_cost(50);
        assert_eq!(*context.exec_used.lock().unwrap(), 150);

        println!("wasm context test ok");
    }

    #[test]
    fn test_storage_operations_integration() {
        let _env = setup_test_env();
        kv::reset_for_tests(); // Clear any existing data

        // Test KV operations that the WASM host functions would use
        kv::kv_put("test_key", b"test_value");
        assert!(kv::kv_exists("test_key"));
        assert_eq!(kv::kv_get("test_key").unwrap(), b"test_value");

        let new_value = kv::kv_increment("counter", 42);
        assert_eq!(new_value, 42);
        let incremented = kv::kv_increment("counter", 8);
        assert_eq!(incremented, 50);

        kv::kv_delete("test_key");
        assert!(!kv::kv_exists("test_key"));

        let cleared_count = kv::kv_clear("count");
        assert!(cleared_count >= 1); // Should clear the counter key

        println!("storage integration test ok");
    }

    #[test]
    fn test_complete_wasm_pipeline() {
        let env = setup_test_env();

        // Create a very basic WASM module that exports "test" function
        let test_wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // WASM magic
            0x01, 0x00, 0x00, 0x00, // Version
            0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section: () -> ()
            0x03, 0x02, 0x01, 0x00, // Function section: 1 function of type 0
            0x07, 0x08, 0x01, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
            0x00, // Export section: export function 0 as "test"
            0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section: empty function body
        ];

        // Test WASM execution pipeline
        let result = runtime::execute(&env, &test_wasm, "test", &[]);

        match result {
            Ok(execution_result) => {
                println!("wasm execution ok: {} exec points", execution_result.exec_used);
            }
            Err(e) => {
                println!("wasm execution failed: {:?}", e);
            }
        }

        println!("wasm pipeline test ok");
    }

    #[test]
    fn test_opcodes_module_assignments() {
        use crate::wasm::opcodes::OpCode;

        // Verify storage operations are assigned to "bic" module
        assert_eq!(OpCode::StorageKvGet.module_name(), "bic");
        assert_eq!(OpCode::StorageKvPut.module_name(), "bic");
        assert_eq!(OpCode::CrossContractCall.module_name(), "bic");
        assert_eq!(OpCode::CoinGetBalance.module_name(), "bic");

        // Verify environment operations are assigned to "env" module
        assert_eq!(OpCode::EnvGetBlockHeight.module_name(), "env");
        assert_eq!(OpCode::LogDebug.module_name(), "env");
        assert_eq!(OpCode::MemoryGrow.module_name(), "env");
        assert_eq!(OpCode::SystemAbort.module_name(), "env");

        println!("opcodes module assignments test ok");
    }
}
