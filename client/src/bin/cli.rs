use std::fs;

use ama_core::bic::contract;
use ama_core::config;
use ama_core::consensus::tx;
use ama_core::misc::bls12_381 as bls;
use bs58;
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde_json::Value as JsonValue;

#[derive(Parser)]
#[command(author, version, about = "Amadeus blockchain CLI tool")]
#[command(long_about = r#"CLI tool for Amadeus blockchain operations.

Notes:
  - args_json must be a JSON array. Each element can be:
      • a string => UTF-8 bytes
      • {"b58": "..."} => Base58-decoded bytes
      • {"hex": "..."} => hex-decoded bytes (with or without 0x)
      • {"utf8": "..."} => UTF-8 bytes
  - Secret key: use --sk-file to read Base58-encoded secret key file (recommended). If omitted, defaults to run.local/sk.
  - deploytx validates the WASM by compiling it with wasmer before building the tx."#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get public key from secret key file (Base58-encoded 64-byte secret key)
    Getpk {
        /// Path to secret key file
        secret_key_file: String,
    },
    /// Generate a new random secret secret key (64 bytes) and save to a file as Base58; prints derived pk
    Gensk {
        /// Output path to write the secret key bytes
        out_file: String,
    },
    /// Build a transaction for contract function call
    Buildtx {
        /// Contract address (Base58) or name
        contract: String,
        /// Function name to call
        function: String,
        /// Arguments as JSON array
        args_json: String,
        /// Optional attachment symbol
        attach_symbol: Option<String>,
        /// Optional attachment amount (required if attach_symbol is provided)
        attach_amount: Option<String>,
        /// Optional path to secret key file
        #[arg(long = "sk-file")]
        sk_file: Option<String>,
    },
    /// Build a transaction to deploy WASM contract
    Deploytx {
        /// Path to WASM file
        wasm_path: String,
        /// Optional path to secret key file
        #[arg(long = "sk-file")]
        sk_file: Option<String>,
    },
}

fn parse_json_arg_elem(v: &JsonValue) -> Result<Vec<u8>, String> {
    match v {
        JsonValue::String(s) => Ok(s.as_bytes().to_vec()),
        JsonValue::Object(map) => {
            if let Some(b58v) = map.get("b58") {
                if let Some(s) = b58v.as_str() {
                    return bs58::decode(s).into_vec().map_err(|e| format!("invalid base58: {}", e));
                }
            }
            if let Some(hexv) = map.get("hex") {
                if let Some(s) = hexv.as_str() {
                    let s2 = s.strip_prefix("0x").unwrap_or(s);
                    return hex::decode(s2).map_err(|e| format!("invalid hex: {}", e));
                }
            }
            if let Some(utf8v) = map.get("utf8") {
                if let Some(s) = utf8v.as_str() {
                    return Ok(s.as_bytes().to_vec());
                }
            }
            Err("unsupported JSON object for arg; expected {b58|hex|utf8}".to_string())
        }
        _ => Err("unsupported JSON value for arg; expected string or object".to_string()),
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Getpk { secret_key_file } => {
            handle_getpk(&secret_key_file);
        }
        Commands::Gensk { out_file } => {
            handle_gensk(&out_file);
        }
        Commands::Buildtx { contract, function, args_json, attach_symbol, attach_amount, sk_file } => {
            // Validate attachment arguments
            if attach_symbol.is_some() && attach_amount.is_none() {
                eprintln!("Error: attach_amount is required when attach_symbol is provided");
                std::process::exit(2);
            }
            if attach_symbol.is_none() && attach_amount.is_some() {
                eprintln!("Error: attach_symbol is required when attach_amount is provided");
                std::process::exit(2);
            }
            handle_buildtx(
                &contract,
                &function,
                &args_json,
                attach_symbol.as_deref(),
                attach_amount.as_deref(),
                sk_file.as_deref(),
            );
        }
        Commands::Deploytx { wasm_path, sk_file } => {
            handle_deploytx(&wasm_path, sk_file.as_deref());
        }
    }
}

fn handle_getpk(secret_key_file: &str) {
    let sk_bytes = read_sk_from_file(secret_key_file);

    match bls::get_public_key(&sk_bytes) {
        Ok(pk) => {
            println!("{}", bs58::encode(pk).into_string());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("failed to derive public key: {}", e);
            std::process::exit(2);
        }
    }
}

fn handle_buildtx(
    contract: &str,
    function: &str,
    args_json: &str,
    attach_symbol: Option<&str>,
    attach_amount: Option<&str>,
    sk_file: Option<&str>,
) {
    // Determine trainer secret secret key: prefer secret key file if provided (Base58 64 bytes)
    let trainer_sk = match sk_file {
        Some(path) => read_sk_from_file(path),
        None => config::trainer_sk(),
    };

    // contract: if Base58 decodes successfully, use decoded bytes, else use raw bytes
    let contract_bytes = match bs58::decode(contract).into_vec() {
        Ok(b) => b,
        Err(_) => contract.as_bytes().to_vec(),
    };

    // Parse args_json into Vec<Vec<u8>>
    let json: JsonValue = match serde_json::from_str(args_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid args_json: {}", e);
            std::process::exit(2);
        }
    };
    let arr = match json.as_array() {
        Some(a) => a,
        None => {
            eprintln!("args_json must be a JSON array");
            std::process::exit(2);
        }
    };
    let mut args_vec: Vec<Vec<u8>> = Vec::with_capacity(arr.len());
    for v in arr {
        match parse_json_arg_elem(v) {
            Ok(b) => args_vec.push(b),
            Err(msg) => {
                eprintln!("{}", msg);
                std::process::exit(2);
            }
        }
    }

    // Handle attachments
    let (attach_symbol_bytes, attach_amount_bytes): (Option<Vec<u8>>, Option<Vec<u8>>) =
        match (attach_symbol, attach_amount) {
            (Some(symbol), Some(amount)) => (Some(symbol.as_bytes().to_vec()), Some(amount.as_bytes().to_vec())),
            _ => (None, None),
        };

    let tx_packed = tx::build(
        &trainer_sk,
        &contract_bytes,
        function,
        &args_vec,
        None,
        attach_symbol_bytes.as_deref(),
        attach_amount_bytes.as_deref(),
    );
    println!("{}", bs58::encode(tx_packed).into_string());
    std::process::exit(0);
}

fn handle_gensk(out_file: &str) {
    // Generate a fresh random 64-byte sk and write as Base58 into file, print derived pk
    let mut sk = [0u8; 64];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut sk);
    let b58 = bs58::encode(sk).into_string();
    if let Err(e) = fs::write(out_file, &b58) {
        eprintln!("failed to write sk file: {}", e);
        std::process::exit(2);
    }
    if let Ok(pk) = bls::get_public_key(&sk) {
        println!("generated random sk, your pk is {}", bs58::encode(pk).into_string());
    }
    std::process::exit(0);
}

fn read_sk_from_file(path: &str) -> [u8; 64] {
    let s = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read sk file '{}': {}", path, e);
            std::process::exit(2);
        }
    };
    let s_trim = s.trim();
    let bytes = match bs58::decode(s_trim).into_vec() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invalid Base58 sk in file '{}': {}", path, e);
            std::process::exit(2);
        }
    };
    match <[u8; 64]>::try_from(bytes.as_slice()) {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("sk must decode to exactly 64 bytes");
            std::process::exit(2);
        }
    }
}

fn handle_deploytx(wasm_path: &str, sk_file: Option<&str>) {
    let trainer_sk = match sk_file {
        Some(path) => read_sk_from_file(path),
        None => config::trainer_sk(),
    };

    let wasmbytes = match fs::read(wasm_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read wasm file: {}", e);
            std::process::exit(2);
        }
    };

    // Validate WASM
    if let Err(e) = contract::validate(&wasmbytes) {
        eprintln!("{}", e);
        std::process::exit(2);
    }

    let args_vec = vec![wasmbytes];
    let tx_packed = tx::build(&trainer_sk, b"Contract", "deploy", &args_vec, None, None, None);
    println!("{}", bs58::encode(tx_packed).into_string());
    std::process::exit(0);
}
