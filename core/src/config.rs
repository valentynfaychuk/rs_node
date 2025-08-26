use crate::utils::bls12_381;
use rand::RngCore;
use std::path::PathBuf;
use tokio::fs;

pub const ENTRY_SIZE: usize = 524288; // 512 KiB
pub const TX_SIZE: usize = 393216; // 384 KiB
pub const ATTESTATION_SIZE: usize = 512;
pub const QUORUM: usize = 3; // quorum size for AMA
pub const QUORUM_SINGLE: usize = 1; // quorum size for single shard

// node configuration getters (hardcoded for now)

pub struct Config {
    pub root: String,
    pub sk: [u8; 64],
}

impl Config {
    /// Generates pk from self.sk
    pub fn get_pk(&self) -> [u8; 48] {
        //bls12_381::get_public_key(&self.sk).unwrap_or([0u8; 48])
        bls12_381::get_public_key(&self.sk).unwrap()
    }

    pub fn get_sk(&self) -> [u8; 64] {
        self.sk
    }

    /// Returns root work folder path
    pub fn get_root(&self) -> &str {
        &self.root
    }

    /// Create Config instance with default root and loaded/generated secret key
    pub async fn generate_new(root: Option<String>) -> Self {
        let root = root.unwrap_or_else(|| ".config/amadeusd".to_string());
        let sk = load_or_generate_sk(&root).await;
        Self { root, sk }
    }
}

/// Load or generate secret key for the given root directory
async fn load_or_generate_sk(root: &str) -> [u8; 64] {
    let work_path = PathBuf::from(format!("{root}/sk"));
    if work_path.exists() {
        if let Some(arr) = read_b58_sk(&work_path).await {
            return arr;
        }
    }

    // Not found or invalid: generate new 64-byte secret key, save as Base58, print pk
    let mut sk = [0u8; 64];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut sk);

    // Derive public key and print message
    let pk = bls12_381::get_public_key(&sk).unwrap_or([0u8; 48]);
    println!("generated random sk, your pk is {}", bs58::encode(pk).into_string());

    if let Some(parent) = work_path.parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    let b58 = bs58::encode(sk).into_string();
    let _ = fs::write(&work_path, b58).await;

    sk
}

pub async fn read_b58_sk(path: &PathBuf) -> Option<[u8; 64]> {
    let s = fs::read_to_string(path).await.ok()?;
    let s_trim = s.trim();
    match bs58::decode(s_trim).into_vec() {
        Ok(bytes) => match <[u8; 64]>::try_from(bytes.as_slice()) {
            Ok(arr) => Some(arr),
            Err(_) => None,
        },
        Err(_) => None,
    }
}
