use crate::utils::bls12_381;
pub use crate::utils::bls12_381::generate_sk as gen_sk;
use std::path::Path;
use tokio::fs;

pub const ENTRY_SIZE: usize = 524288; // 512 KiB
pub const TX_SIZE: usize = 393216; // 384 KiB
pub const ATTESTATION_SIZE: usize = 512;
pub const QUORUM: usize = 3; // quorum size for AMA
pub const QUORUM_SINGLE: usize = 1; // quorum size for single shard

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    B58(#[from] bs58::decode::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error("invalid sk length: {0}, expected 64")]
    InvalidSkLength(usize),
    #[error("root directory is not set")]
    RootNotSet,
}

pub struct Config {
    root: Option<String>,
    sk: [u8; 64],
}

impl Config {
    /// Generates pk from self.sk
    pub fn get_pk(&self) -> [u8; 48] {
        get_pk(&self.sk)
    }

    pub fn get_sk(&self) -> [u8; 64] {
        self.sk
    }

    /// Returns root work folder path
    pub fn get_root(&self) -> Result<&str, Error> {
        self.root.as_deref().ok_or(Error::RootNotSet)
    }

    /// Create Config instance with default root and loaded/generated secret key
    pub async fn from_fs(root: Option<&str>, sk: Option<&str>) -> Result<Self, Error> {
        let root = root.unwrap_or(".config/amadeusd");
        fs::create_dir_all(&root).await?; // make sure directory exists

        // if sk path is provided, it MUST be valid
        if let Some(path) = sk {
            let sk = read_sk(path).await?;
            return Ok(Self { root: Some(root.into()), sk });
        }

        if let Ok(sk) = read_sk(&format!("{root}/sk")).await {
            return Ok(Self { root: Some(root.into()), sk });
        }

        let sk = gen_sk();
        write_sk(format!("{root}/sk"), sk).await?;
        println!("created {root}/sk, pk {}", bs58::encode(get_pk(&sk)).into_string());

        Ok(Self { root: Some(root.into()), sk })
    }

    pub fn from_sk(sk: [u8; 64]) -> Self {
        Self { root: None, sk }
    }
}

pub fn get_pk(sk: &[u8; 64]) -> [u8; 48] {
    bls12_381::get_public_key(sk).unwrap() // 64-byte sk is always be valid
}

pub async fn write_sk(path: impl AsRef<Path>, sk: [u8; 64]) -> Result<(), Error> {
    let sk_b58 = bs58::encode(sk).into_string();
    fs::write(path, sk_b58).await.map_err(Into::into)
}

pub async fn read_sk(path: impl AsRef<Path>) -> Result<[u8; 64], Error> {
    let sk_bs58 = fs::read_to_string(path).await?;
    let sk_vec = bs58::decode(sk_bs58.trim()).into_vec()?;
    sk_vec.try_into().map_err(|v: Vec<u8>| Error::InvalidSkLength(v.len()))
}
