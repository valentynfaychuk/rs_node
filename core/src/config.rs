pub const ENTRY_SIZE: usize = 524288; // 512 KiB
pub const TX_SIZE: usize = 393216; // 384 KiB
pub const ATTESTATION_SIZE: usize = 512;
pub const QUORUM: usize = 3; // quorum size for AMA
pub const QUORUM_SINGLE: usize = 1; // quorum size for single shard

// node configuration getters (hardcoded for now)

struct ClientConfig {
    //pub directory: ,
    pub sk: [u8; 64],
}

/// Root work folder, DBs will be placed under this path
pub fn work_dir() -> &'static str {
    "run.local"
}

/// Trainer public key (48 bytes, compressed G1), hardcoded for now
pub fn trainer_pk() -> [u8; 48] {
    [
        140, 27, 75, 245, 48, 112, 140, 244, 78, 114, 11, 45, 8, 201, 199, 184, 71, 69, 96, 112, 52, 204, 31, 56, 143,
        115, 222, 87, 7, 185, 3, 168, 252, 90, 91, 114, 16, 244, 47, 228, 198, 82, 12, 130, 10, 126, 118, 193,
    ]
}

/// Trainer secret key used for BLS signing (64 bytes). Persists to file as Base58.
pub fn trainer_sk() -> [u8; 64] {
    use rand::RngCore;
    use std::fs;
    use std::path::PathBuf;

    // Resolve candidate paths
    // 1) ~/.cache/amadeusd/sk
    // 2) $WORKFOLDER/sk (relative work_dir())
    let mut home_path: Option<PathBuf> = None;
    if let Ok(home) = std::env::var("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".cache");
        p.push("amadeusd");
        p.push("sk");
        home_path = Some(p);
    }
    let mut work_path = PathBuf::from(work_dir());
    work_path.push("sk");

    // Helper: try read Base58 secret key from file
    fn read_b58_sk(path: &PathBuf) -> Option<[u8; 64]> {
        let s = fs::read_to_string(path).ok()?;
        let s_trim = s.trim();
        match bs58::decode(s_trim).into_vec() {
            Ok(bytes) => match <[u8; 64]>::try_from(bytes.as_slice()) {
                Ok(arr) => Some(arr),
                Err(_) => None,
            },
            Err(_) => None,
        }
    }

    // Try to read from home cache first, then work folder
    if let Some(home) = &home_path {
        if home.exists() {
            if let Some(arr) = read_b58_sk(home) {
                return arr;
            }
        }
    }
    if work_path.exists() {
        if let Some(arr) = read_b58_sk(&work_path) {
            return arr;
        }
    }

    // Not found or invalid: generate new 64-byte secret key, save as Base58, print pk
    let mut sk = [0u8; 64];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut sk);

    // Derive public key and print message
    let pk = crate::misc::bls12_381::get_public_key(&sk).unwrap_or([0u8; 48]);
    let pk_b58 = bs58::encode(pk).into_string();
    println!("generated random sk, your pk is {}", pk_b58);

    // Choose save path: prefer home cache if available, else work folder
    let save_path = if let Some(home) = home_path { home } else { work_path };

    if let Some(parent) = save_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let b58 = bs58::encode(sk).into_string();
    let _ = fs::write(&save_path, b58);

    sk
}
