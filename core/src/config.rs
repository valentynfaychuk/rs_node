pub const ENTRY_SIZE: usize = 524288; // 512 KiB
pub const TX_SIZE: usize = 393216; // 384 KiB
pub const ATTESTATION_SIZE: usize = 512;
pub const QUORUM: usize = 3; // quorum size for AMA
pub const QUORUM_SINGLE: usize = 1; // quorum size for single shard

// node configuration getters (hardcoded for now)

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

/// Trainer secret seed used for BLS signing, hardcoded for now (32 bytes)
pub fn trainer_sk_seed() -> [u8; 32] {
    // NOTE: replace with real secret handling, this is a placeholder
    [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32,
    ]
}
