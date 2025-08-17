use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;

// Use internal Blake3 helpers (hash, freivalds) translated in Rust
use crate::misc::blake3 as b3;
use crate::proto::Sol;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum SolError {
    #[error("invalid sol seed size")]
    InvalidSolSeedSize,
    #[error("invalid sol format: too short")]
    TooShort,
}

pub const PREAMBLE_SIZE: usize = 240;
pub const MATRIX_SIZE: usize = 1024;
pub const SOL_SIZE: usize = PREAMBLE_SIZE + MATRIX_SIZE; // 1264

pub fn size() -> usize {
    SOL_SIZE
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV2 {
    pub epoch: u32,
    pub segment_vr_hash: [u8; 32],
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub tensor_c: [u8; 1024],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV1 {
    pub epoch: u32,
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub segment_vr: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV0 {
    pub epoch: u32,
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolParsed {
    V2(SolV2), // epoch >= 156
    V1(SolV1), // 1 <= epoch < 156
    V0(SolV0), // epoch < 1
}

impl TryFrom<&Sol> for SolParsed {
    type Error = SolError;

    fn try_from(sol: &Sol) -> Result<Self, Self::Error> {
        if verify(&sol.sol)? { unpack(&sol.sol) } else { Err(SolError::InvalidSolSeedSize) }
    }
}

pub fn unpack(sol: &[u8]) -> Result<SolParsed, SolError> {
    if sol.len() < 4 {
        return Err(SolError::TooShort);
    }
    let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap());

    if epoch >= 156 {
        // <<epoch::32-little, segment_vr_hash::32-binary, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, nonce::12-binary, tensor_c::1024-binary>>
        if sol.len() < 4 + 32 + 48 + 96 + 48 + 12 + 1024 {
            return Err(SolError::TooShort);
        }
        let segment_vr_hash: [u8; 32] = sol[4..36].try_into().unwrap();
        let pk: [u8; 48] = sol[36..84].try_into().unwrap();
        let pop: [u8; 96] = sol[84..180].try_into().unwrap();
        let computor: [u8; 48] = sol[180..228].try_into().unwrap();
        // skip nonce (12 bytes)
        let tensor_c: [u8; 1024] = sol[240..(240 + 1024)].try_into().unwrap();
        Ok(SolParsed::V2(SolV2 { epoch, segment_vr_hash, pk, pop, computor, tensor_c }))
    } else if epoch >= 1 {
        // <<epoch::32-little, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, segment_vr::96-binary, _::binary>>
        if sol.len() < 4 + 48 + 96 + 48 + 96 {
            return Err(SolError::TooShort);
        }
        let pk: [u8; 48] = sol[4..52].try_into().unwrap();
        let pop: [u8; 96] = sol[52..148].try_into().unwrap();
        let computor: [u8; 48] = sol[148..196].try_into().unwrap();
        let segment_vr: [u8; 96] = sol[196..292].try_into().unwrap();
        Ok(SolParsed::V1(SolV1 { epoch, pk, pop, computor, segment_vr }))
    } else {
        // <<epoch::32-little, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, _::binary>>
        if sol.len() < 4 + 48 + 96 + 48 {
            return Err(SolError::TooShort);
        }
        let pk: [u8; 48] = sol[4..52].try_into().unwrap();
        let pop: [u8; 96] = sol[52..148].try_into().unwrap();
        let computor: [u8; 48] = sol[148..196].try_into().unwrap();
        Ok(SolParsed::V0(SolV0 { epoch, pk, pop, computor }))
    }
}

pub fn verify_hash(epoch: u32, hash: &[u8; 32]) -> bool {
    if epoch >= 244 {
        hash[0] == 0 && hash[1] == 0 && hash[2] == 0
    } else if epoch >= 156 {
        hash[0] == 0 && hash[1] == 0
    } else if epoch >= 1 {
        hash[0] == 0 && hash[1] == 0
    } else {
        hash[0] == 0
    }
}

fn vr_b3_stub() -> [u8; 32] {
    // TODO: Provide cryptographically strong random 32 bytes if available.
    // Stubbed to zeros to avoid introducing external dependencies.
    [0u8; 32]
}

// Minimalistic global cache emulating SOLVerifyCache ETS behavior.
static SOL_VERIFY_CACHE: Lazy<Mutex<HashMap<Vec<u8>, bool>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn cache_mark_valid(sol: &[u8]) {
    let mut m = SOL_VERIFY_CACHE.lock().unwrap();
    m.insert(sol.to_vec(), true);
}

fn verify_cache(epoch: u32, sol: &[u8], _use_upow1: bool) -> bool {
    if let Some(is_valid) = SOL_VERIFY_CACHE.lock().unwrap().get(sol).copied() {
        if is_valid {
            // delete like :ets.delete
            SOL_VERIFY_CACHE.lock().unwrap().remove(sol);
            return true;
        }
    }
    // module.calculate(sol) placeholder: use blake3 hash
    let hash: [u8; 32] = b3::hash(sol);
    verify_hash(epoch, &hash)
}

pub fn verify_with_hash(sol: &[u8], hash: &[u8; 32]) -> Result<bool, SolError> {
    if sol.len() < 4 {
        return Err(SolError::TooShort);
    }
    let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap());
    if epoch >= 260 {
        if sol.len() != SOL_SIZE {
            return Err(SolError::InvalidSolSeedSize);
        }
        let vr_b3 = vr_b3_stub();
        Ok(verify_hash(epoch, hash) && b3::freivalds_e260(sol, &vr_b3))
    } else if epoch >= 156 {
        if sol.len() != SOL_SIZE {
            return Err(SolError::InvalidSolSeedSize);
        }
        Ok(verify_hash(epoch, hash) && b3::freivalds(sol))
    } else if epoch >= 1 {
        if sol.len() != 320 {
            return Err(SolError::InvalidSolSeedSize);
        }
        Ok(verify_cache(epoch, sol, true))
    } else {
        if sol.len() != 256 {
            return Err(SolError::InvalidSolSeedSize);
        }
        Ok(verify_cache(epoch, sol, false))
    }
}

pub fn verify(sol: &[u8]) -> Result<bool, SolError> {
    if sol.len() < 4 {
        return Err(SolError::TooShort);
    }
    let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap());
    if epoch >= 260 {
        if sol.len() != SOL_SIZE {
            return Err(SolError::InvalidSolSeedSize);
        }
        let hash = b3::hash(sol);
        let vr_b3 = vr_b3_stub();
        Ok(verify_hash(epoch, &hash) && b3::freivalds_e260(sol, &vr_b3))
    } else if epoch >= 156 {
        if sol.len() != SOL_SIZE {
            return Err(SolError::InvalidSolSeedSize);
        }
        let hash = b3::hash(sol);
        Ok(verify_hash(epoch, &hash) && b3::freivalds(sol))
    } else if epoch >= 1 {
        if sol.len() != 320 {
            return Err(SolError::InvalidSolSeedSize);
        }
        Ok(verify_cache(epoch, sol, true))
    } else {
        if sol.len() != 256 {
            return Err(SolError::InvalidSolSeedSize);
        }
        Ok(verify_cache(epoch, sol, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match() {
        assert_eq!(size(), 1264);
        assert_eq!(SOL_SIZE, 1264);
    }

    #[test]
    fn verify_hash_rules() {
        let mut h = [0u8; 32];
        assert!(verify_hash(0, &h));
        assert!(verify_hash(1, &h));
        assert!(verify_hash(156, &h));
        assert!(verify_hash(244, &h));
        h[0] = 1;
        assert!(!verify_hash(0, &h));
        assert!(!verify_hash(1, &h));
        h[0] = 0;
        h[1] = 1;
        assert!(!verify_hash(1, &h));
        assert!(!verify_hash(156, &h));
        h[1] = 0;
        h[2] = 1;
        assert!(verify_hash(156, &h));
        assert!(!verify_hash(244, &h));
    }

    #[test]
    fn unpack_v2() {
        // Build minimal V2 buffer
        let epoch: u32 = 200;
        let mut buf = vec![];
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]); // segment_vr_hash
        buf.extend_from_slice(&[1u8; 48]); // pk
        buf.extend_from_slice(&[2u8; 96]); // pop
        buf.extend_from_slice(&[3u8; 48]); // computor
        buf.extend_from_slice(&[4u8; 12]); // nonce
        buf.extend_from_slice(&[5u8; 1024]); // tensor_c
        match unpack(&buf).unwrap() {
            SolParsed::V2(v2) => {
                assert_eq!(v2.epoch, epoch);
                assert_eq!(v2.segment_vr_hash, [0u8; 32]);
                assert_eq!(v2.pk, [1u8; 48]);
                assert_eq!(v2.pop, [2u8; 96]);
                assert_eq!(v2.computor, [3u8; 48]);
                assert_eq!(v2.tensor_c, [5u8; 1024]);
            }
            _ => panic!("expected V2"),
        }
    }
}
