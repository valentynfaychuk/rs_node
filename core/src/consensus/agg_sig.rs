use crate::misc::bls12_381::{Error, aggregate_signatures};

// Domain Separation Tags (DST), aligned with the Elixir implementation
pub const DST: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub const DST_POP: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const DST_ATT: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ATTESTATION_";
pub const DST_ENTRY: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ENTRY_";
pub const DST_VRF: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_VRF_";
pub const DST_TX: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TX_";
pub const DST_MOTION: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_MOTION_";
pub const DST_NODE: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NODE_";

/// Aggregate signature with a bitmask of trainers who have signed.
/// - `mask[i] == true` means trainer at index `i` has contributed their signature.
/// - `aggsig` is the aggregated signature (compressed G2, 96 bytes in min_pk scheme).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggSig {
    pub mask: Vec<bool>,
    pub aggsig: [u8; 96],
}

impl AggSig {
    /// Create a new aggregate signature structure with a single signer set in the mask.
    /// `trainers` is a list of public keys (compressed G1, 48 bytes) in a canonical order.
    /// `pk` must be present in `trainers`; otherwise returns Error::InvalidPoint.
    pub fn new<TPk>(trainers: &[TPk], pk: &TPk, signature: &[u8]) -> Result<Self, Error>
    where
        TPk: AsRef<[u8]>,
    {
        let len = trainers.len();
        let mut mask = vec![false; len];
        let index = index_of(trainers, pk).ok_or(Error::InvalidPoint)?;

        mask[index] = true;
        let aggsig = copy_sig(signature)?;

        Ok(Self { mask, aggsig })
    }

    /// Add another signer's signature if not already present in the mask.
    /// Aggregates the signature with the existing aggregate using bls::aggregate_signatures.
    /// If the signer is already set, this is a no-op and returns Ok(())
    pub fn add<TPk>(&mut self, trainers: &[TPk], pk: &TPk, signature: &[u8]) -> Result<(), Error>
    where
        TPk: AsRef<[u8]>,
    {
        let index = index_of(trainers, pk).ok_or(Error::InvalidPoint)?;
        if self.mask.get(index).copied().unwrap_or(false) {
            return Ok(());
        }
        self.mask[index] = true;

        let agg = aggregate_signatures([self.aggsig.as_slice(), signature])?;
        self.aggsig = agg;
        Ok(())
    }

    /// Return indices of trainers which are set in the mask.
    pub fn signed_indices(&self) -> Vec<usize> {
        self.mask.iter().enumerate().filter_map(|(i, &b)| if b { Some(i) } else { None }).collect()
    }

    /// Return the subset of trainers whose bits are set in the mask.
    /// Clones the public key bytes into a vector of vectors.
    pub fn unmask_trainers<TPk>(&self, trainers: &[TPk]) -> Vec<Vec<u8>>
    where
        TPk: AsRef<[u8]>,
    {
        self.mask
            .iter()
            .zip(trainers.iter())
            .filter_map(|(&bit, pk)| if bit { Some(pk.as_ref().to_vec()) } else { None })
            .collect()
    }

    /// Compute a score using a provided weight function over signed trainers.
    /// The result mirrors the Elixir behavior: sum(weights_of_signed) / trainers.len()
    pub fn score_by<TPk, F>(&self, trainers: &[TPk], weight_fn: F) -> f64
    where
        TPk: AsRef<[u8]>,
        F: FnMut(&[u8]) -> f64,
    {
        let total = trainers.len();
        if total == 0 {
            return 0.0;
        }
        let sum: f64 = self
            .mask
            .iter()
            .zip(trainers.iter())
            .filter_map(|(&bit, pk)| if bit { Some(pk.as_ref()) } else { None })
            .map(weight_fn)
            .sum();
        sum / (total as f64)
    }

    /// Convenience: unit weights (each signed trainer contributes 1.0)
    pub fn score<TPk>(&self, trainers: &[TPk]) -> f64
    where
        TPk: AsRef<[u8]>,
    {
        self.score_by(trainers, |_| 1.0)
    }
}

fn index_of<TPk>(trainers: &[TPk], pk: &TPk) -> Option<usize>
where
    TPk: AsRef<[u8]>,
{
    let target = pk.as_ref();
    trainers.iter().position(|cand| cand.as_ref() == target)
}

fn copy_sig(signature: &[u8]) -> Result<[u8; 96], Error> {
    if signature.len() != 96 {
        return Err(Error::InvalidSignature);
    }
    let mut out = [0u8; 96];
    out.copy_from_slice(signature);
    Ok(out)
}
