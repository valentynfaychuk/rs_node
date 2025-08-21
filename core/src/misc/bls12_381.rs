use bls12_381::*;
use group::Curve;

// we use blst for signing/verification (hash_to_curve with DST) and serialization
use blst::BLST_ERROR;
use blst::min_pk::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid seed")]
    InvalidSeed,
    #[error("invalid point")]
    InvalidPoint,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("verification failed")]
    VerificationFailed,
    #[error("zero-sized input")]
    ZeroSizedInput,
}

/// Parse a secret key from seed, accepts either 64 or 32 bytes
fn parse_secret_key(seed: &[u8]) -> Result<Scalar, Error> {
    if let Ok(bytes_64) = <&[u8; 64]>::try_from(seed) {
        return Ok(Scalar::from_bytes_wide(bytes_64));
    }
    if let Ok(bytes_32) = <&[u8; 32]>::try_from(seed) {
        let ct_scalar = Scalar::from_bytes(bytes_32);
        if ct_scalar.is_some().unwrap_u8() == 1 {
            return Ok(ct_scalar.unwrap());
        } else {
            return Err(Error::InvalidSeed);
        }
    }
    Err(Error::InvalidSeed)
}

fn g1_projective_is_valid(projective: &G1Projective) -> bool {
    let is_identity: bool = projective.is_identity().into();
    let is_on_curve = projective.is_on_curve().into();
    let is_torsion_free = projective.to_affine().is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn g2_affine_is_valid(affine: &G2Affine) -> bool {
    let is_identity: bool = affine.is_identity().into();
    let is_on_curve = affine.is_on_curve().into();
    let is_torsion_free = affine.is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn parse_public_key(bytes: &[u8]) -> Result<G1Projective, Error> {
    if bytes.len() != 48 {
        return Err(Error::InvalidPoint);
    }
    let mut res = [0u8; 48];
    res.copy_from_slice(bytes);

    match Option::<G1Affine>::from(G1Affine::from_compressed(&res)) {
        Some(affine) => {
            let projective = G1Projective::from(affine);
            if g1_projective_is_valid(&projective) { Ok(projective) } else { Err(Error::InvalidPoint) }
        }
        None => Err(Error::InvalidPoint),
    }
}

fn parse_signature(bytes: &[u8]) -> Result<G2Projective, Error> {
    if bytes.len() != 96 {
        return Err(Error::InvalidPoint);
    }
    let mut res = [0u8; 96];
    res.copy_from_slice(bytes);

    match Option::from(G2Affine::from_compressed(&res)) {
        Some(affine) => {
            if g2_affine_is_valid(&affine) {
                Ok(G2Projective::from(affine))
            } else {
                Err(Error::InvalidPoint)
            }
        }
        None => Err(Error::InvalidPoint),
    }
}

fn sign_from_scalar(scalar: Scalar, msg: &[u8], dst: &[u8]) -> Result<BlsSignature, Error> {
    // convert Scalar to big-endian bytes for blst SecretKey
    let mut sk_be = scalar.to_bytes();
    sk_be.reverse();
    let sk = BlsSecretKey::from_bytes(&sk_be).map_err(|_| Error::InvalidSeed)?;
    Ok(sk.sign(msg, dst, &[]))
}

// public API

/// Derive compressed G1 public key (48 bytes) from seed (32 or 64 bytes)
pub fn get_public_key(seed: &[u8]) -> Result<[u8; 48], Error> {
    let sk = parse_secret_key(seed)?;
    let g1 = G1Projective::generator() * sk;
    Ok(g1.to_affine().to_compressed())
}

/// Sign a message with seed-derived secret key, returns signature bytes (96 bytes in min_pk)
pub fn sign(seed: &[u8], message: &[u8], dst: &[u8]) -> Result<[u8; 96], Error> {
    let sk = parse_secret_key(seed)?;
    let signature = sign_from_scalar(sk, message, dst)?;
    Ok(signature.to_bytes())
}

/// Verify a signature using a compressed G1 public key (48 bytes) and signature (96 bytes)
/// Errors out if the signature is invalid
pub fn verify(pk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8], dst: &[u8]) -> Result<(), Error> {
    let pk = BlsPublicKey::deserialize(pk_bytes).map_err(|_| Error::InvalidPoint)?;
    let sig = BlsSignature::deserialize(sig_bytes).map_err(|_| Error::InvalidSignature)?;

    let err = sig.verify(
        true, // hash_to_curve
        msg,
        dst, // domain separation tag
        &[], // no augmentation
        &pk,
        true, // validate pk ∈ G1
    );

    if err == BLST_ERROR::BLST_SUCCESS { Ok(()) } else { Err(Error::VerificationFailed) }
}

/// Aggregate multiple compressed G1 public keys into one compressed G1 public key (48 bytes)
pub fn aggregate_public_keys<T>(public_keys: T) -> Result<[u8; 48], Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut iter = public_keys.into_iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Err(Error::ZeroSizedInput),
    };
    let mut acc = parse_public_key(first.as_ref())?;
    for pk in iter {
        let p = parse_public_key(pk.as_ref())?;
        acc += p;
    }
    Ok(acc.to_affine().to_compressed())
}

/// Aggregate multiple signatures (compressed G2, 96 bytes) into one compressed G2 (96 bytes)
pub fn aggregate_signatures<T>(signatures: T) -> Result<[u8; 96], Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut iter = signatures.into_iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Err(Error::ZeroSizedInput),
    };
    let mut acc = parse_signature(first.as_ref())?;
    for s in iter {
        let p = parse_signature(s.as_ref())?;
        acc += p;
    }
    Ok(acc.to_affine().to_compressed())
}

/// Compute Diffie-Hellman shared secret: pk_g1 * sk -> compressed G1 (48 bytes).
pub fn get_shared_secret(public_key: &[u8], seed: &[u8]) -> Result<[u8; 48], Error> {
    let sk = parse_secret_key(seed)?;
    let pk_g1 = parse_public_key(public_key)?; // validates pk
    Ok((pk_g1 * sk).to_affine().to_compressed())
}

/// Validate a compressed G1 public key.
pub fn validate_public_key(public_key: &[u8]) -> Result<(), Error> {
    parse_public_key(public_key).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed32(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn pk_sign_verify_and_validate() {
        let seed = seed32(1);
        let pk = get_public_key(&seed).expect("pk");
        validate_public_key(&pk).expect("valid pk");

        let msg = b"context7:message";
        let dst = b"CONTEXT7-BLS-DST";
        let sig = sign(&seed, msg, dst).expect("sign");
        verify(&pk, &sig, msg, dst).expect("verify");
    }

    #[test]
    fn shared_secret_symmetry() {
        let a = seed32(2);
        let b = seed32(3);
        let pk_a = get_public_key(&a).unwrap();
        let pk_b = get_public_key(&b).unwrap();
        let ab = get_shared_secret(&pk_b, &a).unwrap();
        let ba = get_shared_secret(&pk_a, &b).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn aggregation_behaviour() {
        let s1 = seed32(4);
        let s2 = seed32(5);
        let pk1 = get_public_key(&s1).unwrap();
        let pk2 = get_public_key(&s2).unwrap();

        // test single public key aggregation
        let agg1 = aggregate_public_keys([pk1]).unwrap();
        assert_eq!(agg1.len(), 48);
        assert_eq!(agg1, pk1); // single key aggregation should equal original key

        // test multiple public key aggregation
        let agg_pk = aggregate_public_keys([pk1, pk2]).unwrap();
        assert_eq!(agg_pk.len(), 48);
        assert_ne!(agg_pk, pk1); // aggregated key should differ from individual keys
        assert_ne!(agg_pk, pk2);

        // zero-sized input should fail
        assert!(matches!(aggregate_public_keys::<[&[u8]; 0]>([]), Err(Error::ZeroSizedInput)));

        // test signature aggregation
        let dst = b"DST";
        let msg = b"m";
        let sig1 = sign(&s1, msg, dst).unwrap();
        let sig2 = sign(&s2, msg, dst).unwrap();

        // test single signature aggregation
        let agg_sig1 = aggregate_signatures([sig1.as_slice()]).unwrap();
        assert_eq!(agg_sig1.len(), 96);
        assert_eq!(agg_sig1, sig1); // single signature aggregation should equal original

        // test multiple signature aggregation
        let agg_sig = aggregate_signatures([sig1.as_slice(), sig2.as_slice()]).unwrap();
        assert_eq!(agg_sig.len(), 96);
        assert_ne!(agg_sig, sig1); // aggregated signature should differ from individual signatures
        assert_ne!(agg_sig, sig2);

        // zero-sized signature input should fail
        assert!(matches!(aggregate_signatures::<[&[u8]; 0]>([]), Err(Error::ZeroSizedInput)));

        // test that aggregated signature verifies against aggregated public key
        verify(&agg_pk, &agg_sig, msg, dst).expect("aggregated signature should verify against aggregated public key");

        // test that individual signatures don't verify against aggregated public key
        assert!(verify(&agg_pk, &sig1, msg, dst).is_err());
        assert!(verify(&agg_pk, &sig2, msg, dst).is_err());

        // test that aggregated signature doesn't verify against individual public keys
        assert!(verify(&pk1, &agg_sig, msg, dst).is_err());
        assert!(verify(&pk2, &agg_sig, msg, dst).is_err());
    }
}
