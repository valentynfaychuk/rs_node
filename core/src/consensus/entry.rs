use crate::bls::{self, DST_ENTRY, DST_VRF};
use crate::consensus::tx;
use crate::misc::blake3;
use crate::proto::{Entry, EntryHeader};
use crate::proto_enc::{ParseError, get_map_field};
use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, List, Term};

#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    #[error("etf decode error")]
    Decode,
    #[error("wrong term type: {0}")]
    WrongType(&'static str),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("too large")]
    TooLarge,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("wrong epoch or unsupported aggregate signature path")]
    WrongEpochOrUnsupportedAgg,
    #[error("txs_hash invalid")]
    TxsHashInvalid,
    #[error("tx error: {0}")]
    TxError(&'static str),
}

impl From<ParseError> for EntryError {
    fn from(err: ParseError) -> Self {
        match err {
            ParseError::Decode(_) => Self::Decode,
            ParseError::Missing(f) => Self::Missing(f),
            ParseError::WrongType(t) => Self::WrongType(t),
            _ => Self::Decode,
        }
    }
}

trait TermExt {
    fn atom(&self) -> Option<&Atom>;
    fn integer(&self) -> Option<i64>;
    fn binary(&self) -> Option<&[u8]>;
    fn list(&self) -> Option<&[Term]>;
}
impl TermExt for Term {
    fn atom(&self) -> Option<&Atom> {
        TryAsRef::<Atom>::try_as_ref(self)
    }
    fn integer(&self) -> Option<i64> {
        match self {
            Term::FixInteger(i) => Some(i.value as i64),
            Term::BigInteger(bi) => num_traits::ToPrimitive::to_i64(&bi.value),
            _ => None,
        }
    }
    fn binary(&self) -> Option<&[u8]> {
        TryAsRef::<Binary>::try_as_ref(self).map(|b| b.bytes.as_slice())
    }
    fn list(&self) -> Option<&[Term]> {
        TryAsRef::<List>::try_as_ref(self).map(|l| l.elements.as_slice())
    }
}

fn parse_header_from_bin(bin: &[u8]) -> Result<EntryHeader, EntryError> {
    let term = Term::decode(bin).map_err(|_| EntryError::Decode)?;
    let map = match term {
        Term::Map(m) => m.map,
        _ => return Err(EntryError::WrongType("header map")),
    };

    let slot = get_map_field(&map, "slot").and_then(|t| t.integer()).ok_or(EntryError::Missing("slot"))?;
    let dr = get_map_field(&map, "dr").and_then(|t| t.binary()).ok_or(EntryError::Missing("dr"))?.to_vec();
    let height = get_map_field(&map, "height").and_then(|t| t.integer()).ok_or(EntryError::Missing("height"))?;
    let prev_hash =
        get_map_field(&map, "prev_hash").and_then(|t| t.binary()).ok_or(EntryError::Missing("prev_hash"))?.to_vec();
    let prev_slot =
        get_map_field(&map, "prev_slot").and_then(|t| t.integer()).ok_or(EntryError::Missing("prev_slot"))?;
    let signer = get_map_field(&map, "signer").and_then(|t| t.binary()).ok_or(EntryError::Missing("signer"))?.to_vec();
    let txs_hash =
        get_map_field(&map, "txs_hash").and_then(|t| t.binary()).ok_or(EntryError::Missing("txs_hash"))?.to_vec();
    let vr = get_map_field(&map, "vr").and_then(|t| t.binary()).ok_or(EntryError::Missing("vr"))?.to_vec();

    Ok(EntryHeader { slot, dr, height, prev_hash, prev_slot, signer, txs_hash, vr })
}

pub struct ParsedEntry {
    pub entry: Entry,
    pub header_bin: Vec<u8>,
    pub mask: Option<Vec<u8>>, // bitstring as raw bytes if present
}

fn parse_entry_from_bin(bin: &[u8]) -> Result<ParsedEntry, EntryError> {
    let t = Term::decode(bin).map_err(|_| EntryError::Decode)?;
    let m = match t {
        Term::Map(m) => m.map,
        _ => return Err(EntryError::WrongType("entry")),
    };

    let hash = get_map_field(&m, "hash").and_then(|t| t.binary()).ok_or(EntryError::Missing("hash"))?.to_vec();

    let header_bin =
        get_map_field(&m, "header").and_then(|t| t.binary()).ok_or(EntryError::Missing("header"))?.to_vec();
    let header = parse_header_from_bin(&header_bin)?;

    let signature =
        get_map_field(&m, "signature").and_then(|t| t.binary()).ok_or(EntryError::Missing("signature"))?.to_vec();

    let txs: Vec<Vec<u8>> = match get_map_field(&m, "txs").and_then(|t| t.list()) {
        Some(list) => list.iter().filter_map(|t| t.binary().map(|b| b.to_vec())).collect(),
        None => Vec::new(),
    };

    let mask = get_map_field(&m, "mask").and_then(|t| t.binary()).map(|b| b.to_vec());

    Ok(ParsedEntry { entry: Entry { hash, header, signature, txs }, header_bin, mask })
}

fn bls_verify_header_sig(header_bin: &[u8], signature: &[u8], signer: &[u8]) -> Result<(), EntryError> {
    let h = blake3::hash(header_bin);
    bls::verify(signer, signature, &h, DST_ENTRY).map_err(|_| EntryError::InvalidSignature)
}

fn validate_signature(
    header_bin: &[u8],
    signature: &[u8],
    signer: &[u8],
    mask: Option<&[u8]>,
) -> Result<(), EntryError> {
    if let Some(mask_bytes) = mask {
        // Decode header to get height
        let header = parse_header_from_bin(header_bin)?;
        // Resolve trainers for this height (chain state dependent)
        return if let Some(trainers) = crate::consensus::trainers_for_height(header.height) {
            // Unmask trainers who have signed using the provided bitmask
            let signed: Vec<[u8; 48]> = crate::bic::epoch::unmask_trainers(&trainers, mask_bytes, trainers.len());
            if signed.is_empty() {
                // No signers in mask -> invalid aggregate signature
                return Err(EntryError::InvalidSignature);
            }
            // Aggregate public keys
            let aggpk = bls::aggregate_public_keys(signed.iter()).map_err(|_| EntryError::InvalidSignature)?;
            // Verify aggregate signature over blake3(header_bin)
            let h = blake3::hash(header_bin);
            bls::verify(&aggpk, signature, &h, DST_ENTRY).map_err(|_| EntryError::InvalidSignature)
        } else {
            // Trainers unavailable (e.g., wrong epoch or not implemented)
            Err(EntryError::WrongEpochOrUnsupportedAgg)
        };
    }
    bls_verify_header_sig(header_bin, signature, signer)
}

fn concat_vecs(vs: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = vs.iter().map(|v| v.len()).sum();
    let mut out = Vec::with_capacity(total);
    for v in vs {
        out.extend_from_slice(v);
    }
    out
}

fn validate_entry_contents(e: &Entry, is_special_meeting_block: bool) -> Result<(), EntryError> {
    // Basic length checks (delegate to proto::EntryHeader as well)
    if e.hash.len() != 32 {
        return Err(EntryError::WrongType("entry_hash_len"));
    }
    if e.signature.len() != 96 {
        return Err(EntryError::WrongType("entry_signature_len"));
    }
    e.header.validate().map_err(|_| EntryError::WrongType("entry_header_invalid"))?;

    // txs constraints
    if e.txs.len() > 100 {
        return Err(EntryError::WrongType("txs_len_over_100"));
    }

    // txs_hash must be blake3 of concatenated tx binaries
    let joined = concat_vecs(&e.txs);
    let h = blake3::hash(&joined);
    if e.header.txs_hash.as_slice() != &h {
        return Err(EntryError::TxsHashInvalid);
    }

    // Validate each tx
    for txp in &e.txs {
        match tx::validate(txp, is_special_meeting_block) {
            Ok(_) => {}
            Err(err) => {
                // Map to static str description to avoid lifetimes
                let msg = match err {
                    tx::TxError::Decode => "decode",
                    tx::TxError::WrongType(_) => "wrong_type",
                    tx::TxError::Missing(_) => "missing",
                    tx::TxError::InvalidHash => "invalid_hash",
                    tx::TxError::InvalidSignature => "invalid_signature",
                    tx::TxError::NonceNotInteger => "nonce_not_integer",
                    tx::TxError::NonceTooHigh => "nonce_too_high",
                    tx::TxError::ActionsNotList => "actions_not_list",
                    tx::TxError::ActionsLenNot1 => "actions_len_not_1",
                    tx::TxError::OpMustBeCall => "op_must_be_call",
                    tx::TxError::ContractMustBeBinary => "contract_must_be_binary",
                    tx::TxError::FunctionMustBeBinary => "function_must_be_binary",
                    tx::TxError::ArgsMustBeList => "args_must_be_list",
                    tx::TxError::ArgMustBeBinary => "arg_must_be_binary",
                    tx::TxError::InvalidContractOrFunction => "invalid_contract_or_function",
                    tx::TxError::InvalidModuleForSpecial => "invalid_module_for_special",
                    tx::TxError::InvalidFunctionForSpecial => "invalid_function_for_special",
                    tx::TxError::AttachedSymbolMustBeBinary => "attached_symbol_must_be_binary",
                    tx::TxError::AttachedSymbolWrongSize => "attached_symbol_wrong_size",
                    tx::TxError::AttachedAmountMustBeBinary => "attached_amount_must_be_binary",
                    tx::TxError::AttachedAmountMustBeIncluded => "attached_amount_must_be_included",
                    tx::TxError::AttachedSymbolMustBeIncluded => "attached_symbol_must_be_included",
                };
                return Err(EntryError::TxError(msg));
            }
        }
    }

    Ok(())
}

/// Translate of Entry.unpack_and_validate/1 minimal variant.
/// - `entry_size_limit` corresponds to Application.fetch_env!(:ama, :entry_size)
pub fn unpack_and_validate(entry_packed: &[u8], entry_size_limit: usize) -> Result<Entry, EntryError> {
    if entry_packed.len() >= entry_size_limit {
        return Err(EntryError::TooLarge);
    }

    let parsed = parse_entry_from_bin(entry_packed)?;

    // Signature validation
    validate_signature(
        &parsed.header_bin,
        &parsed.entry.signature,
        &parsed.entry.header.signer,
        parsed.mask.as_deref(),
    )?;

    // Entry content validation
    let is_special = parsed.mask.is_some();
    validate_entry_contents(&parsed.entry, is_special)?;

    Ok(parsed.entry)
}

/// Build next header skeleton similar to Entry.build_next/2.
/// This requires chain state (pk/sk), so we only provide a helper to derive next header fields given inputs.
pub fn build_next_header(
    cur: &Entry,
    slot: i64,
    signer_pk: &[u8],
    signer_sk: &[u8],
) -> Result<EntryHeader, EntryError> {
    // dr' = blake3(dr)
    let dr = blake3::hash(&cur.header.dr).to_vec();
    // vr' = sign(sk, prev_vr, DST_VRF)
    let vr = bls::sign(signer_sk, &cur.header.vr, DST_VRF).map_err(|_| EntryError::InvalidSignature)?;

    Ok(EntryHeader {
        slot,
        height: cur.header.height + 1,
        prev_slot: cur.header.slot,
        prev_hash: cur.hash.clone(),
        dr,
        vr,
        signer: signer_pk.to_vec(),
        txs_hash: vec![0u8; 32], // to be filled when txs are known
    })
}

pub fn epoch(entry: &Entry) -> i64 {
    entry.header.height / 100_000
}
pub fn height(entry: &Entry) -> i64 {
    entry.header.height
}

pub fn contains_tx(entry: &Entry, tx_function: &str) -> bool {
    entry.txs.iter().any(|txp| {
        if let Ok(txu) = tx::unpack_etf(txp) {
            if let Some(first) = txu.tx.actions.get(0) { first.function == tx_function } else { false }
        } else {
            false
        }
    })
}
