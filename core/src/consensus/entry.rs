/// Entry is a consensus block in Amadeus
use super::agg_sig::{DST_ENTRY, DST_VRF};
use crate::config::ENTRY_SIZE;
use crate::consensus::tx;
use crate::misc::blake3;
use crate::misc::bls12_381;
use crate::misc::utils::{TermExt, get_map_field};
use crate::node::handler::{HandleExt, Instruction};
use crate::node::proto::ProtoExt;
use eetf::Term;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

const MAX_TXS: usize = 100; // Maximum number of transactions in an entry

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Decode(#[from] eetf::DecodeError),
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
    #[error(transparent)]
    TxError(#[from] super::tx::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct EntryHeader {
    pub slot: i64,
    pub dr: Vec<u8>,
    pub height: i64,
    pub prev_hash: Vec<u8>,
    pub prev_slot: i64,
    pub signer: Vec<u8>,
    pub txs_hash: Vec<u8>,
    pub vr: Vec<u8>,
}

impl fmt::Debug for EntryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryHeader")
            .field("slot", &self.slot)
            .field("dr", &bs58::encode(&self.dr).into_string())
            .field("height", &self.height)
            .field("prev_hash", &bs58::encode(&self.prev_hash).into_string())
            .field("prev_slot", &self.prev_slot)
            .field("signer", &bs58::encode(&self.signer).into_string())
            .field("txs_hash", &bs58::encode(&self.txs_hash).into_string())
            .field("vr", &bs58::encode(&self.vr).into_string())
            .finish()
    }
}

impl EntryHeader {
    fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let term = Term::decode(bin).map_err(Error::Decode)?;
        let map = match term {
            Term::Map(m) => m.map,
            _ => return Err(Error::WrongType("header map")),
        };

        let slot = get_map_field(&map, "slot").and_then(|t| t.get_integer()).ok_or(Error::Missing("slot"))?;
        let dr = get_map_field(&map, "dr").and_then(|t| t.get_binary()).ok_or(Error::Missing("dr"))?.to_vec();
        let height = get_map_field(&map, "height").and_then(|t| t.get_integer()).ok_or(Error::Missing("height"))?;
        let prev_hash =
            get_map_field(&map, "prev_hash").and_then(|t| t.get_binary()).ok_or(Error::Missing("prev_hash"))?.to_vec();
        let prev_slot =
            get_map_field(&map, "prev_slot").and_then(|t| t.get_integer()).ok_or(Error::Missing("prev_slot"))?;
        let signer =
            get_map_field(&map, "signer").and_then(|t| t.get_binary()).ok_or(Error::Missing("signer"))?.to_vec();
        let txs_hash =
            get_map_field(&map, "txs_hash").and_then(|t| t.get_binary()).ok_or(Error::Missing("txs_hash"))?.to_vec();
        let vr = get_map_field(&map, "vr").and_then(|t| t.get_binary()).ok_or(Error::Missing("vr"))?.to_vec();

        Ok(EntryHeader { slot, dr, height, prev_hash, prev_slot, signer, txs_hash, vr })
    }
    pub fn validate(&self) -> Result<(), Error> {
        // if self.slot < 0 {
        //     return Err(Error::WrongType("slot_negative"));
        // }
        // if self.height < 0 {
        //     return Err(Error::WrongType("height_negative"));
        // }
        // if self.prev_slot < 0 {
        //     return Err(Error::WrongType("prev_slot_negative"));
        // }
        // if self.vr.len() != 48 {
        //     return Err(Error::WrongType("vr_len"));
        // }
        if self.dr.len() != 32 {
            return Err(Error::WrongType("dr_len"));
        }
        if self.prev_hash.len() != 32 {
            return Err(Error::WrongType("prev_hash_len"));
        }
        if self.txs_hash.len() != 32 {
            return Err(Error::WrongType("txs_hash_len"));
        }
        if self.signer.len() != 48 {
            return Err(Error::WrongType("signer_len"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Entry {
    pub hash: Vec<u8>,       // 32 bytes
    pub header: EntryHeader, // nested decoded header
    pub signature: Vec<u8>,  // 96 bytes
    pub txs: Vec<Vec<u8>>,   // list of tx binaries (can be empty)
}

impl ProtoExt for Entry {
    type Error = Error;

    fn from_etf_map_validated(map: HashMap<Term, Term>) -> Result<Self, Self::Error> {
        let bin =
            get_map_field(&map, "entry_packed").and_then(|t| t.get_binary()).ok_or(Error::Missing("entry_packed"))?;

        Entry::from_etf_bin_validated(bin, ENTRY_SIZE)
    }
}

impl HandleExt for Entry {
    type Error = Error;

    fn handle(self) -> Result<Instruction, Self::Error> {
        // Create log directory if it doesn't exist
        let log_dir = Path::new("log");
        if !log_dir.exists() {
            fs::create_dir_all(log_dir)?;
        }

        // Write entry to the log file
        // TODO: figure out the tip and block type (root finalized or chain top)
        let log_file = log_dir.join("entry-tip");
        let mut file = fs::OpenOptions::new().create(true).append(true).open(log_file)?;

        // Format entry data for logging
        let entry_log = format!(
            "Height: {}, Hash: {}, Slot: {}, Signer: {}, Txs: {}\n",
            self.header.height,
            bs58::encode(&self.hash).into_string(),
            self.header.slot,
            bs58::encode(&self.header.signer).into_string(),
            self.txs.len()
        );

        file.write_all(entry_log.as_bytes())?;
        file.flush()?;

        println!("Entry logged - Height: {}, Hash: {}", self.header.height, bs58::encode(&self.hash).into_string());

        // Clone the entry for the instruction since we've already used self for logging
        let entry_clone = self.clone();
        Ok(Instruction::ReceivedEntry { entry: entry_clone })
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("hash", &bs58::encode(&self.hash).into_string())
            .field("header", &self.header)
            .field("signature", &bs58::encode(&self.signature).into_string())
            .field("txs", &self.txs.iter().map(|tx| bs58::encode(tx).into_string()).collect::<Vec<String>>())
            .finish()
    }
}

impl Entry {
    pub fn from_etf_bin_validated(bin: &[u8], entry_size_limit: usize) -> Result<Entry, Error> {
        if bin.len() >= entry_size_limit {
            return Err(Error::TooLarge);
        }

        let parsed = ParsedEntry::from_etf_bin(bin)?;
        parsed.validate_signature()?;
        let is_special = parsed.mask.is_some();
        parsed.entry.validate_contents(is_special)?;

        Ok(parsed.entry)
    }

    fn validate_contents(&self, is_special_meeting_block: bool) -> Result<(), Error> {
        if self.hash.len() != 32 {
            return Err(Error::WrongType("entry_hash_len"));
        }
        if self.signature.len() != 96 {
            return Err(Error::WrongType("entry_signature_len"));
        }

        self.header.validate()?;

        // txs constraints
        if self.txs.len() > MAX_TXS {
            return Err(Error::WrongType("txs_len_over_100"));
        }

        let txs_bin = self.txs.iter().flatten().cloned().collect::<Vec<u8>>();
        let h = blake3::hash(&txs_bin);
        if self.header.txs_hash.as_slice() != h.as_slice() {
            return Err(Error::TxsHashInvalid);
        }

        for txp in &self.txs {
            tx::validate(txp, is_special_meeting_block)?;
        }

        Ok(())
    }

    /// Build next header skeleton similar to Entry.build_next/2.
    /// This requires chain state (pk/sk), so we only provide a helper to derive next header fields given inputs.
    pub fn build_next_header(&self, slot: i64, signer_pk: &[u8], signer_sk: &[u8]) -> Result<EntryHeader, Error> {
        // dr' = blake3(dr)
        let dr = blake3::hash(&self.header.dr).to_vec();
        // vr' = sign(sk, prev_vr, DST_VRF)
        let vr = bls12_381::sign(signer_sk, &self.header.vr, DST_VRF).map_err(|_| Error::InvalidSignature)?;

        Ok(EntryHeader {
            slot,
            height: self.header.height + 1,
            prev_slot: self.header.slot,
            prev_hash: self.hash.clone(),
            dr,
            vr,
            signer: signer_pk.to_vec(),
            txs_hash: vec![0u8; 32], // to be filled when txs are known
        })
    }

    pub fn get_epoch(&self) -> i64 {
        self.header.height / 100_000
    }
    pub fn get_height(&self) -> i64 {
        self.header.height
    }

    pub fn contains_tx(&self, tx_function: &str) -> bool {
        self.txs.iter().any(|txp| {
            if let Ok(txu) = tx::unpack_etf(txp) {
                if let Some(first) = txu.tx.actions.get(0) { first.function == tx_function } else { false }
            } else {
                false
            }
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedEntry {
    pub entry: Entry,
    pub header_bin: Vec<u8>,
    pub mask: Option<Vec<u8>>, // bitstring as raw bytes if present
}

impl ParsedEntry {
    fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let term = Term::decode(bin).map_err(Error::Decode)?;
        let map = term.get_map().ok_or(Error::WrongType("entry"))?;

        let hash = get_map_field(&map, "hash").and_then(|t| t.get_binary()).ok_or(Error::Missing("hash"))?.to_vec();

        let header_bin =
            get_map_field(&map, "header").and_then(|t| t.get_binary()).ok_or(Error::Missing("header"))?.to_vec();
        let header = EntryHeader::from_etf_bin(header_bin.as_slice())?;

        let signature =
            get_map_field(&map, "signature").and_then(|t| t.get_binary()).ok_or(Error::Missing("signature"))?.to_vec();

        let txs: Vec<Vec<u8>> = match get_map_field(&map, "txs").and_then(|t| t.get_list()) {
            Some(list) => list.iter().filter_map(|t| t.get_binary().map(|b| b.to_vec())).collect(),
            None => Vec::new(),
        };

        let mask = get_map_field(&map, "mask").and_then(|t| t.get_binary()).map(|b| b.to_vec());

        Ok(ParsedEntry { entry: Entry { hash, header, signature, txs }, header_bin, mask })
    }
    fn validate_signature(&self) -> Result<(), Error> {
        if let Some(mask_bytes) = self.mask.as_deref() {
            // Resolve trainers for this height (chain state dependent)
            if let Some(trainers) = crate::consensus::trainers_for_height(self.entry.header.height) {
                // Unmask trainers who have signed using the provided bitmask
                let signed: Vec<[u8; 48]> = crate::bic::epoch::unmask_trainers(&trainers, mask_bytes, trainers.len());
                if signed.is_empty() {
                    // No signers in mask -> invalid aggregate signature
                    return Err(Error::InvalidSignature);
                }
                // Aggregate public keys
                let agg_pk = bls12_381::aggregate_public_keys(signed.iter())?;
                // Verify aggregate signature over blake3(header_bin)
                let h = blake3::hash(&self.header_bin);
                bls12_381::verify(&agg_pk, &self.entry.signature, &h, DST_ENTRY)?;
            } else {
                return Err(Error::WrongEpochOrUnsupportedAgg); // Trainers unavailable
            }
        } else {
            let h = blake3::hash(&self.header_bin);
            bls12_381::verify(&self.entry.header.signer, &self.entry.signature, &h, DST_ENTRY)?;
        }

        Ok(())
    }
}
