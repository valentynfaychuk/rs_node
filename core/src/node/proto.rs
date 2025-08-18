use super::proto_ser::Error;
use crate::bic::sol::SolParsed;
use crate::consensus::tx;
use eetf::convert::TryAsRef;
use eetf::{Binary, List, Term};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Top-level message enumeration.
#[derive(Debug)]
pub enum NodeProto {
    Ping(Ping),
    Pong(Pong),
    WhoAreYou(WhoAreYou),
    TxPool(TxPool),
    Peers(Peers),
    Sol(Sol),
    Entry(Entry),
    AttestationBulk(AttestationBulk),
    ConsensusBulk(ConsensusBulk),
    CatchupEntry(CatchupEntry),
    CatchupTri(CatchupTri),
    CatchupBi(CatchupBi),
    CatchupAttestation(CatchupAttestation),
    SpecialBusiness(SpecialBusiness),
    SpecialBusinessReply(SpecialBusinessReply),
    SolicitEntry(SolicitEntry),
    SolicitEntry2(SolicitEntry2),
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
    pub fn validate(&self) -> Result<(), Error> {
        // Required lengths based on protocol:
        // - dr: 32 bytes
        // - prev_hash: 32 bytes
        // - txs_hash: 32 bytes
        // - signer: 48 bytes
        if self.dr.len() != 32 {
            return Err(Error::WrongType("entry_header_dr_len"));
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
    pub fn validate(&self) -> Result<(), Error> {
        // TODO: cryptographic checks: verify signature over header and hash; validate VR, DR fields.
        // TODO: dedup by checking existence in Fabric/RocksDB; insert into Fabric if new; trigger tick.
        // TODO: handle optional consensus_packed or attestation_packed from the message when parser supports them.

        // Required lengths based on protocol:
        // - hash: 32 bytes
        // - signature: 96 bytes
        if self.hash.len() != 32 {
            return Err(Error::WrongType("entry_hash_len"));
        }
        if self.signature.len() != 96 {
            return Err(Error::WrongType("entry_signature_len"));
        }

        self.header.validate()
    }
}

/// Shared summary of an entry’s tip.
#[derive(Debug)]
pub struct EntrySummary {
    pub header: Vec<u8>,
    pub signature: Vec<u8>,
    pub mask: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Ping {
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
    pub ts_m: i64,
}

#[derive(Debug)]
pub struct Pong {
    pub ts_m: i64,
}

#[derive(Debug)]
pub struct WhoAreYou;

#[derive(Debug)]
pub struct TxPool {
    pub txs_packed: Vec<u8>,
}

impl TxPool {
    /// Returns valid tx binaries.
    pub fn get_valid_txs(&self) -> Result<Vec<Vec<u8>>, Error> {
        Self::parse_and_filter_txs(&self.txs_packed)
    }

    /// Decodes an ETF-encoded list of binary transactions, validates each, and returns only the valid ones.
    fn parse_and_filter_txs(txs_packed_blob: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let term = Term::decode(txs_packed_blob)?;

        let list = if let Some(l) = TryAsRef::<List>::try_as_ref(&term) {
            &l.elements
        } else {
            return Err(Error::WrongType("txs_packed must be list"));
        };

        let mut good: Vec<Vec<u8>> = Vec::with_capacity(list.len());

        for t in list {
            // each item must be a binary()
            let bin = if let Some(b) = TryAsRef::<Binary>::try_as_ref(t) {
                b.bytes.as_slice()
            } else {
                // skip non-binary entries silently (Elixir code assumes binaries)
                continue;
            };

            // Validate basic tx rules; special-meeting context is false in gossip path
            if tx::validate(bin, false).is_ok() {
                good.push(bin.to_vec());
            }
        }

        Ok(good)
    }
}

#[derive(Debug)]
pub struct Peers {
    pub ips: Vec<String>,
}

#[derive(Debug)]
pub struct Sol {
    pub sol: Vec<u8>,
}

#[derive(Clone)]
pub struct Attestation {
    pub entry_hash: Vec<u8>,     // 32 bytes
    pub mutations_hash: Vec<u8>, // 32 bytes
    pub signature: Vec<u8>,      // 96 bytes
    pub signer: Vec<u8>,         // 48 bytes
}

impl fmt::Debug for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attestation")
            .field("entry_hash", &bs58::encode(&self.entry_hash).into_string())
            .field("mutations_hash", &bs58::encode(&self.mutations_hash).into_string())
            .field("signature", &bs58::encode(&self.signature).into_string())
            .field("signer", &bs58::encode(&self.signer).into_string())
            .finish()
    }
}

#[derive(Debug)]
pub struct AttestationBulk {
    pub attestations: Vec<Attestation>,
}

#[derive(Debug)]
pub struct ConsensusBulk {
    pub consensuses_packed: Vec<u8>,
}

#[derive(Debug)]
pub struct CatchupEntry {
    pub heights: Vec<u64>,
}

#[derive(Debug)]
pub struct CatchupTri {
    pub heights: Vec<u64>,
}

#[derive(Debug)]
pub struct CatchupBi {
    pub heights: Vec<u64>,
}

#[derive(Debug)]
pub struct CatchupAttestation {
    pub hashes: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct SpecialBusiness {
    pub business: Vec<u8>,
}

#[derive(Debug)]
pub struct SpecialBusinessReply {
    pub business: Vec<u8>,
}

#[derive(Debug)]
pub struct SolicitEntry {
    pub hash: Vec<u8>,
}

#[derive(Debug)]
pub struct SolicitEntry2;

// udp transport headers:

//<<"AMA",                   # 3 bytes magic
//  version_3byte::3-binary, # 3 bytes version triplet
//  0::7, 1::1,              # 7 bits zero + 1 bit flag
//  pk::48-binary,           # 48 bytes public key
//  signature::96-binary,    # 96 bytes signature
//  shard_index::16,         # u16
//  shard_total::16,         # u16
//  ts_n::64,                # u64
//  original_size::32,       # u32
//  msg_compressed_or_shard::binary>>  # rest of the bytes
#[derive(Debug)]
pub struct MessageV2 {
    pub version: String,
    pub pk: Vec<u8>,
    // Is present if the message is signed
    pub signature: Vec<u8>,
    pub shard_index: u16,
    pub shard_total: u16,
    pub ts_nano: u64,
    pub original_size: u32,
    pub payload: Vec<u8>,
}

/// Result of handling an incoming NodeProto message.
#[derive(Debug)]
pub enum HandleResult {
    Noop,
    ReplyPong { ts_m: i64 },
    ObservedPong { ts_m: i64, seen_time_ms: i64 },
    ValidTxs { txs: Vec<Vec<u8>> },
    Peers { ips: Vec<String> },
    ReceivedSol { sol: SolParsed },
    ReceivedEntry { entry: Entry },
    Attestations { attestations: Vec<Attestation> },
    ConsensusesPacked { packed: Vec<u8> },
    CatchupEntryReq { heights: Vec<u64> },
    CatchupTriReq { heights: Vec<u64> },
    CatchupBiReq { heights: Vec<u64> },
    CatchupAttestationReq { hashes: Vec<Vec<u8>> },
    SpecialBusiness { business: Vec<u8> },
    SpecialBusinessReply { business: Vec<u8> },
    SolicitEntry { hash: Vec<u8> },
    SolicitEntry2,
    Error(String),
}

impl NodeProto {
    /// Handle a message in a side-effect-light way, returning instructions for upper layers.
    pub fn handle(&self) -> HandleResult {
        match self {
            NodeProto::WhoAreYou(_) => HandleResult::Noop,
            NodeProto::Ping(p) => {
                // TODO: validate temporal/rooted signatures and update peer shared secret; broadcast peers
                HandleResult::ReplyPong { ts_m: p.ts_m }
            }
            NodeProto::Pong(p) => {
                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
                // TODO: update ETS-like peer table with latency now_ms - p.ts_m
                HandleResult::ObservedPong { ts_m: p.ts_m, seen_time_ms: now_ms }
            }
            NodeProto::TxPool(t) => match t.get_valid_txs() {
                Ok(txs) => HandleResult::ValidTxs { txs },
                Err(e) => HandleResult::Error(format!("txpool: {:?}", e)),
            },
            NodeProto::Peers(p) => {
                // TODO: insert into peer table
                HandleResult::Peers { ips: p.ips.clone() }
            }
            NodeProto::Sol(sol) => {
                // TODO: PoP verification, TXPool.add_gifted_sol; possibly build and broadcast txs
                match SolParsed::try_from(sol) {
                    Ok(sol) => HandleResult::ReceivedSol { sol },
                    Err(e) => HandleResult::Error(format!("sol: {:?}", e)),
                }
            }
            NodeProto::Entry(e) => {
                // TODO: deduplicate via DB/Fabric and insert; process optional consensus/attestation when parser supports.
                HandleResult::ReceivedEntry { entry: e.clone() }
            }
            NodeProto::AttestationBulk(b) => {
                // TODO: per-attestation unpack_and_validate and coordinator routing
                HandleResult::Attestations { attestations: b.attestations.clone() }
            }
            NodeProto::ConsensusBulk(c) => {
                // TODO: consensuses_packed should be list of binaries; parser currently not implemented for this op
                HandleResult::ConsensusesPacked { packed: c.consensuses_packed.clone() }
            }
            NodeProto::CatchupEntry(c) => HandleResult::CatchupEntryReq { heights: c.heights.clone() },
            NodeProto::CatchupTri(c) => HandleResult::CatchupTriReq { heights: c.heights.clone() },
            NodeProto::CatchupBi(c) => HandleResult::CatchupBiReq { heights: c.heights.clone() },
            NodeProto::CatchupAttestation(c) => HandleResult::CatchupAttestationReq { hashes: c.hashes.clone() },
            NodeProto::SpecialBusiness(b) => {
                // TODO: decode business map, sign/verify, respond
                HandleResult::SpecialBusiness { business: b.business.clone() }
            }
            NodeProto::SpecialBusinessReply(b) => {
                // TODO: verify signatures and forward to SpecialMeeting
                HandleResult::SpecialBusinessReply { business: b.business.clone() }
            }
            NodeProto::SolicitEntry(s) => HandleResult::SolicitEntry { hash: s.hash.clone() },
            NodeProto::SolicitEntry2(_) => HandleResult::SolicitEntry2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eetf::{List, Term};

    #[test]
    fn empty_list_produces_empty_vec() {
        // Encode an empty list as ETF manually via eetf types
        let etf = Term::from(List { elements: vec![] });
        let mut buf = Vec::new();
        etf.encode(&mut buf).expect("encode");

        let res = TxPool::parse_and_filter_txs(&buf).expect("ok");
        assert!(res.is_empty());
    }

    #[test]
    fn non_list_errors() {
        // Encode an integer instead of list
        let etf = Term::from(eetf::FixInteger { value: 42 });
        let mut buf = Vec::new();
        etf.encode(&mut buf).expect("encode");

        let err = TxPool::parse_and_filter_txs(&buf).err().unwrap();
        matches!(err, Error::WrongType(_));
    }
}
