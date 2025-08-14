#![allow(dead_code)]

use bs58;
use std::fmt;

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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Entry {
    pub hash: Vec<u8>,       // 32 bytes
    pub header: EntryHeader, // nested decoded header
    pub signature: Vec<u8>,  // 96 bytes
    pub txs: Vec<Vec<u8>>,   // list of tx binaries (can be empty)
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

#[derive(Debug)]
pub struct Peers {
    pub ips: Vec<String>,
}

#[derive(Debug)]
pub struct Sol {
    pub sol: Vec<u8>,
}

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
            .field(
                "mutations_hash",
                &bs58::encode(&self.mutations_hash).into_string(),
            )
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
