#![allow(dead_code)]

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

#[derive(Debug)]
pub struct Entry {
    pub entry_packed: Vec<u8>,
    pub attestation_packed: Option<Vec<u8>>,
    pub consensus_packed: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Attestation {
    pub entry_hash: Vec<u8>,     // 32 bytes
    pub mutations_hash: Vec<u8>, // 32 bytes
    pub signature: Vec<u8>,      // 96 bytes
    pub signer: Vec<u8>,         // 48 bytes
}

#[derive(Debug, Clone)]
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
    pub signature: Vec<u8>,
    pub shard_index: u16,
    pub shard_total: u16,
    pub ts_nano: u64,
    pub original_size: u32,
    pub payload: Vec<u8>,
}
