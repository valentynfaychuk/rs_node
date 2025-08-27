use crate::bic::sol;
use crate::bic::sol::Solution;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::consensus::{get_chain_rooted_tip_entry, get_chain_tip_entry};
use crate::consensus::entry::{Entry, EntrySummary};
use crate::consensus::tx;
use crate::consensus::{DST_NODE, attestation, entry};
use crate::node::msg_v2;
use crate::node::msg_v2::MessageV2;
use crate::utils::misc::Typename;
use crate::utils::misc::{TermExt, TermMap, get_unix_millis_now, get_unix_nanos_now};
use crate::utils::reed_solomon::ReedSolomonResource;
use crate::utils::{bls12_381 as bls, reed_solomon};
use crate::{Context, config};
use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, DecodeError as EtfDecodeError, EncodeError as EtfEncodeError, List, Map, Term};
use miniz_oxide::deflate::{CompressionLevel, compress_to_vec};
use miniz_oxide::inflate::{DecompressError, decompress_to_vec};
use std::collections::HashMap;
use std::io::Error as IoError;
use tracing::{instrument, warn};

/// Every object that has this trait must be convertible from an Erlang ETF
/// Binary representation and must be able to handle itself as a message
#[async_trait::async_trait]
pub trait Protocol: Typename + Send + Sync {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error>
    where
        Self: Sized;
    /// Handle a message returning instructions for upper layers
    #[instrument(skip(self, ctx), fields(proto = %self.typename()), name = "Proto::handle")]
    async fn handle(&self, ctx: &Context) -> Result<Instruction, Error> {
        ctx.metrics.add_handled_proto_by_name(self.typename());
        self.handle_inner().await.inspect_err(|e| ctx.metrics.add_error(e))
    }
    async fn handle_inner(&self) -> Result<Instruction, Error>;
}

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    EtfDecode(#[from] EtfDecodeError),
    #[error(transparent)]
    EtfEncode(#[from] EtfEncodeError),
    #[error(transparent)]
    Tx(#[from] tx::Error),
    #[error(transparent)]
    Entry(#[from] entry::Error),
    #[error(transparent)]
    Sol(#[from] sol::Error),
    #[error(transparent)]
    Att(#[from] attestation::Error),
    #[error(transparent)]
    ReedSolomon(#[from] reed_solomon::Error),
    #[error(transparent)]
    MsgV2(#[from] msg_v2::Error),
    #[error("failed to decompress: {0}")]
    Decompress(DecompressError),
    #[error("bad etf: {0}")]
    BadEtf(&'static str),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

impl From<DecompressError> for Error {
    fn from(e: DecompressError) -> Self {
        Self::Decompress(e)
    }
}

/// Result of handling an incoming message.
#[derive(Debug)]
pub enum Instruction {
    Noop,
    ReplyPong { ts_m: u128 },
    ObservedPong { ts_m: u128, seen_time_ms: u128 },
    ValidTxs { txs: Vec<Vec<u8>> },
    Peers { ips: Vec<String> },
    ReceivedSol { sol: Solution },
    ReceivedEntry { entry: Entry },
    AttestationBulk { bulk: AttestationBulk },
    ConsensusesPacked { packed: Vec<u8> },
    CatchupEntryReq { heights: Vec<u64> },
    CatchupTriReq { heights: Vec<u64> },
    CatchupBiReq { heights: Vec<u64> },
    CatchupAttestationReq { hashes: Vec<Vec<u8>> },
    SpecialBusiness { business: Vec<u8> },
    SpecialBusinessReply { business: Vec<u8> },
    SolicitEntry { hash: Vec<u8> },
    SolicitEntry2,
}

/// Does proto parsing and validation
#[instrument(skip(bin), name = "Proto::from_etf_validated")]
pub fn from_etf_bin(bin: &[u8]) -> Result<Box<dyn Protocol>, Error> {
    let decompressed = decompress_to_vec(bin)?;
    let term = Term::decode(decompressed.as_slice())?;
    let map = term.get_term_map().ok_or(Error::BadEtf("map"))?;

    // `op` determines the variant
    let op_atom = map.get_atom("op").ok_or(Error::BadEtf("op"))?;
    let proto: Box<dyn Protocol> = match op_atom.name.as_str() {
        Ping::NAME => Box::new(Ping::from_etf_map_validated(map)?),
        Pong::NAME => Box::new(Pong::from_etf_map_validated(map)?),
        Entry::NAME => Box::new(Entry::from_etf_map_validated(map)?),
        AttestationBulk::NAME => Box::new(AttestationBulk::from_etf_map_validated(map)?),
        Solution::NAME => Box::new(Solution::from_etf_map_validated(map)?),
        TxPool::NAME => Box::new(TxPool::from_etf_map_validated(map)?),
        Peers::NAME => Box::new(Peers::from_etf_map_validated(map)?),
        _ => {
            warn!("Unknown operation: {}", op_atom.name);
            return Err(Error::BadEtf("op"));
        }
    };

    Ok(proto)
}

#[derive(Debug)]
pub struct Ping {
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
    pub ts_m: u128,
}

#[derive(Debug)]
pub struct Pong {
    pub ts_m: u128,
    pub seen_time_ms: u128,
}

#[derive(Debug)]
pub struct WhoAreYou;

#[derive(Debug)]
pub struct TxPool {
    pub valid_txs: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct Peers {
    pub ips: Vec<String>,
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

impl Typename for Ping {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for Ping {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let temporal_term = map.get_term_map("temporal").ok_or(Error::BadEtf("temporal"))?;
        let rooted_term = map.get_term_map("rooted").ok_or(Error::BadEtf("rooted"))?;
        let temporal = EntrySummary::from_etf_term(&temporal_term)?;
        let rooted = EntrySummary::from_etf_term(&rooted_term)?;
        // TODO: validate temporal/rooted signatures and update peer shared secret, broadcast peers
        let ts_m = map.get_integer("ts_m").ok_or(Error::BadEtf("ts_m"))?;
        Ok(Self { temporal, rooted, ts_m })
    }
    async fn handle_inner(&self) -> Result<Instruction, Error> {
        Ok(Instruction::ReplyPong { ts_m: self.ts_m })
    }
}

impl Ping {
    pub const NAME: &'static str = "ping";
    /// Create a new Ping with current timestamp
    pub fn new(temporal: EntrySummary, rooted: EntrySummary) -> Self {
        let ts_m = get_unix_millis_now();

        Self { temporal, rooted, ts_m }
    }

    /// Assemble Ping from current temporal and rooted tips stored in RocksDB
    /// Takes only header, signature, mask for each tip
    pub fn from_current_tips() -> Result<Self, Error> {
        // temporal summary
        let temporal = match get_chain_tip_entry() {
            Ok(Some(entry)) => entry.into(),
            _ => return Err(Error::BadEtf("temporal_tip")),
        };

        // rooted summary
        let rooted = match get_chain_rooted_tip_entry() {
            Ok(Some(entry)) => entry.into(),
            _ => return Err(Error::BadEtf("rooted_tip")),
        };

        Ok(Self::new(temporal, rooted))
    }

    pub fn to_msg_v2(&self, config: &config::Config) -> Result<MessageV2, Error> {
        // create a MessageV2 from this Ping
        let compressed_payload = self.to_compressed_etf_bin()?;

        // get signing keys from config
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();

        // create message metadata
        let ts_nano = get_unix_nanos_now() as u64;

        let original_size = compressed_payload.len() as u32;
        let version = "1.1.2".to_string();

        // for single shard (no Reed-Solomon needed)
        let shard_index = 0;
        let shard_total = 2; // total shards * 2 as per protocol

        // create message to sign: compressed payload
        let signature =
            bls::sign(&trainer_sk, &compressed_payload, DST_NODE).map_err(|_| Error::BadEtf("signing_failed"))?;

        Ok(MessageV2 {
            version,
            pk,
            signature,
            shard_index,
            shard_total,
            ts_nano,
            original_size,
            payload: compressed_payload,
        })
    }

    /// Convert Ping to ETF binary format (compressed, symmetric with from_etf_bin)
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("ping")));
        m.insert(Term::Atom(Atom::from("temporal")), self.temporal.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("rooted")), self.rooted.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }

    /// Create compressed ETF binary for transmission (same as to_etf_bin now)
    pub fn to_compressed_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // to_etf_bin now returns compressed data, so this is the same
        self.to_etf_bin()
    }

    /// Create a signed MessageV2 from this Ping (single shard)
    pub fn to_message_v2(&self, config: &config::Config) -> Result<MessageV2, Error> {
        let compressed_payload = self.to_compressed_etf_bin()?;

        // get signing keys from config
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();

        // create message metadata
        let ts_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let original_size = compressed_payload.len() as u32;
        let version = "1.1.2".to_string();

        // for single shard (no Reed-Solomon needed)
        let shard_index = 0;
        let shard_total = 2; // total shards * 2 as per protocol

        // create message to sign: compressed payload
        let signature =
            bls::sign(&trainer_sk, &compressed_payload, DST_NODE).map_err(|_| Error::BadEtf("signing_failed"))?;

        Ok(MessageV2 {
            version,
            pk,
            signature,
            shard_index,
            shard_total,
            ts_nano,
            original_size,
            payload: compressed_payload,
        })
    }

    /// Create multiple signed MessageV2 packets with Reed-Solomon sharding for large payloads
    pub fn to_message_v2_sharded(&self, config: &config::Config) -> Result<Vec<Vec<u8>>, Error> {
        const MAX_UDP_SIZE: usize = 1300; // ~1.3KB UDP limit
        const HEADER_SIZE: usize = 167; // messagev2 header size from protocol spec

        let compressed_payload = self.to_compressed_etf_bin()?;

        // check if we need sharding
        let total_size = HEADER_SIZE + compressed_payload.len();
        if total_size <= MAX_UDP_SIZE {
            // single packet - no sharding needed
            let msg = self.to_message_v2(config)?;
            let packet: Vec<u8> = msg.try_into()?;
            return Ok(vec![packet]);
        }

        // need Reed-Solomon sharding
        let mut rs = ReedSolomonResource::new(4, 4)?; // 4 data + 4 recovery shards
        let shards = rs.encode_shards(&compressed_payload)?;

        // get signing keys from config
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();

        let ts_nano = get_unix_nanos_now() as u64; // TODO: check if this is fine

        let original_size = compressed_payload.len() as u32;
        let version = "1.1.2".to_string();
        let total_shards = (shards.len() * 2) as u16; // total shards * 2 as per protocol

        let mut packets = Vec::new();

        // create a MessageV2 for each shard
        for (shard_index, shard_data) in shards {
            // sign the shard data
            let signature =
                bls::sign(&trainer_sk, &shard_data, DST_NODE).map_err(|_| Error::BadEtf("signing_failed"))?;

            let msg = MessageV2 {
                version: version.clone(),
                pk,
                signature,
                shard_index: shard_index as u16,
                shard_total: total_shards,
                ts_nano,
                original_size,
                payload: shard_data,
            };

            let packet: Vec<u8> = msg.try_into()?;
            packets.push(packet);
        }

        Ok(packets)
    }
}

impl Typename for Pong {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for Pong {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let ts_m = map.get_integer("ts_m").ok_or(Error::BadEtf("ts_m"))?;
        let seen_time_ms = get_unix_millis_now();
        // check what else must be validated
        Ok(Self { ts_m, seen_time_ms })
    }

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // TODO: update ETS-like peer table with latency now_ms - p.ts_m
        Ok(Instruction::Noop)
    }
}

impl Pong {
    pub const NAME: &'static str = "pong";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }
}

impl Typename for TxPool {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for TxPool {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let txs = map.get_binary("txs_packed").ok_or(Error::BadEtf("txs_packed"))?;
        let valid_txs = TxPool::get_valid_txs(txs)?;
        Ok(Self { valid_txs })
    }

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(Instruction::Noop)
    }
}

impl TxPool {
    pub const NAME: &'static str = "txpool";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // create list of transaction binaries
        let tx_terms: Vec<Term> = self.valid_txs.iter().map(|tx| Term::from(Binary { bytes: tx.clone() })).collect();

        let txs_list = Term::from(List { elements: tx_terms });

        // encode the list to binary for txs_packed field
        let mut txs_packed = Vec::new();
        txs_list.encode(&mut txs_packed).map_err(Error::EtfEncode)?;

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("txs_packed")), Term::from(Binary { bytes: txs_packed }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }

    fn get_valid_txs(txs_packed: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let term = Term::decode(txs_packed)?;

        let list = if let Some(l) = TryAsRef::<List>::try_as_ref(&term) {
            &l.elements
        } else {
            return Err(Error::BadEtf("txs_packed must be list"));
        };

        let mut good: Vec<Vec<u8>> = Vec::with_capacity(list.len());

        for t in list {
            // each item must be a binary
            let bin = if let Some(b) = TryAsRef::<Binary>::try_as_ref(t) {
                b.bytes.as_slice()
            } else {
                // skip non-binary entries silently
                continue;
            };

            // validate basic tx rules, special-meeting context is false in gossip path
            if tx::validate(bin, false).is_ok() {
                good.push(bin.to_vec());
            }
        }

        Ok(good)
    }
}

impl Typename for Peers {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for Peers {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let list = map.get_list("ips").ok_or(Error::BadEtf("ips"))?;
        let ips = list
            .iter()
            .map(|t| t.get_string().map(|s| s.to_string()))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::BadEtf("ips"))?;
        Ok(Self { ips })
    }

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // TODO: update ETS-like peer table with new IPs
        Ok(Instruction::Noop)
    }
}

impl Peers {
    pub const NAME: &'static str = "peers";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // create list of IP strings
        let ip_terms: Vec<Term> =
            self.ips.iter().map(|ip| Term::from(Binary { bytes: ip.as_bytes().to_vec() })).collect();

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("ips")), Term::from(List { elements: ip_terms }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::entry::{EntryHeader, EntrySummary};

    #[tokio::test]
    async fn test_ping_etf_roundtrip() {
        // create a sample ping message
        let temporal = create_dummy_entry_summary();
        let rooted = create_dummy_entry_summary();
        let ping = Ping::new(temporal, rooted);

        // serialize to ETF (now compressed by default)
        let compressed_bin = ping.to_etf_bin().expect("should serialize");

        // deserialize back
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_etf_roundtrip() {
        let pong = Pong { ts_m: 1234567890, seen_time_ms: 9876543210 };

        let compressed_bin = pong.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        // check that the result type is Pong
        assert_eq!(result.typename(), "pong");
    }

    #[tokio::test]
    async fn test_txpool_etf_roundtrip() {
        let txpool = TxPool { valid_txs: vec![vec![1, 2, 3], vec![4, 5, 6]] };

        let compressed_bin = txpool.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        assert_eq!(result.typename(), "txpool");
    }

    #[tokio::test]
    async fn test_peers_etf_roundtrip() {
        let peers = Peers { ips: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()] };

        let compressed_bin = peers.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        assert_eq!(result.typename(), "peers");
    }

    fn create_dummy_entry_summary() -> EntrySummary {
        let header = EntryHeader {
            height: 1,
            slot: 1,
            prev_slot: 0,
            prev_hash: [0u8; 32],
            dr: [1u8; 32],
            vr: [2u8; 96],
            signer: [3u8; 48],
            txs_hash: [4u8; 32],
        };

        EntrySummary { header, signature: [5u8; 96], mask: None }
    }
}
