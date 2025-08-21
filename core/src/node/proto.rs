use super::handler::HandleExt;
use crate::bic::sol::Solution;
use crate::consensus::DST_NODE;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::consensus::{get_chain_rooted_tip_entry, get_chain_tip_entry};
use crate::consensus::entry::{Entry, EntryHeader};
use crate::consensus::tx;
use crate::metrics;
use crate::misc::bls12_381 as bls;
use crate::misc::reed_solomon::ReedSolomonResource;
use crate::misc::utils::{TermExt, TermMap, bitvec_to_bools, bools_to_bitvec, get_unix_millis_now, get_unix_nanos_now};
use crate::node::handler::Instruction;
use crate::node::msg_v2::MessageV2;
use crate::config;
use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, DecodeError as EtfDecodeError, EncodeError as EtfEncodeError, List, Map, Term};
use miniz_oxide::deflate::{CompressionLevel, compress_to_vec};
use miniz_oxide::inflate::{DecompressError, decompress_to_vec};
use std::collections::HashMap;
use std::io::Error as IoError;
use tracing::{instrument, warn};

/// Every object that has this trait must be convertible from an Erlang ETF
/// binary representation and must be able to handle itself as a message
pub trait ProtoExt
where
    Self: Sized + Into<Proto>,
    Self::Error: Into<Error>,
{
    type Error;
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Self::Error>;
}

#[derive(Debug)]
pub enum Proto {
    Ping(Ping),
    Pong(Pong),
    WhoAreYou(WhoAreYou),
    TxPool(TxPool),
    Peers(Peers),
    Sol(Solution),
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

macro_rules! impl_from {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$ty> for Proto {
                fn from(v: $ty) -> Self {
                    Proto::$variant(v)
                }
            }
        )*
    };
}

impl_from!(
    Ping => Ping,
    Pong => Pong,
    WhoAreYou => WhoAreYou,
    TxPool => TxPool,
    Peers => Peers,
    Solution => Sol,
    Entry => Entry,
    AttestationBulk => AttestationBulk,
    ConsensusBulk => ConsensusBulk,
    CatchupEntry => CatchupEntry,
    CatchupTri => CatchupTri,
    CatchupBi => CatchupBi,
    CatchupAttestation => CatchupAttestation,
    SpecialBusiness => SpecialBusiness,
    SpecialBusinessReply => SpecialBusinessReply,
    SolicitEntry => SolicitEntry,
    SolicitEntry2 => SolicitEntry2,
);

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    EtfDecode(#[from] EtfDecodeError),
    #[error(transparent)]
    EtfEncode(#[from] EtfEncodeError),
    #[error(transparent)]
    Tx(#[from] crate::consensus::tx::Error),
    #[error(transparent)]
    Entry(#[from] crate::consensus::entry::Error),
    #[error(transparent)]
    Sol(#[from] crate::bic::sol::Error),
    #[error(transparent)]
    Att(#[from] crate::consensus::attestation::Error),
    #[error(transparent)]
    ReedSolomon(#[from] crate::misc::reed_solomon::Error),
    #[error(transparent)]
    MsgV2(#[from] crate::node::msg_v2::Error),
    #[error("failed to decompress: {0}")]
    Decompress(DecompressError),
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("wrong type, expected: {0}")]
    WrongType(&'static str),
}

impl From<DecompressError> for Error {
    fn from(e: DecompressError) -> Self {
        Self::Decompress(e)
    }
}

impl Proto {
    #[instrument(skip(bin), name = "Proto::from_etf_validated")]
    pub fn from_etf_validated(bin: &[u8]) -> Result<Proto, Error> {
        Self::from_etf_validated_inner(bin).map_err(|e| {
            crate::metrics::inc_parsing_and_validation_errors();
            e
        })
    }

    pub fn from_etf_validated_inner(bin: &[u8]) -> Result<Proto, Error> {
        let decompressed = decompress_to_vec(bin)?;
        //let term = Term::decode(decompressed.as_slice())?; // decode ETF
        let term = Term::decode(&decompressed[..])?;
        let map = term.get_term_map().ok_or(Error::WrongType("map"))?;

        // `op` determines the variant.
        let op_atom = map.get_atom("op").ok_or(Error::Missing("op"))?;
        match op_atom.name.as_str() {
            "pong" => Pong::from_etf_map_validated(map).map(Into::into),
            "ping" => Ping::from_etf_map_validated(map).map(Into::into),
            "entry" => Entry::from_etf_map_validated(map).map(Into::into).map_err(Into::into),
            "attestation_bulk" => AttestationBulk::from_etf_map_validated(map).map(Into::into).map_err(Into::into),
            "sol" => Solution::from_etf_map_validated(map).map(Into::into).map_err(Into::into),
            "txpool" => TxPool::from_etf_map_validated(map).map(Into::into),
            "peers" => Peers::from_etf_map_validated(map).map(Into::into),
            // Implement following later
            "who_are_you" => Ok(Proto::WhoAreYou(WhoAreYou {})),
            "solicit_entry2" => Ok(Proto::SolicitEntry2(SolicitEntry2 {})),
            _ => {
                warn!("Unknown operation: {}", op_atom.name);
                crate::metrics::inc_unknown_proto();
                Err(Error::WrongType("op"))
            }
        }
    }

    pub fn get_name(&self) -> &'static str {
        match self {
            Proto::Ping(_) => "ping",
            Proto::Pong(_) => "pong",
            Proto::WhoAreYou(_) => "who_are_you",
            Proto::TxPool(_) => "txpool",
            Proto::Peers(_) => "peers",
            Proto::Sol(_) => "sol",
            Proto::Entry(_) => "entry",
            Proto::AttestationBulk(_) => "attestation_bulk",
            Proto::ConsensusBulk(_) => "consensus_bulk",
            Proto::CatchupEntry(_) => "catchup_entry",
            Proto::CatchupTri(_) => "catchup_tri",
            Proto::CatchupBi(_) => "catchup_bi",
            Proto::CatchupAttestation(_) => "catchup_attestation",
            Proto::SpecialBusiness(_) => "special_business",
            Proto::SpecialBusinessReply(_) => "special_business_reply",
            Proto::SolicitEntry(_) => "solicit_entry",
            Proto::SolicitEntry2(_) => "solicit_entry2",
        }
    }
    #[instrument(skip(self), name = "Proto::handle")]
    pub async fn handle(self) -> Result<Instruction, Error> {
        Self::handle_inner(self).await.map_err(|e| {
            crate::metrics::inc_handling_errors();
            e
        })
    }

    pub async fn handle_inner(self) -> Result<Instruction, Error> {
        // Track metrics for this message type
        metrics::inc_handled_counter_by_name(self.get_name());

        match self {
            Proto::Ping(ping) => ping.handle().await,
            Proto::Pong(pong) => pong.handle().await,
            Proto::TxPool(tx_pool) => tx_pool.handle().await,
            Proto::Peers(peers) => peers.handle().await,
            Proto::Sol(sol) => sol.handle().await.map_err(Into::into),
            Proto::Entry(entry) => entry.handle().await.map_err(Into::into),
            Proto::AttestationBulk(att_bulk) => att_bulk.handle().await.map_err(Into::into),
            _ => Ok(Instruction::Noop),
        }
    }
}

#[derive(Debug)]
pub struct Ping {
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
    pub ts_m: u128,
}

/// Shared summary of an entry’s tip.
#[derive(Debug)]
pub struct EntrySummary {
    pub header: EntryHeader,
    pub signature: [u8; 96],
    pub mask: Option<Vec<bool>>,
}

impl From<Entry> for EntrySummary {
    fn from(entry: Entry) -> Self {
        Self { header: entry.header, signature: entry.signature, mask: entry.mask }
    }
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

impl ProtoExt for Ping {
    type Error = Error;

    fn from_etf_map_validated(map: TermMap) -> Result<Self, Self::Error> {
        let temporal_term = map.get_term_map("temporal").ok_or(Error::Missing("temporal"))?;
        let rooted_term = map.get_term_map("rooted").ok_or(Error::Missing("rooted"))?;
        let temporal = EntrySummary::from_etf_term(&temporal_term)?;
        let rooted = EntrySummary::from_etf_term(&rooted_term)?;
        // TODO: validate temporal/rooted signatures and update peer shared secret; broadcast peers
        let ts_m = map.get_integer("ts_m").ok_or(Error::Missing("ts_m"))?;
        Ok(Self { temporal, rooted, ts_m })
    }
}

impl Ping {
    /// Create a new Ping with current timestamp
    pub fn new(temporal: EntrySummary, rooted: EntrySummary) -> Self {
        let ts_m = get_unix_millis_now();

        Self { temporal, rooted, ts_m }
    }

    /// Assemble Ping from current temporal and rooted tips stored in RocksDB.
    /// Equivalent to Elixir NodeProto.ping/0: takes only header, signature, mask for each tip.
    pub fn from_current_tips() -> Result<Self, Error> {
        // Temporal summary
        let temporal = match get_chain_tip_entry() {
            Ok(Some(entry)) => entry.into(),
            _ => return Err(Error::Missing("temporal_tip")),
        };

        // Rooted summary
        let rooted = match get_chain_rooted_tip_entry() {
            Ok(Some(entry)) => entry.into(),
            _ => return Err(Error::Missing("rooted_tip")),
        };

        Ok(Self::new(temporal, rooted))
    }

    /// Convert Ping to ETF binary format
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("ping")));
        m.insert(Term::Atom(Atom::from("temporal")), self.temporal.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("rooted")), self.rooted.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));

        let term = Term::from(Map { map: m });
        let mut out = Vec::new();
        term.encode(&mut out).map_err(Error::EtfEncode)?;
        Ok(out)
    }

    /// Create compressed ETF binary for transmission
    pub fn to_compressed_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let etf_data = self.to_etf_bin()?;
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }

    /// Create a signed MessageV2 from this Ping (single shard)
    pub fn to_message_v2(&self) -> Result<MessageV2, Error> {
        let compressed_payload = self.to_compressed_etf_bin()?;

        // Get signing keys from config
        let pk = config::trainer_pk();
        let sk_seed = config::trainer_sk_seed();

        // Create message metadata
        let ts_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let original_size = compressed_payload.len() as u32;
        let version = "1.1.2".to_string();

        // For single shard (no Reed-Solomon needed)
        let shard_index = 0;
        let shard_total = 2; // Total shards * 2 as per protocol

        // Create message to sign: compressed payload
        let signature =
            bls::sign(&sk_seed, &compressed_payload, DST_NODE).map_err(|_| Error::WrongType("signing_failed"))?;

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
    pub fn to_message_v2_sharded(&self) -> Result<Vec<Vec<u8>>, Error> {
        const MAX_UDP_SIZE: usize = 1300; // ~1.3KB UDP limit
        const HEADER_SIZE: usize = 167; // MessageV2 header size from protocol spec

        let compressed_payload = self.to_compressed_etf_bin()?;

        // Check if we need sharding
        let total_size = HEADER_SIZE + compressed_payload.len();
        if total_size <= MAX_UDP_SIZE {
            // Single packet - no sharding needed
            let msg = self.to_message_v2()?;
            let packet: Vec<u8> = msg.try_into()?;
            return Ok(vec![packet]);
        }

        // Need Reed-Solomon sharding
        let mut rs = ReedSolomonResource::new(4, 4)?; // 4 data + 4 recovery shards
        let shards = rs.encode_shards(&compressed_payload)?;

        // Get signing keys from config
        let pk = config::trainer_pk();
        let sk_seed = config::trainer_sk_seed();

        let ts_nano = get_unix_nanos_now() as u64; // TODO: check if this is fine

        let original_size = compressed_payload.len() as u32;
        let version = "1.1.2".to_string();
        let total_shards = (shards.len() * 2) as u16; // Total shards * 2 as per protocol

        let mut packets = Vec::new();

        // Create a MessageV2 for each shard
        for (shard_index, shard_data) in shards {
            // Sign the shard data
            let signature =
                bls::sign(&sk_seed, &shard_data, DST_NODE).map_err(|_| Error::WrongType("signing_failed"))?;

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

impl EntrySummary {
    /// Helper that reads an EntrySummary from an ETF term.
    fn from_etf_term(map: &TermMap) -> Result<Self, Error> {
        let header_bin: Vec<u8> = map.get_binary("header").ok_or(Error::Missing("header"))?;
        let signature = map.get_binary("signature").ok_or(Error::Missing("signature"))?;
        let mask = map.get_binary("mask").map(bitvec_to_bools);
        let header = EntryHeader::from_etf_bin(&header_bin).map_err(|_| Error::WrongType("header"))?;
        Ok(Self { header, signature, mask })
    }

    /// Convert EntrySummary to ETF term for encoding
    pub fn to_etf_term(&self) -> Result<Term, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("header")), Term::from(Binary { bytes: self.header.to_etf_bin()? }));
        m.insert(Term::Atom(Atom::from("signature")), Term::from(Binary { bytes: self.signature.to_vec() }));
        if let Some(mask) = &self.mask {
            m.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: bools_to_bitvec(mask) }));
        }
        Ok(Term::from(Map { map: m }))
    }
}

impl ProtoExt for Pong {
    type Error = Error;

    fn from_etf_map_validated(map: TermMap) -> Result<Self, Self::Error> {
        let ts_m = map.get_integer("ts_m").ok_or(Error::Missing("ts_m"))?;
        let seen_time_ms = get_unix_millis_now();
        // check what else must be validated
        Ok(Self { ts_m, seen_time_ms })
    }
}

impl ProtoExt for TxPool {
    type Error = Error;

    fn from_etf_map_validated(map: TermMap) -> Result<Self, Self::Error> {
        let txs = map.get_binary("txs_packed").ok_or(Error::Missing("txs_packed"))?;
        let valid_txs = TxPool::get_valid_txs(txs)?;
        Ok(Self { valid_txs })
    }
}

impl TxPool {
    fn get_valid_txs(txs_packed: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let term = Term::decode(txs_packed)?;

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

impl ProtoExt for Peers {
    type Error = Error;

    fn from_etf_map_validated(map: TermMap) -> Result<Self, Self::Error> {
        let list = map.get_list("ips").ok_or(Error::Missing("ips"))?;
        let ips = list
            .iter()
            .map(|t| t.get_string().map(|s| s.to_string()))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::WrongType("ips"))?;
        Ok(Self { ips })
    }
}
