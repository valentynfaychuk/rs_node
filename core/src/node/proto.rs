use super::handler::HandleExt;
use crate::bic::sol::Solution;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::entry::Entry;
use crate::consensus::tx;
use crate::metrics;
use crate::misc::utils::{TermExt, get_map_field};
use crate::node::handler::Instruction;
use eetf::convert::TryAsRef;
use eetf::{Binary, DecodeError as EtfDecodeError, List, Term};
use miniz_oxide::inflate::{DecompressError, decompress_to_vec};
use std::collections::HashMap;
use std::io::Error as IoError;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{instrument, warn};

/// Every object that has this trait must be convertible from an Erlang ETF
/// binary representation and must be able to handle itself as a message
pub trait ProtoExt
where
    Self: Sized + Into<Proto>,
    Self::Error: Into<Error>,
{
    type Error;
    fn from_etf_map_validated(map: HashMap<Term, Term>) -> Result<Self, Self::Error>;
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
    Tx(#[from] crate::consensus::tx::Error),
    #[error(transparent)]
    Entry(#[from] crate::consensus::entry::Error),
    #[error(transparent)]
    Sol(#[from] crate::bic::sol::Error),
    #[error(transparent)]
    Att(#[from] crate::consensus::attestation::Error),
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
        let map = term.get_map().ok_or(Error::WrongType("map"))?;

        // `op` determines the variant.
        let op_atom = get_map_field(&map, "op").and_then(|t| t.as_atom()).ok_or(Error::Missing("op"))?;
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
    pub fn handle(self) -> Result<Instruction, Error> {
        Self::handle_inner(self).map_err(|e| {
            crate::metrics::inc_handling_errors();
            e
        })
    }

    pub fn handle_inner(self) -> Result<Instruction, Error> {
        // Track metrics for this message type
        metrics::inc_handled_counter_by_name(self.get_name());

        match self {
            Proto::Ping(ping) => ping.handle(),
            Proto::Pong(pong) => pong.handle(),
            Proto::TxPool(tx_pool) => tx_pool.handle(),
            Proto::Peers(peers) => peers.handle(),
            Proto::Sol(sol) => sol.handle().map_err(Into::into),
            Proto::Entry(entry) => entry.handle().map_err(Into::into),
            Proto::AttestationBulk(att_bulk) => att_bulk.handle().map_err(Into::into),
            _ => Ok(Instruction::Noop),
        }
    }
}

#[derive(Debug)]
pub struct Ping {
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
    pub ts_m: i64,
}

/// Shared summary of an entry’s tip.
#[derive(Debug)]
pub struct EntrySummary {
    pub header: Vec<u8>,
    pub signature: Vec<u8>,
    pub mask: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Pong {
    pub ts_m: i64,
    pub seen_time_ms: i64,
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

    fn from_etf_map_validated(map: HashMap<Term, Term>) -> Result<Self, Self::Error> {
        let temporal_term = get_map_field(&map, "temporal").ok_or(Error::Missing("temporal"))?;
        let rooted_term = get_map_field(&map, "rooted").ok_or(Error::Missing("rooted"))?;
        let temporal = EntrySummary::from_etf_term(temporal_term)?;
        let rooted = EntrySummary::from_etf_term(rooted_term)?;
        // TODO: validate temporal/rooted signatures and update peer shared secret; broadcast peers
        let ts_m = get_map_field(&map, "ts_m").ok_or(Error::Missing("ts_m"))?;
        let ts_m = ts_m.get_integer().ok_or(Error::WrongType("ts_m"))?;
        Ok(Self { temporal, rooted, ts_m })
    }
}

impl EntrySummary {
    /// Helper that reads an EntrySummary from an ETF term.
    fn from_etf_term(term: &Term) -> Result<Self, Error> {
        let map = term.get_map().ok_or(Error::WrongType("EntrySummary"))?;
        let header = get_map_field(&map, "header").and_then(|t| t.get_binary()).ok_or(Error::Missing("header"))?;
        let signature =
            get_map_field(&map, "signature").and_then(|t| t.get_binary()).ok_or(Error::Missing("signature"))?;
        let mask = get_map_field(&map, "mask").and_then(|t| t.get_binary()).map(|b| b.to_vec());
        Ok(Self { header: header.to_vec(), signature: signature.to_vec(), mask })
    }
}

impl ProtoExt for Pong {
    type Error = Error;

    fn from_etf_map_validated(map: HashMap<Term, Term>) -> Result<Self, Self::Error> {
        let ts_m = get_map_field(&map, "ts_m").ok_or(Error::Missing("ts_m"))?;
        let ts_m = ts_m.get_integer().ok_or(Error::WrongType("ts_m"))?;
        let seen_time_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        // check what else must be validated
        Ok(Self { ts_m, seen_time_ms })
    }
}

impl ProtoExt for TxPool {
    type Error = Error;

    fn from_etf_map_validated(map: HashMap<Term, Term>) -> Result<Self, Self::Error> {
        let txs = get_map_field(&map, "txs_packed").and_then(|t| t.get_binary()).ok_or(Error::Missing("txs_packed"))?;
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

    fn from_etf_map_validated(map: HashMap<Term, Term>) -> Result<Self, Self::Error> {
        let list = get_map_field(&map, "ips").and_then(|t| t.get_list()).ok_or(Error::Missing("ips"))?;
        let ips = list
            .iter()
            .map(|t| t.get_string().map(|s| s.to_string()))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::WrongType("ips"))?;
        Ok(Self { ips })
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
        let mut bin = Vec::new();
        etf.encode(&mut bin).expect("encode");

        let res = TxPool::get_valid_txs(&bin).expect("ok");
        assert!(res.is_empty());
    }

    #[test]
    fn non_list_errors() {
        // Encode an integer instead of list
        let etf = Term::from(eetf::FixInteger { value: 42 });
        let mut bin = Vec::new();
        etf.encode(&mut bin).expect("encode");

        let err = TxPool::get_valid_txs(&bin).err().unwrap();
        matches!(err, Error::WrongType(_));
    }
}
