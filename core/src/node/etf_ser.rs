use super::proto::*;
use crate::bic::sol::Error as SolError;
use crate::bic::sol::Solution;
use crate::config::ENTRY_SIZE;
use crate::consensus::entry::Entry;
use crate::consensus::entry::Error as EntryError;
use crate::consensus::tx::Error as TxError;
use eetf::convert::TryAsRef;
use eetf::{Atom, DecodeError, Term};
use eetf::{Binary, List};
use miniz_oxide::inflate::{DecompressError, decompress_to_vec};
use num_traits::ToPrimitive;
use std::collections::HashMap;
use std::io::Error as IoError;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    EtfDecode(#[from] DecodeError),
    #[error(transparent)]
    Tx(#[from] TxError),
    #[error(transparent)]
    Entry(#[from] EntryError),
    #[error(transparent)]
    Sol(#[from] SolError),
    #[error("failed to decompress: {0}")]
    Decompress(DecompressError),
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("wrong type, expected: {0}")]
    WrongType(&'static str),
}

impl From<DecompressError> for Error {
    fn from(e: DecompressError) -> Self {
        Error::Decompress(e)
    }
}

/// Top-level message enumeration.
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

impl TryFrom<&[u8]> for Proto {
    type Error = Error;
    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        let decompressed = decompress_to_vec(bin)?;
        let term = Term::decode(&decompressed[..])?; // decode ETF

        // Turn the ETF map into a real HashMap so `.get()` works
        let map = match term {
            Term::Map(m) => m.map.clone(),
            _ => return Err(Error::WrongType("map")),
        };

        // `op` determines the variant.
        let op_atom = map.get(&Term::Atom(Atom::from("op"))).and_then(|t| t.as_atom()).ok_or(Error::Missing("op"))?;

        match op_atom.name.as_str() {
            "ping" => {
                let temporal_term = map.get(&Term::Atom(Atom::from("temporal"))).ok_or(Error::Missing("temporal"))?;
                let rooted_term = map.get(&Term::Atom(Atom::from("rooted"))).ok_or(Error::Missing("rooted"))?;
                let (temporal, rooted) = (EntrySummary::try_from(temporal_term)?, EntrySummary::try_from(rooted_term)?);
                let ts_m = map.get(&Term::Atom(Atom::from("ts_m"))).ok_or(Error::Missing("ts_m"))?;
                let ts_m = ts_m.get_integer().ok_or(Error::WrongType("ts_m"))?;

                Ok(Proto::Ping(Ping { temporal, rooted, ts_m }))
            }
            "pong" => {
                let ts_m = map.get(&Term::Atom(Atom::from("ts_m"))).ok_or(Error::Missing("ts_m"))?;
                let ts_m = ts_m.get_integer().ok_or(Error::WrongType("ts_m"))?;

                Ok(Proto::Pong(Pong { ts_m }))
            }
            "entry" => {
                let bin = map
                    .get(&Term::Atom(Atom::from("entry_packed")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("entry_packed"))?;

                let entry = Entry::new(bin, ENTRY_SIZE)?;
                Ok(Proto::Entry(entry))
            }
            "sol" => {
                let bin = map
                    .get(&Term::Atom(Atom::from("sol")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("sol"))?;
                let sol = Solution::new(bin)?;
                Ok(Proto::Sol(sol))
            }
            "who_are_you" => Ok(Proto::WhoAreYou(WhoAreYou)),
            "txpool" => {
                let txs = map
                    .get(&Term::Atom(Atom::from("txs_packed")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("txs_packed"))?;
                Ok(Proto::TxPool(TxPool { txs_packed: txs.to_vec() }))
            }
            "peers" => {
                let list =
                    map.get(&Term::Atom(Atom::from("ips"))).and_then(|t| t.get_list()).ok_or(Error::Missing("ips"))?;
                let ips = list
                    .iter()
                    .map(|t| t.get_string().map(|s| s.to_string()))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Error::WrongType("ips"))?;

                Ok(Proto::Peers(Peers { ips }))
            }
            "solicit_entry2" => Ok(Proto::SolicitEntry2(SolicitEntry2)),
            "attestation_bulk" => {
                let list = map
                    .get(&Term::Atom(Atom::from("attestations_packed")))
                    .and_then(|t| t.get_list())
                    .ok_or(Error::Missing("attestations_packed"))?;

                let mut attestations = Vec::with_capacity(list.len());
                for item in list {
                    let bin = item.get_binary().ok_or(Error::WrongType("attestations_packed:binary"))?;
                    attestations.push(Attestation::try_from(bin)?);
                }

                Ok(Proto::AttestationBulk(AttestationBulk { attestations }))
            }
            _ => {
                println!("{:?}", &map);
                Err(Error::WrongType("op"))
            }
        }
    }
}

impl Proto {
    /// Returns the operation name for this message.
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
}

impl TryFrom<&Term> for EntrySummary {
    type Error = Error;
    /// Helper that reads an EntrySummary from an ETF term.
    fn try_from(term: &Term) -> Result<Self, Error> {
        let map = term.get_map().ok_or(Error::WrongType("EntrySummary"))?;

        let header =
            map.get(&Term::Atom(Atom::from("header"))).and_then(|t| t.get_binary()).ok_or(Error::Missing("header"))?;
        let signature = map
            .get(&Term::Atom(Atom::from("signature")))
            .and_then(|t| t.get_binary())
            .ok_or(Error::Missing("signature"))?;

        let mask = map.get(&Term::Atom(Atom::from("mask"))).and_then(|t| t.get_binary()).map(|b| b.to_vec());

        Ok(Self { header: header.to_vec(), signature: signature.to_vec(), mask })
    }
}

impl TryFrom<&[u8]> for Attestation {
    type Error = Error;
    /// Helper that reads an EntrySummary from an ETF term.
    fn try_from(bin: &[u8]) -> Result<Self, Error> {
        let map = Term::decode(bin)?.get_map().ok_or(Error::WrongType("Attestation"))?;
        //let map = term.get_map().ok_or(Error::WrongType("Attestation"))?;

        let entry_hash = map
            .get(&Term::Atom(Atom::from("entry_hash")))
            .and_then(|t| t.get_binary())
            .ok_or(Error::Missing("entry_hash"))?
            .to_vec();

        let mutations_hash = map
            .get(&Term::Atom(Atom::from("mutations_hash")))
            .and_then(|t| t.get_binary())
            .ok_or(Error::Missing("mutations_hash"))?
            .to_vec();

        let signature = map
            .get(&Term::Atom(Atom::from("signature")))
            .and_then(|t| t.get_binary())
            .ok_or(Error::Missing("signature"))?
            .to_vec();

        let signer = map
            .get(&Term::Atom(Atom::from("signer")))
            .and_then(|t| t.get_binary())
            .ok_or(Error::Missing("signer"))?
            .to_vec();

        Ok(Self { entry_hash, mutations_hash, signature, signer })
    }
}

/// Lightweight helpers so you can keep calling `.atom()`, `.integer()`, etc.
pub trait TermExt {
    fn as_atom(&self) -> Option<&Atom>;
    fn get_integer(&self) -> Option<i64>;
    fn get_binary(&self) -> Option<&[u8]>;
    fn get_list(&self) -> Option<&[Term]>;
    fn get_string(&self) -> Option<String>;
    fn get_map(&self) -> Option<HashMap<Term, Term>>;
}

impl TermExt for Term {
    fn as_atom(&self) -> Option<&Atom> {
        TryAsRef::<Atom>::try_as_ref(self)
    }

    fn get_integer(&self) -> Option<i64> {
        match self {
            Term::FixInteger(i) => Some(i.value as i64),
            Term::BigInteger(bi) => bi.value.to_i64(),
            _ => None,
        }
    }

    fn get_binary(&self) -> Option<&[u8]> {
        TryAsRef::<Binary>::try_as_ref(self).map(|b| b.bytes.as_slice())
    }

    fn get_list(&self) -> Option<&[Term]> {
        TryAsRef::<List>::try_as_ref(self).map(|l| l.elements.as_slice())
    }

    fn get_string(&self) -> Option<String> {
        // Erlang strings come across either as ByteList or Binary
        if let Term::ByteList(bl) = self {
            std::str::from_utf8(&bl.bytes).ok().map(|s| s.to_owned())
        } else if let Term::Binary(b) = self {
            std::str::from_utf8(&b.bytes).ok().map(|s| s.to_owned())
        } else if let Term::Atom(a) = self {
            Some(a.name.clone())
        } else {
            None
        }
    }

    fn get_map(&self) -> Option<HashMap<Term, Term>> {
        match self {
            Term::Map(m) => Some(m.map.clone()),
            _ => None,
        }
    }
}

pub fn get_map_field<'a>(map: &'a HashMap<Term, Term>, key: &str) -> Option<&'a Term> {
    map.get(&Term::Atom(Atom::from(key)))
}
