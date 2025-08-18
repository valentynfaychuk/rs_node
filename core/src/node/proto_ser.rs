use super::proto::*;
use eetf::convert::TryAsRef;
use eetf::{Atom, Term};
use num_traits::ToPrimitive;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    TxError(#[from] crate::consensus::tx::Error),
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("wrong type, expected: {0}")]
    WrongType(&'static str),
}

use miniz_oxide::inflate::decompress_to_vec;

pub fn deflate_decompress(compressed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    decompress_to_vec(compressed).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))
}

pub fn map_term_to_map(term: &Term) -> Result<std::collections::HashMap<Term, Term>, Error> {
    match term {
        Term::Map(m) => Ok(m.map.clone()),
        _ => Err(Error::WrongType("map")),
    }
}

fn parse_attestation_from_bin(bin: &[u8]) -> Result<Attestation, Error> {
    let t = Term::decode(bin)?; // nested ETF
    let m = map_term_to_map(&t)?; // as HashMap<Term, Term>

    let entry_hash = m
        .get(&Term::Atom(Atom::from("entry_hash")))
        .and_then(|t| t.binary())
        .ok_or(Error::Missing("entry_hash"))?
        .to_vec();

    let mutations_hash = m
        .get(&Term::Atom(Atom::from("mutations_hash")))
        .and_then(|t| t.binary())
        .ok_or(Error::Missing("mutations_hash"))?
        .to_vec();

    let signature = m
        .get(&Term::Atom(Atom::from("signature")))
        .and_then(|t| t.binary())
        .ok_or(Error::Missing("signature"))?
        .to_vec();

    let signer =
        m.get(&Term::Atom(Atom::from("signer"))).and_then(|t| t.binary()).ok_or(Error::Missing("signer"))?.to_vec();

    Ok(Attestation { entry_hash, mutations_hash, signature, signer })
}
/// Parse any NodeProto message.
pub fn parse_nodeproto(buf: &[u8]) -> Result<NodeProto, Error> {
    let decompressed = deflate_decompress(buf)?;
    let term = Term::decode(&decompressed[..])?; // decode ETF

    // Turn the ETF map into a real HashMap so `.get()` works
    let map = match term {
        Term::Map(m) => m.map.clone(),
        _ => return Err(Error::WrongType("map")),
    };

    // `op` determines the variant.
    let op_atom = map.get(&Term::Atom(Atom::from("op"))).and_then(|t| t.atom()).ok_or(Error::Missing("op"))?;

    match op_atom.name.as_str() {
        "ping" => {
            let temporal = parse_entry_summary(map.get(&Term::Atom(Atom::from("temporal"))))?;
            let rooted = parse_entry_summary(map.get(&Term::Atom(Atom::from("rooted"))))?;
            let ts_m =
                map.get(&Term::Atom(Atom::from("ts_m"))).and_then(|t| t.integer()).ok_or(Error::Missing("ts_m"))?;
            Ok(NodeProto::Ping(Ping { temporal, rooted, ts_m }))
        }
        "pong" => {
            let ts_m =
                map.get(&Term::Atom(Atom::from("ts_m"))).and_then(|t| t.integer()).ok_or(Error::Missing("ts_m"))?;
            Ok(NodeProto::Pong(Pong { ts_m }))
        }
        "entry" => {
            let bin = map
                .get(&Term::Atom(Atom::from("entry_packed")))
                .and_then(|t| t.binary())
                .ok_or(Error::Missing("entry_packed"))?;

            let entry = unpack_entry_and_validate(bin, ENTRY_SIZE).map_err(Into::<Error>::into)?;
            Ok(NodeProto::Entry(entry))
        }
        "who_are_you" => Ok(NodeProto::WhoAreYou(WhoAreYou)),
        "txpool" => {
            let txs = map
                .get(&Term::Atom(Atom::from("txs_packed")))
                .and_then(|t| t.binary())
                .ok_or(Error::Missing("txs_packed"))?;
            Ok(NodeProto::TxPool(TxPool { txs_packed: txs.to_vec() }))
        }
        "peers" => {
            let list = map.get(&Term::Atom(Atom::from("ips"))).and_then(|t| t.list()).ok_or(Error::Missing("ips"))?;
            let ips = list
                .iter()
                .map(|t| t.string().map(|s| s.to_string()))
                .collect::<Option<Vec<_>>>()
                .ok_or(Error::WrongType("ips"))?;
            Ok(NodeProto::Peers(Peers { ips }))
        }
        "solicit_entry2" => Ok(NodeProto::SolicitEntry2(SolicitEntry2)),
        "attestation_bulk" => {
            let list = map
                .get(&Term::Atom(Atom::from("attestations_packed")))
                .and_then(|t| t.list())
                .ok_or(Error::Missing("attestations_packed"))?;

            let mut attestations = Vec::with_capacity(list.len());
            for item in list {
                let bin = item.binary().ok_or(Error::WrongType("attestations_packed:binary"))?;
                let att = parse_attestation_from_bin(bin)?;
                attestations.push(att);
            }

            Ok(NodeProto::AttestationBulk(AttestationBulk { attestations }))
        }
        _ => {
            println!("{:?}", &map);
            Err(Error::WrongType("op"))
        }
    }
}

/// Helper that reads an EntrySummary from an ETF term.
fn parse_entry_summary(term: Option<&Term>) -> Result<EntrySummary, Error> {
    let map = match term {
        Some(Term::Map(m)) => m.map.clone(), // borrow the vec
        _ => return Err(Error::WrongType("EntrySummary")),
    };

    let header = map.get(&Term::Atom(Atom::from("header"))).and_then(|t| t.binary()).ok_or(Error::Missing("header"))?;
    let signature =
        map.get(&Term::Atom(Atom::from("signature"))).and_then(|t| t.binary()).ok_or(Error::Missing("signature"))?;

    let mask = map.get(&Term::Atom(Atom::from("mask"))).and_then(|t| t.binary()).map(|b| b.to_vec());

    Ok(EntrySummary { header: header.to_vec(), signature: signature.to_vec(), mask })
}

use crate::config::ENTRY_SIZE;
use crate::consensus::entry::unpack_entry_and_validate;
use eetf::{Binary, List};

/// Lightweight helpers so you can keep calling `.atom()`, `.integer()`, etc.
pub trait TermExt {
    fn atom(&self) -> Option<&Atom>;
    fn integer(&self) -> Option<i64>;
    fn binary(&self) -> Option<&[u8]>;
    fn list(&self) -> Option<&[Term]>;
    fn string(&self) -> Option<String>;
}

impl TermExt for Term {
    fn atom(&self) -> Option<&Atom> {
        TryAsRef::<Atom>::try_as_ref(self)
    }

    fn integer(&self) -> Option<i64> {
        match self {
            Term::FixInteger(i) => Some(i.value as i64),
            Term::BigInteger(bi) => bi.value.to_i64(),
            _ => None,
        }
    }

    fn binary(&self) -> Option<&[u8]> {
        TryAsRef::<Binary>::try_as_ref(self).map(|b| b.bytes.as_slice())
    }

    fn list(&self) -> Option<&[Term]> {
        TryAsRef::<List>::try_as_ref(self).map(|l| l.elements.as_slice())
    }

    fn string(&self) -> Option<String> {
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
}

pub fn get_map_field<'a>(map: &'a std::collections::HashMap<Term, Term>, key: &str) -> Option<&'a Term> {
    map.get(&Term::Atom(Atom::from(key)))
}

pub fn to_string_required(t: &Term, field: &'static str) -> Result<String, Error> {
    t.string().ok_or(Error::Missing(field))
}

pub fn to_binary_required(t: &Term, field: &'static str) -> Result<Vec<u8>, Error> {
    t.binary().map(|b| b.to_vec()).ok_or(Error::Missing(field))
}

pub fn to_list_required<'a>(t: &'a Term, field: &'static str) -> Result<&'a [Term], Error> {
    t.list().ok_or(Error::Missing(field))
}

pub fn unpack_message_v2(buf: &[u8]) -> Result<MessageV2, String> {
    // Must be at least header length
    if buf.len() < 3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 {
        return Err(format!("message v2 is only {} bytes", buf.len()));
    }

    // Magic
    if &buf[0..3] != b"AMA" {
        return Err(format!("invalid magic: {:?}", &buf[0..3]));
    }

    let version_bytes = &buf[3..6];
    let version = format!("{}.{}.{}", version_bytes[0], version_bytes[1], version_bytes[2]);

    // Next is 7 zero bits and 1 flag bit, total 1 byte
    let flag_byte = buf[6];
    if flag_byte & 0b11111110 != 0 {
        return Err(format!("invalid flags: {}", flag_byte));
    }

    if flag_byte & 0b00000001 == 0 {
        return Err("message not signed".into());
    }

    let pk_start = 7;
    let pk_end = pk_start + 48;
    let pk = buf[pk_start..pk_end].to_vec();

    let sig_start = pk_end;
    let sig_end = sig_start + 96;
    let signature = buf[sig_start..sig_end].to_vec();

    let shard_index = u16::from_be_bytes(buf[sig_end..sig_end + 2].try_into().unwrap());
    let shard_total = u16::from_be_bytes(buf[sig_end + 2..sig_end + 4].try_into().unwrap());

    let ts_nano = u64::from_be_bytes(buf[sig_end + 4..sig_end + 12].try_into().unwrap());
    let original_size = u32::from_be_bytes(buf[sig_end + 12..sig_end + 16].try_into().unwrap());

    let payload = buf[sig_end + 16..].to_vec();

    Ok(MessageV2 { version, pk, signature, shard_index, shard_total, ts_nano, original_size, payload })
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum EncodeError {
    VersionFormat,
    VersionOutOfRange,
    BadPkLen(usize),
    BadSigLen(usize),
}

fn version_triplet_bytes(v: &str) -> Result<[u8; 3], EncodeError> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return Err(EncodeError::VersionFormat);
    }
    let mut out = [0u8; 3];
    for (i, p) in parts.iter().enumerate() {
        let n: i64 = p.parse().map_err(|_| EncodeError::VersionFormat)?;
        if !(0..=255).contains(&n) {
            return Err(EncodeError::VersionOutOfRange);
        }
        out[i] = n as u8;
    }
    Ok(out)
}

pub fn encode_message_v2(m: &MessageV2) -> Result<Vec<u8>, EncodeError> {
    if m.pk.len() != 48 {
        return Err(EncodeError::BadPkLen(m.pk.len()));
    }
    if m.signature.len() != 96 {
        return Err(EncodeError::BadSigLen(m.signature.len()));
    }
    let ver = version_triplet_bytes(&m.version)?;

    // 3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + payload
    let mut out = Vec::with_capacity(3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + m.payload.len());

    // "AMA"
    out.extend_from_slice(b"AMA");

    // version_3byte
    out.extend_from_slice(&ver);

    // 0::7, 1::1 → one byte with LSB set
    out.push(0b0000_0001);

    // pk (48), signature (96)
    out.extend_from_slice(&m.pk);
    out.extend_from_slice(&m.signature);

    // shard_index::16, shard_total::16 (big-endian)
    out.extend_from_slice(&m.shard_index.to_be_bytes());
    out.extend_from_slice(&m.shard_total.to_be_bytes());

    // ts_n::64 (big-endian)
    out.extend_from_slice(&m.ts_nano.to_be_bytes());

    // original_size::32 (big-endian)
    out.extend_from_slice(&m.original_size.to_be_bytes());

    // msg_compressed_or_shard::binary (rest)
    out.extend_from_slice(&m.payload);

    Ok(out)
}

fn parse_header_from_bin(bin: &[u8]) -> Result<EntryHeader, Error> {
    let term = Term::decode(bin)?;
    let map = match term {
        Term::Map(m) => m.map,
        _ => return Err(Error::WrongType("header map")),
    };

    let slot = map.get(&Term::Atom(Atom::from("slot"))).and_then(|t| t.integer()).ok_or(Error::Missing("slot"))?;

    let dr = map.get(&Term::Atom(Atom::from("dr"))).and_then(|t| t.binary()).ok_or(Error::Missing("dr"))?.to_vec();

    let height =
        map.get(&Term::Atom(Atom::from("height"))).and_then(|t| t.integer()).ok_or(Error::Missing("height"))?;

    let prev_hash = map
        .get(&Term::Atom(Atom::from("prev_hash")))
        .and_then(|t| t.binary())
        .ok_or(Error::Missing("prev_hash"))?
        .to_vec();

    let prev_slot =
        map.get(&Term::Atom(Atom::from("prev_slot"))).and_then(|t| t.integer()).ok_or(Error::Missing("prev_slot"))?;

    let signer =
        map.get(&Term::Atom(Atom::from("signer"))).and_then(|t| t.binary()).ok_or(Error::Missing("signer"))?.to_vec();

    let txs_hash = map
        .get(&Term::Atom(Atom::from("txs_hash")))
        .and_then(|t| t.binary())
        .ok_or(Error::Missing("txs_hash"))?
        .to_vec();

    let vr = map.get(&Term::Atom(Atom::from("vr"))).and_then(|t| t.binary()).ok_or(Error::Missing("vr"))?.to_vec();

    Ok(EntryHeader { slot, dr, height, prev_hash, prev_slot, signer, txs_hash, vr })
}

// fn parse_entry_from_bin(bin: &[u8]) -> Result<Entry, ParseError> {
//     let t = Term::decode(bin)?;
//     let m = match t {
//         Term::Map(m) => m.map,
//         _ => return Err(ParseError::WrongType("entry")),
//     };
//
//     let hash =
//         m.get(&Term::Atom(Atom::from("hash"))).and_then(|t| t.binary()).ok_or(ParseError::Missing("hash"))?.to_vec();
//
//     let header_bin =
//         m.get(&Term::Atom(Atom::from("header"))).and_then(|t| t.binary()).ok_or(ParseError::Missing("header"))?;
//     let header = parse_header_from_bin(header_bin)?;
//
//     let signature = m
//         .get(&Term::Atom(Atom::from("signature")))
//         .and_then(|t| t.binary())
//         .ok_or(ParseError::Missing("signature"))?
//         .to_vec();
//
//     let txs = m
//         .get(&Term::Atom(Atom::from("txs")))
//         .and_then(|t| t.list())
//         .map(|l| l.iter().filter_map(|t| t.binary().map(|b| b.to_vec())).collect())
//         .unwrap_or_default();
//
//     Ok(Entry { hash, header, signature, txs })
// }

// Signed Message Format (BLS Signature)
//
// Offset  Length  Field               Description
// ──────────────────────────────────────────────────────────────────
// 0-2     3       Magic               "AMA" (0x414D41)
// 3-5     3       Version             3-byte version (e.g., 1.1.2)
// 6       1       Flags               Bits: 0000000[signed=1]
// 7-54    48      Public Key          BLS12-381 public key (48 bytes)
// 55-150  96      Signature           BLS12-381 signature (96 bytes)
// 151-152 2       Shard Index         Current shard number (big-endian)
// 153-154 2       Shard Total         Total shards * 2 (big-endian)
// 155-162 8       Timestamp           Nanosecond timestamp (big-endian)
// 163-166 4       Original Size       Size of original message (big-endian)
// 167+    N       Payload/Shard       Message data or Reed-Solomon shard
