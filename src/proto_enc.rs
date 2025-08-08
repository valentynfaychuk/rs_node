use crate::proto::*;
use eetf::DecodeError;
use eetf::convert::TryAsRef;
use eetf::{Atom, Term};
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum ParseError {
    /// Failed while reading or inflating bytes.
    Io(std::io::Error),
    /// ETF decoding failed.
    Decode(DecodeError),
    /// A required field is absent.
    Missing(&'static str),
    /// The term/type found in the ETF stream is not what we expected.
    WrongType(&'static str),
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

impl From<DecodeError> for ParseError {
    fn from(e: DecodeError) -> Self {
        ParseError::Decode(e)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "I/O error: {e}"),
            ParseError::Decode(e) => write!(f, "ETF decode error: {e}"),
            ParseError::Missing(key) => write!(f, "required key \"{key}\" is missing"),
            ParseError::WrongType(t) => write!(f, "unexpected type, expected {t}"),
        }
    }
}

impl Error for ParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ParseError::Io(e) => Some(e),
            ParseError::Decode(e) => Some(e),
            _ => None,
        }
    }
}

use miniz_oxide::inflate::decompress_to_vec;

pub fn deflate_decompress(compressed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    decompress_to_vec(compressed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)))
}

/// Parse any NodeProto message.
pub fn parse_nodeproto(buf: &[u8]) -> Result<NodeProto, ParseError> {
    let decompressed = deflate_decompress(buf)?;
    let term = Term::decode(&decompressed[..])?; // decode ETF

    // Turn the ETF map into a real HashMap so `.get()` works
    let map = match term {
        Term::Map(m) => m.map.clone(),
        _ => return Err(ParseError::WrongType("map")),
    };

    // `op` determines the variant.
    let op_atom = map
        .get(&Term::Atom(Atom::from("op")))
        .and_then(|t| t.atom())
        .ok_or(ParseError::Missing("op"))?;

    match op_atom.name.as_str() {
        "ping" => {
            let temporal = parse_entry_summary(map.get(&Term::Atom(Atom::from("temporal"))))?;
            let rooted = parse_entry_summary(map.get(&Term::Atom(Atom::from("rooted"))))?;
            let ts_m = map
                .get(&Term::Atom(Atom::from("ts_m")))
                .and_then(|t| t.integer())
                .ok_or(ParseError::Missing("ts_m"))?;
            Ok(NodeProto::Ping(Ping {
                temporal,
                rooted,
                ts_m,
            }))
        }
        "pong" => {
            let ts_m = map
                .get(&Term::Atom(Atom::from("ts_m")))
                .and_then(|t| t.integer())
                .ok_or(ParseError::Missing("ts_m"))?;
            Ok(NodeProto::Pong(Pong { ts_m }))
        }
        "who_are_you" => Ok(NodeProto::WhoAreYou(WhoAreYou)),
        "txpool" => {
            let txs = map
                .get(&Term::Atom(Atom::from("txs_packed")))
                .and_then(|t| t.binary())
                .ok_or(ParseError::Missing("txs_packed"))?;
            Ok(NodeProto::TxPool(TxPool {
                txs_packed: txs.to_vec(),
            }))
        }
        "peers" => {
            let list = map
                .get(&Term::Atom(Atom::from("ips")))
                .and_then(|t| t.list())
                .ok_or(ParseError::Missing("ips"))?;
            let ips = list
                .iter()
                .map(|t| t.string().map(|s| s.to_string()))
                .collect::<Option<Vec<_>>>()
                .ok_or(ParseError::WrongType("ips"))?;
            Ok(NodeProto::Peers(Peers { ips }))
        }
        "solicit_entry2" => Ok(NodeProto::SolicitEntry2(SolicitEntry2)),
        _ => Err(ParseError::WrongType("op")),
    }
}

/// Helper that reads an EntrySummary from an ETF term.
fn parse_entry_summary(term: Option<&Term>) -> Result<EntrySummary, ParseError> {
    let map = match term {
        Some(Term::Map(m)) => m.map.clone(), // borrow the vec
        _ => return Err(ParseError::WrongType("EntrySummary")),
    };

    let header = map
        .get(&Term::Atom(Atom::from("header")))
        .and_then(|t| t.binary())
        .ok_or(ParseError::Missing("header"))?;
    let signature = map
        .get(&Term::Atom(Atom::from("signature")))
        .and_then(|t| t.binary())
        .ok_or(ParseError::Missing("signature"))?;
    let mask = map
        .get(&Term::Atom(Atom::from("mask")))
        .and_then(|t| t.binary())
        .ok_or(ParseError::Missing("mask"))?;

    Ok(EntrySummary {
        header: header.to_vec(),
        signature: signature.to_vec(),
        mask: mask.to_vec(),
    })
}

use eetf::{Binary, List};
use num_traits::ToPrimitive; // already pulled by eetf

/// Lightweight helpers so you can keep calling `.atom()`, `.integer()`, etc.
trait TermExt {
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

pub fn unpack_message_v2(buf: &[u8]) -> Result<MessageV2, String> {
    // Must be at least header length
    if buf.len() < 3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 {
        return Err("buffer too short".into());
    }

    // Magic
    if &buf[0..3] != b"AMA" {
        return Err("invalid magic".into());
    }

    let version_bytes = &buf[3..6];
    let version = format!(
        "{}.{}.{}",
        version_bytes[0], version_bytes[1], version_bytes[2]
    );

    // Next is 7 zero bits and 1 flag bit, total 1 byte
    let flag_byte = buf[6];
    if flag_byte & 0b11111110 != 0 {
        return Err("invalid 7-bit zero field".into());
    }
    let _flag = flag_byte & 0b00000001;

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

    Ok(MessageV2 {
        version,
        pk,
        signature,
        shard_index,
        shard_total,
        ts_nano,
        original_size,
        payload,
    })
}

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
