use super::etf_ser::Error as SerializerError;
use crate::consensus::tx;
use eetf::convert::TryAsRef;
use eetf::{Binary, List, Term};
use std::fmt;

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
}

#[derive(Debug)]
pub struct WhoAreYou;

#[derive(Debug)]
pub struct TxPool {
    pub txs_packed: Vec<u8>,
}

impl TxPool {
    /// Returns valid tx binaries.
    pub fn get_valid_txs(&self) -> Result<Vec<Vec<u8>>, SerializerError> {
        Self::parse_and_filter_txs(&self.txs_packed)
    }

    /// Decodes an ETF-encoded list of binary transactions, validates each, and returns only the valid ones.
    fn parse_and_filter_txs(txs_packed_blob: &[u8]) -> Result<Vec<Vec<u8>>, SerializerError> {
        let term = Term::decode(txs_packed_blob)?;

        let list = if let Some(l) = TryAsRef::<List>::try_as_ref(&term) {
            &l.elements
        } else {
            return Err(SerializerError::WrongType("txs_packed must be list"));
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

        let res = TxPool::parse_and_filter_txs(&bin).expect("ok");
        assert!(res.is_empty());
    }

    #[test]
    fn non_list_errors() {
        // Encode an integer instead of list
        let etf = Term::from(eetf::FixInteger { value: 42 });
        let mut bin = Vec::new();
        etf.encode(&mut bin).expect("encode");

        let err = TxPool::parse_and_filter_txs(&bin).err().unwrap();
        matches!(err, SerializerError::WrongType(_));
    }
}
