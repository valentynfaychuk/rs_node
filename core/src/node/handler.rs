/// Oversimplified proto handler that decides the action per incoming message
use crate::bic::sol::Solution;
use crate::consensus::entry::Entry;
use crate::node::etf_ser::Proto;
use crate::node::proto::Attestation;
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of handling an incoming message.
#[derive(Debug)]
pub enum HandleResult {
    Noop,
    ReplyPong { ts_m: i64 },
    ObservedPong { ts_m: i64, seen_time_ms: i64 },
    ValidTxs { txs: Vec<Vec<u8>> },
    Peers { ips: Vec<String> },
    ReceivedSol { sol: Solution },
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

impl From<Proto> for HandleResult {
    /// Handle a message in a side-effect-light way, returning instructions for upper layers.
    fn from(proto: Proto) -> Self {
        match proto {
            Proto::WhoAreYou(_) => Self::Noop,
            Proto::Ping(p) => {
                // TODO: validate temporal/rooted signatures and update peer shared secret; broadcast peers
                Self::ReplyPong { ts_m: p.ts_m }
            }
            Proto::Pong(p) => {
                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
                // TODO: update ETS-like peer table with latency now_ms - p.ts_m
                Self::ObservedPong { ts_m: p.ts_m, seen_time_ms: now_ms }
            }
            Proto::TxPool(t) => match t.get_valid_txs() {
                Ok(txs) => Self::ValidTxs { txs },
                Err(e) => Self::Error(format!("txpool: {:?}", e)),
            },
            Proto::Peers(p) => {
                // TODO: insert into peer table
                Self::Peers { ips: p.ips.clone() }
            }
            Proto::Sol(sol) => {
                // TODO: PoP verification, TXPool.add_gifted_sol; possibly build and broadcast txs

                Self::ReceivedSol { sol: sol.clone() }
            }
            Proto::Entry(e) => {
                // TODO: deduplicate via DB/Fabric and insert; process optional consensus/attestation when parser supports.

                Self::ReceivedEntry { entry: e.clone() }
            }
            Proto::AttestationBulk(b) => {
                // TODO: per-attestation unpack_and_validate and coordinator routing
                Self::Attestations { attestations: b.attestations.clone() }
            }
            Proto::ConsensusBulk(c) => {
                // TODO: consensuses_packed should be list of binaries; parser currently not implemented for this op
                Self::ConsensusesPacked { packed: c.consensuses_packed.clone() }
            }
            Proto::CatchupEntry(c) => Self::CatchupEntryReq { heights: c.heights.clone() },
            Proto::CatchupTri(c) => Self::CatchupTriReq { heights: c.heights.clone() },
            Proto::CatchupBi(c) => Self::CatchupBiReq { heights: c.heights.clone() },
            Proto::CatchupAttestation(c) => Self::CatchupAttestationReq { hashes: c.hashes.clone() },
            Proto::SpecialBusiness(b) => {
                // TODO: decode business map, sign/verify, respond
                Self::SpecialBusiness { business: b.business.clone() }
            }
            Proto::SpecialBusinessReply(b) => {
                // TODO: verify signatures and forward to SpecialMeeting
                Self::SpecialBusinessReply { business: b.business.clone() }
            }
            Proto::SolicitEntry(s) => Self::SolicitEntry { hash: s.hash.clone() },
            Proto::SolicitEntry2(_) => Self::SolicitEntry2,
        }
    }
}
