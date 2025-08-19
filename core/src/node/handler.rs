use super::proto::Error;
/// Oversimplified proto handler that decides the action per incoming message
use crate::bic::sol::Solution;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::entry::Entry;
use crate::node::proto::{Peers, Ping, Pong, TxPool};

pub trait HandleExt
where
    Self: Sized,
{
    type Error;
    /// Handle a message returning instructions for upper layers
    fn handle(self) -> Result<Instruction, Self::Error>;
}

/// Result of handling an incoming message.
#[derive(Debug)]
pub enum Instruction {
    Noop,
    ReplyPong { ts_m: i64 },
    ObservedPong { ts_m: i64, seen_time_ms: i64 },
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

impl HandleExt for Ping {
    type Error = Error;

    fn handle(self) -> Result<Instruction, Self::Error> {
        println!("{:#?}", self);
        Ok(Instruction::ReplyPong { ts_m: self.ts_m })
    }
}

impl HandleExt for Pong {
    type Error = Error;

    fn handle(self) -> Result<Instruction, Self::Error> {
        // TODO: update ETS-like peer table with latency now_ms - p.ts_m
        Ok(Instruction::Noop)
    }
}

impl HandleExt for TxPool {
    type Error = Error;

    fn handle(self) -> Result<Instruction, Self::Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(Instruction::Noop)
    }
}

impl HandleExt for Peers {
    type Error = Error;

    fn handle(self) -> Result<Instruction, Self::Error> {
        // TODO: update ETS-like peer table with new IPs
        Ok(Instruction::Noop)
    }
}
