use super::proto::Error;
/// Oversimplified proto handler that decides the action per incoming message
use crate::bic::sol::Solution;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::entry::Entry;
use crate::node::proto::{Peers, Ping, Pong, TxPool};

#[async_trait::async_trait]
pub trait HandleExt
where
    Self: Sized,
{
    type Error;
    /// Handle a message returning instructions for upper layers
    async fn handle(self) -> Result<Instruction, Self::Error>;
    //fn get_name(&self) -> &'static str;
}

#[async_trait::async_trait]
impl HandleExt for Ping {
    type Error = Error;

    async fn handle(self) -> Result<Instruction, Self::Error> {
        Ok(Instruction::ReplyPong { ts_m: self.ts_m })
    }
}

#[async_trait::async_trait]
impl HandleExt for Pong {
    type Error = Error;

    async fn handle(self) -> Result<Instruction, Self::Error> {
        // TODO: update ETS-like peer table with latency now_ms - p.ts_m
        Ok(Instruction::Noop)
    }
}

#[async_trait::async_trait]
impl HandleExt for TxPool {
    type Error = Error;

    async fn handle(self) -> Result<Instruction, Self::Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(Instruction::Noop)
    }
}

#[async_trait::async_trait]
impl HandleExt for Peers {
    type Error = Error;

    async fn handle(self) -> Result<Instruction, Self::Error> {
        // TODO: update ETS-like peer table with new IPs
        Ok(Instruction::Noop)
    }
}
