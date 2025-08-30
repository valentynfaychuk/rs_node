#![allow(dead_code)]

use crate::node::{anr, peers};

pub mod bic;
pub mod config;
pub mod consensus;
pub mod genesis;
pub mod metrics;
pub mod node;
pub mod utils;
pub mod wasm;
pub mod context;

pub use context::{Context, PeerInfo, read_udp_packet};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Fabric(#[from] consensus::fabric::Error),
    #[error(transparent)]
    Archiver(#[from] utils::archiver::Error),
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error(transparent)]
    Peers(#[from] peers::Error),
}


