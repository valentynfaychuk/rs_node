#![allow(dead_code)]

use crate::config::Config;

pub mod bic;
pub mod config;
pub mod consensus;
pub mod genesis;
pub mod metrics;
pub mod node;
pub mod utils;
pub mod wasm;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Fabric(#[from] consensus::fabric::Error),
    #[error(transparent)]
    Archiver(#[from] utils::archiver::Error),
}

pub async fn init(config: &Config) -> Result<(), Error> {
    // initialize the global state or perform any necessary setup
    // this function can be used to set up logging, metrics, etc
    // currently, it does nothing but can be extended in the future
    consensus::fabric::init(config.get_root()).await?;
    utils::archiver::init(config.get_root()).await?;

    Ok(())
}
