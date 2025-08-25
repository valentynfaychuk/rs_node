#![allow(dead_code)]

pub mod bic;
pub mod config;
pub mod consensus;
pub mod genesis;
pub mod metrics;
pub mod misc;
pub mod node;
pub mod wasm;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Fabric(#[from] consensus::fabric::Error),
    #[error(transparent)]
    Archiver(#[from] misc::archiver::Error),
}

pub async fn init(path: Option<&str>) -> Result<(), Error> {
    // initialize the global state or perform any necessary setup
    // this function can be used to set up logging, metrics, etc
    // currently, it does nothing but can be extended in the future
    let base = path.unwrap_or(config::work_dir());
    consensus::fabric::init(base).await?;
    misc::archiver::init(base).await?;

    Ok(())
}
