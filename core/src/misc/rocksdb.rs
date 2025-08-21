use once_cell::sync::OnceCell;
use rocksdb::{
    ColumnFamilyDescriptor, Direction, IteratorMode, MultiThreaded, OptimisticTransactionDB, Options, ReadOptions,
};
use tokio::fs::create_dir_all;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
}

pub struct DbHandles {
    pub db: OptimisticTransactionDB<MultiThreaded>,
}

static GLOBAL_DB: OnceCell<DbHandles> = OnceCell::new();

fn cf_names() -> &'static [&'static str] {
    &[
        "default",
        "entry_by_height",
        "entry_by_slot",
        "tx",
        "tx_account_nonce",
        "tx_receiver_nonce",
        "my_seen_time_for_entry",
        "my_attestation_for_entry",
        // "my_mutations_hash_for_entry", // was commented in Elixir, skipping for now
        "consensus",
        "consensus_by_entryhash",
        "contractstate",
        "muts",
        "muts_rev",
        "sysconf",
    ]
}

/// Expects path directory to exist
pub async fn init(base: &str) -> Result<(), Error> {
    if GLOBAL_DB.get().is_some() {
        return Ok(());
    }

    let path = format!("{}/db", base);
    create_dir_all(&path).await?;

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    let cf_descs: Vec<_> = cf_names()
        .iter()
        .map(|&name| {
            let mut opts = Options::default();
            opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
            opts.set_target_file_size_multiplier(2);
            ColumnFamilyDescriptor::new(name, opts)
        })
        .collect();

    let db: OptimisticTransactionDB<MultiThreaded> =
        OptimisticTransactionDB::open_cf_descriptors(&db_opts, path, cf_descs)?;
    GLOBAL_DB.set(DbHandles { db }).ok();
    Ok(())
}

pub fn close() {
    // rocksdb closes on drop, we cannot drop OnceCell contents safely here
}

fn get_handles() -> &'static DbHandles {
    GLOBAL_DB.get().expect("DB not initialized")
}

pub fn get(cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let h = get_handles();
    let cf_h = h.db.cf_handle(cf).expect("cf name");
    let v = h.db.get_cf(&cf_h, key)?;
    Ok(v)
}

pub fn put(cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
    let h = get_handles();
    let cf_h = h.db.cf_handle(cf).expect("cf name");
    h.db.put_cf(&cf_h, key, value)?;
    Ok(())
}

pub fn iter_prefix(cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    let h = get_handles();
    let cf_h = h.db.cf_handle(cf).expect("cf name");
    let mut ro = ReadOptions::default();
    ro.set_prefix_same_as_start(true);
    let mode = IteratorMode::From(prefix, Direction::Forward);
    let mut it = h.db.iterator_cf_opt(&cf_h, ro, mode);
    let mut out = Vec::new();
    while let Some(kv) = it.next() {
        let (k, v) = kv?;
        if !k.starts_with(prefix) {
            break;
        }
        out.push((k.to_vec(), v.to_vec()));
    }
    Ok(out)
}

/// Find the latest key-value under `prefix` with key <= `prefix || key_suffix`
/// Returns the raw key and value if found, otherwise None
pub fn get_prev_or_first(cf: &str, prefix: &str, key_suffix: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
    let h = get_handles();
    let cf_h = h.db.cf_handle(cf).expect("cf name");
    let seek_key = format!("{}{}", prefix, key_suffix);
    let mut it = h.db.iterator_cf(&cf_h, IteratorMode::From(seek_key.as_bytes(), Direction::Reverse));

    if let Some(res) = it.next() {
        let (k, v) = res?;
        if k.starts_with(prefix.as_bytes()) {
            return Ok(Some((k.to_vec(), v.to_vec())));
        }
    }
    Ok(None)
}
