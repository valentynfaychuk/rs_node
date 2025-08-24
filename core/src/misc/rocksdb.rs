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
        // "my_mutations_hash_for_entry",
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

pub fn delete(cf: &str, key: &[u8]) -> Result<(), Error> {
    let h = get_handles();
    let cf_h = h.db.cf_handle(cf).expect("cf name");
    h.db.delete_cf(&cf_h, key)?;
    Ok(())
}

pub fn iter_prefix(cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    let h = get_handles();
    let cf_h = h.db.cf_handle(cf).expect("cf name");
    let mut ro = ReadOptions::default();
    ro.set_prefix_same_as_start(true);
    let mode = IteratorMode::From(prefix, Direction::Forward);
    let it = h.db.iterator_cf_opt(&cf_h, ro, mode);
    let mut out = Vec::new();
    for kv in it {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_base() -> String {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let pid = std::process::id();
        format!("{}/rs_node_rocks_test_{}_{}", std::env::temp_dir().display(), pid, ts)
    }

    #[tokio::test]
    async fn rocksdb_basic_ops_and_iters() {
        let base = unique_base();
        init(&base).await.expect("init db");

        // basic put/get on default CF
        put("default", b"a:1", b"v1").expect("put");
        let v = get("default", b"a:1").expect("get").unwrap();
        assert_eq!(v, b"v1");

        // insert a few keys with common prefix for iter_prefix
        for i in 0..5u8 {
            put("default", format!("p:{}", i).as_bytes(), &[i]).unwrap();
        }
        let items = iter_prefix("default", b"p:").expect("iter_prefix");
        assert!(!items.is_empty());
        for (k, _v) in &items {
            assert!(k.starts_with(b"p:"));
        }

        // test get_prev_or_first semantics
        put("default", b"h:001", b"x").unwrap();
        put("default", b"h:010", b"y").unwrap();
        put("default", b"h:020", b"z").unwrap();

        let r = get_prev_or_first("default", "h:", "015").unwrap().unwrap();
        assert_eq!(r.0, b"h:010");
        let r2 = get_prev_or_first("default", "h:", "000").unwrap();
        assert!(r2.is_none());
        let r3 = get_prev_or_first("default", "h:", "999").unwrap().unwrap();
        assert_eq!(r3.0, b"h:020");
    }
}
