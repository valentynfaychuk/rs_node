use once_cell::sync::OnceCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;
use crate::misc::rocksdb as rdb;

/// Persistent key-value store inspired by Elixir Mnesia-backed helper used in node.local/ex.
///
/// Goals:
/// - Simple thread-safe tables keyed by bytes (Vec<u8>)
/// - Values are dynamic (KV) and commonly Maps with String keys
/// - API mirrors Elixir-side usage:
///   - load(schema, opts): initialize tables and remember index fields
///   - get(table): get all records in the table
///   - get(table, key): get a record by primary key
///   - merge(table, key, map): insert/update by top-level merging existing map with the provided map
///
/// Notes:
/// - Uses RocksDB for disk persistence like Elixir Mnesia disc_copies
/// - Index fields stored for ETS-style secondary indexes
/// - Merge semantics are top-level (like Elixir Map.merge/2): for Map values, new keys override existing ones;
///   nested maps are not merged recursively.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("MnesiaKV not loaded. Call load() first")] 
    NotLoaded,
    #[error("Table '{0}' not found")] 
    TableNotFound(String),
    #[error("Value is not a Map for merge operation")] 
    ValueNotMap,
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rdb::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[derive(Clone, Debug, PartialEq, bincode::Encode, bincode::Decode)]
pub enum KV {
    Nil,
    Bool(bool),
    Int(i128),
    Bytes(Vec<u8>),
    List(Vec<KV>),
    Map(BTreeMap<String, KV>),
}

impl KV {
    /// Top-level merge for Map values (right overrides left). Does not recurse into nested Maps.
    fn merge_top_level(left: &KV, right: &KV) -> Result<KV, Error> {
        match (left, right) {
            (KV::Map(a), KV::Map(b)) => {
                let mut out = a.clone();
                for (k, v) in b {
                    out.insert(k.clone(), v.clone());
                }
                Ok(KV::Map(out))
            }
            // If either side is not a Map, behave like replacement with `right`.
            (_, _) => Ok(right.clone()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TableSchema {
    /// Names of fields to index. Currently recorded but not exposed via API.
    pub index: Vec<String>,
}

struct Store {
    schemas: HashMap<String, TableSchema>,
    initialized: bool,
}

static GLOBAL: OnceCell<RwLock<Store>> = OnceCell::new();

fn store() -> Result<&'static RwLock<Store>, Error> {
    GLOBAL.get().ok_or(Error::NotLoaded)
}

// serialize KV to bytes for rocksdb storage
fn serialize_kv(kv: &KV) -> Result<Vec<u8>, Error> {
    bincode::encode_to_vec(kv, bincode::config::standard()).map_err(|e| Error::Serialization(e.to_string()))
}

// deserialize bytes from rocksdb to KV
fn deserialize_kv(bytes: &[u8]) -> Result<KV, Error> {
    let (kv, _len) = bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(kv)
}

// create table key for rocksdb: "table_name:key"
fn make_table_key(table: &str, key: &[u8]) -> Vec<u8> {
    let mut table_key = Vec::with_capacity(table.len() + 1 + key.len());
    table_key.extend_from_slice(table.as_bytes());
    table_key.push(b':');
    table_key.extend_from_slice(key);
    table_key
}

// create index key for rocksdb: "table_name_index:indexed_values:primary_key"
fn make_index_key(table: &str, index_values: &[&[u8]], primary_key: &[u8]) -> Vec<u8> {
    let mut index_key = Vec::new();
    index_key.extend_from_slice(table.as_bytes());
    index_key.extend_from_slice(b"_index:");
    
    for (i, value) in index_values.iter().enumerate() {
        if i > 0 {
            index_key.push(b':');
        }
        index_key.extend_from_slice(value);
    }
    index_key.push(b':');
    index_key.extend_from_slice(primary_key);
    index_key
}

// extract indexed field values from a KV Map
fn extract_index_values(kv: &KV, index_fields: &[String]) -> Vec<Vec<u8>> {
    let mut values = Vec::new();
    if let KV::Map(map) = kv {
        for field in index_fields {
            match map.get(field) {
                Some(KV::Bool(b)) => values.push(vec![if *b { 1 } else { 0 }]),
                Some(KV::Bytes(bytes)) => values.push(bytes.clone()),
                Some(KV::Int(i)) => values.push(i.to_le_bytes().to_vec()),
                _ => values.push(vec![]), // nil/missing fields
            }
        }
    }
    values
}

/// Initialize the persistent store with the provided schema.
/// If called multiple times, subsequent calls are no-ops.
/// Requires RocksDB to be initialized first via rocksdb::init().
pub fn load(schema: BTreeMap<String, TableSchema>) -> Result<(), Error> {
    if GLOBAL.get().is_some() {
        return Ok(());
    }
    let _ = GLOBAL.set(RwLock::new(Store { 
        schemas: schema.into_iter().collect(),
        initialized: true,
    }));
    Ok(())
}

/// Auto-create table with default schema if not exists (matches Elixir Mnesia behavior)
fn ensure_table_exists(table: &str, index_fields: Vec<String>) -> Result<(), Error> {
    let lock = store()?;
    let mut s = lock.write().unwrap();
    if !s.schemas.contains_key(table) {
        s.schemas.insert(table.to_string(), TableSchema { index: index_fields });
    }
    Ok(())
}

/// Get all records from a table as a vector of (key, value) pairs.
pub fn get_all(table: &str) -> Result<Vec<(Vec<u8>, KV)>, Error> {
    // auto-create table if it doesn't exist
    ensure_table_exists(table, vec![])?;
    
    // use rocksdb prefix iterator to get all records for this table
    let prefix = format!("{}:", table);
    let items = rdb::iter_prefix("default", prefix.as_bytes())?;
    let mut result = Vec::new();
    
    for (full_key, value_bytes) in items {
        // extract original key by removing "table:" prefix
        if let Some(key_start) = full_key.iter().position(|&b| b == b':') {
            let original_key = full_key[key_start + 1..].to_vec();
            let kv = deserialize_kv(&value_bytes)?;
            result.push((original_key, kv));
        }
    }
    Ok(result)
}

/// Get a single record by table and key.
pub fn get(table: &str, key: &[u8]) -> Result<Option<KV>, Error> {
    // auto-create table if it doesn't exist
    ensure_table_exists(table, vec![])?;
    
    let table_key = make_table_key(table, key);
    match rdb::get("default", &table_key)? {
        Some(bytes) => Ok(Some(deserialize_kv(&bytes)?)),
        None => Ok(None),
    }
}

/// Create or ensure table exists with specific index fields
pub fn create_table(table: &str, index_fields: Vec<String>) -> Result<(), Error> {
    ensure_table_exists(table, index_fields)
}

/// Insert or update a record by merging the provided value into existing one (if present).
/// For Map values, new fields overwrite existing fields (top-level). For non-Map values, it replaces entirely.
pub fn merge(table: &str, key: &[u8], value: KV) -> Result<KV, Error> {
    // auto-create table if it doesn't exist
    ensure_table_exists(table, vec![])?;
    
    let lock = store()?;
    let s = lock.read().unwrap();
    let schema = s.schemas.get(table).ok_or_else(|| Error::TableNotFound(table.to_string()))?;
    let index_fields = schema.index.clone();
    // release locks
    
    let table_key = make_table_key(table, key);
    
    // get existing value if present and remove old index entries
    let old_val = match rdb::get("default", &table_key)? {
        Some(existing_bytes) => {
            let existing = deserialize_kv(&existing_bytes)?;
            // remove old index entries
            if !index_fields.is_empty() {
                let old_index_values = extract_index_values(&existing, &index_fields);
                let old_index_refs: Vec<&[u8]> = old_index_values.iter().map(|v| v.as_slice()).collect();
                let old_index_key = make_index_key(table, &old_index_refs, key);
                let _ = rdb::put("default", &old_index_key, &[]); // delete by storing empty value
            }
            Some(existing)
        },
        None => None,
    };
    
    // merge values
    let new_val = match old_val {
        Some(existing) => KV::merge_top_level(&existing, &value)?,
        None => value.clone(),
    };
    
    // persist the merged value
    let serialized = serialize_kv(&new_val)?;
    rdb::put("default", &table_key, &serialized)?;
    
    // create new index entries
    if !index_fields.is_empty() {
        let new_index_values = extract_index_values(&new_val, &index_fields);
        let new_index_refs: Vec<&[u8]> = new_index_values.iter().map(|v| v.as_slice()).collect();
        let new_index_key = make_index_key(table, &new_index_refs, key);
        rdb::put("default", &new_index_key, key)?; // store primary key as value
    }
    
    Ok(new_val)
}

/// Query records using ETS-style secondary index patterns
/// Similar to Elixir's :ets.select(table_index, match_spec)
pub fn select_index(table: &str, index_pattern: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
    let lock = store()?;
    let s = lock.read().unwrap();
    if !s.schemas.contains_key(table) {
        return Err(Error::TableNotFound(table.to_string()));
    }
    // release locks
    
    // create index prefix for querying
    let mut prefix = Vec::new();
    prefix.extend_from_slice(table.as_bytes());
    prefix.extend_from_slice(b"_index:");
    
    for (i, pattern_value) in index_pattern.iter().enumerate() {
        if i > 0 {
            prefix.push(b':');
        }
        prefix.extend_from_slice(pattern_value);
    }
    
    // query all matching index entries
    let index_entries = rdb::iter_prefix("default", &prefix)?;
    let mut primary_keys = Vec::new();
    
    for (_index_key, primary_key_bytes) in index_entries {
        if !primary_key_bytes.is_empty() {
            primary_keys.push(primary_key_bytes);
        }
    }
    
    Ok(primary_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema_with(table: &str, idx: &[&str]) -> BTreeMap<String, TableSchema> {
        let mut s = BTreeMap::new();
        s.insert(
            table.to_string(),
            TableSchema { index: idx.iter().map(|s| s.to_string()).collect() },
        );
        s
    }

    #[test]
    fn load_and_basic_ops() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        
        // initialize RocksDB for test (only once)
        INIT.call_once(|| {
            let test_db_path = "target/test_mnesiakv_db";
            std::fs::create_dir_all(test_db_path).unwrap();
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let _ = rdb::init("target").await; // ignore error if already initialized
            });
        });
        
        // Ensure isolated GLOBAL per test process is fine for unit tests.
        load(schema_with("NODEANR_TEST1", &["handshaked", "ip4"]))
            .expect("load ok");

        // Initially empty
        let all = get_all("NODEANR_TEST1").unwrap();
        assert!(all.is_empty());

        // Insert a record via merge (no existing value)
        let mut rec = BTreeMap::new();
        rec.insert("pk".to_string(), KV::Bytes(vec![1, 2, 3]));
        rec.insert("ip4".to_string(), KV::Bytes(vec![127, 0, 0, 1]));
        rec.insert("handshaked".to_string(), KV::Bool(false));
        rec.insert("port".to_string(), KV::Int(36969));
        let v = KV::Map(rec);
        let merged = merge("NODEANR_TEST1", b"pk123", v.clone()).unwrap();
        assert_eq!(merged, v);

        // Fetch by key
        let fetched = get("NODEANR_TEST1", b"pk123").unwrap().unwrap();
        assert_eq!(fetched, v);

        // Merge update: overwrite handshaked -> true, add ts
        let mut up = BTreeMap::new();
        up.insert("handshaked".to_string(), KV::Bool(true));
        up.insert("ts".to_string(), KV::Int(12345));
        let _updated = merge("NODEANR_TEST1", b"pk123", KV::Map(up)).unwrap();
        let got = get("NODEANR_TEST1", b"pk123").unwrap().unwrap();
        if let KV::Map(m) = got {
            assert_eq!(m.get("handshaked"), Some(&KV::Bool(true)));
            assert_eq!(m.get("ts"), Some(&KV::Int(12345)));
            assert!(m.get("ip4").is_some());
            assert!(m.get("port").is_some());
        } else {
            panic!("expected map");
        }

        // get_all returns our single row
        let all = get_all("NODEANR_TEST1").unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, b"pk123");
    }
    
    #[test]
    fn test_secondary_indexes() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        
        // initialize RocksDB for test (only once)
        INIT.call_once(|| {
            let test_db_path = "target/test_mnesiakv_index_db";
            std::fs::create_dir_all(test_db_path).unwrap();
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let _ = rdb::init("target").await; // ignore error if already initialized
            });
        });
        
        // initialize store (ignore error if already initialized)
        let _ = load(BTreeMap::new());
        
        // create table with index on handshaked and ip4 fields (like Elixir NodeANR)
        create_table("NODEANR_TEST2", vec!["handshaked".to_string(), "ip4".to_string()]).unwrap();
        
        // insert records with different handshaked values
        let mut rec1 = BTreeMap::new();
        rec1.insert("pk".to_string(), KV::Bytes(vec![1, 2, 3]));
        rec1.insert("handshaked".to_string(), KV::Bool(true));
        rec1.insert("ip4".to_string(), KV::Bytes(vec![192, 168, 1, 1]));
        merge("NODEANR_TEST2", b"key1", KV::Map(rec1)).unwrap();
        
        let mut rec2 = BTreeMap::new();
        rec2.insert("pk".to_string(), KV::Bytes(vec![4, 5, 6]));
        rec2.insert("handshaked".to_string(), KV::Bool(false));
        rec2.insert("ip4".to_string(), KV::Bytes(vec![192, 168, 1, 2]));
        merge("NODEANR_TEST2", b"key2", KV::Map(rec2)).unwrap();
        
        // query by index: find all handshaked=true records
        let handshaked_keys = select_index("NODEANR_TEST2", &[&[1], &[192, 168, 1, 1]]).unwrap();
        assert_eq!(handshaked_keys.len(), 1);
        assert_eq!(handshaked_keys[0], b"key1");
        
        // query by index: find all handshaked=false records
        let not_handshaked_keys = select_index("NODEANR_TEST2", &[&[0]]).unwrap();
        assert!(not_handshaked_keys.len() >= 1);
    }
}
