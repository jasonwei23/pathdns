//! Sharded singleflight deduplication table for in-flight DNS requests.
//!
//! Callers register a cache key before sending upstream; subsequent callers with the same
//! key subscribe and wait. When the first caller gets a response it publishes via `publish`,
//! which broadcasts to all waiters and removes the key. On upstream error, `remove` clears
//! the key so waiters receive an error from `register`.

use crate::cache::CacheKey;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::watch;

const SHARDS: usize = 64;
type Shard = Mutex<HashMap<CacheKey, watch::Sender<Option<Bytes>>>>;

pub struct InflightTable {
    shards: [Shard; SHARDS],
}

impl InflightTable {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    fn shard(&self, key: CacheKey) -> &Shard {
        &self.shards[(key as usize) & (SHARDS - 1)]
    }
}

impl Default for InflightTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Register interest in `key`. Returns `None` if this caller is the leader (must send
/// upstream and call `publish`). Returns `Some(rx)` if another caller is already in
/// flight; await `rx.changed()` to receive the result.
#[allow(clippy::type_complexity)]
pub fn register(
    table: &InflightTable,
    key: CacheKey,
) -> Result<Option<watch::Receiver<Option<Bytes>>>> {
    let mut inflight = table
        .shard(key)
        .lock()
        .map_err(|_| anyhow!("singleflight map poisoned"))?;
    if let Some(tx) = inflight.get(&key) {
        return Ok(Some(tx.subscribe()));
    }
    let (tx, _rx) = watch::channel(None);
    inflight.insert(key, tx);
    Ok(None)
}

/// Broadcast a shared response buffer to all waiters for `key` and remove the entry.
pub fn publish_bytes(table: &InflightTable, key: &CacheKey, resp: Bytes) {
    let tx = table
        .shard(*key)
        .lock()
        .ok()
        .and_then(|mut inflight| inflight.remove(key));
    if let Some(tx) = tx {
        let _ = tx.send(Some(resp));
    }
}

/// Broadcast "no reply" to all waiters for `key` (the leader's rule filter decided to
/// drop this query) and remove the entry. Distinct from `remove`: this is a deliberate,
/// successful outcome, not an error, so waiters propagate it as "send nothing" rather
/// than falling back to SERVFAIL.
pub fn publish_drop(table: &InflightTable, key: &CacheKey) {
    let tx = table
        .shard(*key)
        .lock()
        .ok()
        .and_then(|mut inflight| inflight.remove(key));
    if let Some(tx) = tx {
        let _ = tx.send(None);
    }
}

/// Remove `key` without broadcasting (called on upstream error so waiters see a dropped sender).
pub fn remove(table: &InflightTable, key: &CacheKey) {
    if let Ok(mut inflight) = table.shard(*key).lock() {
        inflight.remove(key);
    }
}
