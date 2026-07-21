//! Sharded singleflight deduplication table for in-flight DNS requests.
//!
//! Callers register a cache key before sending upstream; subsequent callers with the same
//! key subscribe and wait. When the first caller gets a response it publishes via
//! `publish_bytes`/`publish_drop`, which completes every waiter and removes the key. On
//! upstream error, `remove` clears the key so waiters receive an error from their receiver.
//!
//! A leader's entry is just an (inline-capacity) waiter list — **no channel is
//! allocated until a real follower shows up**. Under high-cardinality traffic
//! (unique qnames, cache disabled/missing) nearly every query is a leader with
//! zero followers, and the previous design paid a `watch::channel` allocation
//! per query for a broadcast that never happened. A `oneshot` per actual
//! follower moves that cost to the (rare) coalescing case, where it is
//! amortized by the upstream round-trip it saves.

use crate::cache::CacheKey;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::sync::Mutex;
use tokio::sync::oneshot;

const SHARDS: usize = 64;
/// Followers waiting on a leader. Inline capacity 2: coalescing bursts beyond
/// a couple of concurrent duplicates are rare, and the empty (leader-only)
/// case must stay allocation-free.
type Waiters = SmallVec<[oneshot::Sender<Option<Bytes>>; 2]>;
// `CacheKey` is already a well-mixed FNV-1a hash (see `cache_key_with_variant`),
// so re-hashing it through the std HashMap's SipHash on every register/publish
// is pure overhead — same rationale as `DnsCache`/`InflightRegistry`'s hashers.
type Shard = Mutex<FxHashMap<CacheKey, Waiters>>;

pub struct InflightTable {
    shards: [Shard; SHARDS],
}

impl InflightTable {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(FxHashMap::default())),
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
/// upstream and call `publish_bytes`/`publish_drop`/`remove`). Returns `Some(rx)` if
/// another caller is already in flight; await `rx` to receive the result (`Err` means
/// the leader was removed without publishing — upstream error or cancellation).
#[allow(clippy::type_complexity)]
pub fn register(
    table: &InflightTable,
    key: CacheKey,
) -> Result<Option<oneshot::Receiver<Option<Bytes>>>> {
    let mut inflight = table
        .shard(key)
        .lock()
        .map_err(|_| anyhow!("singleflight map poisoned"))?;
    match inflight.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut waiters) => {
            let (tx, rx) = oneshot::channel();
            waiters.get_mut().push(tx);
            Ok(Some(rx))
        }
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(Waiters::new());
            Ok(None)
        }
    }
}

/// Take `key`'s waiter list out of the table (releasing the shard lock before
/// any sends). Empty when there were no followers or the key wasn't present.
fn take_waiters(table: &InflightTable, key: &CacheKey) -> Waiters {
    table
        .shard(*key)
        .lock()
        .ok()
        .and_then(|mut inflight| inflight.remove(key))
        .unwrap_or_default()
}

/// Send a shared response buffer to every waiter for `key` and remove the entry.
pub fn publish_bytes(table: &InflightTable, key: &CacheKey, resp: Bytes) {
    for tx in take_waiters(table, key) {
        let _ = tx.send(Some(resp.clone()));
    }
}

/// Send "no reply" to every waiter for `key` (the leader's rule filter decided to
/// drop this query) and remove the entry. Distinct from `remove`: this is a deliberate,
/// successful outcome, not an error, so waiters propagate it as "send nothing" rather
/// than falling back to SERVFAIL.
pub fn publish_drop(table: &InflightTable, key: &CacheKey) {
    for tx in take_waiters(table, key) {
        let _ = tx.send(None);
    }
}

/// Remove `key` without publishing (called on upstream error so waiters see a dropped
/// sender and their receiver resolves to `Err`).
pub fn remove(table: &InflightTable, key: &CacheKey) {
    drop(take_waiters(table, key));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn leader_then_followers_share_one_published_response() {
        let table = InflightTable::new();
        assert!(register(&table, 42).unwrap().is_none(), "first caller leads");
        let rx1 = register(&table, 42).unwrap().expect("second caller follows");
        let rx2 = register(&table, 42).unwrap().expect("third caller follows");

        publish_bytes(&table, &42, Bytes::from_static(b"resp"));
        assert_eq!(rx1.await.unwrap().as_deref(), Some(&b"resp"[..]));
        assert_eq!(rx2.await.unwrap().as_deref(), Some(&b"resp"[..]));

        // Publishing removed the key: the next caller becomes a fresh leader.
        assert!(register(&table, 42).unwrap().is_none());
    }

    #[tokio::test]
    async fn publish_drop_delivers_deliberate_no_reply() {
        let table = InflightTable::new();
        assert!(register(&table, 7).unwrap().is_none());
        let rx = register(&table, 7).unwrap().expect("follower");
        publish_drop(&table, &7);
        assert!(
            rx.await.expect("drop is a delivery, not an error").is_none(),
            "followers see 'send nothing'"
        );
    }

    #[tokio::test]
    async fn remove_closes_followers_without_a_value() {
        let table = InflightTable::new();
        assert!(register(&table, 9).unwrap().is_none());
        let rx = register(&table, 9).unwrap().expect("follower");
        remove(&table, &9);
        assert!(
            rx.await.is_err(),
            "waiters observe a dropped sender and fall back to SERVFAIL"
        );
        // The key is free again for a new leader.
        assert!(register(&table, 9).unwrap().is_none());
    }
}
