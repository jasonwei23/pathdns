//! In-memory ring buffer and QPS history ring for the query log.

use super::QueryLogEvent;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

// ── Event ring ───────────────────────────────────────────────────────────────

/// Fixed-capacity FIFO of recent query events.
/// Push drops the oldest entry when full and notifies SSE subscribers.
///
/// Uses a plain `Mutex` rather than `RwLock`: on Linux `pthread_rwlock` can
/// starve writers indefinitely when readers arrive continuously (SSE backfill
/// or polling API calls).  Push operations are O(1) and the critical section
/// is short in both push and query, so mutual exclusion costs less than
/// starvation.
pub struct EventRing {
    buf: Mutex<VecDeque<Arc<QueryLogEvent>>>,
    capacity: usize,
    tx: broadcast::Sender<Arc<QueryLogEvent>>,
}

impl EventRing {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            buf: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
            capacity,
            tx,
        }
    }

    /// Append an event, evicting the oldest entry if at capacity.
    /// Also broadcasts to any active SSE subscribers.
    pub fn push(&self, ev: Arc<QueryLogEvent>) -> bool {
        if self.capacity == 0 {
            return false;
        }
        if let Ok(mut buf) = self.buf.lock() {
            let mut evicted = false;
            if buf.len() >= self.capacity {
                buf.pop_front();
                evicted = true;
            }
            buf.push_back(Arc::clone(&ev));
            drop(buf); // release lock before notifying SSE subscribers
            let _ = self.tx.send(ev);
            return evicted;
        }
        false
    }

    /// Subscribe to live event broadcasts (for SSE).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<QueryLogEvent>> {
        self.tx.subscribe()
    }

    /// Return up to `limit` events, optionally bounded by `before_seq`/`after_seq`
    /// (newest-first), and optionally filtered by a qname substring.
    pub fn query(
        &self,
        before_seq: Option<u64>,
        after_seq: Option<u64>,
        limit: usize,
        filter: Option<&str>,
    ) -> Vec<Arc<QueryLogEvent>> {
        let Ok(buf) = self.buf.lock() else {
            return vec![];
        };
        let limit = limit.clamp(1, 1000);
        buf.iter()
            .rev()
            .filter(|ev| {
                if let Some(seq) = before_seq {
                    if ev.seq >= seq {
                        return false;
                    }
                }
                if let Some(seq) = after_seq {
                    if ev.seq <= seq {
                        return false;
                    }
                }
                if let Some(f) = filter {
                    if !f.is_empty() && !ev.qname.contains(f) {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Clear all events from the ring.
    pub fn clear(&self) {
        if let Ok(mut buf) = self.buf.lock() {
            buf.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.buf.lock().map(|b| b.len()).unwrap_or(0)
    }

    pub fn enabled(&self) -> bool {
        self.capacity > 0
    }
}

// ── QPS history ring ─────────────────────────────────────────────────────────

/// Stores per-second query counts for the last 3600 seconds (1 hour).
/// The background worker pushes one entry per second.
pub struct QpsRing {
    data: RwLock<VecDeque<u64>>,
}

impl QpsRing {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(VecDeque::with_capacity(3600)),
        }
    }

    /// Record a per-second count. Called by the worker once per second.
    pub fn push(&self, count: u64) {
        if let Ok(mut data) = self.data.write() {
            if data.len() == 3600 {
                data.pop_front();
            }
            data.push_back(count);
        }
    }

    /// Return the last `n` per-second counts, oldest-first. Max 3600.
    pub fn snapshot(&self, n: usize) -> Vec<u64> {
        let Ok(data) = self.data.read() else {
            return vec![];
        };
        let take = n.min(3600).min(data.len());
        data.iter().skip(data.len() - take).copied().collect()
    }
}

// ── Per-second stats ring ─────────────────────────────────────────────────────

/// Per-second counter snapshot (deltas from the previous second).
#[derive(Default, Clone, Copy)]
pub struct PerSecondSnapshot {
    pub unix_secs: u64,
    pub queries: u64,
    pub cache_hits: u64,
    pub upstream_ok: u64,
    pub upstream_err: u64,
    pub local_responses: u64,
    pub filtered: u64,
}

/// Stores per-second counter snapshots for the last 86400 seconds (24 hours).
pub struct StatsRing {
    data: RwLock<VecDeque<PerSecondSnapshot>>,
}

impl StatsRing {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(VecDeque::with_capacity(3601)),
        }
    }

    pub fn push(&self, snap: PerSecondSnapshot) {
        if let Ok(mut data) = self.data.write() {
            if data.len() == 86400 {
                data.pop_front();
            }
            data.push_back(snap);
        }
    }

    /// Aggregate the last `seconds` snapshots. Returns (aggregated totals, window_start_unix_secs).
    pub fn aggregate(&self, seconds: usize) -> (PerSecondSnapshot, u64) {
        let Ok(data) = self.data.read() else {
            return (PerSecondSnapshot::default(), 0);
        };
        let take = seconds.min(86400).min(data.len());
        let mut agg = PerSecondSnapshot::default();
        let mut from_secs = 0u64;
        let skip = data.len().saturating_sub(take);
        for (i, snap) in data.iter().skip(skip).enumerate() {
            if i == 0 {
                from_secs = snap.unix_secs;
            }
            agg.queries += snap.queries;
            agg.cache_hits += snap.cache_hits;
            agg.upstream_ok += snap.upstream_ok;
            agg.upstream_err += snap.upstream_err;
            agg.local_responses += snap.local_responses;
            agg.filtered += snap.filtered;
        }
        (agg, from_secs)
    }

    /// Divide the last `seconds` per-second snapshots into `buckets` equal-width
    /// rules, summing each rule. Returns exactly `buckets` entries, oldest-first.
    /// Empty buckets (when the ring has fewer samples than `buckets`) contain zeros.
    pub fn bucket_aggregate(&self, seconds: usize, buckets: usize) -> Vec<PerSecondSnapshot> {
        let buckets = buckets.max(1);
        let Ok(data) = self.data.read() else {
            return vec![PerSecondSnapshot::default(); buckets];
        };
        let take = seconds.min(86400).min(data.len());
        if take == 0 {
            return vec![PerSecondSnapshot::default(); buckets];
        }
        let skip = data.len() - take;
        let snaps: Vec<&PerSecondSnapshot> = data.iter().skip(skip).collect();
        let n = snaps.len();
        let mut result = Vec::with_capacity(buckets);
        for b in 0..buckets {
            let start = b * n / buckets;
            let end = if b + 1 == buckets {
                n
            } else {
                (b + 1) * n / buckets
            };
            let mut agg = PerSecondSnapshot::default();
            for snap in &snaps[start..end] {
                agg.queries += snap.queries;
                agg.cache_hits += snap.cache_hits;
                agg.upstream_ok += snap.upstream_ok;
                agg.upstream_err += snap.upstream_err;
                agg.local_responses += snap.local_responses;
                agg.filtered += snap.filtered;
            }
            if start < end {
                agg.unix_secs = snaps[start].unix_secs;
            }
            result.push(agg);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_ring_discards_events() {
        let ring = EventRing::new(0);
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn qps_snapshot_returns_newest_window_in_order() {
        let ring = QpsRing::new();
        ring.push(1);
        ring.push(2);
        ring.push(3);
        assert_eq!(ring.snapshot(2), vec![2, 3]);
    }
}
