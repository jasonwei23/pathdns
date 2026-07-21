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

    /// Append a batch of events under **one** lock acquisition, evicting the
    /// oldest entries once at capacity. Returns the number evicted.
    ///
    /// The worker drains the event channel in batches; taking the mutex (and
    /// checking the SSE broadcast) once per batch instead of once per event
    /// keeps the worker's cost per event low under load — which matters even
    /// though it's off the resolver hot path, since the worker competes for
    /// the same cores as the listener shards.
    ///
    /// Broadcasting to SSE subscribers happens after the lock is released,
    /// and only when there is at least one live subscriber — `send` on a
    /// subscriber-less broadcast channel still costs the Arc clone and an
    /// error round-trip per event otherwise.
    pub fn push_batch(&self, events: &[Arc<QueryLogEvent>]) -> u64 {
        if self.capacity == 0 || events.is_empty() {
            return 0;
        }
        let mut evicted = 0u64;
        if let Ok(mut buf) = self.buf.lock() {
            for ev in events {
                if buf.len() >= self.capacity {
                    buf.pop_front();
                    evicted += 1;
                }
                buf.push_back(Arc::clone(ev));
            }
        } else {
            return 0;
        }
        if self.tx.receiver_count() > 0 {
            for ev in events {
                let _ = self.tx.send(Arc::clone(ev));
            }
        }
        evicted
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

impl Default for QpsRing {
    fn default() -> Self {
        Self::new()
    }
}

// ── Per-second stats ring ─────────────────────────────────────────────────────

/// One stats sample: counter deltas accumulated over [`STATS_SAMPLE_SECS`]
/// seconds. The worker folds that many per-second deltas into one sample.
#[derive(Default, Clone, Copy)]
pub struct StatsSample {
    pub unix_secs: u64,
    pub queries: u64,
    pub cache_hits: u64,
    pub upstream_ok: u64,
    pub upstream_err: u64,
    pub filtered: u64,
}

/// Seconds of per-second deltas the worker folds into a single ring sample.
/// The dashboard draws at most a few dozen buckets over its window, so
/// per-second detail is never displayed — per-minute samples give the same
/// picture at 1/60th the memory.
pub(super) const STATS_SAMPLE_SECS: usize = 60;
/// Samples retained: 24 hours at per-minute granularity (1440 × 48 B ≈ 69 KB,
/// vs. ~4 MB if the ring kept every second of that day).
const STATS_RING_LEN: usize = 24 * 60;

/// Stores counter-delta samples (one per [`STATS_SAMPLE_SECS`] seconds) for the
/// last [`STATS_RING_LEN`] samples — i.e. the last 24 hours.
pub struct StatsRing {
    data: RwLock<VecDeque<StatsSample>>,
}

impl StatsRing {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(VecDeque::with_capacity(STATS_RING_LEN + 1)),
        }
    }

    pub fn push(&self, snap: StatsSample) {
        if let Ok(mut data) = self.data.write() {
            if data.len() == STATS_RING_LEN {
                data.pop_front();
            }
            data.push_back(snap);
        }
    }

    /// Aggregate the most recent `seconds` worth of samples. Returns
    /// (aggregated totals, window_start_unix_secs).
    pub fn aggregate(&self, seconds: usize) -> (StatsSample, u64) {
        let Ok(data) = self.data.read() else {
            return (StatsSample::default(), 0);
        };
        let take = (seconds / STATS_SAMPLE_SECS)
            .min(STATS_RING_LEN)
            .min(data.len());
        let mut agg = StatsSample::default();
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
            agg.filtered += snap.filtered;
        }
        (agg, from_secs)
    }

    /// Divide the most recent `seconds` worth of samples into `buckets`
    /// equal-width groups, summing each. Returns exactly `buckets` entries,
    /// oldest-first. Empty buckets (when the ring has fewer samples than
    /// `buckets`) contain zeros.
    pub fn bucket_aggregate(&self, seconds: usize, buckets: usize) -> Vec<StatsSample> {
        let buckets = buckets.max(1);
        let Ok(data) = self.data.read() else {
            return vec![StatsSample::default(); buckets];
        };
        let take = (seconds / STATS_SAMPLE_SECS)
            .min(STATS_RING_LEN)
            .min(data.len());
        if take == 0 {
            return vec![StatsSample::default(); buckets];
        }
        let skip = data.len() - take;
        let snaps: Vec<&StatsSample> = data.iter().skip(skip).collect();
        let n = snaps.len();
        let mut result = Vec::with_capacity(buckets);
        for b in 0..buckets {
            let start = b * n / buckets;
            let end = if b + 1 == buckets {
                n
            } else {
                (b + 1) * n / buckets
            };
            let mut agg = StatsSample::default();
            for snap in &snaps[start..end] {
                agg.queries += snap.queries;
                agg.cache_hits += snap.cache_hits;
                agg.upstream_ok += snap.upstream_ok;
                agg.upstream_err += snap.upstream_err;
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

impl Default for StatsRing {
    fn default() -> Self {
        Self::new()
    }
}
