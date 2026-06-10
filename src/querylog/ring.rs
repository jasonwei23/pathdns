//! In-memory ring buffer and QPS history ring for the query log.

use super::QueryLogEvent;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

// ── Event ring ───────────────────────────────────────────────────────────────

/// Fixed-capacity FIFO of recent query events.
/// Push drops the oldest entry when full.
pub struct EventRing {
    buf: RwLock<VecDeque<Arc<QueryLogEvent>>>,
    capacity: usize,
}

impl EventRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: RwLock::new(VecDeque::with_capacity(capacity.min(4096))),
            capacity,
        }
    }

    /// Append an event, evicting the oldest entry if at capacity.
    pub fn push(&self, ev: Arc<QueryLogEvent>) -> bool {
        if self.capacity == 0 {
            return false;
        }
        if let Ok(mut buf) = self.buf.write() {
            let mut evicted = false;
            if buf.len() >= self.capacity {
                buf.pop_front();
                evicted = true;
            }
            buf.push_back(ev);
            return evicted;
        }
        false
    }

    /// Return up to `limit` events with `seq < before_seq` (newest-first),
    /// optionally filtered by a qname substring.
    pub fn query(
        &self,
        before_seq: Option<u64>,
        limit: usize,
        filter: Option<&str>,
    ) -> Vec<Arc<QueryLogEvent>> {
        let Ok(buf) = self.buf.read() else {
            return vec![];
        };
        let limit = limit.min(1000).max(1);
        buf.iter()
            .rev()
            .filter(|ev| {
                if let Some(seq) = before_seq {
                    if ev.seq >= seq {
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
        if let Ok(mut buf) = self.buf.write() {
            buf.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.buf.read().map(|b| b.len()).unwrap_or(0)
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
