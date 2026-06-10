//! Per-upstream node statistics used by selection and the dashboard.
//!
//! Global counters have been moved to `querylog::QueryLogCounters` which the hot
//! path increments directly. Only `NodeStats` (used for upstream EWMA scoring and
//! selection) and its snapshot type remain here.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// Per-upstream node statistics.

/// Per-upstream-node statistics.  Embedded in each `UpstreamNode`.
/// All fields use `Relaxed` atomics; approximate totals are sufficient for selection and display.
pub struct NodeStats {
    pub queries_ok: AtomicU64,
    /// All upstream errors (network failures, timeouts, etc.).
    pub queries_err: AtomicU64,
    /// Timeout-specific subset of `queries_err`.
    pub queries_timeout: AtomicU64,
    /// Queries cancelled mid-flight when a hedge partner responded first.
    pub queries_cancelled: AtomicU64,
    /// Currently in-flight queries on this node (tracked for selection scoring).
    pub active_inflight: AtomicI64,
    /// Cumulative RTT sum in microseconds.
    pub rtt_sum_us: AtomicU64,
}

impl NodeStats {
    pub fn new() -> Self {
        Self {
            queries_ok: AtomicU64::new(0),
            queries_err: AtomicU64::new(0),
            queries_timeout: AtomicU64::new(0),
            queries_cancelled: AtomicU64::new(0),
            active_inflight: AtomicI64::new(0),
            rtt_sum_us: AtomicU64::new(0),
        }
    }

    pub fn record_ok(&self, rtt_us: u64) {
        self.queries_ok.fetch_add(1, Ordering::Relaxed);
        self.rtt_sum_us.fetch_add(rtt_us, Ordering::Relaxed);
    }

    pub fn record_err(&self) {
        self.queries_err.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a timeout error: increments both the general error counter and the
    /// timeout-specific counter so callers can compute non-timeout error rates.
    pub fn record_timeout(&self) {
        self.queries_err.fetch_add(1, Ordering::Relaxed);
        self.queries_timeout.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a hedge cancellation: the exchange was in-flight but dropped because
    /// the hedge partner responded first.  Does not count as an error.
    pub fn record_cancelled(&self) {
        self.queries_cancelled.fetch_add(1, Ordering::Relaxed);
    }

    /// Read all fields as a point-in-time snapshot for rendering.
    pub fn snapshot(&self, name: &str, addr: &str) -> NodeStatsSnapshot {
        NodeStatsSnapshot {
            name: name.to_string(),
            addr: addr.to_string(),
            queries_ok: self.queries_ok.load(Ordering::Relaxed),
            queries_err: self.queries_err.load(Ordering::Relaxed),
            queries_timeout: self.queries_timeout.load(Ordering::Relaxed),
            queries_cancelled: self.queries_cancelled.load(Ordering::Relaxed),
            active_inflight: self.active_inflight.load(Ordering::Relaxed),
            rtt_sum_us: self.rtt_sum_us.load(Ordering::Relaxed),
        }
    }
}

impl Default for NodeStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of one upstream node's stats.
pub struct NodeStatsSnapshot {
    pub name: String,
    pub addr: String,
    pub queries_ok: u64,
    pub queries_err: u64,
    pub queries_timeout: u64,
    pub queries_cancelled: u64,
    pub active_inflight: i64,
    pub rtt_sum_us: u64,
}

impl NodeStatsSnapshot {
    pub fn rtt_count(&self) -> u64 {
        self.queries_ok
    }
}
