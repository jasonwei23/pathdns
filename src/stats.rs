//! Lightweight runtime metrics for DNS query processing.
//!
//! All counters are `AtomicU64` with `Relaxed` ordering; exact ordering between counters
//! is not required; what matters is monotonically increasing totals visible to the metrics
//! scraper with at most one-scrape lag.
//!
//! Per-upstream statistics (RTT histogram, inflight count, error breakdown) live in
//! `NodeStats`, which is embedded in each upstream node.  The metrics renderer in
//! `metrics.rs` collects snapshots from all nodes at scrape time.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// RTT histogram configuration.
// 11 finite bucket boundaries (in microseconds) + 1 overflow bucket = 12 total.
// Boundaries are chosen to cover the 1 ms to 5 s range that typical DNS upstreams hit.
pub const RTT_BUCKET_BOUNDS_US: &[u64] = &[
    1_000,     // 0.001 s
    5_000,     // 0.005 s
    10_000,    // 0.010 s
    25_000,    // 0.025 s
    50_000,    // 0.050 s
    100_000,   // 0.100 s
    250_000,   // 0.250 s
    500_000,   // 0.500 s
    1_000_000, // 1.000 s
    2_500_000, // 2.500 s
    5_000_000, // 5.000 s
];
pub const RTT_BUCKETS: usize = 12; // 11 bounds + overflow

// Global counters.

static QUERIES_UDP: AtomicU64 = AtomicU64::new(0);
static QUERIES_TCP: AtomicU64 = AtomicU64::new(0);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
/// Expired entry served proactively from get() while a background refresh runs.
static CACHE_STALE_REFRESH: AtomicU64 = AtomicU64::new(0);
/// Stale entry served as an error fallback (upstream SERVFAIL / network failure).
static CACHE_STALE_ERROR: AtomicU64 = AtomicU64::new(0);
/// Stale entry served because upstream did not respond within stale-client-timeout.
static CACHE_STALE_CLIENT_TIMEOUT: AtomicU64 = AtomicU64::new(0);
static CACHE_REFRESH_STARTED: AtomicU64 = AtomicU64::new(0);
static CACHE_REFRESH_SKIPPED: AtomicU64 = AtomicU64::new(0);
static CACHE_REFRESH_FAILED: AtomicU64 = AtomicU64::new(0);
static SINGLEFLIGHT_HITS: AtomicU64 = AtomicU64::new(0);
static INFLIGHT_DROPS: AtomicU64 = AtomicU64::new(0);
static HEDGED_QUERIES: AtomicU64 = AtomicU64::new(0);
static HEDGE_WINS: AtomicU64 = AtomicU64::new(0);
static GEOSITE_RELOAD_OK: AtomicU64 = AtomicU64::new(0);
static GEOSITE_RELOAD_ERR: AtomicU64 = AtomicU64::new(0);

// Routing decision counters.

static ROUTED_NONE_RACE: AtomicU64 = AtomicU64::new(0);
static ROUTED_NULL: AtomicU64 = AtomicU64::new(0);
static ROUTED_GROUP: AtomicU64 = AtomicU64::new(0);
static ROUTED_AAAA_FILTERED: AtomicU64 = AtomicU64::new(0);

// Slow-path (cache-miss) query latency histogram.
// Uses the same bucket boundaries as the upstream RTT histogram.

static QUERY_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static QUERY_LATENCY_SUM_US: AtomicU64 = AtomicU64::new(0);
static QUERY_LATENCY_HIST: [AtomicU64; RTT_BUCKETS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; RTT_BUCKETS]
};

#[inline]
#[cfg_attr(not(unix), allow(dead_code))] // only called from listener.rs which is #[cfg(unix)]
pub fn inc_queries_udp() {
    QUERIES_UDP.fetch_add(1, Ordering::Relaxed);
}
#[inline]
#[cfg_attr(not(unix), allow(dead_code))] // only called from listener.rs which is #[cfg(unix)]
pub fn inc_queries_tcp() {
    QUERIES_TCP.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_hits() {
    CACHE_HITS.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_misses() {
    CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_stale_refresh() {
    CACHE_STALE_REFRESH.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_stale_error() {
    CACHE_STALE_ERROR.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_stale_client_timeout() {
    CACHE_STALE_CLIENT_TIMEOUT.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_refresh_started() {
    CACHE_REFRESH_STARTED.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_refresh_skipped() {
    CACHE_REFRESH_SKIPPED.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cache_refresh_failed() {
    CACHE_REFRESH_FAILED.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_singleflight_hits() {
    SINGLEFLIGHT_HITS.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_inflight_drops() {
    INFLIGHT_DROPS.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_hedged_queries() {
    HEDGED_QUERIES.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_hedge_wins() {
    HEDGE_WINS.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_geosite_reload_ok() {
    GEOSITE_RELOAD_OK.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_geosite_reload_err() {
    GEOSITE_RELOAD_ERR.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn inc_routed_none_race() {
    ROUTED_NONE_RACE.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_routed_null() {
    ROUTED_NULL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_routed_group() {
    ROUTED_GROUP.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_routed_aaaa_filtered() {
    ROUTED_AAAA_FILTERED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_query_latency(rtt_us: u64) {
    QUERY_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
    QUERY_LATENCY_SUM_US.fetch_add(rtt_us, Ordering::Relaxed);
    let bucket = RTT_BUCKET_BOUNDS_US
        .iter()
        .position(|&bound| rtt_us < bound)
        .unwrap_or(RTT_BUCKETS - 1);
    QUERY_LATENCY_HIST[bucket].fetch_add(1, Ordering::Relaxed);
}

/// Read all global counters as a snapshot for rendering.
pub fn global_snapshot() -> GlobalSnapshot {
    GlobalSnapshot {
        queries_udp: QUERIES_UDP.load(Ordering::Relaxed),
        queries_tcp: QUERIES_TCP.load(Ordering::Relaxed),
        cache_hits: CACHE_HITS.load(Ordering::Relaxed),
        cache_misses: CACHE_MISSES.load(Ordering::Relaxed),
        cache_stale_refresh: CACHE_STALE_REFRESH.load(Ordering::Relaxed),
        cache_stale_error: CACHE_STALE_ERROR.load(Ordering::Relaxed),
        cache_stale_client_timeout: CACHE_STALE_CLIENT_TIMEOUT.load(Ordering::Relaxed),
        cache_refresh_started: CACHE_REFRESH_STARTED.load(Ordering::Relaxed),
        cache_refresh_skipped: CACHE_REFRESH_SKIPPED.load(Ordering::Relaxed),
        cache_refresh_failed: CACHE_REFRESH_FAILED.load(Ordering::Relaxed),
        singleflight_hits: SINGLEFLIGHT_HITS.load(Ordering::Relaxed),
        inflight_drops: INFLIGHT_DROPS.load(Ordering::Relaxed),
        hedged_queries: HEDGED_QUERIES.load(Ordering::Relaxed),
        hedge_wins: HEDGE_WINS.load(Ordering::Relaxed),
        geosite_reload_ok: GEOSITE_RELOAD_OK.load(Ordering::Relaxed),
        geosite_reload_err: GEOSITE_RELOAD_ERR.load(Ordering::Relaxed),
        routed_none_race: ROUTED_NONE_RACE.load(Ordering::Relaxed),
        routed_null: ROUTED_NULL.load(Ordering::Relaxed),
        routed_group: ROUTED_GROUP.load(Ordering::Relaxed),
        routed_aaaa_filtered: ROUTED_AAAA_FILTERED.load(Ordering::Relaxed),
    }
}

pub fn query_latency_snapshot() -> QueryLatencySnapshot {
    QueryLatencySnapshot {
        count: QUERY_LATENCY_COUNT.load(Ordering::Relaxed),
        sum_us: QUERY_LATENCY_SUM_US.load(Ordering::Relaxed),
        hist: std::array::from_fn(|i| QUERY_LATENCY_HIST[i].load(Ordering::Relaxed)),
    }
}

pub struct GlobalSnapshot {
    pub queries_udp: u64,
    pub queries_tcp: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_stale_refresh: u64,
    pub cache_stale_error: u64,
    pub cache_stale_client_timeout: u64,
    pub cache_refresh_started: u64,
    pub cache_refresh_skipped: u64,
    pub cache_refresh_failed: u64,
    pub singleflight_hits: u64,
    pub inflight_drops: u64,
    pub hedged_queries: u64,
    pub hedge_wins: u64,
    pub geosite_reload_ok: u64,
    pub geosite_reload_err: u64,
    pub routed_none_race: u64,
    pub routed_null: u64,
    pub routed_group: u64,
    pub routed_aaaa_filtered: u64,
}

pub struct QueryLatencySnapshot {
    pub count: u64,
    pub sum_us: u64,
    pub hist: [u64; RTT_BUCKETS],
}

// Per-upstream node statistics.

/// Per-upstream-node statistics.  Embedded in each `UpstreamNode`.
/// All fields use `Relaxed` atomics; approximate totals are sufficient for metrics.
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
    /// Cumulative RTT sum in microseconds (for histogram _sum label).
    pub rtt_sum_us: AtomicU64,
    /// Non-cumulative count per RTT bucket.
    pub rtt_hist: [AtomicU64; RTT_BUCKETS],
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
            rtt_hist: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub fn record_ok(&self, rtt_us: u64) {
        self.queries_ok.fetch_add(1, Ordering::Relaxed);
        self.rtt_sum_us.fetch_add(rtt_us, Ordering::Relaxed);
        let bucket = RTT_BUCKET_BOUNDS_US
            .iter()
            .position(|&bound| rtt_us < bound)
            .unwrap_or(RTT_BUCKETS - 1);
        self.rtt_hist[bucket].fetch_add(1, Ordering::Relaxed);
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
    pub fn snapshot(&self, name: &str) -> NodeStatsSnapshot {
        let hist: [u64; RTT_BUCKETS] =
            std::array::from_fn(|i| self.rtt_hist[i].load(Ordering::Relaxed));
        NodeStatsSnapshot {
            name: name.to_string(),
            queries_ok: self.queries_ok.load(Ordering::Relaxed),
            queries_err: self.queries_err.load(Ordering::Relaxed),
            queries_timeout: self.queries_timeout.load(Ordering::Relaxed),
            queries_cancelled: self.queries_cancelled.load(Ordering::Relaxed),
            active_inflight: self.active_inflight.load(Ordering::Relaxed),
            rtt_sum_us: self.rtt_sum_us.load(Ordering::Relaxed),
            rtt_hist: hist,
        }
    }
}

impl Default for NodeStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of one upstream node's stats, ready for Prometheus rendering.
pub struct NodeStatsSnapshot {
    pub name: String,
    pub queries_ok: u64,
    pub queries_err: u64,
    pub queries_timeout: u64,
    pub queries_cancelled: u64,
    pub active_inflight: i64,
    pub rtt_sum_us: u64,
    pub rtt_hist: [u64; RTT_BUCKETS],
}

impl NodeStatsSnapshot {
    /// Total RTT observation count.
    pub fn rtt_count(&self) -> u64 {
        self.rtt_hist.iter().sum()
    }
}
