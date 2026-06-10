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

/// Declare a batch of plain `AtomicU64` counters with their `inc_*` functions, the
/// `GlobalSnapshot` struct, and `global_snapshot()` in one place.
///
/// Each entry has the form:
///   `$(#[attr])* STATIC_NAME / inc_fn_name => snapshot_field_name`
///
/// Adding a new counter requires editing only this macro invocation — no manual
/// static, inc function, struct field, or snapshot initialiser to keep in sync.
macro_rules! declare_counters {
    ( $( $(#[$attr:meta])* $STATIC:ident / $fn_name:ident => $field:ident ),+ $(,)? ) => {
        $(
            $(#[$attr])*
            static $STATIC: AtomicU64 = AtomicU64::new(0);
            $(#[$attr])*
            #[inline]
            pub fn $fn_name() {
                $STATIC.fetch_add(1, Ordering::Relaxed);
            }
        )+

        pub struct GlobalSnapshot {
            $(pub $field: u64,)+
        }

        pub fn global_snapshot() -> GlobalSnapshot {
            GlobalSnapshot {
                $($field: $STATIC.load(Ordering::Relaxed),)+
            }
        }
    };
}

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

declare_counters!(
    // Incoming query counts (only incremented on unix listener paths).
    #[cfg_attr(not(unix), allow(dead_code))]
    QUERIES_UDP / inc_queries_udp => queries_udp,
    #[cfg_attr(not(unix), allow(dead_code))]
    QUERIES_TCP / inc_queries_tcp => queries_tcp,

    // DNS response cache outcomes.
    CACHE_HITS / inc_cache_hits => cache_hits,
    CACHE_MISSES / inc_cache_misses => cache_misses,
    /// Expired entry served proactively while a background refresh runs.
    CACHE_STALE_REFRESH / inc_cache_stale_refresh => cache_stale_refresh,
    /// Stale entry served as an error fallback (upstream SERVFAIL / network failure).
    CACHE_STALE_ERROR / inc_cache_stale_error => cache_stale_error,
    /// Stale entry served because upstream did not respond within stale-client-timeout.
    CACHE_STALE_CLIENT_TIMEOUT / inc_cache_stale_client_timeout => cache_stale_client_timeout,
    CACHE_REFRESH_STARTED / inc_cache_refresh_started => cache_refresh_started,
    CACHE_REFRESH_SKIPPED / inc_cache_refresh_skipped => cache_refresh_skipped,
    CACHE_REFRESH_FAILED / inc_cache_refresh_failed => cache_refresh_failed,

    // Request deduplication / load control.
    SINGLEFLIGHT_HITS / inc_singleflight_hits => singleflight_hits,
    INFLIGHT_DROPS / inc_inflight_drops => inflight_drops,
    HEDGED_QUERIES / inc_hedged_queries => hedged_queries,
    HEDGE_WINS / inc_hedge_wins => hedge_wins,

    // Routing hot-path effectiveness.
    /// Route resolved from the L1 route cache (no matcher walk).
    ROUTE_CACHE_HITS / inc_route_cache_hit => route_cache_hits,
    /// Route computed by walking the routing index (L1 miss).
    /// Updated by record_route_compute(); generated inc_route_computed() is unused.
    #[allow(dead_code)]
    ROUTE_COMPUTED / inc_route_computed => route_computed,
    /// Cumulative time for L1 misses, µs. Updated by record_route_compute().
    #[allow(dead_code)]
    ROUTE_COMPUTE_SUM_US / inc_route_compute_sum_us => route_compute_sum_us,
    /// GeoSite verdict answered from the L2 result cache.
    GEOSITE_CACHE_HITS / inc_geosite_cache_hit => geosite_cache_hits,
    /// GeoSite verdict required a full matcher walk.
    GEOSITE_WALKS / inc_geosite_walk => geosite_walks,

    // Upstream transport health.
    /// UDP responses that arrived truncated (TC=1) and were retried over TCP.
    TC_FALLBACKS / inc_tc_fallback => tc_fallbacks,
    /// UDP upstream recv loops restarted after a socket error.
    UDP_RECV_RESTARTS / inc_udp_recv_restart => udp_recv_restarts,

    // Routing decisions.
    ROUTED_NONE_RACE / inc_routed_none_race => routed_none_race,
    ROUTED_NULL / inc_routed_null => routed_null,
    ROUTED_GROUP / inc_routed_group => routed_group,
    ROUTED_AAAA_FILTERED / inc_routed_aaaa_filtered => routed_aaaa_filtered,
);

/// Record one route computation (L1 route-cache miss) and its duration.
#[inline]
pub fn record_route_compute(elapsed_us: u64) {
    ROUTE_COMPUTED.fetch_add(1, Ordering::Relaxed);
    ROUTE_COMPUTE_SUM_US.fetch_add(elapsed_us, Ordering::Relaxed);
}

// Slow-path (cache-miss) query latency histogram.
// Uses the same bucket boundaries as the upstream RTT histogram.

static QUERY_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
static QUERY_LATENCY_SUM_US: AtomicU64 = AtomicU64::new(0);
static QUERY_LATENCY_HIST: [AtomicU64; RTT_BUCKETS] =
    [const { AtomicU64::new(0) }; RTT_BUCKETS];

pub fn record_query_latency(rtt_us: u64) {
    QUERY_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
    QUERY_LATENCY_SUM_US.fetch_add(rtt_us, Ordering::Relaxed);
    let bucket = RTT_BUCKET_BOUNDS_US
        .iter()
        .position(|&bound| rtt_us < bound)
        .unwrap_or(RTT_BUCKETS - 1);
    QUERY_LATENCY_HIST[bucket].fetch_add(1, Ordering::Relaxed);
}

pub fn query_latency_snapshot() -> QueryLatencySnapshot {
    QueryLatencySnapshot {
        count: QUERY_LATENCY_COUNT.load(Ordering::Relaxed),
        sum_us: QUERY_LATENCY_SUM_US.load(Ordering::Relaxed),
        hist: std::array::from_fn(|i| QUERY_LATENCY_HIST[i].load(Ordering::Relaxed)),
    }
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
