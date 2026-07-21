//! Native query log subsystem.
//!
//! Hot-path counters use relaxed atomics and detailed events are opt-in.
//! Detailed per-query events are opt-in: when the `querylog` config section is absent
//! and no dashboard is configured, no event channel or worker is created.
//!
//! Architecture:
//!   Hot path → `try_emit()` → per-shard bounded mpsc channel (non-blocking `try_send`)
//!   Worker task ← channels → ring buffer + optional MessagePack file rotation
//!   HTTP API reads ring buffer under a short RwLock; historical files read on demand
//!   QPS history ring sampled every second by the worker ticker
//!
//! The event channel is *sharded* — one bounded mpsc per shard, and each
//! producer thread sends only to its own shard (assigned once via a thread-local).
//! A single-shared `mpsc::Sender` serialises every logging worker thread on one
//! atomic permit counter; at high QPS that contention showed up as a measurable
//! throughput tax. Sharding gives each thread its own channel head, so producers
//! never contend. The consumer stays a single worker task (ring push + the
//! single-writer segment file must remain serial) that drains all shards.

pub mod api;
pub mod ring;
pub mod worker;

use std::cell::Cell;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Hands out a stable, process-wide-monotonic id to each thread the first time
/// it logs an event; `id % shards` is the thread's channel shard. With
/// `shards == worker-threads` the runtime's worker threads land on distinct
/// shards, so producers never share a channel head.
static SHARD_COUNTER: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static SHARD_ID: Cell<usize> = Cell::new(SHARD_COUNTER.fetch_add(1, Ordering::Relaxed));
}

#[inline]
fn thread_shard(shards: usize) -> usize {
    SHARD_ID.with(|s| s.get()) % shards
}

pub use ring::{EventRing, QpsRing, StatsRing};

// ── Serialization helpers ─────────────────────────────────────────────────────

/// Serialize an `IpAddr` as its string representation regardless of format.
fn ser_ip<S: serde::Serializer>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ip.to_string())
}

// ── Event ────────────────────────────────────────────────────────────────────

/// One completed DNS query, ready for the log worker.
/// All expensive formatting (timestamps, IP→string) is deferred to the worker.
#[derive(serde::Serialize)]
pub struct QueryLogEvent {
    pub seq: u64,
    /// Microseconds since Unix epoch.
    pub unix_micros: u64,
    #[serde(serialize_with = "ser_ip")]
    pub client: IpAddr,
    pub client_port: u16,
    pub qname: Arc<str>,
    pub qtype: u16,
    pub rcode: u8,
    pub elapsed_us: u64,
    pub response_bytes: u32,
    pub source: &'static str, // "cache"|"upstream"|"singleflight"|"filtered"|"forwarded"|"overload"
    /// The upstream (`route.servers` entry, or `final-><name>`) that answered
    /// this query — see `router::RouteTarget::upstream_name_arc`.
    pub upstream: Option<Arc<str>>,
}

/// Owned counterpart of `QueryLogEvent` — used when decoding historical
/// MessagePack log files back into JSON for the API.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DecodedEvent {
    pub seq: u64,
    pub unix_micros: u64,
    pub client: String,
    pub client_port: u16,
    pub qname: String,
    pub qtype: u16,
    pub rcode: u8,
    pub elapsed_us: u64,
    pub response_bytes: u32,
    pub source: String,
    pub upstream: Option<String>,
}

/// Return current Unix time as microseconds since epoch — cheap, no alloc.
#[inline]
pub fn unix_micros_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

// ── Counters ─────────────────────────────────────────────────────────────────

/// Hot-path counters — always incremented, never blocked.
pub struct QueryLogCounters {
    pub queries_udp: AtomicU64,
    pub queries_tcp: AtomicU64,
    pub cache_hits: AtomicU64,
    pub upstream_ok: AtomicU64,
    pub upstream_err: AtomicU64,
    pub inflight_queued: AtomicU64,
    pub inflight_drops: AtomicU64,
    /// Queries that SERVFAIL'd because a chosen upstream's per-upstream inflight
    /// cap (`runtime.upstream-max-inflight`) was saturated. A persistently rising
    /// value means the cap is the throughput bottleneck — raise it.
    pub upstream_inflight_drops: AtomicU64,
    /// UDP datagrams silently dropped because they exceeded MAX_PKT (MSG_TRUNC).
    pub udp_truncated: AtomicU64,
    /// UDP responses dropped because of send backpressure or a permanent send error.
    pub udp_send_drops: AtomicU64,
    /// Non-transient errors returned by sendmmsg.
    pub udp_send_errors: AtomicU64,
    /// Datagrams the kernel dropped on the listen socket because the receive buffer
    /// overflowed before userspace read them (reported via SO_RXQ_OVFL).
    pub udp_rx_overflow: AtomicU64,
    /// Rolling peak UDP receive-buffer occupancy (percent of rcvbuf, via SO_MEMINFO),
    /// accumulated by the recv loops with fetch_max and reset each second.
    pub udp_rmem_pct_acc: AtomicU32,
    /// Last completed 1-second peak of `udp_rmem_pct_acc`; what the dashboard reads.
    pub udp_rmem_pct: AtomicU32,
    /// Rolling peak kernel→userspace UDP receive latency in µs (SO_TIMESTAMPNS:
    /// kernel-stamp to drain time), accumulated with fetch_max and reset each second.
    pub udp_recv_lat_us_acc: AtomicU32,
    /// Last completed 1-second peak of `udp_recv_lat_us_acc`; surfaces scheduling jitter.
    pub udp_recv_lat_us: AtomicU32,
    /// Cumulative upstream RTT sum (µs) — for average latency computation.
    pub rtt_sum_us: AtomicU64,
    pub rtt_count: AtomicU64,
    /// Number of queries that joined an existing in-flight singleflight request.
    pub singleflight_hits: AtomicU64,
    /// Number of hedged (speculative second) upstream queries fired.
    pub hedged_queries: AtomicU64,
    pub filtered: AtomicU64,
    pub events_enqueued: AtomicU64,
    pub events_processed: AtomicU64,
    pub events_dropped_full: AtomicU64,
    pub events_dropped_closed: AtomicU64,
    pub queue_high_watermark: AtomicU64,
    pub ring_evictions: AtomicU64,
    pub file_write_errors: AtomicU64,
}

impl QueryLogCounters {
    /// Total received queries, derived from the per-protocol counters instead
    /// of a third hot-path atomic. Reads of the two counters are not a single
    /// snapshot, but a ±1 skew between two relaxed reads is irrelevant for a
    /// monotonically growing statistic.
    pub fn queries_total(&self) -> u64 {
        self.queries_udp.load(Ordering::Relaxed) + self.queries_tcp.load(Ordering::Relaxed)
    }

    pub fn new() -> Self {
        Self {
            queries_udp: AtomicU64::new(0),
            queries_tcp: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            upstream_ok: AtomicU64::new(0),
            upstream_err: AtomicU64::new(0),
            inflight_queued: AtomicU64::new(0),
            inflight_drops: AtomicU64::new(0),
            upstream_inflight_drops: AtomicU64::new(0),
            udp_truncated: AtomicU64::new(0),
            udp_send_drops: AtomicU64::new(0),
            udp_send_errors: AtomicU64::new(0),
            udp_rx_overflow: AtomicU64::new(0),
            udp_rmem_pct_acc: AtomicU32::new(0),
            udp_rmem_pct: AtomicU32::new(0),
            udp_recv_lat_us_acc: AtomicU32::new(0),
            udp_recv_lat_us: AtomicU32::new(0),
            rtt_sum_us: AtomicU64::new(0),
            rtt_count: AtomicU64::new(0),
            singleflight_hits: AtomicU64::new(0),
            hedged_queries: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            events_enqueued: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
            events_dropped_full: AtomicU64::new(0),
            events_dropped_closed: AtomicU64::new(0),
            queue_high_watermark: AtomicU64::new(0),
            ring_evictions: AtomicU64::new(0),
            file_write_errors: AtomicU64::new(0),
        }
    }
}

impl Default for QueryLogCounters {
    fn default() -> Self {
        Self::new()
    }
}

// ── Handle ───────────────────────────────────────────────────────────────────

/// Cheap-clone handle held by the hot path.
#[derive(Clone)]
pub struct QueryLogHandle {
    pub counters: Arc<QueryLogCounters>,
    seq: Arc<AtomicU64>,
    /// One bounded channel per shard; `None` when collection is disabled. Each
    /// producer thread sends only to `txs[thread_shard(txs.len())]`.
    txs: Option<Arc<[mpsc::Sender<QueryLogEvent>]>>,
}

impl QueryLogHandle {
    /// Returns the next monotonically increasing sequence number.
    #[inline]
    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Reserve channel capacity before constructing an event.
    #[inline]
    pub fn try_emit_with<F>(&self, build: F)
    where
        F: FnOnce(u64) -> QueryLogEvent,
    {
        if let Some(txs) = &self.txs {
            // Send to this thread's own shard so producers never contend on a
            // shared channel head.
            let tx = &txs[thread_shard(txs.len())];
            match tx.try_reserve() {
                Ok(permit) => {
                    let seq = self.next_seq();
                    permit.send(build(seq));
                    let depth = tx.max_capacity().saturating_sub(tx.capacity()) as u64;
                    self.counters
                        .queue_high_watermark
                        .fetch_max(depth, Ordering::Relaxed);
                    self.counters
                        .events_enqueued
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Full(())) => {
                    self.counters
                        .events_dropped_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(())) => {
                    self.counters
                        .events_dropped_closed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Whether event collection is active (channels exist).
    #[inline]
    pub fn collecting(&self) -> bool {
        self.txs.is_some()
    }

    /// Total events currently buffered across all shards (used for a stat).
    pub fn queue_depth(&self) -> usize {
        self.txs.as_ref().map_or(0, |txs| {
            txs.iter()
                .map(|tx| tx.max_capacity().saturating_sub(tx.capacity()))
                .sum()
        })
    }
}

// ── Config + constructor ──────────────────────────────────────────────────────

pub struct QueryLogConfig {
    pub enabled: bool,
    /// In-memory ring buffer capacity. 0 = no event collection (only counters).
    pub memory: usize,
    /// Total mpsc channel capacity, split across shards.
    pub channel: usize,
    /// Number of producer-side channel shards (typically the worker-thread
    /// count). Clamped to a sane range in `build`.
    pub shards: usize,
    pub file: Option<QueryLogFileConfig>,
}

pub struct QueryLogFileConfig {
    pub dir: std::path::PathBuf,
    /// Rotate the active segment when it exceeds this size in MiB.
    pub max_mb: u64,
    /// Maximum number of completed (compressed) segments to retain.
    pub max_segments: usize,
    /// Maximum events to batch into a single write call.
    pub batch_size: usize,
    /// How often to flush the OS buffer (milliseconds).
    pub flush_interval_ms: u64,
    /// Delete compressed segments older than this many days. `None` = no age limit.
    pub retention_days: Option<u32>,
    /// Gzip-compress segments after rotation.
    pub compress: bool,
}

pub struct WorkerState {
    /// One receiver per shard; the worker drains all of them.
    pub rxs: Vec<mpsc::Receiver<QueryLogEvent>>,
    pub ring: Arc<EventRing>,
    pub counters: Arc<QueryLogCounters>,
    pub file_cfg: Option<QueryLogFileConfig>,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
}

/// Build a `QueryLogHandle` + optional worker state from config.
/// Returns `(handle, None)` when collection is disabled (memory=0, no file, no bind).
pub fn build(
    cfg: QueryLogConfig,
) -> (
    QueryLogHandle,
    Option<WorkerState>,
    Arc<QpsRing>,
    Arc<StatsRing>,
    tokio::sync::watch::Sender<bool>,
) {
    let counters = Arc::new(QueryLogCounters::new());
    let seq = Arc::new(AtomicU64::new(0));
    let qps_ring = Arc::new(QpsRing::new());
    let stats_ring = Arc::new(StatsRing::new());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let collect = cfg.enabled && (cfg.memory > 0 || cfg.file.is_some());
    if !collect {
        let handle = QueryLogHandle {
            counters,
            seq,
            txs: None,
        };
        return (handle, None, qps_ring, stats_ring, shutdown_tx);
    }

    // Split the configured channel capacity across shards; each shard keeps a
    // usable floor so a large shard count can't starve any single channel.
    let shards = cfg.shards.clamp(1, 32);
    let per_shard = (cfg.channel.max(64) / shards).max(16);
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..shards).map(|_| mpsc::channel(per_shard)).unzip();
    let ring = Arc::new(EventRing::new(cfg.memory));

    let handle = QueryLogHandle {
        counters: counters.clone(),
        seq,
        txs: Some(txs.into()),
    };
    let worker = WorkerState {
        rxs,
        ring,
        counters,
        file_cfg: cfg.file,
        shutdown: shutdown_rx,
    };
    (handle, Some(worker), qps_ring, stats_ring, shutdown_tx)
}
