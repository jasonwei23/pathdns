//! Native query log subsystem.
//!
//! Hot-path counters use relaxed atomics and detailed events are opt-in.
//! Detailed per-query events are opt-in: when the `querylog` config section is absent
//! and no dashboard is configured, no event channel or worker is created.
//!
//! Architecture:
//!   Hot path → `try_emit()` → bounded mpsc channel (non-blocking `try_send`)
//!   Worker task ← channel → ring buffer + optional MessagePack file rotation
//!   HTTP API reads ring buffer under a short RwLock; historical files read on demand
//!   QPS history ring sampled every second by the worker ticker

pub mod api;
pub mod ring;
pub mod worker;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

pub use ring::{EventRing, QpsRing, StatsRing};

// ── Serialization helpers ─────────────────────────────────────────────────────

/// Serialize an `IpAddr` as its string representation regardless of format.
fn ser_ip<S: serde::Serializer>(ip: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ip.to_string())
}

/// Serialize `SmallVec<[IpAddr; 4]>` as a sequence of IP strings.
fn ser_ip_list<S: serde::Serializer>(
    ips: &smallvec::SmallVec<[IpAddr; 4]>,
    s: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(ips.len()))?;
    for ip in ips {
        seq.serialize_element(&ip.to_string())?;
    }
    seq.end()
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
    pub source: &'static str, // "cache"|"upstream"|"singleflight"|"stale"|"null"
    pub group: Option<Arc<str>>,
    #[serde(serialize_with = "ser_ip_list")]
    pub answer_ips: smallvec::SmallVec<[IpAddr; 4]>,
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
    pub group: Option<String>,
    pub answer_ips: Vec<String>,
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
    pub queries_total: AtomicU64,
    pub queries_udp: AtomicU64,
    pub queries_tcp: AtomicU64,
    pub cache_hits: AtomicU64,
    pub upstream_ok: AtomicU64,
    pub upstream_err: AtomicU64,
    pub inflight_queued: AtomicU64,
    pub inflight_drops: AtomicU64,
    /// Cumulative upstream RTT sum (µs) — for average latency computation.
    pub rtt_sum_us: AtomicU64,
    pub rtt_count: AtomicU64,
    /// Number of queries that joined an existing in-flight singleflight request.
    pub singleflight_hits: AtomicU64,
    /// Number of stale responses served to clients.
    pub stale_served: AtomicU64,
    /// Number of background cache refresh tasks started.
    pub cache_refresh_started: AtomicU64,
    /// Number of cache refresh attempts that failed.
    pub cache_refresh_failed: AtomicU64,
    /// Number of hedged (speculative second) upstream queries fired.
    pub hedged_queries: AtomicU64,
    pub filtered: AtomicU64,
    pub null_responses: AtomicU64,
    pub events_enqueued: AtomicU64,
    pub events_processed: AtomicU64,
    pub events_dropped_full: AtomicU64,
    pub events_dropped_closed: AtomicU64,
    pub queue_high_watermark: AtomicU64,
    pub ring_evictions: AtomicU64,
    pub file_write_errors: AtomicU64,
}

impl QueryLogCounters {
    pub fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            queries_udp: AtomicU64::new(0),
            queries_tcp: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            upstream_ok: AtomicU64::new(0),
            upstream_err: AtomicU64::new(0),
            inflight_queued: AtomicU64::new(0),
            inflight_drops: AtomicU64::new(0),
            rtt_sum_us: AtomicU64::new(0),
            rtt_count: AtomicU64::new(0),
            singleflight_hits: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            cache_refresh_started: AtomicU64::new(0),
            cache_refresh_failed: AtomicU64::new(0),
            hedged_queries: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            null_responses: AtomicU64::new(0),
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

// ── Handle ───────────────────────────────────────────────────────────────────

/// Cheap-clone handle held by the hot path.
#[derive(Clone)]
pub struct QueryLogHandle {
    pub counters: Arc<QueryLogCounters>,
    seq: Arc<AtomicU64>,
    tx: Option<mpsc::Sender<QueryLogEvent>>,
    answer_ips: bool,
}

impl QueryLogHandle {
    /// Returns a handle where event emission is disabled (no channel).
    /// Counters are still active.
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self {
            counters: Arc::new(QueryLogCounters::new()),
            seq: Arc::new(AtomicU64::new(0)),
            tx: None,
            answer_ips: false,
        }
    }

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
        if let Some(tx) = &self.tx {
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

    /// Whether event collection is active (channel exists).
    #[inline]
    pub fn collecting(&self) -> bool {
        self.tx.is_some()
    }

    #[inline]
    pub fn collect_answer_ips(&self) -> bool {
        self.answer_ips
    }

    pub fn queue_depth(&self) -> usize {
        self.tx
            .as_ref()
            .map_or(0, |tx| tx.max_capacity().saturating_sub(tx.capacity()))
    }
}

// ── Config + constructor ──────────────────────────────────────────────────────

pub struct QueryLogConfig {
    pub enabled: bool,
    /// In-memory ring buffer capacity. 0 = no event collection (only counters).
    pub memory: usize,
    /// mpsc channel capacity.
    pub channel: usize,
    pub answer_ips: bool,
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
    pub rx: mpsc::Receiver<QueryLogEvent>,
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
            tx: None,
            answer_ips: false,
        };
        return (handle, None, qps_ring, stats_ring, shutdown_tx);
    }

    let cap = cfg.channel.max(64);
    let (tx, rx) = mpsc::channel(cap);
    let ring = Arc::new(EventRing::new(cfg.memory));

    let handle = QueryLogHandle {
        counters: counters.clone(),
        seq,
        tx: Some(tx),
        answer_ips: cfg.answer_ips,
    };
    let worker = WorkerState {
        rx,
        ring,
        counters,
        file_cfg: cfg.file,
        shutdown: shutdown_rx,
    };
    (handle, Some(worker), qps_ring, stats_ring, shutdown_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> QueryLogEvent {
        QueryLogEvent {
            seq,
            unix_micros: 0,
            client: "127.0.0.1".parse().unwrap(),
            client_port: 53,
            qname: Arc::from("example.com"),
            qtype: 1,
            rcode: 0,
            elapsed_us: 1,
            response_bytes: 32,
            source: "cache",
            group: None,
            answer_ips: smallvec::SmallVec::new(),
        }
    }

    #[test]
    fn disabled_config_has_no_event_channel() {
        let (handle, worker, _, _, _) = build(QueryLogConfig {
            enabled: false,
            memory: 1000,
            channel: 4096,
            answer_ips: false,
            file: None,
        });
        assert!(!handle.collecting());
        assert!(worker.is_none());
    }

    #[test]
    fn full_channel_is_counted_without_blocking() {
        let (handle, worker, _, _, _) = build(QueryLogConfig {
            enabled: true,
            memory: 1,
            channel: 1,
            answer_ips: false,
            file: None,
        });
        let _worker = worker.unwrap();
        for seq in 0..65 {
            handle.try_emit(event(seq));
        }
        assert_eq!(handle.counters.events_enqueued.load(Ordering::Relaxed), 64);
        assert_eq!(
            handle.counters.events_dropped_full.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn worker_drains_events_during_shutdown() {
        let (handle, worker, _, _, shutdown) = build(QueryLogConfig {
            enabled: true,
            memory: 4,
            channel: 64,
            answer_ips: false,
            file: None,
        });
        let worker = worker.unwrap();
        let ring = worker.ring.clone();
        let counters = handle.counters.clone();
        let task = tokio::spawn(crate::querylog::worker::run(
            worker.rx,
            worker.ring,
            worker.counters,
            worker.file_cfg,
            worker.shutdown,
        ));
        handle.try_emit(event(0));
        handle.try_emit(event(1));
        handle.try_emit(event(2));
        shutdown.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(ring.len(), 3);
        assert_eq!(counters.events_processed.load(Ordering::Relaxed), 3);
    }
}
