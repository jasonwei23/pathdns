//! Upstream DNS transport: UDP socket pool, TCP/TLS mux, and EWMA+inflight selection.
//!
//! # UDP
//! Each UDP upstream owns a pool of N bound sockets (`runtime.upstream-udp-sockets`,
//! default `max(worker-threads, 32)`).
//! Sends are distributed round-robin across the pool; each socket has its own recv loop.
//! All sockets share one in-flight `DashMap` and one ID counter so IDs are globally unique
//! per pool, preventing aliasing in the shared table.
//!
//! # TCP / DoT (TLS)
//! `TcpMux` maintains a single long-lived connection per upstream node and multiplexes all
//! concurrent queries over it by DNS ID.  A generation counter lets background reader tasks
//! exit cleanly after a reconnect.  `TCP_NODELAY` is always enabled.
//! DoT (DNS-over-TLS, RFC 7858) reuses the same mux path with a `tokio-rustls` stream.
//!
//! # Node selection
//! `UpstreamPool::exchange` scores each node as EWMA RTT × (1 + active_inflight) and
//! picks pseudo-randomly among all nodes within a band of the best score
//! (Unbound-style RTT banding): near-equal nodes share load, keeping their RTT
//! estimates fresh and providing warm failover targets.  Failover is driven purely
//! by the RTT estimate: a failure doubles it (Unbound-style backoff) so banding
//! steers traffic away after the first error, while `probe_interval` periodically
//! re-routes one query to the least-recently-selected node so a recovered upstream
//! is re-measured and rejoins.  The first success after failures adopts the fresh
//! RTT sample directly for fast recovery.
//!
//! # Truncated UDP responses
//! A UDP response with TC=1 triggers an automatic one-shot TCP retry.

#[cfg(feature = "doh")]
mod doh;
mod inflight;
pub(crate) use inflight::InflightCapReached;
#[cfg(any(feature = "doq", feature = "h3"))]
mod quic;
mod tcp_mux;
mod udp;

use crate::config::{EcsMode, UpstreamConfig, UpstreamEndpoint, UpstreamProto};
use crate::dns;
use crate::stats::{NodeStats, NodeStatsSnapshot};
use crate::sys;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
#[cfg(feature = "doh")]
use doh::DoHUpstream;
#[cfg(feature = "doq")]
use quic::DoQUpstream;
#[cfg(feature = "h3")]
use quic::H3Upstream;
#[cfg(feature = "dot")]
use rustls::pki_types::ServerName;
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tcp_mux::{MuxConnector, TcpMux};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use udp::UdpUpstream;

/// Additive band floor in microseconds so sub-millisecond scores are treated as equal.
const SELECT_BAND_FLOOR_US: u64 = 2_000;
/// RTT estimate applied on failure when the node has no RTT data yet.
const FAILURE_RTT_FLOOR_US: u64 = 50_000;
/// Upper bound for the failure-inflated RTT estimate (10 s).
const FAILURE_RTT_CAP_US: u64 = 10_000_000;
/// Score multiplier applied to a node when active_inflight ≥ its AIMD concurrency window.
/// Deprioritises congestion-signalled nodes in banded selection without blocking them
/// outright (the hard semaphore cap enforced by InflightRegistry handles that).
const CONGESTION_SCORE_FACTOR: u64 = 4;
/// Force-probe the least-recently-selected eligible node every N upstream selections.
const PROBE_INTERVAL: u64 = 100;
/// Banded selection factor: nodes within this multiple of the best score share traffic.
const SELECT_BAND_FACTOR: u64 = 2;
/// Multiplier applied to a healthy primary's own EWMA RTT to derive its hedge-trigger
/// delay, so the hedge fires relative to how fast *this* upstream normally answers
/// instead of one fixed delay shared by every node — a fast node hides its tail
/// latency sooner, a naturally slower-but-healthy node isn't hedged against
/// prematurely. Picked so the hedge is a "safely late" event well past a healthy
/// node's typical RTT, not a coin-flip race against its own normal response time.
const HEDGE_RTT_MULTIPLIER: u64 = 3;
/// Floor on the RTT-derived hedge delay, so a very fast (or just-reset, near-zero)
/// RTT estimate can't make the hedge fire near-instantly and turn every query into
/// a de-facto broadcast to every upstream.
const HEDGE_MIN_DELAY: Duration = Duration::from_millis(2);

/// Upper score bound for banded selection.  Nodes scoring at or below this limit
/// are considered interchangeable with the best node: `best × factor`,
/// with an additive floor so microsecond-scale scores (LAN resolvers, untested
/// nodes) are all treated as equal rather than split by measurement noise.
fn band_limit(best: u64, factor: u64, floor: u64) -> u64 {
    best.saturating_mul(factor).max(best.saturating_add(floor))
}

pub(super) fn now_ms() -> u64 {
    // Use a process-start Instant as epoch so TCP reconnect backoff is immune to NTP jumps.
    // On OpenWrt (CLOCK_MONOTONIC resets on reboot), this is always monotonic within a
    // single process run, which is all we need.
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Rate-limits and de-duplicates a "force refresh the connection(s)" action shared
/// by `UdpUpstream::trigger_refresh` and `TcpMux::force_reconnect`: both used to
/// hand-roll the same cooldown-timestamp + CAS-reentrancy-guard pair.
#[derive(Debug, Default)]
pub(super) struct RefreshGuard {
    /// Epoch-ms before which another refresh attempt is rejected.
    not_before_ms: AtomicU64,
    /// Guards against triggering more than one refresh concurrently.
    in_progress: std::sync::atomic::AtomicBool,
}

impl RefreshGuard {
    /// Claim the right to run a refresh now, or reject it: still cooling down
    /// from a previous refresh, or one is already in flight. On success, the
    /// caller is responsible for calling [`Self::finish`] once its refresh
    /// work completes (typically from the spawned task doing that work).
    pub(super) fn try_begin(&self, cooldown_ms: u64) -> bool {
        let now = now_ms();
        if now < self.not_before_ms.load(Ordering::Relaxed) {
            return false;
        }
        if self
            .in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        self.not_before_ms.store(now + cooldown_ms, Ordering::Relaxed);
        true
    }

    /// Release the in-flight guard claimed by a successful [`Self::try_begin`].
    pub(super) fn finish(&self) {
        self.in_progress.store(false, Ordering::Release);
    }
}

/// Shared connection-cache mechanics for the persistent-connection upstream
/// transports (DoQ/H3's `quinn::Connection`, DoH's `h2::client::SendRequest`),
/// which each independently hand-rolled the same `Mutex<Option<C>>`
/// get-or-connect + evict-if-unhealthy shape around a different health check
/// (quinn's `close_reason()` is a synchronous predicate; h2's `ready()` is an
/// async probe that consumes its receiver, so its `is_healthy` closure clones
/// internally) — `is_healthy` abstracts over that difference.
///
/// Both [`Self::get_or_connect`] and [`Self::evict_if_unhealthy`] hold their
/// lock continuously across the health check, including through the `.await`.
/// That's deliberate, not incidental: dropping and re-acquiring the lock
/// between checking and clearing would open a window where a concurrent
/// `get_or_connect` installs a fresh, healthy connection that this stale
/// check then evicts anyway (the exact TOCTOU shape fixed elsewhere in this
/// module's siblings — see `tcp_mux.rs::disconnect`). Holding the lock across
/// the health check is what makes that race structurally impossible here:
/// every caller goes through this same choke point, so there's no way to
/// call it in a way that reopens the window.
#[cfg(any(feature = "doh", feature = "doq", feature = "h3"))]
pub(super) struct ConnSlot<C>(tokio::sync::Mutex<Option<C>>);

#[cfg(any(feature = "doh", feature = "doq", feature = "h3"))]
impl<C: Clone> ConnSlot<C> {
    pub(super) fn new() -> Self {
        Self(tokio::sync::Mutex::new(None))
    }

    /// Return the existing connection if `is_healthy` accepts it, otherwise
    /// await `connect` to establish a fresh one and store it.
    pub(super) async fn get_or_connect<H, HFut>(
        &self,
        is_healthy: H,
        connect: impl std::future::Future<Output = Result<C>>,
    ) -> Result<C>
    where
        H: FnOnce(&C) -> HFut,
        HFut: std::future::Future<Output = bool>,
    {
        let mut guard = self.0.lock().await;
        if let Some(c) = guard.as_ref() {
            if is_healthy(c).await {
                return Ok(c.clone());
            }
        }
        let c = connect.await?;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Clear the stored connection if `is_healthy` rejects it. A no-op if the
    /// slot is already empty.
    pub(super) async fn evict_if_unhealthy<H, HFut>(&self, is_healthy: H)
    where
        H: FnOnce(&C) -> HFut,
        HFut: std::future::Future<Output = bool>,
    {
        let mut guard = self.0.lock().await;
        if let Some(c) = guard.as_ref() {
            if !is_healthy(c).await {
                *guard = None;
            }
        }
    }
}

/// Seed the upstream query-ID counter from the current time.
/// XORs whole seconds with sub-second nanoseconds so the seed is different on
/// every process start even when two restarts happen within the same second.
pub(super) fn random_id_seed() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() as u32) ^ d.subsec_nanos())
        .unwrap_or(0xdeadbeef)
}

/// Map a sequential counter value to a pseudo-random 16-bit DNS query ID.
///
/// Uses a finalizer mix (Murmur3-style) so that consecutive counter values
/// produce outputs that are uniformly scattered across [1, 65535]. An attacker
/// who observes one upstream query ID cannot predict future IDs without knowing
/// the seed.  Avoids 0 because DNS reserves query ID 0 for no practical purpose
/// and several implementations reject it.
#[inline]
pub(super) fn mix16(x: u32) -> u16 {
    let x = x.wrapping_mul(0x45d9f3b);
    let x = x ^ (x >> 16);
    let id = x as u16;
    if id == 0 {
        1
    } else {
        id
    }
}

/// Acquire one permit from an upstream's inflight semaphore, bounded by its
/// query timeout. Shared by every transport that enforces `upstream-max-inflight`
/// via a plain `Semaphore` (DoH, DoQ, H3 — UDP and TCP/TLS mux enforce their cap
/// through `InflightRegistry` instead, which has no separate semaphore to acquire).
#[cfg(any(feature = "doh", feature = "doq", feature = "h3"))]
pub(super) async fn acquire_inflight_permit(
    sem: &Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    name: &str,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    tokio::time::timeout(timeout, sem.clone().acquire_owned())
        .await
        .map_err(|e| {
            anyhow::Error::from(e).context(format!("upstream {name}: inflight wait timeout"))
        })?
        .map_err(|_| anyhow!("upstream {name}: inflight semaphore closed"))
}

// -- Health tracking ----------------------------------------------------------

/// Per-upstream health state.  All fields are atomic so the hot path reads them lock-free.
///
/// Failover is driven entirely by the EWMA RTT estimate: a failure inflates it
/// (Unbound-style backoff), which—combined with banded selection—steers traffic away
/// from a failing node, while `probe_interval` periodically re-measures it for recovery.
struct HealthStats {
    /// Exponential moving average RTT in microseconds (alpha = 0.25). 0 = no data yet.
    ewma_rtt_us: AtomicU64,
    consecutive_failures: AtomicU32,
    /// AIMD dynamic concurrency window (soft limit on active_inflight).
    /// Starts at max_inflight; +1 on success, /2 on timeout; bounded [1, max_inflight].
    /// Nodes with active_inflight ≥ window are scored higher (deprioritised) by
    /// CONGESTION_SCORE_FACTOR. The hard semaphore in InflightRegistry is unchanged.
    concurrency_window: AtomicU64,
    /// Configured hard cap (upstream-max-inflight). 0 = unlimited (AIMD disabled).
    max_inflight: u64,
}

impl HealthStats {
    fn new(max_inflight: u64) -> Self {
        let window = if max_inflight > 0 {
            max_inflight
        } else {
            u64::MAX
        };
        Self {
            ewma_rtt_us: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            concurrency_window: AtomicU64::new(window),
            max_inflight,
        }
    }

    fn record_success(&self, rtt_us: u64) {
        let old = self.ewma_rtt_us.load(Ordering::Relaxed);
        let had_failures = self.consecutive_failures.load(Ordering::Relaxed) != 0;
        let new_ewma = if old == 0 || had_failures {
            // First sample, or first success after failures: adopt the fresh
            // measurement directly.  The stored value is either absent or inflated
            // by failure backoff; blending would keep the node deprioritized long
            // after it has recovered.
            rtt_us
        } else {
            // EWMA alpha=0.25: new = 0.75*old + 0.25*rtt
            old.wrapping_sub(old >> 2).wrapping_add(rtt_us >> 2)
        };
        self.ewma_rtt_us.store(new_ewma, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        // AIMD additive increase: window += 1, bounded by max_inflight.
        if self.max_inflight > 0 {
            let w = self.concurrency_window.load(Ordering::Relaxed);
            if w < self.max_inflight {
                self.concurrency_window.store(w + 1, Ordering::Relaxed);
            }
        }
    }

    /// `is_timeout` should be true when the error was a timeout (congestion signal for AIMD).
    fn record_failure(&self, is_timeout: bool) {
        // Unbound-style RTT backoff: each failure doubles the RTT estimate so the
        // selection score sheds load after the FIRST failure, steering banded
        // selection away from the node.  Floor covers nodes with no RTT data; cap
        // keeps the estimate recoverable.
        let old = self.ewma_rtt_us.load(Ordering::Relaxed);
        let inflated = old
            .saturating_mul(2)
            .clamp(FAILURE_RTT_FLOOR_US, FAILURE_RTT_CAP_US);
        self.ewma_rtt_us.store(inflated, Ordering::Relaxed);
        // AIMD multiplicative decrease on timeout (congestion signal only).
        if is_timeout && self.max_inflight > 0 {
            let w = self.concurrency_window.load(Ordering::Relaxed);
            self.concurrency_window
                .store(w.saturating_div(2).max(1), Ordering::Relaxed);
        }
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }
}

// -- Upstream pool ------------------------------------------------------------

/// Fields shared by every transport's constructor: node name, remote address,
/// per-query timeout, ECS handling, the inflight cap, and the routing fwmark.
/// Bundled into one struct instead of repeating the same positional prefix on
/// `UdpUpstream::create`/`TcpMux::new`/`DoHUpstream::new`/`DoQUpstream::new`/
/// `H3Upstream::new` (which otherwise all need `#[allow(clippy::too_many_arguments)]`
/// and grow another parameter every time a shared knob is added).
pub(super) struct UpstreamCommonConfig {
    pub(super) name: String,
    pub(super) remote: SocketAddr,
    pub(super) timeout: Duration,
    pub(super) ecs_mode: EcsMode,
    pub(super) max_inflight: usize,
    pub(super) mark: Option<u32>,
}

pub struct UpstreamPool {
    nodes: Vec<UpstreamNode>,
    next: AtomicUsize,
    /// When `Some(δ)`, a second upstream is started after δ with no response.
    hedge_delay: Option<Duration>,
    /// Optional querylog counters — used to increment hedged_queries when Phase 2 fires.
    querylog_counters: Option<Arc<crate::querylog::QueryLogCounters>>,
    /// Number of hedged requests currently in Phase 2 (awaiting a secondary response).
    /// Capped at `max(nodes.len(), 4)` to prevent amplification storms when the primary
    /// pool is degraded and every query would otherwise spawn a secondary.
    active_hedges: AtomicU64,
}

pub(super) struct UpstreamRequest {
    pub(super) packet: Bytes,
    pub(super) client_id: u16,
    /// Question bytes (`packet[12..question_end]`) for stale/mismatch response detection.
    pub(super) question: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProto {
    Udp,
    Tcp,
}

fn format_upstream_addr(ep: &UpstreamEndpoint) -> String {
    let default_port = ep.proto.default_port();
    let host = if ep.addr.port() == default_port {
        ep.addr.ip().to_string()
    } else {
        ep.addr.to_string()
    };
    match ep.proto {
        UpstreamProto::Udp => format!("udp://{host}"),
        UpstreamProto::Tcp => format!("tcp://{host}"),
        UpstreamProto::Tls => format!("tls://{host}"),
        UpstreamProto::Https => format!(
            "https://{host}{}",
            ep.path.as_deref().unwrap_or("/dns-query")
        ),
        UpstreamProto::Quic => format!("quic://{host}"),
        UpstreamProto::H3 => format!("h3://{host}{}", ep.path.as_deref().unwrap_or("/dns-query")),
    }
}

impl UpstreamPool {
    pub async fn new(
        name: &str,
        addrs: &[UpstreamEndpoint],
        cfg: &UpstreamConfig,
        querylog_counters: Option<Arc<crate::querylog::QueryLogCounters>>,
    ) -> Result<Self> {
        let mut nodes = Vec::new();
        let mut udp = 0usize;
        let mut tcp = 0usize;
        let mut tls = 0usize;
        let mut https = 0usize;
        let mut quic = 0usize;
        let mut h3 = 0usize;
        for (idx, endpoint) in addrs.iter().cloned().enumerate() {
            match endpoint.proto {
                UpstreamProto::Udp => udp += 1,
                UpstreamProto::Tcp => tcp += 1,
                UpstreamProto::Tls => tls += 1,
                UpstreamProto::Https => https += 1,
                UpstreamProto::Quic => quic += 1,
                UpstreamProto::H3 => h3 += 1,
            }

            let node_name = format!("{name}-{idx}");
            let node_addr_display = format_upstream_addr(&endpoint);
            let common = UpstreamCommonConfig {
                name: node_name.clone(),
                remote: endpoint.addr,
                timeout: cfg.timeout,
                ecs_mode: endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                max_inflight: cfg.upstream_max_inflight,
                mark: endpoint.mark,
            };
            let transport = match endpoint.proto {
                UpstreamProto::Udp => {
                    let udp_upstream =
                        UdpUpstream::create(common, cfg.udp_sockets, cfg.udp_buf_size).await?;
                    UpstreamTransport::Udp(udp_upstream)
                }
                UpstreamProto::Tcp => UpstreamTransport::Tcp(Arc::new(TcpMux::new(
                    common,
                    MuxConnector::Tcp,
                    cfg.upstream_max_response_bytes,
                ))),
                UpstreamProto::Tls => make_tls_transport(
                    common,
                    &endpoint,
                    &node_name,
                    cfg.upstream_max_response_bytes,
                )?,
                UpstreamProto::Https => make_doh_transport(common, &endpoint, &node_name)?,
                UpstreamProto::Quic => {
                    let server_name = endpoint
                        .server_name
                        .clone()
                        .unwrap_or_else(|| endpoint.addr.ip().to_string());
                    crate::startup!(
                        "upstream {node_name} proto=doq remote={} sni={server_name}",
                        endpoint.addr
                    );
                    make_doq_transport(common, server_name)?
                }
                UpstreamProto::H3 => {
                    let server_name = endpoint
                        .server_name
                        .clone()
                        .unwrap_or_else(|| endpoint.addr.ip().to_string());
                    let path = endpoint
                        .path
                        .clone()
                        .unwrap_or_else(|| "/dns-query".to_string());
                    crate::startup!(
                        "upstream {node_name} proto=h3 remote={} sni={server_name} path={path}",
                        endpoint.addr
                    );
                    make_h3_transport(common, server_name, path)?
                }
            };
            nodes.push(UpstreamNode {
                transport,
                health: HealthStats::new(cfg.upstream_max_inflight as u64),
                stats: NodeStats::new(),
                last_selected: AtomicU64::new(0),
                addr_display: node_addr_display,
            });
        }
        {
            let mut msg = format!("upstream {name}");
            if udp > 0 {
                msg.push_str(&format!(" udp={udp}"));
            }
            if tcp > 0 {
                msg.push_str(&format!(" tcp={tcp}"));
            }
            if tls > 0 {
                msg.push_str(&format!(" tls={tls}"));
            }
            if https > 0 {
                msg.push_str(&format!(" https={https}"));
            }
            if quic > 0 {
                msg.push_str(&format!(" quic={quic}"));
            }
            if h3 > 0 {
                msg.push_str(&format!(" h3={h3}"));
            }
            if udp > 0 {
                msg.push_str(&format!(" udp_pool={}", cfg.udp_sockets));
            }
            crate::startup!("{msg}");
        }
        Ok(Self {
            nodes,
            next: AtomicUsize::new(0),
            hedge_delay: cfg.hedge_delay,
            querylog_counters,
            active_hedges: AtomicU64::new(0),
        })
    }

    /// Pick the primary node index using probe + EWMA scoring.
    /// Returns `None` only when the pool has no nodes.
    fn select_primary_idx(&self, query_ix: u64) -> Option<usize> {
        // Periodic probe: force-route to the least-recently-selected node every
        // PROBE_INTERVAL queries so deprioritised nodes are re-measured and can recover.
        let probe = self
            .nodes
            .iter()
            .enumerate()
            .min_by_key(|(_, n)| n.last_selected.load(Ordering::Relaxed));
        if let Some((probe_idx, probe_node)) = probe {
            if query_ix.wrapping_sub(probe_node.last_selected.load(Ordering::Relaxed))
                >= PROBE_INTERVAL
            {
                return Some(probe_idx);
            }
        }

        // Normal path: banded selection (Unbound-style RTT banding, AdGuard-style
        // load spreading).  Collect each node's score, find the best, then
        // pick pseudo-randomly among all nodes whose score falls within the band.
        // Near-equal nodes share traffic, which keeps their RTT estimates fresh and
        // gives instant warm failover targets; a clearly slower node still gets
        // nothing outside its periodic probe.
        let mut candidates: SmallVec<[(usize, u64); 8]> = SmallVec::new();
        let mut best_score = u64::MAX;
        for (idx, node) in self.nodes.iter().enumerate() {
            let score = node.selection_score();
            best_score = best_score.min(score);
            candidates.push((idx, score));
        }
        if !candidates.is_empty() {
            let limit = band_limit(best_score, SELECT_BAND_FACTOR, SELECT_BAND_FLOOR_US);
            let in_band = candidates.iter().filter(|&&(_, s)| s <= limit).count();
            // Fibonacci-hash the query counter for a cheap, well-scattered pick.
            let pick = (query_ix.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 33) as usize % in_band;
            let mut seen = 0usize;
            for &(idx, score) in &candidates {
                if score <= limit {
                    if seen == pick {
                        return Some(idx);
                    }
                    seen += 1;
                }
            }
        }

        // Empty pool.
        None
    }

    /// Pick the best secondary node for hedging: the lowest-scoring node that is not
    /// the primary.  Returns `None` only when there is no other node.
    fn select_secondary_idx(&self, primary_idx: usize) -> Option<usize> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != primary_idx)
            .min_by_key(|(_, n)| n.selection_score())
            .map(|(i, _)| i)
    }

    pub async fn exchange_observed(
        &self,
        packet: Bytes,
        client_id: u16,
        client_proto: ClientProto,
    ) -> Result<Bytes> {
        if self.nodes.is_empty() {
            return Err(anyhow!("empty upstream pool"));
        }
        let query_ix = self.next.fetch_add(1, Ordering::Relaxed) as u64;

        // Extract question bytes once for stale/mismatch validation in UDP/TCP recv loops.
        let question = match dns::question_end(&packet) {
            Some(end) => packet.slice(12..end),
            None => Bytes::new(),
        };

        let Some(primary_idx) = self.select_primary_idx(query_ix) else {
            return Err(anyhow!(
                "empty upstream pool for {:?} client transport",
                client_proto
            ));
        };
        let primary_node = &self.nodes[primary_idx];
        primary_node
            .last_selected
            .store(query_ix, Ordering::Relaxed);

        // Fast path: no hedging configured.
        let Some(hedge_delay_cfg) = self.hedge_delay else {
            return primary_node
                .exchange(UpstreamRequest {
                    packet,
                    client_id,
                    question,
                })
                .await;
        };

        // Hedge path ------------------------------------------------------------------
        //
        // Phase 1: give primary its own RTT-derived delay to respond (falling back to
        // `hedge_delay_cfg` until it has RTT data, or right after a failure — see
        // `UpstreamNode::hedge_delay`). If it answers in time, return immediately with
        // zero extra upstream traffic.
        let hedge_delay = primary_node.hedge_delay(hedge_delay_cfg);
        let primary_fut = primary_node.exchange(UpstreamRequest {
            packet: packet.clone(),
            client_id,
            question: question.clone(),
        });
        tokio::pin!(primary_fut);

        tokio::select! {
            biased;
            result = &mut primary_fut => return result,
            _ = tokio::time::sleep(hedge_delay) => {}
        }

        // Phase 2: hedge timer fired; check budget before starting second upstream.
        // Limit concurrent hedges to max(nodes, 4) to prevent amplification storms when
        // the primary pool is degraded and every query would otherwise launch a secondary.
        let hedge_budget = (self.nodes.len() as u64).max(4);
        if self.active_hedges.fetch_add(1, Ordering::Relaxed) >= hedge_budget {
            self.active_hedges.fetch_sub(1, Ordering::Relaxed);
            return primary_fut.await;
        }
        // Guard decrements active_hedges when Phase 2 exits (any branch, including cancel).
        let _hedge = HedgeGuard(&self.active_hedges);

        if let Some(ctr) = &self.querylog_counters {
            ctr.hedged_queries.fetch_add(1, Ordering::Relaxed);
        }
        let Some(secondary_idx) = self.select_secondary_idx(primary_idx) else {
            // Only one node available; just wait for primary.
            return primary_fut.await;
        };
        let secondary_node = &self.nodes[secondary_idx];
        let secondary_fut = secondary_node.exchange(UpstreamRequest {
            packet,
            client_id,
            question,
        });
        tokio::pin!(secondary_fut);

        tokio::select! {
            result = &mut primary_fut => {
                if result.is_ok() {
                    // Primary recovered; secondary is dropped (cancelled by tokio::select!).
                    self.nodes[secondary_idx].stats.record_cancelled();
                    result
                } else {
                    // Primary errored; let secondary complete.
                    let secondary_result = secondary_fut.await;
                    secondary_result.or(result)
                }
            }
            result = &mut secondary_fut => {
                if result.is_ok() {
                    // Secondary succeeded first; cancel primary.
                    self.nodes[primary_idx].stats.record_cancelled();
                    result
                } else {
                    // Secondary failed first; keep waiting for primary.
                    primary_fut.await
                }
            }
        }
    }

    /// Collect per-node stats snapshots for the dashboard.
    pub fn node_snapshots(&self, pool_name: &str) -> Vec<NodeStatsSnapshot> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                n.stats
                    .snapshot(&format!("{pool_name}-{i}"), &n.addr_display)
            })
            .collect()
    }
}

// -- Upstream node ------------------------------------------------------------

enum UpstreamTransport {
    Udp(Arc<UdpUpstream>),
    Tcp(Arc<TcpMux>),
    #[cfg(feature = "doh")]
    Doh(Arc<DoHUpstream>),
    #[cfg(feature = "doq")]
    Doq(Arc<DoQUpstream>),
    #[cfg(feature = "h3")]
    H3(Arc<H3Upstream>),
}

struct UpstreamNode {
    transport: UpstreamTransport,
    health: HealthStats,
    stats: NodeStats,
    /// Monotonic query index of the last time this node was selected (probe or normal).
    /// Initialized to 0; used by the probe scheduler to find the least-recently-used node.
    last_selected: AtomicU64,
    /// Human-readable address string for this individual node (e.g. "tls://1.1.1.1:853").
    addr_display: String,
}

/// Tear down a UDP node's background recv/send tasks and sockets when the node
/// is dropped.
///
/// Only UDP needs this: its transport eagerly spawns a recv-supervisor task per
/// pooled socket at construction time, and each task holds a strong
/// `Arc<UdpUpstream>` that keeps it (and its open socket) alive forever with no
/// self-terminating signal once the node is orphaned. TCP/TLS/DoQ/H3/DoH
/// connect lazily on first use and their reader/writer tasks hold only
/// per-connection state, so an orphaned node for those transports has no live
/// task to leak.
///
/// Hanging this off `Drop` (rather than an explicit pool-level `shutdown()`
/// call sites must remember) covers every way a node can be orphaned with one
/// mechanism:
/// - a config hot-reload superseding the pool's `HotState` generation — the
///   node drops exactly when the last in-flight query holding that generation
///   finishes, so teardown can never cut off a still-legitimate exchange the
///   way a fixed post-reload grace period could;
/// - a construction failure part-way through `UpstreamPool::new` or
///   `build_hot_state` (a later node/server/ruleset erroring), where the
///   already-built nodes are dropped during unwinding — previously each such
///   failed reload attempt leaked the built nodes' recv tasks and sockets.
impl Drop for UpstreamNode {
    fn drop(&mut self) {
        if let UpstreamTransport::Udp(u) = &self.transport {
            u.shutdown();
        }
    }
}

/// RAII guard that decrements `active_inflight` on drop.
/// Ensures the counter is corrected even when the owning future is cancelled
/// mid-flight by `tokio::select!` (e.g., the losing side of a hedged race).
struct ActiveInflightGuard<'a>(&'a AtomicI64);

/// RAII guard that decrements `active_hedges` when Phase 2 of a hedged exchange exits,
/// including on cancellation via `tokio::select!`.
struct HedgeGuard<'a>(&'a AtomicU64);

macro_rules! impl_atomic_dec_drop {
    ($guard:ident) => {
        impl Drop for $guard<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
    };
}
impl_atomic_dec_drop!(ActiveInflightGuard);
impl_atomic_dec_drop!(HedgeGuard);

impl UpstreamNode {
    /// Selection score: EWMA RTT × (1 + active_inflight).
    /// Nodes without RTT data score 0 (optimistic) so they tie for best priority and are
    /// tried immediately via round-robin.  Steady-state probing of measured-but-slow nodes
    /// is handled by the `PROBE_INTERVAL` scheduler in `UpstreamPool::exchange`.
    /// When active_inflight ≥ the AIMD concurrency window the score is multiplied by
    /// `CONGESTION_SCORE_FACTOR` to deprioritise the node without blocking it outright.
    fn selection_score(&self) -> u64 {
        let ewma = self.health.ewma_rtt_us.load(Ordering::Relaxed);
        let inflight = self.stats.active_inflight.load(Ordering::Relaxed).max(0) as u64;
        let base = if ewma == 0 {
            inflight
        } else {
            ewma.saturating_mul(1 + inflight)
        };
        let window = self.health.concurrency_window.load(Ordering::Relaxed);
        if window > 0 && inflight >= window {
            base.saturating_mul(CONGESTION_SCORE_FACTOR)
        } else {
            base
        }
    }

    /// Adaptive hedge-trigger delay for this node as the primary of a hedged
    /// exchange: `HEDGE_RTT_MULTIPLIER × its own EWMA RTT`, floored at
    /// `HEDGE_MIN_DELAY`. Falls back to `fallback` (the configured `hedge-delay-ms`)
    /// when there's no RTT sample yet, or when the node has just failed —
    /// `record_failure` deliberately inflates the EWMA to steer *selection* away
    /// from a struggling node, so trusting it here would make the hedge wait
    /// *longer* against a node already known to be struggling, backwards from the
    /// point of hedging. `fallback` is always a fixed, sane value to fall back on.
    fn hedge_delay(&self, fallback: Duration) -> Duration {
        if self.health.consecutive_failures.load(Ordering::Relaxed) > 0 {
            return fallback;
        }
        let ewma_us = self.health.ewma_rtt_us.load(Ordering::Relaxed);
        if ewma_us == 0 {
            return fallback;
        }
        Duration::from_micros(ewma_us.saturating_mul(HEDGE_RTT_MULTIPLIER)).max(HEDGE_MIN_DELAY)
    }

    async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        self.stats.active_inflight.fetch_add(1, Ordering::Relaxed);
        // Guard ensures the counter is decremented even on future cancellation.
        let _inflight = ActiveInflightGuard(&self.stats.active_inflight);
        let t0 = Instant::now();
        let result = self.transport.exchange(req).await;
        let rtt_us = t0.elapsed().as_micros() as u64;
        match &result {
            Ok(_) => {
                let recovered = self.health.consecutive_failures.load(Ordering::Relaxed) != 0;
                self.health.record_success(rtt_us);
                self.stats.record_ok(rtt_us);
                if recovered {
                    crate::startup!(
                        "upstream {} event=recovered rtt_us={rtt_us}",
                        self.transport.name()
                    );
                }
            }
            Err(err) => {
                let is_timeout = err
                    .chain()
                    .any(|e| e.downcast_ref::<tokio::time::error::Elapsed>().is_some());
                self.health.record_failure(is_timeout);
                if is_timeout {
                    self.stats.record_timeout();
                    // A run of consecutive timeouts on a UDP upstream can mean its
                    // long-lived connected sockets are using a route that changed
                    // underneath them (e.g. a policy-routed/VPN path re-established
                    // with a new gateway) — UDP has no protocol-level signal for
                    // this the way TCP would, so sustained timeouts are the only
                    // available trigger to recreate the sockets and pick up the
                    // current route. See `UdpUpstream::trigger_refresh`.
                    match &self.transport {
                        UpstreamTransport::Udp(u) => {
                            let failures = self.health.consecutive_failures.load(Ordering::Relaxed);
                            if failures >= udp::STALE_SOCKET_REFRESH_THRESHOLD {
                                u.trigger_refresh();
                            }
                        }
                        // A TCP mux connection normally has a protocol-level signal
                        // (RST/FIN) for a broken path, but a middlebox silently
                        // black-holing only the return path leaves the socket
                        // looking alive forever — sustained timeouts are the same
                        // fallback signal here. See `TcpMux::force_reconnect`.
                        UpstreamTransport::Tcp(t) => {
                            let failures = self.health.consecutive_failures.load(Ordering::Relaxed);
                            if failures >= tcp_mux::STALE_CONNECTION_REFRESH_THRESHOLD {
                                t.force_reconnect();
                            }
                        }
                        // DoH/DoQ/H3 handle their own reconnect internally.
                        #[cfg(any(feature = "doh", feature = "doq", feature = "h3"))]
                        _ => {}
                    }
                } else {
                    self.stats.record_err();
                }
            }
        }
        result
    }
}

impl UpstreamTransport {
    fn name(&self) -> &str {
        match self {
            Self::Udp(u) => &u.name,
            Self::Tcp(t) => &t.name,
            #[cfg(feature = "doh")]
            Self::Doh(d) => &d.name,
            #[cfg(feature = "doq")]
            Self::Doq(d) => &d.name,
            #[cfg(feature = "h3")]
            Self::H3(h) => &h.name,
        }
    }

    async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        match self {
            Self::Udp(u) => u.exchange(req).await,
            Self::Tcp(t) => t.exchange(req).await,
            #[cfg(feature = "doh")]
            Self::Doh(d) => d.exchange(req).await,
            #[cfg(feature = "doq")]
            Self::Doq(d) => d.exchange(req).await,
            #[cfg(feature = "h3")]
            Self::H3(h) => h.exchange(req).await,
        }
    }
}

// -- TLS config ---------------------------------------------------------------

/// Build a `rustls::ClientConfig` using the Mozilla root certificate store.
#[cfg(feature = "dot")]
pub(super) fn make_tls_config() -> Arc<rustls::ClientConfig> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// -- TLS/HTTPS transport factories --------------------------------------------

/// Return a DoT (`tls://`) transport when the `dot` feature is compiled in;
/// otherwise return a descriptive error so the user knows which flag to enable.
#[allow(unreachable_code)]
fn make_tls_transport(
    common: UpstreamCommonConfig,
    endpoint: &UpstreamEndpoint,
    node_name: &str,
    max_response_bytes: usize,
) -> Result<UpstreamTransport> {
    #[cfg(feature = "dot")]
    {
        let tls_config = make_tls_config();
        let server_name = if endpoint.no_sni {
            // Use IP address as ServerName so rustls omits SNI.
            match endpoint.addr.ip() {
                std::net::IpAddr::V4(ip) => {
                    ServerName::IpAddress(rustls::pki_types::IpAddr::V4(ip.into()))
                }
                std::net::IpAddr::V6(ip) => {
                    ServerName::IpAddress(rustls::pki_types::IpAddr::V6(ip.into()))
                }
            }
        } else {
            ServerName::try_from(
                endpoint
                    .server_name
                    .clone()
                    .unwrap_or_else(|| endpoint.addr.ip().to_string()),
            )
            .map_err(|e| anyhow!("invalid TLS server name for upstream {}: {e}", endpoint.addr))?
        };
        crate::startup!(
            "upstream {node_name} proto=tls remote={} sni={}",
            endpoint.addr,
            if endpoint.no_sni {
                "disabled"
            } else {
                endpoint.server_name.as_deref().unwrap_or("(ip)")
            }
        );
        return Ok(UpstreamTransport::Tcp(Arc::new(TcpMux::new(
            common,
            MuxConnector::Tls {
                config: tls_config,
                server_name,
            },
            max_response_bytes,
        ))));
    }
    drop((common, endpoint, node_name, max_response_bytes));
    Err(anyhow!(
        "tls:// upstream requires the 'dot' feature; recompile with: cargo build --features dot"
    ))
}

/// Return a DoH (`https://`) transport when the `doh` feature is compiled in;
/// otherwise return a descriptive error.
#[allow(unreachable_code)]
fn make_doh_transport(
    common: UpstreamCommonConfig,
    endpoint: &UpstreamEndpoint,
    node_name: &str,
) -> Result<UpstreamTransport> {
    #[cfg(feature = "doh")]
    {
        let server_name = endpoint
            .server_name
            .clone()
            .unwrap_or_else(|| endpoint.addr.ip().to_string());
        let path = endpoint
            .path
            .clone()
            .unwrap_or_else(|| "/dns-query".to_string());
        crate::startup!(
            "upstream {node_name} proto=https remote={} sni={server_name} path={path}",
            endpoint.addr
        );
        return Ok(UpstreamTransport::Doh(Arc::new(DoHUpstream::new(
            common,
            server_name,
            path,
        )?)));
    }
    drop((common, endpoint, node_name));
    Err(anyhow!(
        "https:// upstream requires the 'doh' feature; recompile with: cargo build --features doh"
    ))
}

// -- QUIC/H3 transport factories ----------------------------------------------

/// Return a `Doq` transport when the `doq` feature is compiled in; otherwise
/// return a descriptive error so the user knows which flag to enable.
#[allow(unreachable_code)]
fn make_doq_transport(
    common: UpstreamCommonConfig,
    server_name: String,
) -> Result<UpstreamTransport> {
    #[cfg(feature = "doq")]
    return Ok(UpstreamTransport::Doq(Arc::new(DoQUpstream::new(
        common,
        server_name,
    )?)));
    drop((common, server_name));
    Err(anyhow!(
        "quic:// upstream requires the 'doq' feature; recompile with: cargo build --features doq"
    ))
}

/// Return an `H3` transport when the `h3` feature is compiled in; otherwise
/// return a descriptive error.
#[allow(unreachable_code)]
fn make_h3_transport(
    common: UpstreamCommonConfig,
    server_name: String,
    path: String,
) -> Result<UpstreamTransport> {
    #[cfg(feature = "h3")]
    return Ok(UpstreamTransport::H3(Arc::new(H3Upstream::new(
        common,
        server_name,
        path,
    )?)));
    drop((common, server_name, path));
    Err(anyhow!(
        "h3:// upstream requires the 'h3' feature; recompile with: cargo build --features h3"
    ))
}

// -- Low-level TCP / ECS helpers ----------------------------------------------

/// Validate a response received from an upstream (DoH, DoQ, H3, TCP fallback).
/// Checks QR=1, ID match, and QNAME/QTYPE/QCLASS match.
/// Returns an error string (not logged here; caller adds transport context).
pub(super) fn validate_upstream_response(
    resp: &[u8],
    upstream_id: u16,
    question: &[u8],
) -> Result<()> {
    if !dns::is_reply(resp) {
        return Err(anyhow!("response QR bit not set"));
    }
    if dns::get_id(resp).ok() != Some(upstream_id) {
        return Err(anyhow!("response ID mismatch"));
    }
    let resp_qend = dns::question_end(resp);
    let resp_q = resp_qend.and_then(|e| resp.get(12..e)).unwrap_or(&[][..]);
    if !dns::questions_match(resp_q, question) {
        return Err(anyhow!("response question mismatch"));
    }
    Ok(())
}

/// Build the wire bytes for an outgoing upstream query, shared by every multiplexed
/// transport (TCP/DoT, DoH, DoQ, DoH3).  Applies the ECS mode and patches the upstream
/// DNS ID.
pub(super) fn prepare_query(
    packet: &Bytes,
    ecs_mode: &EcsMode,
    upstream_id: u16,
) -> Result<Bytes> {
    let mut pkt = apply_ecs_mode(packet, ecs_mode);
    dns::set_id(&mut pkt, upstream_id)?;
    Ok(pkt.freeze())
}

/// Validate an upstream response against the query it answers and rewrite its ID back
/// to the client's.  Consumes `resp`, returning the client-facing bytes.  Errors are
/// generic (no transport prefix); callers add their own.
///
/// Used by the transports whose libraries correlate request/response per stream
/// (DoH, DoQ, DoH3).  TCP/DoT instead validates and restores the ID inside
/// `InflightRegistry::complete`, so it only uses [`prepare_query`].
#[cfg(any(feature = "doh", feature = "doq", feature = "h3"))]
pub(super) fn finalize_response(
    mut resp: Vec<u8>,
    upstream_id: u16,
    question: &[u8],
    client_id: u16,
) -> Result<Bytes> {
    validate_upstream_response(&resp, upstream_id, question)?;
    dns::set_id(&mut resp, client_id)?;
    Ok(Bytes::from(resp))
}

/// Stateless one-shot TCP exchange used as fallback for TC-bit UDP responses.
pub(super) async fn tcp_exchange_packet(
    remote: SocketAddr,
    packet: &[u8],
    timeout: Duration,
    name: &str,
    mark: Option<u32>,
) -> Result<Vec<u8>> {
    let fut = async {
        let mut stream = connect_tcp_nodelay(remote, timeout, name, mark).await?;
        tcp_write_framed(&mut stream, packet, name).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        Ok(resp)
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("upstream {name} tcp timeout: {remote}"))?
}

/// Open a TCP connection to `remote` with `TCP_NODELAY`, subject to `timeout`.
/// Used by both the plain-TCP and TLS branches of `TcpMux::ensure_connection`.
pub(super) async fn connect_tcp_nodelay(
    remote: SocketAddr,
    timeout: Duration,
    name: &str,
    mark: Option<u32>,
) -> Result<TcpStream> {
    use std::os::unix::io::AsRawFd;
    tokio::time::timeout(timeout, async {
        let socket = if remote.is_ipv6() {
            tokio::net::TcpSocket::new_v6()
        } else {
            tokio::net::TcpSocket::new_v4()
        }
        .with_context(|| format!("upstream {name}: create tcp socket"))?;
        // SO_MARK before connect so the SYN itself carries the fwmark for policy routing.
        if let Some(m) = mark {
            set_so_mark(socket.as_raw_fd(), m).with_context(|| format!("upstream {name}"))?;
        }
        // TCP Fast Open (client): once a cookie is cached for this peer, the request
        // rides in the SYN and the upstream's response comes back without waiting for
        // the handshake to finish — saving one RTT per reconnect. Best-effort: needs
        // Linux 4.11+ and the client bit of net.ipv4.tcp_fastopen (value 1) enabled.
        set_tcp_fastopen_connect(&socket);
        // Keepalive + user-timeout so a persistent DoT/DoH/TCP connection whose peer
        // has silently gone away (NAT drop, upstream restart) is detected and torn
        // down in tens of seconds instead of lingering until the next query stalls.
        set_tcp_keepalive(socket.as_raw_fd());
        let s = socket
            .connect(remote)
            .await
            .with_context(|| format!("upstream {name}: TCP connect to {remote}"))?;
        s.set_nodelay(true)?;
        Ok::<TcpStream, anyhow::Error>(s)
    })
    .await
    .map_err(|_| anyhow!("upstream {name} tcp connect timeout: {remote}"))
    .and_then(|r| r)
}

/// Enable `TCP_FASTOPEN_CONNECT` on an unconnected client socket. Best-effort: a
/// failure (old kernel, sysctl disabled) just means the connection proceeds with a
/// normal three-way handshake.
fn set_tcp_fastopen_connect(socket: &tokio::net::TcpSocket) {
    use std::os::unix::io::AsRawFd;
    let yes: libc::c_int = 1;
    let _ = sys::set_socket_i32(
        socket.as_raw_fd(),
        libc::IPPROTO_TCP,
        libc::TCP_FASTOPEN_CONNECT,
        yes,
    );
}

/// Enable TCP keepalive and a user-timeout on an upstream socket. Best-effort.
///
/// - SO_KEEPALIVE + KEEPIDLE/INTVL/CNT: after 30s idle, probe every 10s, declare the
///   peer dead after 3 unanswered probes (~60s total).
/// - TCP_USER_TIMEOUT: fail the connection if *sent* data goes unacknowledged for 30s,
///   which catches a hung peer faster than waiting on keepalive when a query is inflight.
fn set_tcp_keepalive(fd: libc::c_int) {
    let set = |level: libc::c_int, opt: libc::c_int, val: libc::c_int| {
        let _ = sys::set_socket_i32(fd, level, opt, val);
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 30);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 3);
    set(libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, 30_000);
}

/// Write a DNS-over-TCP framed message (2-byte big-endian length prefix + payload).
///
/// Two separate write_all calls avoid a Vec allocation per write. tokio-rustls buffers
/// writes internally so both calls flush in one TLS record; plain TCP with TCP_NODELAY
/// sends them back-to-back (DNS framing handles reassembly correctly).
pub(super) async fn tcp_write_framed(
    w: &mut (impl AsyncWrite + Unpin),
    packet: &[u8],
    name: &str,
) -> Result<()> {
    let pkt_len = u16::try_from(packet.len())
        .map_err(|_| anyhow!("upstream {name}: dns packet too large for tcp"))?;
    w.write_all(&pkt_len.to_be_bytes()).await?;
    w.write_all(packet).await?;
    Ok(())
}

/// Apply the upstream ECS mode to a query packet, returning an owned, mutable
/// `BytesMut`. Every caller goes on to patch the upstream query ID in place
/// (`dns::set_id`), so this returns a mutable buffer directly instead of an
/// immutable `Bytes` that each caller would then have to copy a second time
/// just to get something patchable — `strip_edns_ecs`/`inject_or_replace_ecs`
/// already hand back a freshly allocated `Vec<u8>` on the modified-path, so
/// wrapping that in `Bytes` (immutable) and then copying it back out into a
/// `BytesMut` (as callers used to) was a wasted second copy on every query
/// that didn't just forward ECS unchanged.
pub(super) fn apply_ecs_mode(packet: &Bytes, mode: &EcsMode) -> BytesMut {
    // `BytesMut` has no `From<Vec<u8>>`, but `From<Bytes>` is zero-copy for a
    // uniquely-owned buffer — which a `Vec<u8>` just wrapped in `Bytes` always
    // is — so routing through `Bytes::from(vec)` first still avoids a copy.
    match mode {
        EcsMode::Strip => dns::strip_edns_ecs(packet)
            .map(|v| BytesMut::from(Bytes::from(v)))
            .unwrap_or_else(|| BytesMut::from(&packet[..])),
        EcsMode::Forward => BytesMut::from(&packet[..]),
        EcsMode::Fixed(subnet) => dns::inject_or_replace_ecs(packet, subnet)
            .map(|v| BytesMut::from(Bytes::from(v)))
            .unwrap_or_else(|| BytesMut::from(&packet[..])),
    }
}

// -- Socket buffer helpers ----------------------------------------------------

fn set_buf_size_fd(fd: libc::c_int, size: usize) {
    let size_i32 = size.min(i32::MAX as usize) as libc::c_int;
    for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        let _ = sys::set_socket_i32(fd, libc::SOL_SOCKET, opt, size_i32);
    }
}

/// Set SO_RCVBUF and SO_SNDBUF on a tokio UdpSocket.
pub fn set_socket_buf_size(socket: &tokio::net::UdpSocket, size: usize) {
    if size == 0 {
        return;
    }
    use std::os::unix::io::AsRawFd;
    set_buf_size_fd(socket.as_raw_fd(), size);
}

/// Set SO_RCVBUF and SO_SNDBUF on a raw file descriptor.
pub fn set_raw_socket_buf_size(fd: libc::c_int, size: usize) {
    if size == 0 {
        return;
    }
    set_buf_size_fd(fd, size);
}

/// Apply the Linux `SO_MARK` (fwmark) to an egress socket for policy routing.
///
/// Unlike the buffer-size helpers this is **not** best-effort: a configured `?mark=`
/// that can't be applied (typically missing `CAP_NET_ADMIN`) would silently send the
/// upstream's traffic out the wrong route, so the error is surfaced to the caller.
pub(super) fn set_so_mark(fd: libc::c_int, mark: u32) -> Result<()> {
    sys::set_socket_u32(fd, libc::SOL_SOCKET, libc::SO_MARK, mark).with_context(|| {
        format!("failed to set SO_MARK={mark:#x} (fwmark requires CAP_NET_ADMIN or root)")
    })
}
