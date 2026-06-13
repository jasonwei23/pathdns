//! Upstream DNS transport: UDP socket pool, TCP/TLS mux, and EWMA+inflight selection.
//!
//! # UDP
//! Each UDP upstream owns a pool of N bound sockets (default 4, `--upstream-udp-sockets`).
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
//! estimates fresh and providing warm failover targets.  Failures double a node's
//! RTT estimate (Unbound-style backoff) so traffic shifts away after the first
//! error; `FAILURE_THRESHOLD` consecutive failures add a hard penalty window.
//! The first success after failures adopts the fresh RTT sample directly for fast
//! recovery.  Nodes in the penalty window are skipped in the first pass; if all are
//! penalized they are used anyway (fallback round-robin).
//!
//! # Truncated UDP responses
//! A UDP response with TC=1 triggers an automatic one-shot TCP retry.

mod doh;
mod inflight;
#[cfg(any(feature = "doq", feature = "h3"))]
mod quic;
mod tcp_mux;
mod udp;

use crate::config::{EcsMode, UpstreamConfig, UpstreamEndpoint, UpstreamProto};
use crate::dns;
use crate::stats::{NodeStats, NodeStatsSnapshot};
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use doh::DoHUpstream;
#[cfg(feature = "doq")]
use quic::DoQUpstream;
#[cfg(feature = "h3")]
use quic::H3Upstream;
use rustls::pki_types::ServerName;
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tcp_mux::{MuxConnector, TcpMux};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use udp::UdpUpstream;

/// Failures before a node enters the penalty window.
const FAILURE_THRESHOLD: u32 = 3;
/// How long a penalized node is skipped before being retried.
const PENALTY_DURATION_MS: u64 = 30_000;
/// Every N upstream selections, force-route to the least-recently-used eligible node so
/// healthy-but-slow nodes are periodically re-probed rather than starved forever.
const PROBE_INTERVAL: u64 = 100;
/// Banded selection (Unbound-style): nodes whose score is within this multiple of the
/// best score share traffic via pseudo-random pick instead of herding onto the single
/// minimum.
const SELECT_BAND_FACTOR: u64 = 2;
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

/// Upper score bound for banded selection.  Nodes scoring at or below this limit
/// are considered interchangeable with the best node: `best × SELECT_BAND_FACTOR`,
/// with an additive floor so microsecond-scale scores (LAN resolvers, untested
/// nodes) are all treated as equal rather than split by measurement noise.
fn band_limit(best: u64) -> u64 {
    best.saturating_mul(SELECT_BAND_FACTOR)
        .max(best.saturating_add(SELECT_BAND_FLOOR_US))
}

pub(super) fn now_ms() -> u64 {
    // Use a process-start Instant as epoch so penalty windows are immune to NTP jumps.
    // On OpenWrt (CLOCK_MONOTONIC resets on reboot), this is always monotonic within a
    // single process run, which is all we need.
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
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

// -- Health tracking ----------------------------------------------------------

/// Per-upstream health state.  All fields are atomic so the hot path reads them lock-free.
struct HealthStats {
    /// Exponential moving average RTT in microseconds (alpha = 0.25). 0 = no data yet.
    ewma_rtt_us: AtomicU64,
    consecutive_failures: AtomicU32,
    /// Epoch-ms after which the penalty expires. 0 = not penalized.
    penalty_until_ms: AtomicU64,
    /// AIMD dynamic concurrency window (soft limit on active_inflight).
    /// Starts at max_inflight; +1 on success, /2 on timeout; bounded [1, max_inflight].
    /// Nodes with active_inflight ≥ window are scored higher (deprioritised) by
    /// CONGESTION_SCORE_FACTOR. The hard semaphore in InflightRegistry is unchanged.
    concurrency_window: AtomicU64,
    /// Half-open probe gate: true while the single probe request (after penalty expiry)
    /// is in flight. set by the first caller that claims the probe via is_penalized_at's
    /// CAS; cleared by record_success, record_failure, or release_probe (on cancellation).
    probe_in_progress: AtomicBool,
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
            penalty_until_ms: AtomicU64::new(0),
            concurrency_window: AtomicU64::new(window),
            probe_in_progress: AtomicBool::new(false),
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
        self.penalty_until_ms.store(0, Ordering::Relaxed);
        // AIMD additive increase: window += 1, bounded by max_inflight.
        if self.max_inflight > 0 {
            let w = self.concurrency_window.load(Ordering::Relaxed);
            if w < self.max_inflight {
                self.concurrency_window.store(w + 1, Ordering::Relaxed);
            }
        }
        // Release half-open probe slot.
        self.probe_in_progress.store(false, Ordering::Relaxed);
    }

    /// `is_timeout` should be true when the error was a timeout (congestion signal for AIMD).
    fn record_failure(&self, is_timeout: bool) -> u32 {
        // Unbound-style RTT backoff: each failure doubles the RTT estimate so the
        // selection score sheds load after the FIRST failure instead of keeping the
        // node attractive until the hard penalty trips.  Floor covers nodes with no
        // RTT data; cap keeps the estimate recoverable.
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
        // Release half-open probe slot before re-penalizing.
        self.probe_in_progress.store(false, Ordering::Relaxed);

        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= FAILURE_THRESHOLD {
            self.penalty_until_ms
                .store(now_ms() + PENALTY_DURATION_MS, Ordering::Relaxed);
        }
        n
    }

    /// Returns `true` when this node should be excluded from normal selection.
    ///
    /// Hard penalty while `penalty_until_ms > now`.  After the penalty expires the
    /// node enters **half-open** state: the first caller performs a CAS to claim the
    /// probe slot (sets `probe_in_progress = true`) and is allowed through
    /// (returns `false`).  All subsequent callers find the probe in progress and are
    /// blocked (returns `true`) until `record_success`, `record_failure`, or
    /// `release_probe` clears the slot.
    fn is_penalized_at(&self, now: u64) -> bool {
        let until = self.penalty_until_ms.load(Ordering::Relaxed);
        if until == 0 {
            return false;
        }
        if now < until {
            return true; // hard penalty window active
        }
        // Penalty elapsed: half-open. Gate all but one probe.
        if self.probe_in_progress.load(Ordering::Acquire) {
            return true; // probe already in flight
        }
        // Atomically claim probe slot. The caller that wins CAS is allowed through;
        // concurrent callers that lose see it as still penalized.
        self.probe_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    }

    /// Release the half-open probe slot without recording a success or failure.
    /// Called when a probe request is cancelled mid-flight (lost the hedge race) so
    /// the next selection can claim the slot and retry.
    fn release_probe(&self) {
        self.probe_in_progress.store(false, Ordering::Relaxed);
    }
}

// -- Upstream pool ------------------------------------------------------------

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

impl UpstreamProto {
    fn client_filter(self) -> Option<ClientProto> {
        None
    }
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
            let transport = match endpoint.proto {
                UpstreamProto::Udp => {
                    let udp_upstream = UdpUpstream::create(
                        node_name,
                        endpoint.addr,
                        cfg.timeout,
                        cfg.udp_pool_size,
                        cfg.udp_buf_size,
                        cfg.upstream_max_inflight,
                        endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                    )
                    .await?;
                    UpstreamTransport::Udp(udp_upstream)
                }
                UpstreamProto::Tcp => UpstreamTransport::Tcp(Arc::new(TcpMux::new(
                    node_name,
                    endpoint.addr,
                    cfg.timeout,
                    MuxConnector::Tcp,
                    cfg.upstream_max_inflight,
                    endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                    cfg.upstream_max_response_bytes,
                ))),
                UpstreamProto::Tls => {
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
                        .map_err(|e| {
                            anyhow!(
                                "invalid TLS server name for upstream {}: {e}",
                                endpoint.addr
                            )
                        })?
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
                    UpstreamTransport::Tcp(Arc::new(TcpMux::new(
                        node_name,
                        endpoint.addr,
                        cfg.timeout,
                        MuxConnector::Tls {
                            config: tls_config,
                            server_name,
                        },
                        cfg.upstream_max_inflight,
                        endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                        cfg.upstream_max_response_bytes,
                    )))
                }
                UpstreamProto::Https => {
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
                    UpstreamTransport::Doh(Arc::new(DoHUpstream::new(
                        node_name,
                        endpoint.addr,
                        server_name,
                        path,
                        cfg.timeout,
                        endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                    )?))
                }
                UpstreamProto::Quic => {
                    let server_name = endpoint
                        .server_name
                        .clone()
                        .unwrap_or_else(|| endpoint.addr.ip().to_string());
                    crate::startup!(
                        "upstream {node_name} proto=doq remote={} sni={server_name}",
                        endpoint.addr
                    );
                    make_doq_transport(
                        node_name,
                        endpoint.addr,
                        server_name,
                        cfg.timeout,
                        endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                        cfg.upstream_max_inflight,
                    )?
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
                    make_h3_transport(
                        node_name,
                        endpoint.addr,
                        server_name,
                        path,
                        cfg.timeout,
                        endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                        cfg.upstream_max_inflight,
                    )?
                }
            };
            nodes.push(UpstreamNode {
                transport,
                client_filter: endpoint.proto.client_filter(),
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
                msg.push_str(&format!(" udp_pool={}", cfg.udp_pool_size));
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
    /// Returns `None` only when no node is compatible with `client_proto`.
    fn select_primary_idx(
        &self,
        start: usize,
        query_ix: u64,
        now: u64,
        client_proto: ClientProto,
    ) -> Option<usize> {
        // Periodic probe: force-route to the least-recently-selected eligible node every
        // PROBE_INTERVAL queries so healthy-but-slow nodes are re-measured periodically.
        let probe = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.enabled_for(client_proto) && !n.health.is_penalized_at(now))
            .min_by_key(|(_, n)| n.last_selected.load(Ordering::Relaxed));
        if let Some((probe_idx, probe_node)) = probe {
            if query_ix.wrapping_sub(probe_node.last_selected.load(Ordering::Relaxed))
                >= PROBE_INTERVAL
            {
                return Some(probe_idx);
            }
        }

        // Normal path: banded selection (Unbound-style RTT banding, AdGuard-style
        // load spreading).  Collect each eligible node's score, find the best, then
        // pick pseudo-randomly among all nodes whose score falls within the band.
        // Near-equal nodes share traffic, which keeps their RTT estimates fresh and
        // gives instant warm failover targets; a clearly slower node still gets
        // nothing outside its periodic probe.
        let mut candidates: SmallVec<[(usize, u64); 8]> = SmallVec::new();
        let mut best_score = u64::MAX;
        for (idx, node) in self.nodes.iter().enumerate() {
            if !node.enabled_for(client_proto) || node.health.is_penalized_at(now) {
                continue;
            }
            let score = node.selection_score();
            best_score = best_score.min(score);
            candidates.push((idx, score));
        }
        if !candidates.is_empty() {
            let limit = band_limit(best_score);
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

        // All eligible nodes are penalized; use them in round-robin order.
        for offset in 0..self.nodes.len() {
            let idx = (start + offset) % self.nodes.len();
            if self.nodes[idx].enabled_for(client_proto) {
                return Some(idx);
            }
        }
        None
    }

    /// Pick the best secondary node for hedging: the lowest-scoring non-penalized node
    /// that is not the primary.  Falls back to penalized nodes when no healthy alternative
    /// exists, and returns `None` only when there is truly no other compatible node.
    fn select_secondary_idx(&self, primary_idx: usize, client_proto: ClientProto) -> Option<usize> {
        let now = now_ms();
        self.nodes
            .iter()
            .enumerate()
            .filter(|(i, n)| {
                *i != primary_idx && n.enabled_for(client_proto) && !n.health.is_penalized_at(now)
            })
            .min_by_key(|(_, n)| n.selection_score())
            .or_else(|| {
                // All alternatives are penalized; pick the least-bad one.
                self.nodes
                    .iter()
                    .enumerate()
                    .filter(|(i, n)| *i != primary_idx && n.enabled_for(client_proto))
                    .min_by_key(|(_, n)| n.selection_score())
            })
            .map(|(i, _)| i)
    }

    pub async fn exchange_observed(
        &self,
        packet: Bytes,
        client_id: u16,
        client_proto: ClientProto,
        count_hedge: bool,
    ) -> Result<Bytes> {
        if self.nodes.is_empty() {
            return Err(anyhow!("empty upstream group"));
        }
        let raw = self.next.fetch_add(1, Ordering::Relaxed);
        let query_ix = raw as u64;
        let now = now_ms();

        // Extract question bytes once for stale/mismatch validation in UDP/TCP recv loops.
        let question = match dns::question_end(&packet) {
            Some(end) => packet.slice(12..end),
            None => Bytes::new(),
        };

        let Some(primary_idx) = self.select_primary_idx(raw, query_ix, now, client_proto) else {
            return Err(anyhow!(
                "empty upstream group for {:?} client transport",
                client_proto
            ));
        };
        let primary_node = &self.nodes[primary_idx];
        primary_node
            .last_selected
            .store(query_ix, Ordering::Relaxed);

        // Fast path: no hedging configured.
        let Some(hedge_delay) = self.hedge_delay else {
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
        // Phase 1: give primary `hedge_delay` to respond.  If it answers in time, return
        //          immediately with zero extra upstream traffic.
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

        if count_hedge {
            if let Some(ctr) = &self.querylog_counters {
                ctr.hedged_queries.fetch_add(1, Ordering::Relaxed);
            }
        }
        let Some(secondary_idx) = self.select_secondary_idx(primary_idx, client_proto) else {
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
                    self.nodes[secondary_idx].health.release_probe();
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
                    self.nodes[primary_idx].health.release_probe();
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
    Doh(Arc<DoHUpstream>),
    #[cfg(feature = "doq")]
    Doq(Arc<DoQUpstream>),
    #[cfg(feature = "h3")]
    H3(Arc<H3Upstream>),
}

struct UpstreamNode {
    transport: UpstreamTransport,
    client_filter: Option<ClientProto>,
    health: HealthStats,
    stats: NodeStats,
    /// Monotonic query index of the last time this node was selected (probe or normal).
    /// Initialized to 0; used by the probe scheduler to find the least-recently-used node.
    last_selected: AtomicU64,
    /// Human-readable address string for this individual node (e.g. "tls://1.1.1.1:853").
    addr_display: String,
}

/// RAII guard that decrements `active_inflight` on drop.
/// Ensures the counter is corrected even when the owning future is cancelled
/// mid-flight by `tokio::select!` (e.g., the losing side of a hedged race).
struct ActiveInflightGuard<'a>(&'a AtomicI64);

/// RAII guard that decrements `active_hedges` when Phase 2 of a hedged exchange exits,
/// including on cancellation via `tokio::select!`.
struct HedgeGuard<'a>(&'a AtomicU64);

impl Drop for ActiveInflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for HedgeGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl UpstreamNode {
    fn enabled_for(&self, client_proto: ClientProto) -> bool {
        self.client_filter.is_none_or(|proto| proto == client_proto)
    }

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

    async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        self.stats.active_inflight.fetch_add(1, Ordering::Relaxed);
        // Guard ensures the counter is decremented even on future cancellation.
        let _inflight = ActiveInflightGuard(&self.stats.active_inflight);
        let t0 = Instant::now();
        let result = self.transport.exchange(req).await;
        let rtt_us = t0.elapsed().as_micros() as u64;
        match &result {
            Ok(_) => {
                let was_penalized = self.health.penalty_until_ms.load(Ordering::Relaxed) != 0;
                self.health.record_success(rtt_us);
                self.stats.record_ok(rtt_us);
                if was_penalized {
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
                let n = self.health.record_failure(is_timeout);
                if is_timeout {
                    self.stats.record_timeout();
                } else {
                    self.stats.record_err();
                }
                if n == FAILURE_THRESHOLD {
                    crate::startup!(
                        "upstream {} event=penalized consecutive_failures={n}",
                        self.transport.name()
                    );
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
pub(super) fn make_tls_config() -> Arc<rustls::ClientConfig> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

// -- QUIC/H3 transport factories ----------------------------------------------

/// Return a `Doq` transport when the `doq` feature is compiled in; otherwise
/// return a descriptive error so the user knows which flag to enable.
#[allow(unreachable_code)]
fn make_doq_transport(
    name: String,
    remote: SocketAddr,
    server_name: String,
    timeout: Duration,
    ecs_mode: EcsMode,
    max_inflight: usize,
) -> Result<UpstreamTransport> {
    #[cfg(feature = "doq")]
    return Ok(UpstreamTransport::Doq(Arc::new(DoQUpstream::new(
        name,
        remote,
        server_name,
        timeout,
        ecs_mode,
        max_inflight,
    )?)));
    drop((name, remote, server_name, timeout, ecs_mode, max_inflight));
    Err(anyhow!(
        "quic:// upstream requires the 'doq' feature; recompile with: cargo build --features doq"
    ))
}

/// Return an `H3` transport when the `h3` feature is compiled in; otherwise
/// return a descriptive error.
#[allow(unreachable_code)]
fn make_h3_transport(
    name: String,
    remote: SocketAddr,
    server_name: String,
    path: String,
    timeout: Duration,
    ecs_mode: EcsMode,
    max_inflight: usize,
) -> Result<UpstreamTransport> {
    #[cfg(feature = "h3")]
    return Ok(UpstreamTransport::H3(Arc::new(H3Upstream::new(
        name,
        remote,
        server_name,
        path,
        timeout,
        ecs_mode,
        max_inflight,
    )?)));
    drop((
        name,
        remote,
        server_name,
        path,
        timeout,
        ecs_mode,
        max_inflight,
    ));
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

/// Stateless one-shot TCP exchange used as fallback for TC-bit UDP responses.
pub(super) async fn tcp_exchange_packet(
    remote: SocketAddr,
    packet: &[u8],
    timeout: Duration,
    name: &str,
) -> Result<Vec<u8>> {
    let fut = async {
        let mut stream = connect_tcp_nodelay(remote, timeout, name).await?;
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
) -> Result<TcpStream> {
    tokio::time::timeout(timeout, async {
        let s = TcpStream::connect(remote)
            .await
            .with_context(|| format!("upstream {name}: TCP connect to {remote}"))?;
        s.set_nodelay(true)?;
        Ok::<TcpStream, anyhow::Error>(s)
    })
    .await
    .map_err(|_| anyhow!("upstream {name} tcp connect timeout: {remote}"))
    .and_then(|r| r)
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

/// Apply the upstream ECS mode to a query packet, returning a (possibly new) `Bytes`.
pub(super) fn apply_ecs_mode(packet: &Bytes, mode: &EcsMode) -> Bytes {
    match mode {
        EcsMode::Strip => dns::strip_edns_ecs(packet)
            .map(Bytes::from)
            .unwrap_or_else(|| packet.clone()),
        EcsMode::Forward => packet.clone(),
        EcsMode::Fixed(subnet) => dns::inject_or_replace_ecs(packet, subnet)
            .map(Bytes::from)
            .unwrap_or_else(|| packet.clone()),
    }
}

// -- Socket buffer helpers ----------------------------------------------------

fn set_buf_size_fd(fd: libc::c_int, size: usize) {
    let size_i32 = size.min(i32::MAX as usize) as libc::c_int;
    for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &size_i32 as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size_i32) as libc::socklen_t,
            );
        }
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

// -- Tests ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_inflates_rtt_estimate() {
        let h = HealthStats::new(0);
        h.record_success(20_000);
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), 20_000);

        // First failure: 20_000 * 2 = 40_000 < floor, so the floor applies.
        h.record_failure(false);
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_FLOOR_US);

        // Subsequent failures double the estimate.
        h.record_failure(false);
        assert_eq!(
            h.ewma_rtt_us.load(Ordering::Relaxed),
            FAILURE_RTT_FLOOR_US * 2
        );
    }

    #[test]
    fn failure_inflation_is_capped() {
        let h = HealthStats::new(0);
        h.record_success(8_000_000);
        h.record_failure(false);
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_CAP_US);
        h.record_failure(false);
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_CAP_US);
    }

    #[test]
    fn failure_with_no_data_uses_floor() {
        let h = HealthStats::new(0);
        h.record_failure(false);
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_FLOOR_US);
    }

    #[test]
    fn success_after_failure_adopts_fresh_sample() {
        let h = HealthStats::new(0);
        h.record_success(20_000);
        h.record_failure(false);
        h.record_failure(false);
        // Recovery: fresh sample replaces the inflated estimate outright.
        h.record_success(22_000);
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), 22_000);
        assert_eq!(h.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn steady_state_success_blends_ewma() {
        let h = HealthStats::new(0);
        h.record_success(20_000);
        h.record_success(40_000);
        // 0.75 * 20_000 + 0.25 * 40_000 = 25_000
        assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), 25_000);
    }

    #[test]
    fn penalty_after_threshold_and_reset_on_success() {
        let h = HealthStats::new(0);
        for _ in 0..FAILURE_THRESHOLD {
            h.record_failure(false);
        }
        assert!(h.is_penalized_at(now_ms()));
        h.record_success(1_000);
        assert!(!h.is_penalized_at(now_ms()));
    }

    #[test]
    fn band_limit_floor_and_factor() {
        // No data / zero best: floor only.
        assert_eq!(band_limit(0), SELECT_BAND_FLOOR_US);
        // Sub-millisecond best: additive floor dominates (500*2 < 500+2000).
        assert_eq!(band_limit(500), 500 + SELECT_BAND_FLOOR_US);
        // Above the floor crossover: multiplicative factor dominates.
        assert_eq!(band_limit(10_000), 20_000);
    }
}
