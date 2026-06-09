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
//! `UpstreamPool::exchange` uses EWMA RTT × (1 + active_inflight) as a selection score
//! rather than pure round-robin.  Ties are broken by round-robin offset so load is spread
//! when all nodes are equally fast.  Nodes in the penalty window are skipped in the first
//! pass; if all are penalized they are used anyway (fallback round-robin).
//!
//! # Truncated UDP responses
//! A UDP response with TC=1 triggers an automatic one-shot TCP retry.

mod doh;
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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
}

impl HealthStats {
    fn new() -> Self {
        Self {
            ewma_rtt_us: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            penalty_until_ms: AtomicU64::new(0),
        }
    }

    fn record_success(&self, rtt_us: u64) {
        let old = self.ewma_rtt_us.load(Ordering::Relaxed);
        let new_ewma = if old == 0 {
            rtt_us
        } else {
            // EWMA alpha=0.25: new = 0.75*old + 0.25*rtt
            old.wrapping_sub(old >> 2).wrapping_add(rtt_us >> 2)
        };
        self.ewma_rtt_us.store(new_ewma, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.penalty_until_ms.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self) -> u32 {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= FAILURE_THRESHOLD {
            self.penalty_until_ms
                .store(now_ms() + PENALTY_DURATION_MS, Ordering::Relaxed);
        }
        n
    }

    fn is_penalized_at(&self, now: u64) -> bool {
        let until = self.penalty_until_ms.load(Ordering::Relaxed);
        until != 0 && now < until
    }
}

// -- Upstream pool ------------------------------------------------------------

pub struct UpstreamPool {
    nodes: Vec<UpstreamNode>,
    next: AtomicUsize,
    /// When `Some(δ)`, a second upstream is started after δ with no response.
    hedge_delay: Option<Duration>,
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
        match self {
            Self::Udp | Self::Tcp | Self::Tls | Self::Https | Self::Quic | Self::H3 => None,
            Self::UdpIncoming => Some(ClientProto::Udp),
            Self::TcpIncoming => Some(ClientProto::Tcp),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Udp | Self::UdpIncoming => "udp",
            Self::Tcp | Self::TcpIncoming => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::H3 => "h3",
        }
    }
}

impl UpstreamPool {
    pub async fn new(name: &str, addrs: &[UpstreamEndpoint], cfg: &UpstreamConfig) -> Result<Self> {
        let mut nodes = Vec::new();
        let mut udp = 0usize;
        let mut tcp = 0usize;
        let mut tls = 0usize;
        let mut https = 0usize;
        let mut quic = 0usize;
        let mut h3 = 0usize;
        let mut udp_incoming = 0usize;
        let mut tcp_incoming = 0usize;
        for (idx, endpoint) in addrs.iter().cloned().enumerate() {
            match endpoint.proto {
                UpstreamProto::Udp => udp += 1,
                UpstreamProto::Tcp => tcp += 1,
                UpstreamProto::Tls => tls += 1,
                UpstreamProto::Https => https += 1,
                UpstreamProto::Quic => quic += 1,
                UpstreamProto::H3 => h3 += 1,
                UpstreamProto::UdpIncoming => udp_incoming += 1,
                UpstreamProto::TcpIncoming => tcp_incoming += 1,
            }

            let node_name = format!("{name}-{idx}");
            let transport = match endpoint.proto {
                UpstreamProto::Udp | UpstreamProto::UdpIncoming => {
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
                UpstreamProto::Tcp | UpstreamProto::TcpIncoming => {
                    UpstreamTransport::Tcp(Arc::new(TcpMux::new(
                        node_name,
                        endpoint.addr,
                        cfg.timeout,
                        MuxConnector::Tcp,
                        cfg.upstream_max_inflight,
                        endpoint.ecs_mode.clone().unwrap_or(EcsMode::Strip),
                    )))
                }
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
                    )))
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
                    )?
                }
            };
            nodes.push(UpstreamNode {
                transport,
                client_filter: endpoint.proto.client_filter(),
                health: HealthStats::new(),
                stats: NodeStats::new(),
                last_selected: AtomicU64::new(0),
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
            if udp_incoming > 0 {
                msg.push_str(&format!(" udp_in={udp_incoming}"));
            }
            if tcp_incoming > 0 {
                msg.push_str(&format!(" tcp_in={tcp_incoming}"));
            }
            if udp > 0 || udp_incoming > 0 {
                msg.push_str(&format!(" udp_pool={}", cfg.udp_pool_size));
            }
            crate::startup!("{msg}");
        }
        crate::verbose!(
            "upstream {} nodes={} timeout={}s",
            name,
            nodes.len(),
            cfg.timeout.as_secs()
        );
        Ok(Self {
            nodes,
            next: AtomicUsize::new(0),
            hedge_delay: cfg.hedge_delay,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
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

        // Normal path: single pass to find the first minimum-EWMA×inflight node,
        // starting at `start` for round-robin tiebreak.
        let mut best_idx: Option<usize> = None;
        let mut best_score = u64::MAX;
        for offset in 0..self.nodes.len() {
            let idx = (start + offset) % self.nodes.len();
            let node = &self.nodes[idx];
            if !node.enabled_for(client_proto) || node.health.is_penalized_at(now) {
                continue;
            }
            let score = node.selection_score();
            if score < best_score {
                best_score = score;
                best_idx = Some(idx);
            }
        }
        if best_idx.is_some() {
            return best_idx;
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

    pub async fn exchange(
        &self,
        packet: Bytes,
        client_id: u16,
        client_proto: ClientProto,
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
            crate::verbose!(
                "upstream event=no_matching_transport client_proto={:?}",
                client_proto
            );
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

        // Phase 2: hedge timer fired; start a second upstream in parallel.
        crate::stats::inc_hedged_queries();
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
                    result
                } else {
                    // Primary errored; let secondary complete.
                    let secondary_result = secondary_fut.await;
                    if secondary_result.is_ok() {
                        crate::stats::inc_hedge_wins();
                    }
                    secondary_result.or(result)
                }
            }
            result = &mut secondary_fut => {
                if result.is_ok() {
                    // Secondary succeeded first; cancel primary.
                    self.nodes[primary_idx].stats.record_cancelled();
                    crate::stats::inc_hedge_wins();
                    result
                } else {
                    // Secondary failed first; keep waiting for primary.
                    primary_fut.await
                }
            }
        }
    }

    /// Collect per-node stats snapshots for the metrics renderer.
    pub fn node_snapshots(&self, pool_name: &str) -> Vec<NodeStatsSnapshot> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, n)| n.stats.snapshot(&format!("{pool_name}-{i}")))
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
}

/// RAII guard that decrements `active_inflight` on drop.
/// Ensures the counter is corrected even when the owning future is cancelled
/// mid-flight by `tokio::select!` (e.g., the losing side of a hedged race).
struct ActiveInflightGuard<'a>(&'a AtomicI64);

impl Drop for ActiveInflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl UpstreamNode {
    fn enabled_for(&self, client_proto: ClientProto) -> bool {
        self.client_filter
            .map_or(true, |proto| proto == client_proto)
    }

    /// Selection score: EWMA RTT × (1 + active_inflight).
    /// Nodes without RTT data score 0 (optimistic) so they tie for best priority and are
    /// tried immediately via round-robin.  Steady-state probing of measured-but-slow nodes
    /// is handled by the `PROBE_INTERVAL` scheduler in `UpstreamPool::exchange`.
    fn selection_score(&self) -> u64 {
        let ewma = self.health.ewma_rtt_us.load(Ordering::Relaxed);
        let inflight = self.stats.active_inflight.load(Ordering::Relaxed).max(0) as u64;
        if ewma == 0 {
            inflight
        } else {
            ewma.saturating_mul(1 + inflight)
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
                let n = self.health.record_failure();
                if err.to_string().contains("timeout") {
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
) -> Result<UpstreamTransport> {
    #[cfg(feature = "doq")]
    return Ok(UpstreamTransport::Doq(Arc::new(DoQUpstream::new(
        name,
        remote,
        server_name,
        timeout,
        ecs_mode,
    )?)));
    drop((name, remote, server_name, timeout, ecs_mode));
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
) -> Result<UpstreamTransport> {
    #[cfg(feature = "h3")]
    return Ok(UpstreamTransport::H3(Arc::new(H3Upstream::new(
        name,
        remote,
        server_name,
        path,
        timeout,
        ecs_mode,
    )?)));
    drop((name, remote, server_name, path, timeout, ecs_mode));
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
    let resp_q = resp_qend
        .and_then(|e| resp.get(12..e))
        .unwrap_or(&[][..]);
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
        crate::verbose!("upstream name={name} proto=tcp remote={remote} event=send");
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

#[cfg(unix)]
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

/// Set SO_RCVBUF and SO_SNDBUF on a tokio UdpSocket (Unix only).
#[cfg(unix)]
pub fn set_socket_buf_size(socket: &tokio::net::UdpSocket, size: usize) {
    if size == 0 {
        return;
    }
    use std::os::unix::io::AsRawFd;
    set_buf_size_fd(socket.as_raw_fd(), size);
}

/// Set SO_RCVBUF and SO_SNDBUF on a raw file descriptor (Unix only).
#[cfg(unix)]
pub fn set_raw_socket_buf_size(fd: libc::c_int, size: usize) {
    if size == 0 {
        return;
    }
    set_buf_size_fd(fd, size);
}
