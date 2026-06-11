//! DNS query pipeline: fast path (parse → qtype filter → cache), slow path (classify →
//! upstream → cache store), and background cache refresh.
//!
//! Listener code owns sockets and framing; this module owns packet lifecycle after a DNS
//! message has been received.

use crate::cache::{cache_key, cache_key_strip_ecs, CacheKey, CacheRefresh};
use crate::dns;
use crate::ipset::TestVerdict;
use crate::router::RouteTarget;
use crate::server::{AppState, CustomGroup};
use crate::upstream::ClientProto;
use crate::{router, singleflight};
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate-limit state for upstream-failure warnings (shared across all targets).
static UPSTREAM_FAIL_LAST_WARN: AtomicU64 = AtomicU64::new(0);

/// Sentinel group_id for NoneIpSet ("none" fallback) cache entries.
/// Cannot use u16::MAX (65535) because that is the existing "no group" sentinel.
const GROUP_ID_NONE_FALLBACK: u16 = 65534;

struct QueryContext {
    packet: Bytes,
    info: dns::QueryInfo,
    origin: QueryOrigin,
}

#[derive(Clone, Copy)]
enum QueryOrigin {
    Client {
        peer: SocketAddr,
        proto: ClientProto,
    },
    CacheRefresh,
}

impl QueryContext {
    /// Raw DNS question bytes (qname + qtype + qclass), used as the cache/singleflight key.
    fn question(&self) -> &[u8] {
        &self.packet[12..self.info.question_end]
    }

    fn client(&self) -> Option<(SocketAddr, ClientProto)> {
        match self.origin {
            QueryOrigin::Client { peer, proto } => Some((peer, proto)),
            QueryOrigin::CacheRefresh => None,
        }
    }

    fn proto(&self) -> ClientProto {
        match self.origin {
            QueryOrigin::Client { proto, .. } => proto,
            QueryOrigin::CacheRefresh => ClientProto::Udp,
        }
    }
}

struct SingleflightLeader<'a> {
    state: &'a AppState,
    key: CacheKey,
}

impl Drop for SingleflightLeader<'_> {
    fn drop(&mut self) {
        singleflight::remove(&self.state.remote_inflight, &self.key);
    }
}

/// Result of the synchronous fast path: parse header, apply qtype filter, check cache.
pub(crate) enum FastPathOutcome {
    /// Ready-to-send response (filter hit or cache hit).
    /// `refresh` carries a background cache-refresh request when the entry is near expiry.
    Response {
        resp: Bytes,
        refresh: Option<CacheRefresh>,
    },
    /// Cache miss; full async resolution is required.
    Miss { info: dns::FastQueryInfo },
    /// Malformed packet; drop silently, send no reply.
    Drop,
}

/// Decode a `group_id` stored in the cache into a display name.
/// - `u16::MAX` (65535) → no group (legacy sentinel, treated as None)
/// - `GROUP_ID_NONE_FALLBACK` (65534) → "none" (NoneIpSet route)
/// - anything else → look up in `state.groups`
fn group_id_to_name(group_id: u16, state: &AppState) -> Option<Arc<str>> {
    if group_id == u16::MAX {
        None
    } else if group_id == GROUP_ID_NONE_FALLBACK {
        Some(Arc::from("none"))
    } else {
        state
            .groups
            .get(group_id as usize)
            .map(|g| Arc::from(g.name.as_str()))
    }
}

#[inline]
fn record_query_received(ql: &crate::querylog::QueryLogHandle, proto: ClientProto) {
    ql.counters.queries_total.fetch_add(1, Ordering::Relaxed);
    match proto {
        ClientProto::Udp => ql.counters.queries_udp.fetch_add(1, Ordering::Relaxed),
        ClientProto::Tcp => ql.counters.queries_tcp.fetch_add(1, Ordering::Relaxed),
    };
}

/// Synchronous fast path: parse header, apply qtype filter, look up the Moka cache.
///
/// Returns immediately with a ready response for the overwhelming majority of queries (cache hits
/// and filter hits) without allocating a Tokio task. Only cache misses need a spawned task.
/// Called both from the UDP receive loop (inline, no spawn) and from `handle_packet` (for TCP
/// and UDP misses that were spawned before this check could short-circuit them).
pub(crate) fn try_fast_path(
    packet: &[u8],
    peer: SocketAddr,
    proto: ClientProto,
    state: &AppState,
) -> FastPathOutcome {
    let t0 = state.querylog.collecting().then(Instant::now);

    // Non-QUERY opcodes (STATUS, NOTIFY, UPDATE, …): return NOTIMP per RFC 1035.
    if packet.len() >= 3 && (packet[2] & 0x80) == 0 && (packet[2] >> 3) & 0x0f != 0 {
        return FastPathOutcome::Response {
            resp: Bytes::from(dns::notimp_opcode_reply(packet)),
            refresh: None,
        };
    }

    let fast_info = match dns::parse_query_fast(packet) {
        Ok(info) => info,
        Err(_) => return FastPathOutcome::Drop,
    };
    record_query_received(&state.querylog, proto);

    // Non-IN/non-ANY QCLASS: return NOTIMP per RFC 1035.
    {
        let i = fast_info.question_end.saturating_sub(2);
        let qclass = u16::from_be_bytes([packet[i], packet[i + 1]]);
        if qclass != 1 && qclass != 255 {
            return FastPathOutcome::Response {
                resp: Bytes::from(
                    dns::notimp_reply(packet, fast_info.question_end).unwrap_or_default(),
                ),
                refresh: None,
            };
        }
    }

    // Fast cache read: no qname allocation needed.
    if let Some(hit) = state
        .cache
        .get_with_ecs_fallback(packet, fast_info.question_end, fast_info.id)
    {
        // When stale-client-timeout is enabled and the hit is stale, fall through to the
        // async path so it can race upstream vs the timeout before deciding to serve stale.
        if hit.is_stale && state.stale_client_timeout_ms > 0 {
            return FastPathOutcome::Miss { info: fast_info };
        }
        let ql = &state.querylog;
        ql.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
        if hit.is_stale {
            ql.counters.stale_served.fetch_add(1, Ordering::Relaxed);
        }
        if ql.collecting() {
            ql.try_emit_with(|seq| crate::querylog::QueryLogEvent {
                seq,
                unix_micros: crate::querylog::unix_micros_now(),
                client: peer.ip(),
                client_port: peer.port(),
                qname: hit.qname.clone(),
                qtype: fast_info.qtype,
                rcode: dns::rcode(&hit.packet),
                elapsed_us: t0.map_or(0, |t| t.elapsed().as_micros() as u64),
                response_bytes: hit.packet.len() as u32,
                source: if hit.is_stale { "stale" } else { "cache" },
                group: group_id_to_name(hit.group_id, state),
                answer_ips: smallvec::SmallVec::new(),
            });
        }
        return FastPathOutcome::Response {
            resp: hit.packet,
            refresh: hit.refresh,
        };
    }

    FastPathOutcome::Miss { info: fast_info }
}

/// UDP fast path variant that writes the cache hit response directly into a reusable send buffer,
/// avoiding the `BytesMut::from(entry.packet.as_ref())` copy in `CacheLookup::packet`.
pub(crate) fn try_fast_path_into(
    packet: &[u8],
    peer: SocketAddr,
    state: &AppState,
    send_buf: &mut BytesMut,
) -> FastPathOutcome {
    let t0 = state.querylog.collecting().then(Instant::now);

    // Non-QUERY opcodes: return NOTIMP per RFC 1035.
    if packet.len() >= 3 && (packet[2] & 0x80) == 0 && (packet[2] >> 3) & 0x0f != 0 {
        return FastPathOutcome::Response {
            resp: Bytes::from(dns::notimp_opcode_reply(packet)),
            refresh: None,
        };
    }

    let fast_info = match dns::parse_query_fast(packet) {
        Ok(info) => info,
        Err(_) => return FastPathOutcome::Drop,
    };
    record_query_received(&state.querylog, ClientProto::Udp);

    // Non-IN/non-ANY QCLASS: return NOTIMP.
    {
        let i = fast_info.question_end.saturating_sub(2);
        let qclass = u16::from_be_bytes([packet[i], packet[i + 1]]);
        if qclass != 1 && qclass != 255 {
            return FastPathOutcome::Response {
                resp: Bytes::from(
                    dns::notimp_reply(packet, fast_info.question_end).unwrap_or_default(),
                ),
                refresh: None,
            };
        }
    }

    // Cache hit: write directly into the caller-provided send buffer.
    if let Some(meta) = state
        .cache
        .get_into_with_ecs_fallback(packet, fast_info.question_end, fast_info.id, send_buf)
    {
        // When stale-client-timeout is enabled and the hit is stale, fall through to the
        // async path so it can race upstream vs the timeout before deciding to serve stale.
        if meta.is_stale && state.stale_client_timeout_ms > 0 {
            return FastPathOutcome::Miss { info: fast_info };
        }
        let ql = &state.querylog;
        ql.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
        if meta.is_stale {
            ql.counters.stale_served.fetch_add(1, Ordering::Relaxed);
        }
        if ql.collecting() {
            ql.try_emit_with(|seq| crate::querylog::QueryLogEvent {
                seq,
                unix_micros: crate::querylog::unix_micros_now(),
                client: peer.ip(),
                client_port: peer.port(),
                qname: meta.qname.clone(),
                qtype: fast_info.qtype,
                rcode: dns::rcode(send_buf),
                elapsed_us: t0.map_or(0, |t| t.elapsed().as_micros() as u64),
                response_bytes: send_buf.len() as u32,
                source: if meta.is_stale { "stale" } else { "cache" },
                group: group_id_to_name(meta.group_id, state),
                answer_ips: smallvec::SmallVec::new(),
            });
        }
        let resp = send_buf.split().freeze();
        return FastPathOutcome::Response {
            resp,
            refresh: meta.refresh,
        };
    }

    FastPathOutcome::Miss { info: fast_info }
}

pub(crate) async fn handle_packet_bytes(
    packet: Bytes,
    peer: SocketAddr,
    proto: ClientProto,
    state: Arc<AppState>,
) -> Result<Option<Bytes>> {
    match try_fast_path(&packet, peer, proto, &state) {
        FastPathOutcome::Response { resp, refresh } => {
            if let Some(r) = refresh {
                spawn_cache_refresh(r, &state);
            }
            Ok(Some(resp))
        }
        FastPathOutcome::Drop => Ok(None),
        FastPathOutcome::Miss { info } => {
            handle_packet_slow_preparsed(packet, peer, proto, state, info, None).await
        }
    }
}

/// Slow path for cache misses. Skips the fast-path check and reuses the already
/// parsed header/question offsets from `try_fast_path`.
///
/// `pre_permit`: a semaphore permit acquired BEFORE spawning the task (UDP path).
/// Pass `None` for the TCP path — the permit is acquired inside the function.
pub(crate) async fn handle_packet_slow_preparsed(
    packet: Bytes,
    peer: SocketAddr,
    proto: ClientProto,
    state: Arc<AppState>,
    fast_info: dns::FastQueryInfo,
    pre_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Option<Bytes>> {
    let info = match dns::parse_query_from_fast(&packet, fast_info) {
        Ok(info) => info,
        Err(_) => return Ok(None),
    };
    handle_packet_slow_with_info(packet, peer, proto, state, info, pre_permit).await
}

async fn handle_packet_slow_with_info(
    packet: Bytes,
    peer: SocketAddr,
    proto: ClientProto,
    state: Arc<AppState>,
    info: dns::QueryInfo,
    pre_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Option<Bytes>> {
    // Use a pre-acquired permit (UDP path, acquired before spawn) or acquire one now (TCP path).
    let permit = match pre_permit {
        Some(p) => p,
        None => match state.limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Queue mode: wait up to inflight_queue_ms for a permit before hard-dropping.
                let acquired = if state.cfg.inflight_queue_ms > 0 {
                    state
                        .querylog
                        .counters
                        .inflight_queued
                        .fetch_add(1, Ordering::Relaxed);
                    let wait = Duration::from_millis(state.cfg.inflight_queue_ms);
                    tokio::time::timeout(wait, state.limit.clone().acquire_owned())
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                } else {
                    None
                };
                match acquired {
                    Some(permit) => permit,
                    None => {
                        state
                            .querylog
                            .counters
                            .inflight_drops
                            .fetch_add(1, Ordering::Relaxed);
                        let servfail = dns::servfail_reply(&packet, info.question_end)
                            .map(Bytes::from)
                            .ok();
                        if let Some(resp) = &servfail {
                            let ctx = QueryContext {
                                packet,
                                info,
                                origin: QueryOrigin::Client { peer, proto },
                            };
                            emit_slow_event(&ctx, &state, resp, "overload", None, 0);
                        }
                        return Ok(servfail);
                    }
                }
            }
        },
    };

    let resp = {
        let _permit = permit;
        resolve_query(
            QueryContext {
                packet,
                info,
                origin: QueryOrigin::Client { peer, proto },
            },
            &state,
        )
        .await?
    };

    Ok(Some(resp))
}

async fn resolve_query(ctx: QueryContext, state: &Arc<AppState>) -> Result<Bytes> {
    let geosite = if state.needs_geosite {
        state.geosite_snapshot()
    } else {
        None
    };
    if let Some(group) =
        state
            .routing_index
            .route(&state.groups, &ctx.info.qname, geosite.as_deref())
    {
        if let Some(target) = group.target() {
            return exchange_with_dedupe(ctx, state, target).await;
        }
        // Null group: block when filter_qtype is empty (block all) or matches this qtype.
        // When filter_qtype is non-empty but does not contain this qtype, fall through to
        // global routing so only the listed types are suppressed.
        if group.filter_qtype.is_empty() || group.filter_qtype.contains(&ctx.info.qtype) {
            state
                .querylog
                .counters
                .null_responses
                .fetch_add(1, Ordering::Relaxed);
            let resp =
                dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from)?;
            emit_slow_event(&ctx, state, &resp, "null", None, 0);
            return Ok(resp);
        }
    }

    let Some(target) = router::classify_target(state, ctx.info.qtype) else {
        state
            .querylog
            .counters
            .null_responses
            .fetch_add(1, Ordering::Relaxed);
        let resp = dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from)?;
        emit_slow_event(&ctx, state, &resp, "null", None, 0);
        return Ok(resp);
    };

    exchange_with_dedupe(ctx, state, target).await
}

/// Check the stale cache for a usable entry. On hit: record stats, log, and return it.
/// The stale entry is also published to singleflight waiters (inside `serve_stale`).
fn try_stale(
    state: &AppState,
    ck: &CacheKey,
    query: &[u8],
    info: &dns::QueryInfo,
    _group_name: &str,
    started: Instant,
    _reason: &str,
    count_client_stats: bool,
) -> Option<Bytes> {
    let stale = serve_stale(state, ck, query, info)?;
    if count_client_stats {
        let elapsed = started.elapsed().as_micros() as u64;
        state
            .querylog
            .counters
            .rtt_sum_us
            .fetch_add(elapsed, Ordering::Relaxed);
        state
            .querylog
            .counters
            .rtt_count
            .fetch_add(1, Ordering::Relaxed);
        state
            .querylog
            .counters
            .stale_served
            .fetch_add(1, Ordering::Relaxed);
    }
    Some(stale)
}

/// Run the appropriate upstream exchange for a given route target.
/// Extracted so it can be pinned and raced against a timeout.
async fn do_upstream_exchange(
    ctx: &QueryContext,
    state: &Arc<AppState>,
    target: &RouteTarget<'_>,
) -> Result<Bytes> {
    match target {
        RouteTarget::Race { primary, secondary } => {
            race(
                ctx.packet.clone(),
                ctx.info.id,
                ctx.proto(),
                primary,
                secondary,
                ctx.client().is_some(),
            )
            .await
        }
        RouteTarget::NoneIpSet { primary, secondary } => {
            resolve_none_group_with_ipset(
                ctx.packet.clone(),
                &ctx.info,
                ctx.proto(),
                primary,
                secondary,
                state,
                ctx.client().is_some(),
            )
            .await
        }
        RouteTarget::Group(_) => {
            let Some(upstream) = target.upstream() else {
                anyhow::bail!("route target requires an upstream");
            };
            upstream
                .exchange_observed(
                    ctx.packet.clone(),
                    ctx.info.id,
                    ctx.proto(),
                    ctx.client().is_some(),
                )
                .await
        }
    }
}

async fn exchange_with_dedupe(
    ctx: QueryContext,
    state: &Arc<AppState>,
    target: RouteTarget<'_>,
) -> Result<Bytes> {
    // Apply qtype filter before any network activity.
    if let RouteTarget::Group(g) = &target {
        if g.filter_qtype.contains(&ctx.info.qtype) {
            let resp = dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from)?;
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .filtered
                    .fetch_add(1, Ordering::Relaxed);
                emit_slow_event(
                    &ctx,
                    state,
                    &resp,
                    "filtered",
                    Some(Arc::from(g.name.as_str())),
                    0,
                );
            }
            return Ok(resp);
        }
    }
    let started = Instant::now();
    // Record routing generation before any upstream I/O. On GeoSite hot-reload, the
    // generation is incremented before the cache is cleared. We check it before writing
    // to the cache below to prevent stale responses from re-populating the fresh cache.
    let routing_gen = state
        .routing_generation
        .load(std::sync::atomic::Ordering::Acquire);
    let ck = cache_key(&ctx.packet, ctx.info.question_end);
    // Normalize cache key for strip-mode targets so all ECS clients share one entry.
    let ck = if target.strip_ecs()
        && dns::extract_variant(&ctx.packet, ctx.info.question_end)
            .ecs_src
            .is_some()
    {
        cache_key_strip_ecs(&ctx.packet, ctx.info.question_end)
    } else {
        ck
    };
    // Mix routing generation into the singleflight key so followers from a previous
    // routing generation do not join an in-flight request for a different route target.
    let sf_ck = ck ^ routing_gen.wrapping_mul(0x9e3779b97f4a7c15);
    let waiter = singleflight::register(&state.remote_inflight, sf_ck)?;

    if let Some(mut rx) = waiter {
        // Bound the follower wait so a panicking leader never leaves clients hung forever.
        let deadline = state.cfg.timeout + Duration::from_secs(1);
        let servfail = Bytes::from(
            dns::servfail_reply(&ctx.packet, ctx.info.question_end).unwrap_or_default(),
        );
        match tokio::time::timeout(deadline, rx.changed()).await {
            Err(_elapsed) => {
                let elapsed = started.elapsed().as_micros() as u64;
                record_client_latency(&ctx, state, elapsed);
                record_singleflight_hit(&ctx, state);
                emit_slow_event(
                    &ctx,
                    state,
                    &servfail,
                    "singleflight",
                    Some(Arc::from(target.group_name())),
                    elapsed,
                );
                return Ok(servfail);
            }
            Ok(Err(_closed)) => {
                let elapsed = started.elapsed().as_micros() as u64;
                record_client_latency(&ctx, state, elapsed);
                record_singleflight_hit(&ctx, state);
                emit_slow_event(
                    &ctx,
                    state,
                    &servfail,
                    "singleflight",
                    Some(Arc::from(target.group_name())),
                    elapsed,
                );
                return Ok(servfail);
            }
            Ok(Ok(())) => {}
        }
        let Some(resp) = rx.borrow().clone() else {
            anyhow::bail!("singleflight leader returned no response");
        };
        let elapsed = started.elapsed().as_micros() as u64;
        // Guard against 64-bit hash collision: the leader may have resolved a different
        // question. Verify the response question section matches ours (case-insensitively,
        // to accommodate 0x20 QNAME case mixing applied by the TCP mux).
        let leader_qend = dns::question_end(&resp);
        if leader_qend != Some(ctx.info.question_end)
            || resp.len() < ctx.info.question_end
            || !resp[12..ctx.info.question_end].eq_ignore_ascii_case(ctx.question())
        {
            let servfail = Bytes::from(
                dns::servfail_reply(&ctx.packet, ctx.info.question_end).unwrap_or_default(),
            );
            record_client_latency(&ctx, state, elapsed);
            record_singleflight_hit(&ctx, state);
            emit_slow_event(
                &ctx,
                state,
                &servfail,
                "singleflight",
                Some(Arc::from(target.group_name())),
                elapsed,
            );
            return Ok(servfail);
        }
        let mut resp = BytesMut::from(resp.as_ref());
        dns::set_id(&mut resp, ctx.info.id)?;
        // Restore canonical case from the client's question (strips upstream 0x20 mixing).
        resp[12..ctx.info.question_end].copy_from_slice(ctx.question());
        let resp = resp.freeze();
        record_client_latency(&ctx, state, elapsed);
        record_singleflight_hit(&ctx, state);
        emit_slow_event(
            &ctx,
            state,
            &resp,
            "singleflight",
            Some(Arc::from(target.group_name())),
            elapsed,
        );
        return Ok(resp);
    }
    // If the leader task is cancelled while awaiting upstream I/O, Drop removes
    // the table entry so later callers can become the new leader instead of waiting forever.
    let _leader = SingleflightLeader { state, key: sf_ck };

    // Leader path: compute skip_cache before consuming packet, clone for cache use.
    let skip_cache = target.skip_cache();
    let query_for_cache = ctx.packet.clone();

    // stale-client-timeout: if enabled, look up the stale cache entry before going upstream.
    // We will race the upstream against the timeout; if it fires first, return stale immediately.
    let stale_fallback: Option<Bytes> = if state.stale_client_timeout_ms > 0 && !skip_cache {
        state
            .cache
            .get_stale(&query_for_cache, ctx.info.question_end, ctx.info.id)
            .filter(|h| h.is_stale)
            .map(|h| h.packet)
    } else {
        None
    };

    let group_name = target.group_name();

    let result = if let Some(stale_pkt) = stale_fallback {
        let timeout_ms = state.stale_client_timeout_ms;
        let upstream_fut = do_upstream_exchange(&ctx, state, &target);
        match tokio::time::timeout(Duration::from_millis(timeout_ms), upstream_fut).await {
            Ok(upstream_result) => upstream_result,
            Err(_timeout) => {
                // Timeout fired first; serve stale to the client and spawn a background refresh.
                singleflight::publish_bytes(&state.remote_inflight, &sf_ck, stale_pkt.clone());
                let elapsed = started.elapsed().as_micros() as u64;
                record_client_latency(&ctx, state, elapsed);
                if ctx.client().is_some() {
                    state
                        .querylog
                        .counters
                        .stale_served
                        .fetch_add(1, Ordering::Relaxed);
                }
                emit_slow_event(
                    &ctx,
                    state,
                    &stale_pkt,
                    "stale",
                    Some(Arc::from(group_name)),
                    elapsed,
                );
                let refresh = CacheRefresh {
                    key: ck,
                    query: query_for_cache.clone(),
                    qname: ctx.info.qname.clone(),
                    question_end: ctx.info.question_end,
                    qtype: ctx.info.qtype,
                };
                spawn_cache_refresh(refresh, state);
                return Ok(stale_pkt);
            }
        }
    } else {
        do_upstream_exchange(&ctx, state, &target).await
    };

    match result {
        Ok(resp) => {
            if !skip_cache && dns::rcode(&resp) == 2 {
                if let Some(stale) = try_stale(
                    state,
                    &ck,
                    &query_for_cache,
                    &ctx.info,
                    group_name,
                    started,
                    "servfail",
                    ctx.client().is_some(),
                ) {
                    let elapsed = started.elapsed().as_micros() as u64;
                    emit_slow_event(
                        &ctx,
                        state,
                        &stale,
                        "stale",
                        Some(Arc::from(group_name)),
                        elapsed,
                    );
                    return Ok(stale);
                }
            }

            maybe_add_response_ips(&target, ctx.info.question_end, state, resp.as_ref());
            // Skip cache write if the routing generation advanced (GeoSite hot-reload cleared
            // the cache between when we started the query and when the response arrived).
            if !skip_cache
                && state
                    .routing_generation
                    .load(std::sync::atomic::Ordering::Acquire)
                    == routing_gen
            {
                let (cache_policy, group_id) = match &target {
                    RouteTarget::Group(g) => {
                        let gid = state
                            .groups
                            .iter()
                            .position(|sg| std::ptr::eq(sg, *g))
                            .map(|i| i as u16)
                            .unwrap_or(u16::MAX);
                        (g.cache_policy, gid)
                    }
                    // NoneIpSet ("none" fallback): use sentinel 65534 so cache hits show group "none".
                    _ => (state.cache.resolve_policy(None), GROUP_ID_NONE_FALLBACK),
                };
                let stripped_query: Option<bytes::Bytes> = if target.strip_ecs()
                    && dns::extract_variant(&ctx.packet, ctx.info.question_end)
                        .ecs_src
                        .is_some()
                {
                    dns::strip_edns_ecs(&query_for_cache).map(bytes::Bytes::from)
                } else {
                    None
                };
                let cache_query: &[u8] = stripped_query.as_deref().unwrap_or(&query_for_cache);
                state.cache.add(
                    crate::cache::CacheInsert {
                        key: ck,
                        qname: ctx.info.qname.clone(),
                        question_end: ctx.info.question_end,
                        query: cache_query,
                        packet: resp.as_ref(),
                    },
                    &cache_policy,
                    group_id,
                );
            }
            singleflight::publish_bytes(&state.remote_inflight, &sf_ck, resp.clone());
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(&ctx, state, elapsed);
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .upstream_ok
                    .fetch_add(1, Ordering::Relaxed);
            }
            emit_slow_event(
                &ctx,
                state,
                &resp,
                "upstream",
                Some(Arc::from(group_name)),
                elapsed,
            );
            Ok(resp)
        }
        Err(err) => {
            if !skip_cache {
                if let Some(stale) = try_stale(
                    state,
                    &ck,
                    &query_for_cache,
                    &ctx.info,
                    group_name,
                    started,
                    "upstream_error",
                    ctx.client().is_some(),
                ) {
                    let elapsed = started.elapsed().as_micros() as u64;
                    emit_slow_event(
                        &ctx,
                        state,
                        &stale,
                        "stale",
                        Some(Arc::from(group_name)),
                        elapsed,
                    );
                    return Ok(stale);
                }
            }
            crate::warn_rate_limited!(
                &UPSTREAM_FAIL_LAST_WARN,
                10,
                "dns event=upstream_failed target={} error={err:#}",
                group_name
            );
            let servfail = match dns::servfail_reply(&query_for_cache, ctx.info.question_end) {
                Ok(pkt) => pkt,
                Err(_) => return Err(err),
            };
            let servfail = Bytes::from(servfail);
            singleflight::publish_bytes(&state.remote_inflight, &sf_ck, servfail.clone());
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(&ctx, state, elapsed);
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .upstream_err
                    .fetch_add(1, Ordering::Relaxed);
            }
            emit_slow_event(
                &ctx,
                state,
                &servfail,
                "upstream",
                Some(Arc::from(group_name)),
                elapsed,
            );
            Ok(servfail)
        }
    }
}

#[inline]
fn record_client_latency(ctx: &QueryContext, state: &AppState, elapsed_us: u64) {
    if ctx.client().is_none() {
        return;
    }
    state
        .querylog
        .counters
        .rtt_sum_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    state
        .querylog
        .counters
        .rtt_count
        .fetch_add(1, Ordering::Relaxed);
}

fn record_singleflight_hit(ctx: &QueryContext, state: &AppState) {
    if ctx.client().is_some() {
        state
            .querylog
            .counters
            .singleflight_hits
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn emit_slow_event(
    ctx: &QueryContext,
    state: &AppState,
    resp: &Bytes,
    source: &'static str,
    group: Option<Arc<str>>,
    elapsed_us: u64,
) {
    let Some((peer, _proto)) = ctx.client() else {
        return;
    };
    let ql = &state.querylog;
    if !ql.collecting() {
        return;
    }
    ql.try_emit_with(|seq| crate::querylog::QueryLogEvent {
        seq,
        unix_micros: crate::querylog::unix_micros_now(),
        client: peer.ip(),
        client_port: peer.port(),
        qname: ctx.info.qname.clone(),
        qtype: ctx.info.qtype,
        rcode: dns::rcode(resp),
        elapsed_us,
        response_bytes: resp.len() as u32,
        source,
        group,
        answer_ips: if ql.collect_answer_ips() && matches!(ctx.info.qtype, 1 | 28) {
            dns::answer_ips(resp, ctx.info.question_end)
        } else {
            smallvec::SmallVec::new()
        },
    });
}

fn serve_stale(
    state: &AppState,
    key: &CacheKey,
    query: &[u8],
    info: &dns::QueryInfo,
) -> Option<Bytes> {
    let stale = state
        .cache
        .get_stale(query, info.question_end, info.id)?
        .packet;
    singleflight::publish_bytes(&state.remote_inflight, key, stale.clone());
    Some(stale)
}

/// Race primary and secondary upstream groups.
///
/// A non-SERVFAIL response wins immediately. If the first responder returns SERVFAIL
/// or a network error, we wait for the other side: a clean response there wins, otherwise
/// we prefer any SERVFAIL over a raw network error, and only return `Err` if both sides
/// failed with network errors.
async fn race(
    packet: Bytes,
    client_id: u16,
    client_proto: ClientProto,
    primary: &CustomGroup,
    secondary: &CustomGroup,
    count_hedge: bool,
) -> Result<Bytes> {
    let primary_upstream = primary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback primary group has no upstream"))?;
    let secondary_upstream = secondary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback secondary group has no upstream"))?;
    let primary_fut =
        primary_upstream.exchange_observed(packet.clone(), client_id, client_proto, count_hedge);
    let secondary_fut =
        secondary_upstream.exchange_observed(packet, client_id, client_proto, count_hedge);
    tokio::pin!(primary_fut);
    tokio::pin!(secondary_fut);
    tokio::select! {
        result = &mut primary_fut => {
            if matches!(&result, Ok(r) if dns::rcode(r) != 2) {
                result
            } else {
                pick_race_winner(result, secondary_fut.await)
            }
        },
        result = &mut secondary_fut => {
            if matches!(&result, Ok(r) if dns::rcode(r) != 2) {
                result
            } else {
                pick_race_winner(result, primary_fut.await)
            }
        },
    }
}

/// Merge two soft-fail results (SERVFAIL or network error).
/// If the second side recovered with a clean response, return it.
/// Otherwise prefer any SERVFAIL DNS response over a raw network error.
fn pick_race_winner(first: Result<Bytes>, second: Result<Bytes>) -> Result<Bytes> {
    if matches!(&second, Ok(r) if dns::rcode(r) != 2) {
        return second;
    }
    match (first, second) {
        (Ok(sf), _) => Ok(sf),
        (Err(_), Ok(sf)) => Ok(sf),
        (Err(e1), Err(e2)) => Err(anyhow!("race failed: {e1:#}; {e2:#}")),
    }
}

async fn resolve_none_group_with_ipset(
    packet: Bytes,
    info: &dns::QueryInfo,
    client_proto: ClientProto,
    primary: &crate::server::CustomGroup,
    secondary: &crate::server::CustomGroup,
    state: &Arc<AppState>,
    count_hedge: bool,
) -> Result<Bytes> {
    let Some(ipset) = &state.ipset else {
        return race(
            packet,
            info.id,
            client_proto,
            primary,
            secondary,
            count_hedge,
        )
        .await;
    };
    let primary_upstream = primary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback primary group has no upstream"))?;
    let secondary_upstream = secondary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback secondary group has no upstream"))?;

    if let Some(is_primary_domain) = state.verdict_cache.get(&info.qname) {
        return if is_primary_domain {
            primary_upstream
                .exchange_observed(packet, info.id, client_proto, count_hedge)
                .await
        } else {
            secondary_upstream
                .exchange_observed(packet, info.id, client_proto, count_hedge)
                .await
        };
    }

    let primary_packet = packet.clone();
    let secondary_packet = packet;
    let (primary_resp, secondary_resp) = tokio::join!(
        primary_upstream.exchange_observed(primary_packet, info.id, client_proto, count_hedge),
        secondary_upstream.exchange_observed(secondary_packet, info.id, client_proto, count_hedge)
    );

    match primary_resp {
        Ok(resp) => {
            let ips = dns::answer_ips(&resp, info.question_end);
            let ipset = ipset.clone();
            let verdict = tokio::task::spawn_blocking(move || ipset.test_response(&ips))
                .await
                .map_err(|e| anyhow!("ipset test task failed: {e}"))?;
            let noip_as_primary = state.cfg.fallback.noip_as_primary_ip;
            match verdict {
                TestVerdict::PrimaryIp => {
                    state.verdict_cache.add(&info.qname, true);
                    Ok(resp)
                }
                TestVerdict::SecondaryIp => {
                    state.verdict_cache.add(&info.qname, false);
                    secondary_resp.or(Ok(resp))
                }
                TestVerdict::NoIpFound if noip_as_primary => Ok(resp),
                TestVerdict::NoIpFound | TestVerdict::OtherCase => secondary_resp.or(Ok(resp)),
            }
        }
        Err(primary_err) => secondary_resp.map_err(|secondary_err| {
            anyhow!(
                "primary upstream failed: {primary_err:#}; secondary upstream failed: {secondary_err:#}"
            )
        }),
    }
}

/// Write resolved IPs from an upstream response into the configured nftset/ipset.
///
/// Called only in `exchange_with_dedupe` (upstream path). Cache hits, singleflight
/// followers, Race, and NoneIpSet all skip this; nftset is populated on the first
/// upstream response only.
fn maybe_add_response_ips(
    target: &RouteTarget<'_>,
    question_end: usize,
    state: &AppState,
    resp: &[u8],
) {
    let Some(ipset) = &state.ipset else {
        return;
    };
    let ips = dns::answer_ips(resp, question_end);
    if ips.is_empty() {
        return;
    }
    if let RouteTarget::Group(group) = target {
        ipset.add_group_ips(&group.name, &ips);
    }
}

/// Send a cache refresh request to the bounded background worker channel.
/// Deduplication is done here, before enqueuing, so identical in-flight keys never pile up.
/// Non-blocking: if the channel is full the gate is released and the refresh is dropped
/// (the stale entry will be re-served on the next hit).
pub(crate) fn spawn_cache_refresh(refresh: CacheRefresh, state: &Arc<AppState>) {
    if !state.refresh_gate.begin(&refresh.key) {
        return;
    }
    let key = refresh.key;
    if state.refresh_tx.try_send(refresh).is_err() {
        // Channel full — undo the gate so a later hit can re-enqueue.
        state.refresh_gate.end(&key);
    }
}

/// Spawn the single background cache refresh worker.
/// Call this once after `AppState` is wrapped in an `Arc`.
pub fn spawn_refresh_worker(
    state: Arc<AppState>,
    mut rx: tokio::sync::mpsc::Receiver<CacheRefresh>,
) {
    tokio::spawn(async move {
        while let Some(refresh) = rx.recv().await {
            state
                .querylog
                .counters
                .cache_refresh_started
                .fetch_add(1, Ordering::Relaxed);
            do_cache_refresh(refresh, &state).await;
        }
    });
}

async fn do_cache_refresh(refresh: CacheRefresh, state: &Arc<AppState>) {
    if refresh.query.len() < 2 {
        state.refresh_gate.end(&refresh.key);
        return;
    }
    let id = u16::from_be_bytes([refresh.query[0], refresh.query[1]]);
    let info = dns::QueryInfo {
        id,
        qname: refresh.qname.clone(),
        qtype: refresh.qtype,
        question_end: refresh.question_end,
    };
    let Some(target) = router::choose_refresh_target(state, &refresh.qname, refresh.qtype) else {
        state.refresh_gate.end(&refresh.key);
        return;
    };
    let result = exchange_with_dedupe(
        QueryContext {
            packet: refresh.query,
            info,
            origin: QueryOrigin::CacheRefresh,
        },
        state,
        target,
    )
    .await;
    if result.is_err() {
        state
            .querylog
            .counters
            .cache_refresh_failed
            .fetch_add(1, Ordering::Relaxed);
    }
    state.refresh_gate.end(&refresh.key);
}

#[cfg(test)]
mod querylog_tests {
    use super::*;

    #[test]
    fn received_queries_are_counted_once_by_protocol() {
        let ql = crate::querylog::QueryLogHandle::disabled();
        record_query_received(&ql, ClientProto::Udp);
        record_query_received(&ql, ClientProto::Tcp);
        assert_eq!(ql.counters.queries_total.load(Ordering::Relaxed), 2);
        assert_eq!(ql.counters.queries_udp.load(Ordering::Relaxed), 1);
        assert_eq!(ql.counters.queries_tcp.load(Ordering::Relaxed), 1);
    }
}
