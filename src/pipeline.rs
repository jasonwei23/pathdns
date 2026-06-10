//! DNS query pipeline: fast path (parse → qtype filter → cache), slow path (classify →
//! upstream → cache store), and background cache refresh.
//!
//! Listener code owns sockets and framing; this module owns packet lifecycle after a DNS
//! message has been received.

use crate::cache::{cache_key, CacheKey, CacheRefresh};
use crate::dns;
use crate::ipset::TestVerdict;
use crate::router::RouteTarget;
use crate::server::{AppState, CustomGroup};
use crate::upstream::ClientProto;
use crate::{router, singleflight};
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Rate-limit state for upstream-failure warnings (shared across all targets).
static UPSTREAM_FAIL_LAST_WARN: AtomicU64 = AtomicU64::new(0);

struct QueryContext {
    packet: Bytes,
    info: dns::QueryInfo,
    peer: SocketAddr,
    client_proto: ClientProto,
}

impl QueryContext {
    /// Raw DNS question bytes (qname + qtype + qclass), used as the cache/singleflight key.
    fn question(&self) -> &[u8] {
        &self.packet[12..self.info.question_end]
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

/// Synchronous fast path: parse header, apply qtype filter, look up the Moka cache.
///
/// Returns immediately with a ready response for the overwhelming majority of queries (cache hits
/// and filter hits) without allocating a Tokio task. Only cache misses need a spawned task.
/// Called both from the UDP receive loop (inline, no spawn) and from `handle_packet` (for TCP
/// and UDP misses that were spawned before this check could short-circuit them).
pub(crate) fn try_fast_path(packet: &[u8], peer: SocketAddr, state: &AppState) -> FastPathOutcome {
    // Only pay for Instant::now() when verbose logging is enabled.
    let t0: Option<Instant> = crate::log::verbose_enabled().then(Instant::now);

    let fast_info = match dns::parse_query_fast(packet) {
        Ok(info) => info,
        Err(err) => {
            crate::verbose!("dns event=parse_error from={peer} error={err:#}");
            return FastPathOutcome::Drop;
        }
    };

    // Fast cache read: no qname allocation needed.
    if let Some(hit) = state
        .cache
        .get(&packet[12..fast_info.question_end], fast_info.id)
    {
        // When stale-client-timeout is enabled and the hit is stale, fall through to the
        // async path so it can race upstream vs the timeout before deciding to serve stale.
        if hit.is_stale && state.stale_client_timeout_ms > 0 {
            return FastPathOutcome::Miss { info: fast_info };
        }
        if hit.is_stale {
            crate::stats::inc_cache_stale_refresh();
        } else {
            crate::stats::inc_cache_hits();
        }
        let group_name = if hit.group_id == u16::MAX {
            "-".to_string()
        } else {
            state
                .groups
                .get(hit.group_id as usize)
                .map(|g| g.name.as_str())
                .unwrap_or("-")
                .to_string()
        };
        crate::verbose!(
            "dns event=reply id={} qtype={} source=cache group={} bytes={} elapsed_us={}",
            fast_info.id,
            fast_info.qtype,
            group_name,
            hit.packet.len(),
            t0.map_or(0, |t| t.elapsed().as_micros() as u64)
        );
        return FastPathOutcome::Response {
            resp: hit.packet,
            refresh: hit.refresh,
        };
    }
    crate::stats::inc_cache_misses();

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
    let t0: Option<Instant> = crate::log::verbose_enabled().then(Instant::now);

    let fast_info = match dns::parse_query_fast(packet) {
        Ok(info) => info,
        Err(err) => {
            crate::verbose!("dns event=parse_error from={peer} error={err:#}");
            return FastPathOutcome::Drop;
        }
    };

    // Cache hit: write directly into the caller-provided send buffer.
    if let Some(meta) =
        state
            .cache
            .get_into(&packet[12..fast_info.question_end], fast_info.id, send_buf)
    {
        // When stale-client-timeout is enabled and the hit is stale, fall through to the
        // async path so it can race upstream vs the timeout before deciding to serve stale.
        if meta.is_stale && state.stale_client_timeout_ms > 0 {
            return FastPathOutcome::Miss { info: fast_info };
        }
        if meta.is_stale {
            crate::stats::inc_cache_stale_refresh();
        } else {
            crate::stats::inc_cache_hits();
        }
        let group_name = if meta.group_id == u16::MAX {
            "-".to_string()
        } else {
            state
                .groups
                .get(meta.group_id as usize)
                .map(|g| g.name.as_str())
                .unwrap_or("-")
                .to_string()
        };
        crate::verbose!(
            "dns event=reply id={} qtype={} source=cache group={} bytes={} elapsed_us={}",
            fast_info.id,
            fast_info.qtype,
            group_name,
            send_buf.len(),
            t0.map_or(0, |t| t.elapsed().as_micros() as u64)
        );
        // Freeze the send buffer content into Bytes for compatibility with FastPathOutcome.
        let resp = send_buf.split().freeze();
        return FastPathOutcome::Response {
            resp,
            refresh: meta.refresh,
        };
    }

    crate::stats::inc_cache_misses();
    FastPathOutcome::Miss { info: fast_info }
}

pub(crate) async fn handle_packet_bytes(
    packet: Bytes,
    peer: SocketAddr,
    proto: ClientProto,
    state: Arc<AppState>,
) -> Result<Option<Bytes>> {
    match try_fast_path(&packet, peer, &state) {
        FastPathOutcome::Response { resp, refresh } => {
            if let Some(r) = refresh {
                spawn_cache_refresh(r, &state);
            }
            Ok(Some(resp))
        }
        FastPathOutcome::Drop => Ok(None),
        FastPathOutcome::Miss { info } => {
            handle_packet_slow_preparsed(packet, peer, proto, state, info).await
        }
    }
}

/// Slow path for cache misses. Skips the fast-path check and reuses the already
/// parsed header/question offsets from `try_fast_path`.
pub(crate) async fn handle_packet_slow_preparsed(
    packet: Bytes,
    peer: SocketAddr,
    proto: ClientProto,
    state: Arc<AppState>,
    fast_info: dns::FastQueryInfo,
) -> Result<Option<Bytes>> {
    let info = match dns::parse_query_from_fast(&packet, fast_info) {
        Ok(info) => info,
        Err(err) => {
            crate::verbose!("dns event=parse_error from={peer} error={err:#}");
            return Ok(None);
        }
    };
    handle_packet_slow_with_info(packet, peer, proto, state, info).await
}

async fn handle_packet_slow_with_info(
    packet: Bytes,
    peer: SocketAddr,
    proto: ClientProto,
    state: Arc<AppState>,
    info: dns::QueryInfo,
) -> Result<Option<Bytes>> {
    let permit = match state.limit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            // Queue mode: wait up to inflight_queue_ms for a permit before hard-dropping.
            let acquired = if state.cfg.inflight_queue_ms > 0 {
                crate::stats::inc_inflight_queued();
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
                    crate::stats::inc_inflight_drops();
                    crate::verbose!(
                        "dns event=drop reason=max_inflight id={} qtype={} qname={} from={}",
                        info.id,
                        info.qtype,
                        info.qname,
                        peer
                    );
                    let servfail = dns::servfail_reply(&packet, info.question_end)
                        .map(Bytes::from)
                        .ok();
                    return Ok(servfail);
                }
            }
        }
    };

    let resp = {
        let _permit = permit;
        resolve_query(
            QueryContext {
                packet,
                info,
                peer,
                client_proto: proto,
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
        crate::verbose!(
            "dns event=query id={} qtype={} qname={} group={} from={}",
            ctx.info.id,
            ctx.info.qtype,
            ctx.info.qname,
            group.name,
            ctx.peer
        );
        if let Some(target) = group.target() {
            crate::stats::inc_routed_group();
            return exchange_with_dedupe(ctx, state, target).await;
        }
        // Null group: apply qtype filter before returning empty.
        if group.filter_qtype.contains(&ctx.info.qtype) {
            crate::stats::inc_routed_aaaa_filtered();
            return dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from);
        }
        crate::stats::inc_routed_null();
        return dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from);
    }

    let Some(target) = router::classify_target(state, ctx.info.qtype) else {
        crate::verbose!(
            "dns event=reply id={} qtype={} qname={} group=null from={}",
            ctx.info.id,
            ctx.info.qtype,
            ctx.info.qname,
            ctx.peer
        );
        crate::stats::inc_routed_null();
        return dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from);
    };
    crate::verbose!(
        "dns event=query id={} qtype={} qname={} group={} from={}",
        ctx.info.id,
        ctx.info.qtype,
        ctx.info.qname,
        target.group_name(),
        ctx.peer
    );

    match &target {
        RouteTarget::Race { .. } | RouteTarget::NoneIpSet { .. } => {
            crate::stats::inc_routed_none_race()
        }
        RouteTarget::Group(_) => crate::stats::inc_routed_group(),
    }
    exchange_with_dedupe(ctx, state, target).await
}

/// Check the stale cache for a usable entry. On hit: record stats, log, and return it.
/// The stale entry is also published to singleflight waiters (inside `serve_stale`).
fn try_stale(
    state: &AppState,
    ck: &CacheKey,
    question: &[u8],
    info: &dns::QueryInfo,
    group_name: &str,
    started: Instant,
    reason: &str,
) -> Option<Bytes> {
    let stale = serve_stale(state, ck, question, info)?;
    crate::verbose!(
        "dns event=serve_stale id={} qtype={} qname={} target={} elapsed_us={} reason={}",
        info.id,
        info.qtype,
        info.qname,
        group_name,
        started.elapsed().as_micros(),
        reason
    );
    crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
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
                ctx.client_proto,
                primary,
                secondary,
            )
            .await
        }
        RouteTarget::NoneIpSet { primary, secondary } => {
            resolve_none_group_with_ipset(
                ctx.packet.clone(),
                &ctx.info,
                ctx.client_proto,
                primary,
                secondary,
                state,
            )
            .await
        }
        RouteTarget::Group(_) => {
            let Some(upstream) = target.upstream() else {
                anyhow::bail!("route target requires an upstream");
            };
            upstream
                .exchange(ctx.packet.clone(), ctx.info.id, ctx.client_proto)
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
            crate::stats::inc_routed_aaaa_filtered();
            return dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from);
        }
    }
    let started = Instant::now();
    let ck = cache_key(ctx.question());
    let waiter = singleflight::register(&state.remote_inflight, ck)?;

    if let Some(mut rx) = waiter {
        crate::stats::inc_singleflight_hits();
        // Bound the follower wait so a panicking leader never leaves clients hung forever.
        let deadline = state.cfg.timeout + Duration::from_secs(1);
        match tokio::time::timeout(deadline, rx.changed()).await {
            Err(_elapsed) => {
                crate::verbose!(
                    "dns event=singleflight_timeout id={} qtype={} qname={} from={}",
                    ctx.info.id,
                    ctx.info.qtype,
                    ctx.info.qname,
                    ctx.peer
                );
                crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
                return Ok(Bytes::from(
                    dns::servfail_reply(&ctx.packet, ctx.info.question_end).unwrap_or_default(),
                ));
            }
            // Sender was dropped without publishing (leader panicked).
            Ok(Err(_closed)) => {
                crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
                return Ok(Bytes::from(
                    dns::servfail_reply(&ctx.packet, ctx.info.question_end).unwrap_or_default(),
                ));
            }
            Ok(Ok(())) => {}
        }
        let Some(resp) = rx.borrow().clone() else {
            anyhow::bail!("singleflight leader returned no response");
        };
        let mut resp = BytesMut::from(resp.as_ref());
        dns::set_id(&mut resp, ctx.info.id)?;
        let resp = resp.freeze();
        crate::verbose!(
            "dns event=reply id={} qtype={} qname={} target={} source=singleflight bytes={} elapsed_us={}",
            ctx.info.id,
            ctx.info.qtype,
            ctx.info.qname,
            target.group_name(),
            resp.len(),
            started.elapsed().as_micros()
        );
        crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
        return Ok(resp);
    }
    // If the leader task is cancelled while awaiting upstream I/O, Drop removes
    // the table entry so later callers can become the new leader instead of waiting forever.
    let _leader = SingleflightLeader { state, key: ck };

    // Leader path: compute skip_cache before consuming packet, clone for cache use.
    let skip_cache = target.skip_cache();
    let query_for_cache = ctx.packet.clone();

    // stale-client-timeout: if enabled, look up the stale cache entry before going upstream.
    // We will race the upstream against the timeout; if it fires first, return stale immediately.
    let stale_fallback: Option<Bytes> = if state.stale_client_timeout_ms > 0 && !skip_cache {
        state
            .cache
            .get_stale(&query_for_cache[12..ctx.info.question_end], ctx.info.id)
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
            Ok(upstream_result) => {
                // Upstream won within timeout; proceed normally with upstream_result.
                upstream_result
            }
            Err(_timeout) => {
                // Timeout fired first; serve stale to the client and spawn a background refresh.
                crate::stats::inc_cache_stale_client_timeout();
                crate::verbose!(
                    "dns event=serve_stale_timeout id={} qtype={} qname={} target={} elapsed_us={}",
                    ctx.info.id,
                    ctx.info.qtype,
                    ctx.info.qname,
                    group_name,
                    started.elapsed().as_micros()
                );
                crate::stats::inc_cache_stale_refresh();
                singleflight::publish_bytes(&state.remote_inflight, &ck, stale_pkt.clone());
                crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
                // Detach: spawn a background refresh task (same pattern as do_cache_refresh).
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
                    &query_for_cache[12..ctx.info.question_end],
                    &ctx.info,
                    group_name,
                    started,
                    "servfail",
                ) {
                    return Ok(stale);
                }
            }

            maybe_add_response_ips(&target, ctx.info.question_end, state, resp.as_ref());
            if !skip_cache {
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
                    // Race/none targets carry no group policy; use the global defaults.
                    _ => (state.cache.resolve_policy(None), u16::MAX),
                };
                state.cache.add(
                    crate::cache::CacheInsert {
                        key: ck,
                        qname: ctx.info.qname.clone(),
                        question_end: ctx.info.question_end,
                        query: &query_for_cache,
                        packet: resp.as_ref(),
                    },
                    &cache_policy,
                    group_id,
                );
            }
            singleflight::publish_bytes(&state.remote_inflight, &ck, resp.clone());
            crate::verbose!(
                "dns event=reply id={} qtype={} qname={} target={} source=upstream bytes={} elapsed_us={}",
                ctx.info.id,
                ctx.info.qtype,
                ctx.info.qname,
                group_name,
                resp.len(),
                started.elapsed().as_micros()
            );
            crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
            Ok(resp)
        }
        Err(err) => {
            if !skip_cache {
                if let Some(stale) = try_stale(
                    state,
                    &ck,
                    &query_for_cache[12..ctx.info.question_end],
                    &ctx.info,
                    group_name,
                    started,
                    "upstream_error",
                ) {
                    return Ok(stale);
                }
            }
            // Rate-limited warn so repeated failures don't flood logs.
            crate::warn_rate_limited!(
                &UPSTREAM_FAIL_LAST_WARN,
                10,
                "dns event=upstream_failed target={} error={err:#}",
                group_name
            );
            crate::verbose!(
                "dns event=upstream_failed id={} qtype={} qname={} target={} elapsed_us={} error={err:#}",
                ctx.info.id,
                ctx.info.qtype,
                ctx.info.qname,
                group_name,
                started.elapsed().as_micros()
            );
            // Synthesize SERVFAIL so the client always gets a DNS response.
            // Publish to singleflight waiters so they share the same fallback.
            let servfail = match dns::servfail_reply(&query_for_cache, ctx.info.question_end) {
                Ok(pkt) => pkt,
                Err(_) => {
                    // Packet is malformed; fall back to propagating the error.
                    return Err(err);
                }
            };
            let servfail = Bytes::from(servfail);
            singleflight::publish_bytes(&state.remote_inflight, &ck, servfail.clone());
            crate::stats::record_query_latency(started.elapsed().as_micros() as u64);
            Ok(servfail)
        }
    }
}

fn serve_stale(
    state: &AppState,
    key: &CacheKey,
    question: &[u8],
    info: &dns::QueryInfo,
) -> Option<Bytes> {
    let stale = state.cache.get_stale(question, info.id)?.packet;
    crate::stats::inc_cache_stale_error();
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
) -> Result<Bytes> {
    let primary_upstream = primary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback primary group has no upstream"))?;
    let secondary_upstream = secondary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback secondary group has no upstream"))?;
    let primary_fut = primary_upstream.exchange(packet.clone(), client_id, client_proto);
    let secondary_fut = secondary_upstream.exchange(packet, client_id, client_proto);
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
) -> Result<Bytes> {
    let Some(ipset) = &state.ipset else {
        return race(packet, info.id, client_proto, primary, secondary).await;
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
        crate::verbose!(
            "dns event=verdict_cache qname={} verdict={}",
            info.qname,
            if is_primary_domain {
                "primary"
            } else {
                "secondary"
            }
        );
        return if is_primary_domain {
            primary_upstream
                .exchange(packet, info.id, client_proto)
                .await
        } else {
            secondary_upstream
                .exchange(packet, info.id, client_proto)
                .await
        };
    }

    let primary_packet = packet.clone();
    let secondary_packet = packet;
    let (primary_resp, secondary_resp) = tokio::join!(
        primary_upstream.exchange(primary_packet, info.id, client_proto),
        secondary_upstream.exchange(secondary_packet, info.id, client_proto)
    );

    match primary_resp {
        Ok(resp) => {
            let ips = dns::answer_ips(&resp, info.question_end);
            let verdict = ipset.test_response(&ips);
            crate::verbose!(
                "dns event=none_group_verdict qname={} ips={} verdict={:?}",
                info.qname,
                ips.len(),
                verdict
            );
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
        crate::stats::inc_cache_refresh_skipped();
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
            crate::stats::inc_cache_refresh_started();
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
    crate::verbose!(
        "dns event=cache_refresh_start qname={} qtype={}",
        refresh.qname,
        refresh.qtype
    );
    let Some(target) = router::choose_refresh_target(state, &refresh.qname, refresh.qtype) else {
        state.refresh_gate.end(&refresh.key);
        return;
    };
    if let Err(err) = exchange_with_dedupe(
        QueryContext {
            packet: refresh.query,
            info,
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            client_proto: ClientProto::Udp,
        },
        state,
        target,
    )
    .await
    {
        crate::stats::inc_cache_refresh_failed();
        crate::verbose!(
            "dns event=cache_refresh_error qname={} error={:#}",
            refresh.qname,
            err
        );
    }
    state.refresh_gate.end(&refresh.key);
}
