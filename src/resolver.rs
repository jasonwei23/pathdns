//! DNS query pipeline: fast path (parse → qtype filter → cache), slow path (classify →
//! upstream → cache store).
//!
//! Listener code owns sockets and framing; this module owns packet lifecycle after a DNS
//! message has been received.

use crate::cache::{cache_key_with_variant, CacheKey};
use crate::config::FixedAnswer;
use crate::dns;
use crate::ipset::TestVerdict;
use crate::router::RouteTarget;
use crate::server::{AppState, Rule, HotState};
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

/// Sentinel rule_id for IpSetTest ("none" fallback) cache entries.
/// Cannot use u16::MAX (65535) because that is the existing "no rule" sentinel.
const RULE_ID_NONE_FALLBACK: u16 = 65534;

struct QueryContext {
    packet: Bytes,
    info: dns::QueryInfo,
    peer: SocketAddr,
    proto: ClientProto,
}

impl QueryContext {
    /// Raw DNS question bytes (qname + qtype + qclass), used as the cache/singleflight key.
    fn question(&self) -> &[u8] {
        &self.packet[12..self.info.question_end]
    }

    fn client(&self) -> Option<(SocketAddr, ClientProto)> {
        Some((self.peer, self.proto))
    }

    fn proto(&self) -> ClientProto {
        self.proto
    }
}

struct SingleflightLeader<'a> {
    state: &'a AppState,
    key: CacheKey,
    /// Set to true after publish_bytes removes the key so Drop does not
    /// accidentally evict a newly registered leader for the same key.
    published: bool,
}

impl Drop for SingleflightLeader<'_> {
    fn drop(&mut self) {
        if !self.published {
            singleflight::remove(&self.state.remote_inflight, &self.key);
        }
    }
}

/// Result of the synchronous fast path: parse header, apply qtype filter, check cache.
pub(crate) enum FastPathOutcome {
    /// Ready-to-send response (filter hit or cache hit).
    Response { resp: Bytes },
    /// Cache miss; full async resolution is required.
    Miss { info: dns::FastQueryInfo },
    /// Malformed packet; drop silently, send no reply.
    Drop,
}

/// Decode a `rule_id` stored in the cache into a display name.
/// - `u16::MAX` (65535) → no rule (legacy sentinel, treated as None)
/// - `RULE_ID_NONE_FALLBACK` (65534) → "none" (IpSetTest route)
/// - anything else → look up in `hot.rules`
fn rule_id_to_name(rule_id: u16, hot: &HotState) -> Option<Arc<str>> {
    if rule_id == u16::MAX {
        None
    } else if rule_id == RULE_ID_NONE_FALLBACK {
        Some(crate::router::none_arc())
    } else {
        hot.rules
            .get(rule_id as usize)
            .map(|g| g.name_arc.clone())
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

/// UDP fast path: writes the cache-hit response directly into a reusable send buffer,
/// avoiding a per-hit `BytesMut` allocation.
pub(crate) fn try_fast_path_into(
    packet: &[u8],
    peer: SocketAddr,
    proto: ClientProto,
    state: &AppState,
    send_buf: &mut BytesMut,
) -> FastPathOutcome {
    let t0 = state.querylog.collecting().then(Instant::now);

    // Non-QUERY opcodes: return NOTIMP per RFC 1035.
    if packet.len() >= 3 && (packet[2] & 0x80) == 0 && (packet[2] >> 3) & 0x0f != 0 {
        record_query_received(&state.querylog, proto);
        return FastPathOutcome::Response {
            resp: Bytes::from(dns::notimp_opcode_reply(packet)),
        };
    }

    let fast_info = match dns::parse_query_fast(packet) {
        Ok(info) => info,
        Err(_) => return FastPathOutcome::Drop,
    };
    record_query_received(&state.querylog, proto);

    // Non-IN/non-ANY QCLASS: return NOTIMP.
    {
        let i = fast_info.question_end.saturating_sub(2);
        let qclass = u16::from_be_bytes([packet[i], packet[i + 1]]);
        if qclass != 1 && qclass != 255 {
            return FastPathOutcome::Response {
                resp: Bytes::from(
                    dns::notimp_reply(packet, fast_info.question_end).unwrap_or_default(),
                ),
            };
        }
    }

    // Cache hit: write directly into the caller-provided send buffer.
    if let Some(meta) = state.cache.get_into_with_ecs_fallback(
        packet,
        fast_info.question_end,
        fast_info.id,
        send_buf,
    ) {
        let ql = &state.querylog;
        let collecting = ql.collecting();
        ql.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
        if collecting {
            let h = state.hot.load_full();
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
                source: "cache",
                rule: rule_id_to_name(meta.rule_id, &h),
                answer_ips: if ql.collect_answer_ips() && matches!(fast_info.qtype, 1 | 28) {
                    dns::answer_ips(send_buf, fast_info.question_end)
                } else {
                    smallvec::SmallVec::new()
                },
            });
        }
        let resp = send_buf.split().freeze();
        return FastPathOutcome::Response { resp };
    }

    FastPathOutcome::Miss { info: fast_info }
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
                let queue_ms = state.hot.load().cfg.inflight_queue_ms;
                let acquired = if queue_ms > 0 {
                    state
                        .querylog
                        .counters
                        .inflight_queued
                        .fetch_add(1, Ordering::Relaxed);
                    let wait = Duration::from_millis(queue_ms);
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
                                peer,
                                proto,
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
                peer,
                proto,
            },
            &state,
        )
        .await?
    };

    Ok(Some(resp))
}

/// Insert a `route.answer` response into the cache so repeat queries are served
/// from the fast path. Answer-map responses are ECS-independent, so the entry is
/// keyed on the ECS-stripped variant and shared across all clients. Stored under
/// the `u16::MAX` sentinel rule_id (cache hits report no rule). For A/AAAA/CNAME
/// the TTL comes from the records in the packet; for an RCODE/NODATA response
/// `nodata_ttl_override` (the entry's `?ttl=`) governs the cache lifetime.
fn cache_answer(
    ctx: &QueryContext,
    state: &AppState,
    resp: &Bytes,
    routing_gen: u64,
    nodata_ttl_override: Option<u32>,
) {
    // A reload between synth and now would have cleared the cache; don't re-fill it.
    if state
        .routing_generation
        .load(std::sync::atomic::Ordering::Acquire)
        != routing_gen
    {
        return;
    }
    let variant = dns::extract_variant(&ctx.packet, ctx.info.question_end);
    let ck = cache_key_with_variant(&ctx.packet, ctx.info.question_end, &variant, true);
    // Key on the stripped variant: drop ECS from the cached query so the entry
    // matches both ECS and non-ECS clients in the lookup path.
    let stripped_query: Option<Bytes> = variant
        .ecs_src
        .is_some()
        .then(|| dns::strip_edns_ecs(&ctx.packet).map(Bytes::from))
        .flatten();
    let cache_query: &[u8] = stripped_query.as_deref().unwrap_or_else(|| ctx.packet.as_ref());
    // Strip per-connection OPT data (COOKIE, NSID, …) from the cached copy.
    let sanitized_resp = dns::strip_opt_rdata(resp.as_ref()).map(Bytes::from);
    let cache_packet: &[u8] = sanitized_resp.as_deref().unwrap_or_else(|| resp.as_ref());
    let policy = match nodata_ttl_override {
        Some(ttl) => state.cache.negative_answer_policy(ttl),
        None => state.cache.resolve_policy(None),
    };
    state.cache.add(
        crate::cache::CacheInsert {
            key: ck,
            qname: ctx.info.qname.clone(),
            question_end: ctx.info.question_end,
            query: cache_query,
            packet: cache_packet,
        },
        &policy,
        u16::MAX,
    );
}

/// Synthesise a response for a `route.answer` map hit. Mirrors the fixed-answer
/// rule path: A/AAAA records, a chased CNAME, or an RCODE/empty reply. CNAME
/// targets are routed through the full rule table (`after = None`).
async fn synth_answer(
    ctx: &QueryContext,
    hot: &crate::server::HotState,
    geosite: Option<&crate::geosite::GeoSiteDb>,
    entry: &crate::answer_map::AnswerEntry,
) -> Result<Bytes> {
    if !entry.fixed_answers.is_empty() {
        let mut a: Option<(std::net::Ipv4Addr, u32)> = None;
        let mut aaaa: Option<(std::net::Ipv6Addr, u32)> = None;
        let mut cname: Option<(&str, u32)> = None;
        for fa in &entry.fixed_answers {
            match fa {
                FixedAnswer::A(addr, ttl) => a = Some((*addr, *ttl)),
                FixedAnswer::Aaaa(addr, ttl) => aaaa = Some((*addr, *ttl)),
                FixedAnswer::Cname(t, ttl) => cname = Some((t, *ttl)),
            }
        }
        if let Some((target, ttl)) = cname {
            return cname_chase(
                &ctx.packet,
                ctx.info.question_end,
                ctx.info.qtype,
                ctx.info.id,
                ctx.proto(),
                hot,
                geosite,
                target,
                ttl,
            )
            .await;
        }
        return match (ctx.info.qtype, a, aaaa) {
            (1, Some((addr, ttl)), _) => {
                dns::a_reply(&ctx.packet, ctx.info.question_end, addr, ttl).map(Bytes::from)
            }
            (28, _, Some((addr, ttl))) => {
                dns::aaaa_reply(&ctx.packet, ctx.info.question_end, addr, ttl).map(Bytes::from)
            }
            _ => dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from),
        };
    }
    // RCODE entry.
    let rcode = entry.fixed_rcode.unwrap_or(0);
    if rcode == 0 {
        dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from)
    } else {
        dns::rcode_reply(&ctx.packet, ctx.info.question_end, rcode).map(Bytes::from)
    }
}

/// Perform server-side CNAME chasing: return `D CNAME T` combined with T's A/AAAA
/// records resolved through the routing rules (`route.answer` is not re-consulted,
/// so a CNAME target cannot loop back into the answer map).
///
/// Falls back to returning just `D CNAME T` if no suitable rule is found or the
/// upstream query fails.
#[allow(clippy::too_many_arguments)]
async fn cname_chase(
    packet: &[u8],
    question_end: usize,
    qtype: u16,
    client_id: u16,
    client_proto: crate::upstream::ClientProto,
    hot: &crate::server::HotState,
    geosite: Option<&crate::geosite::GeoSiteDb>,
    cname_target: &str,
    ttl: u32,
) -> Result<Bytes> {
    // Only chase for A and AAAA queries; other types just get the CNAME record.
    if qtype != 1 && qtype != 28 {
        return dns::cname_reply(packet, question_end, cname_target, ttl).map(Bytes::from);
    }

    // Route the CNAME target through the rule table.
    let Some(target_rule) = hot
        .routing_index
        .route(&hot.rules, cname_target, geosite)
    else {
        return dns::cname_reply(packet, question_end, cname_target, ttl).map(Bytes::from);
    };

    // We need a real upstream to chase; fixed-answer/RCODE rules can't help here.
    let Some(upstream) = target_rule.upstream.as_ref() else {
        return dns::cname_reply(packet, question_end, cname_target, ttl).map(Bytes::from);
    };

    // Build a synthetic query for the CNAME target.
    let (syn_query, syn_qe) = dns::synthetic_query(cname_target, qtype)?;

    // Query the upstream for T.
    let t_resp = match upstream
        .exchange_observed(Bytes::from(syn_query), client_id, client_proto, false)
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return dns::cname_reply(packet, question_end, cname_target, ttl).map(Bytes::from);
        }
    };

    // Extract A/AAAA answer records from the upstream response for T (keeping their
    // upstream TTLs); only the synthesised CNAME record uses the configured `ttl`.
    let extra: Vec<(u16, u32, Vec<u8>)> = dns::extract_answer_records(&t_resp, syn_qe)
        .into_iter()
        .filter(|(rtype, _, _)| *rtype == qtype)
        .collect();

    // Build the combined response: D CNAME T + T A/AAAA IPs.
    dns::cname_with_chase_reply(packet, question_end, cname_target, ttl, &extra).map(Bytes::from)
}

async fn resolve_query(ctx: QueryContext, state: &Arc<AppState>) -> Result<Bytes> {
    let hot = state.hot.load_full();
    let geosite = if hot.needs_geosite {
        state.geosite_snapshot()
    } else {
        None
    };
    // Domain → fixed-answer map: consulted before the routing rules. A matching
    // entry synthesises a response (A/AAAA/CNAME/RCODE) without routing.
    if !hot.cfg.answer_map.is_empty() {
        if let Some(entry) = hot.cfg.answer_map.lookup(&ctx.info.qname, geosite.as_deref()) {
            // Capture the routing generation before any await in synth_answer (a CNAME
            // chase queries an upstream); a hot-reload clears the cache, so we must not
            // re-populate it with a result computed under the old config.
            let routing_gen = state
                .routing_generation
                .load(std::sync::atomic::Ordering::Acquire);
            let resp = synth_answer(&ctx, &hot, geosite.as_deref(), entry).await?;
            // A/AAAA/CNAME records carry their TTL in the packet; for RCODE/NODATA
            // responses (no record) the entry's rcode_ttl governs the cache lifetime.
            let nodata_ttl = entry.fixed_rcode.map(|_| entry.rcode_ttl);
            cache_answer(&ctx, state, &resp, routing_gen, nodata_ttl);
            state
                .querylog
                .counters
                .local_responses
                .fetch_add(1, Ordering::Relaxed);
            let source = if entry.fixed_answers.is_empty() {
                "rcode"
            } else {
                "answer"
            };
            emit_slow_event(&ctx, state, &resp, source, None, 0);
            return Ok(resp);
        }
    }

    if let Some(rule) = hot
        .routing_index
        .route(&hot.rules, &ctx.info.qname, geosite.as_deref())
    {
        if let Some(target) = rule.target() {
            return exchange_with_dedupe(ctx, state, target).await;
        }
    }

    let target = router::classify_target(&hot, ctx.info.qtype);
    exchange_with_dedupe(ctx, state, target).await
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
        RouteTarget::IpSetTest { primary, secondary } => {
            resolve_none_rule_with_ipset(
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
        RouteTarget::Rule(_, _) => {
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
    if let RouteTarget::Rule(g, _) = &target {
        if g.filter_qtype.contains(&ctx.info.qtype) {
            let resp = dns::empty_reply(&ctx.packet, ctx.info.question_end).map(Bytes::from)?;
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .filtered
                    .fetch_add(1, Ordering::Relaxed);
                emit_slow_event(&ctx, state, &resp, "filtered", Some(g.name_arc.clone()), 0);
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
    // Parse the EDNS variant once, then reuse it for cache-key selection and the
    // strip-mode cache-write decision.
    let variant = dns::extract_variant(&ctx.packet, ctx.info.question_end);
    let ecs_in_query = target.strip_ecs() && variant.ecs_src.is_some();
    let ck = cache_key_with_variant(&ctx.packet, ctx.info.question_end, &variant, ecs_in_query);
    // Mix routing generation into the singleflight key so followers from a previous
    // routing generation do not join an in-flight request for a different route target.
    let sf_ck = ck ^ routing_gen.wrapping_mul(0x9e3779b97f4a7c15);
    let waiter = singleflight::register(&state.remote_inflight, sf_ck)?;

    if let Some(mut rx) = waiter {
        // Bound the follower wait so a panicking leader never leaves clients hung forever.
        let deadline = state.hot.load().cfg.timeout + Duration::from_secs(1);
        let servfail = Bytes::from(
            dns::servfail_reply(&ctx.packet, ctx.info.question_end).unwrap_or_default(),
        );
        match tokio::time::timeout(deadline, rx.changed()).await {
            Ok(Ok(())) => {}
            _ => {
                // covers both Err(_timeout) and Ok(Err(_channel_closed))
                let elapsed = started.elapsed().as_micros() as u64;
                record_client_latency(&ctx, state, elapsed);
                record_singleflight_hit(&ctx, state);
                emit_slow_event(
                    &ctx,
                    state,
                    &servfail,
                    "singleflight",
                    Some(target.rule_name_arc()),
                    elapsed,
                );
                return Ok(servfail);
            }
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
                Some(target.rule_name_arc()),
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
            Some(target.rule_name_arc()),
            elapsed,
        );
        return Ok(resp);
    }
    // If the leader task is cancelled while awaiting upstream I/O, Drop removes
    // the table entry so later callers can become the new leader instead of waiting forever.
    let mut _leader = SingleflightLeader {
        state,
        key: sf_ck,
        published: false,
    };

    // Leader path: compute skip_cache before consuming packet, clone for cache use.
    let skip_cache = target.skip_cache();
    let query_for_cache = ctx.packet.clone();

    let rule_name = target.rule_name();
    let rule_arc = target.rule_name_arc();

    let result = do_upstream_exchange(&ctx, state, &target).await;

    match result {
        Ok(resp) => {
            // Response collapse: flatten a CNAME chain to the final A/AAAA records at
            // the query name. Applied before caching so the cache stores the collapsed
            // form and every client (this one and singleflight followers) sees it.
            let resp = if target.collapse() && matches!(ctx.info.qtype, 1 | 28) {
                dns::collapse_cname_chain(resp.as_ref(), ctx.info.question_end)
                    .map(Bytes::from)
                    .unwrap_or(resp)
            } else {
                resp
            };
            maybe_add_response_ips(&target, ctx.info.question_end, state, resp.as_ref());
            // Skip cache write if the routing generation advanced (GeoSite hot-reload cleared
            // the cache between when we started the query and when the response arrived).
            if !skip_cache
                && state
                    .routing_generation
                    .load(std::sync::atomic::Ordering::Acquire)
                    == routing_gen
            {
                let (cache_policy, rule_id) = match &target {
                    RouteTarget::Rule(g, idx) => (g.cache_policy, *idx as u16),
                    // IpSetTest ("none" fallback): use sentinel 65534 so cache hits show rule "none".
                    _ => (state.cache.resolve_policy(None), RULE_ID_NONE_FALLBACK),
                };
                // ecs_in_query was computed once above; reuse here to avoid a second extract_variant.
                let stripped_query: Option<bytes::Bytes> = if ecs_in_query {
                    dns::strip_edns_ecs(&query_for_cache).map(bytes::Bytes::from)
                } else {
                    None
                };
                let cache_query: &[u8] = stripped_query.as_deref().unwrap_or(&query_for_cache);
                // Strip per-connection OPT data (COOKIE, NSID, …) from the cached copy so
                // those options from one client's upstream exchange are not returned to
                // subsequent clients served from cache.  The response sent to the first
                // client is unchanged.
                let sanitized_resp = dns::strip_opt_rdata(resp.as_ref()).map(bytes::Bytes::from);
                let cache_packet: &[u8] =
                    sanitized_resp.as_deref().unwrap_or_else(|| resp.as_ref());
                state.cache.add(
                    crate::cache::CacheInsert {
                        key: ck,
                        qname: ctx.info.qname.clone(),
                        question_end: ctx.info.question_end,
                        query: cache_query,
                        packet: cache_packet,
                    },
                    &cache_policy,
                    rule_id,
                );
            }
            // Restore canonical QNAME case before sending to this client and publishing
            // to singleflight waiters (strips upstream 0x20 case mixing).
            let mut resp_mut = BytesMut::from(resp.as_ref());
            resp_mut[12..ctx.info.question_end].copy_from_slice(ctx.question());
            let resp = resp_mut.freeze();
            singleflight::publish_bytes(&state.remote_inflight, &sf_ck, resp.clone());
            _leader.published = true;
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(&ctx, state, elapsed);
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .upstream_ok
                    .fetch_add(1, Ordering::Relaxed);
            }
            emit_slow_event(&ctx, state, &resp, "upstream", Some(rule_arc), elapsed);
            Ok(resp)
        }
        Err(err) => {
            crate::warn_rate_limited!(
                &UPSTREAM_FAIL_LAST_WARN,
                10,
                "dns event=upstream_failed target={} error={err:#}",
                rule_name
            );
            let servfail = match dns::servfail_reply(&query_for_cache, ctx.info.question_end) {
                Ok(pkt) => pkt,
                Err(_) => return Err(err),
            };
            let servfail = Bytes::from(servfail);
            singleflight::publish_bytes(&state.remote_inflight, &sf_ck, servfail.clone());
            _leader.published = true;
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(&ctx, state, elapsed);
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .upstream_err
                    .fetch_add(1, Ordering::Relaxed);
            }
            emit_slow_event(&ctx, state, &servfail, "upstream", Some(rule_arc), elapsed);
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
    rule: Option<Arc<str>>,
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
        rule,
        answer_ips: if ql.collect_answer_ips() && matches!(ctx.info.qtype, 1 | 28) {
            dns::answer_ips(resp, ctx.info.question_end)
        } else {
            smallvec::SmallVec::new()
        },
    });
}

/// Race primary and secondary upstream rules.
///
/// A non-SERVFAIL response wins immediately. If the first responder returns SERVFAIL
/// or a network error, we wait for the other side: a clean response there wins, otherwise
/// we prefer any SERVFAIL over a raw network error, and only return `Err` if both sides
/// failed with network errors.
async fn race(
    packet: Bytes,
    client_id: u16,
    client_proto: ClientProto,
    primary: &Rule,
    secondary: &Rule,
    count_hedge: bool,
) -> Result<Bytes> {
    let primary_upstream = primary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback primary rule has no upstream"))?;
    let secondary_upstream = secondary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback secondary rule has no upstream"))?;
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

async fn resolve_none_rule_with_ipset(
    packet: Bytes,
    info: &dns::QueryInfo,
    client_proto: ClientProto,
    primary: &crate::server::Rule,
    secondary: &crate::server::Rule,
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
        .ok_or_else(|| anyhow!("fallback primary rule has no upstream"))?;
    let secondary_upstream = secondary
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow!("fallback secondary rule has no upstream"))?;

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
    let primary_query =
        primary_upstream.exchange_observed(primary_packet, info.id, client_proto, count_hedge);
    let secondary_query =
        secondary_upstream.exchange_observed(secondary_packet, info.id, client_proto, count_hedge);
    let (primary_resp, secondary_resp) = tokio::join!(primary_query, secondary_query);

    match primary_resp {
        Ok(resp) => {
            let ips = dns::answer_ips(&resp, info.question_end);
            let ipset = ipset.clone();
            let verdict = tokio::task::spawn_blocking(move || ipset.test_response(&ips))
                .await
                .map_err(|e| anyhow!("ipset test task failed: {e}"))?;
            let noip_as_primary = state.hot.load().cfg.fallback.noip_as_primary_ip;
            match verdict {
                TestVerdict::PrimaryIp => {
                    state.verdict_cache.add(&info.qname, true);
                    Ok(resp)
                }
                TestVerdict::NoIpFound if noip_as_primary => Ok(resp),
                verdict => {
                    if matches!(verdict, TestVerdict::SecondaryIp) {
                        state.verdict_cache.add(&info.qname, false);
                    }
                    secondary_resp.or(Ok(resp))
                }
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
/// followers, Race, and IpSetTest all skip this; nftset is populated on the first
/// upstream response only.
///
/// The IPs are enqueued to the background add worker, which batches and writes them to
/// the configured sets without blocking the DNS reply.
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
    if let RouteTarget::Rule(rule, _) = target {
        ipset.add_rule_ips(&rule.name, &ips);
    }
}

#[cfg(test)]
#[path = "tests/resolver.rs"]
mod querylog_tests;
