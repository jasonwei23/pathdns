//! DNS query pipeline: fast path (parse → opcode/qclass checks → cache), slow path
//! (classify → rule filter chain → upstream → cache store).
//!
//! Listener code owns sockets and framing; this module owns packet lifecycle after a DNS
//! message has been received.

use crate::cache::{cache_key_with_variant, CacheKey};
use crate::config::{FallbackTarget, FixedAnswer};
use crate::dns;
use crate::router::RouteTarget;
use crate::server::{AppState, HotState, Rule};
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

/// What produced a cache entry's `rule_id`. Kept distinct from the packed `u16`
/// actually stored in the cache (see `to_wire`/`from_wire`) so the two "which
/// final branch did this come from" call sites — the encode in
/// `exchange_with_dedupe` and the decode in `rule_id_to_name` — read as plain
/// match arms instead of magic-constant bit twiddling.
#[derive(Clone, Copy)]
enum RuleAttribution {
    /// A plain `RouteTarget::Rule` match: index into `HotState::rules`.
    Rule(usize),
    /// A `route.final` primary/secondary fallback whose winning rule is known:
    /// index into `HotState::rules`.
    FinalWinner(usize),
    /// A `route.final` primary/secondary fallback whose winner is not known
    /// (e.g. both sides failed).
    FinalUnknown,
    /// No rule (e.g. a `route.answer` cache entry).
    None,
}

impl RuleAttribution {
    /// Sentinel for `FinalUnknown`. Cannot use `u16::MAX` (65535) because that
    /// is the wire encoding of `None` (the pre-existing "no rule" sentinel,
    /// also relied on by the persisted cache file format).
    const FINAL_UNKNOWN_WIRE: u16 = 65534;
    /// Set in the wire encoding of `FinalWinner`: the low 15 bits are the
    /// winning rule's index. Rule counts are configuration-sized (never close
    /// to 2^15), so this never collides with a real index.
    const FINAL_WINNER_FLAG: u16 = 0x8000;

    /// Encode as the `u16` stored in the cache (in-memory and persisted-to-disk).
    fn to_wire(self) -> u16 {
        match self {
            Self::Rule(idx) => idx as u16,
            Self::FinalWinner(idx) => Self::FINAL_WINNER_FLAG | (idx as u16),
            Self::FinalUnknown => Self::FINAL_UNKNOWN_WIRE,
            Self::None => u16::MAX,
        }
    }

    /// Decode a `rule_id` read back from the cache.
    fn from_wire(rule_id: u16) -> Self {
        if rule_id == u16::MAX {
            Self::None
        } else if rule_id == Self::FINAL_UNKNOWN_WIRE {
            Self::FinalUnknown
        } else if rule_id & Self::FINAL_WINNER_FLAG != 0 {
            Self::FinalWinner((rule_id & !Self::FINAL_WINNER_FLAG) as usize)
        } else {
            Self::Rule(rule_id as usize)
        }
    }
}

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

/// Result of the synchronous fast path: parse header, check opcode/qclass, check cache.
pub(crate) enum FastPathOutcome {
    /// Ready-to-send response (opcode/qclass rejection or cache hit).
    Response { resp: Bytes },
    /// Cache miss; full async resolution is required.
    Miss { info: dns::FastQueryInfo },
    /// Malformed packet; drop silently, send no reply.
    Drop,
}

/// Decode a `rule_id` stored in the cache into a display name.
fn rule_id_to_name(rule_id: u16, hot: &HotState) -> Option<Arc<str>> {
    match RuleAttribution::from_wire(rule_id) {
        RuleAttribution::None => None,
        RuleAttribution::FinalUnknown => Some(crate::router::final_arc()),
        RuleAttribution::FinalWinner(idx) => Some(
            hot.rules
                .get(idx)
                .map(|r| r.final_name_arc.clone())
                .unwrap_or_else(crate::router::final_arc),
        ),
        RuleAttribution::Rule(idx) => hot.rules.get(idx).map(|g| g.name_arc.clone()),
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

    // Non-QUERY opcodes: return NOTIMP per RFC 1035. Requires a full 12-byte header
    // (matching notimp_opcode_reply's own guard) so a 3-11 byte malformed packet
    // falls through to parse_query_fast's length check and is silently dropped,
    // rather than this branch handing back an empty (zero-length) UDP datagram.
    if packet.len() >= 12 && (packet[2] & 0x80) == 0 && (packet[2] >> 3) & 0x0f != 0 {
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
        // `split()` would look like it reuses `send_buf`, but it actually hands the
        // written prefix's memory to the returned `Bytes` and permanently shrinks
        // `send_buf`'s remaining capacity by that amount — under sustained load
        // (many cache hits queued before a batched send flush, so the earlier
        // responses' `Bytes` are still alive) this degrades into a fresh heap
        // allocation on nearly every hit once the initial capacity is used up.
        // Copying out instead keeps `send_buf` at a stable capacity forever.
        let resp = Bytes::copy_from_slice(send_buf);
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
    .await
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
    if state.hot_generation() != routing_gen {
        return;
    }
    let variant = dns::extract_variant(&ctx.packet, ctx.info.question_end);
    let ck = cache_key_with_variant(&ctx.packet, ctx.info.question_end, &variant, true);
    // Key on the stripped variant: drop ECS from the cached query so the entry
    // matches both ECS and non-ECS clients in the lookup path. When there's no
    // ECS to strip, the stored query is byte-identical to `ctx.packet`, so reuse
    // `variant` (already computed above for `ck`) instead of a second
    // `extract_variant` pass in `DnsCache::add`; only recompute it on the branch
    // where stripping actually produced different bytes.
    let (cache_query, cache_variant): (Bytes, dns::QueryVariant) = if variant.ecs_src.is_some() {
        match dns::strip_edns_ecs(&ctx.packet) {
            Some(stripped) => {
                let stripped = Bytes::from(stripped);
                let v = dns::extract_variant(&stripped, ctx.info.question_end);
                (stripped, v)
            }
            None => (ctx.packet.clone(), variant),
        }
    } else {
        (ctx.packet.clone(), variant)
    };
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
            variant: cache_variant,
            packet: cache_packet,
        },
        &policy,
        RuleAttribution::None.to_wire(),
    );
}

/// Synthesise a response for a `route.answer` map hit. Mirrors the fixed-answer
/// rule path: A/AAAA records, a chased CNAME, or an RCODE/empty reply. CNAME
/// targets are routed through the full rule table (`after = None`).
async fn synth_answer(
    ctx: &QueryContext,
    hot: &crate::server::HotState,
    ruleset: Option<&crate::ruleset::RuleSetDb>,
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
                ruleset,
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
    ruleset: Option<&crate::ruleset::RuleSetDb>,
    cname_target: &str,
    ttl: u32,
) -> Result<Bytes> {
    // Only chase for A and AAAA queries; other types just get the CNAME record.
    if qtype != 1 && qtype != 28 {
        return dns::cname_reply(packet, question_end, cname_target, ttl).map(Bytes::from);
    }

    // Route the CNAME target through the rule table.
    let Some(target_rule) = hot.routing_index.route(&hot.rules, cname_target, ruleset) else {
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

async fn resolve_query(ctx: QueryContext, state: &Arc<AppState>) -> Result<Option<Bytes>> {
    let hot = state.hot.load_full();
    let ruleset = if hot.needs_ruleset {
        hot.ruleset.clone()
    } else {
        None
    };
    // Domain → fixed-answer map: consulted before the routing rules. A matching
    // entry synthesises a response (A/AAAA/CNAME/RCODE) without routing.
    if !hot.cfg.answer_map.is_empty() {
        if let Some(entry) = hot
            .cfg
            .answer_map
            .lookup(&ctx.info.qname, ruleset.as_deref())
        {
            // Capture the routing generation before any await in synth_answer (a CNAME
            // chase queries an upstream); a hot-reload clears the cache, so we must not
            // re-populate it with a result computed under the old config.
            let routing_gen = hot.generation;
            let resp = synth_answer(&ctx, &hot, ruleset.as_deref(), entry).await?;
            // A/AAAA/CNAME records carry their TTL in the packet; for RCODE/NODATA
            // responses (no record) the entry's rcode_ttl governs the cache lifetime.
            let nodata_ttl = entry.fixed_rcode.map(|_| entry.rcode_ttl);
            cache_answer(&ctx, state, &resp, routing_gen, nodata_ttl);
            state
                .querylog
                .counters
                .local_responses
                .fetch_add(1, Ordering::Relaxed);
            // Every route.answer hit — whether it synthesises actual records or just an
            // RCODE — reports as "answer"; the response's own rcode field already
            // conveys NXDOMAIN/NOERROR/etc., so a separate "rcode" source is redundant.
            emit_slow_event(&ctx, state, &resp, "answer", None, 0);
            return Ok(Some(resp));
        }
    }

    if let Some(rule) = hot
        .routing_index
        .route(&hot.rules, &ctx.info.qname, ruleset.as_deref())
    {
        if let Some(target) = rule.target() {
            return exchange_with_dedupe(ctx, state, &hot, ruleset.as_deref(), target).await;
        }
    }

    let target = router::classify_target(&hot, ctx.info.qtype);
    exchange_with_dedupe(ctx, state, &hot, ruleset.as_deref(), target).await
}

/// Run the appropriate upstream exchange for a given route target.
/// Extracted so it can be pinned and raced against a timeout.
///
/// Returns the winning rule's index alongside the response when `target` is a
/// `route.final` `Race`/`CidrTest` fallback (so callers can report/cache against
/// whichever of primary/secondary actually answered, e.g. `"final->domestic"`).
/// `None` for a plain `RouteTarget::Rule`, since the caller already knows its identity.
async fn do_upstream_exchange(
    ctx: &QueryContext,
    state: &Arc<AppState>,
    target: &RouteTarget<'_>,
) -> Result<(Bytes, Option<usize>)> {
    match target {
        RouteTarget::Race { primary, secondary } => race(
            ctx.packet.clone(),
            ctx.info.id,
            ctx.proto(),
            primary,
            secondary,
            ctx.client().is_some(),
        )
        .await
        .map(|(b, idx)| (b, Some(idx))),
        RouteTarget::CidrTest { primary, secondary } => resolve_none_rule_with_cidr(
            ctx.packet.clone(),
            &ctx.info,
            ctx.proto(),
            primary,
            secondary,
            state,
            ctx.client().is_some(),
        )
        .await
        .map(|(b, idx)| (b, Some(idx))),
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
                .map(|b| (b, None))
        }
    }
}

async fn exchange_with_dedupe(
    ctx: QueryContext,
    state: &Arc<AppState>,
    hot: &HotState,
    ruleset: Option<&crate::ruleset::RuleSetDb>,
    target: RouteTarget<'_>,
) -> Result<Option<Bytes>> {
    let started = Instant::now();
    // Record routing generation before any upstream I/O. A hot-reload always swaps
    // `state.hot` (and its embedded `generation`) before clearing the cache, so this
    // snapshot can never be stale relative to the cache clear. We check it before
    // writing to the cache below to prevent stale responses from re-populating the
    // fresh cache.
    let routing_gen = hot.generation;
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
        // Bound the follower wait so a panicking leader never leaves clients hung
        // forever. Must cover the leader's actual worst case, not just one bare
        // `cfg.timeout`: a hedged exchange can run `hedge_delay` before even
        // starting its (fully re-timed-out) second upstream, and a `continue`/
        // `forward` filter chain can hop through up to `MAX_FILTER_HOPS` rules,
        // each its own full exchange. Undershooting this just means followers
        // occasionally get a spurious SERVFAIL for a query the leader was about
        // to answer correctly — this only pads the panic-safety fallback, so
        // erring generous costs nothing in the (overwhelmingly common) case
        // where the leader finishes well before it.
        // Reuse the same `hot` snapshot the caller took `routing_gen`/`sf_ck` from,
        // rather than an independent `state.hot.load()` here: a concurrent
        // hot-reload between the two reads could otherwise pair this generation's
        // routing_gen with a *different* generation's `cfg.timeout`/`hedge_delay`.
        let cfg = &hot.cfg;
        let deadline = cfg.timeout * MAX_FILTER_HOPS
            + cfg.hedge_delay.unwrap_or_default()
            + Duration::from_secs(1);
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
                return Ok(Some(servfail));
            }
        }
        let published = rx.borrow().clone();
        let Some(resp) = published else {
            // The leader's rule filter decided to drop this query (not an error);
            // followers get the same outcome instead of a synthesized SERVFAIL.
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(&ctx, state, elapsed);
            record_singleflight_hit(&ctx, state);
            return Ok(None);
        };
        let elapsed = started.elapsed().as_micros() as u64;
        // Guard against 64-bit hash collision: the leader may have resolved a different
        // question. Verify the response question section matches ours (case-insensitively,
        // since DNS names are compared case-insensitively and some upstreams normalise
        // case in their reply).
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
            return Ok(Some(servfail));
        }
        let mut resp = BytesMut::from(resp.as_ref());
        dns::set_id(&mut resp, ctx.info.id)?;
        // Restore the client's original letter case (some upstreams normalise it).
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
        return Ok(Some(resp));
    }
    // If the leader task is cancelled while awaiting upstream I/O, Drop removes
    // the table entry so later callers can become the new leader instead of waiting forever.
    let mut _leader = SingleflightLeader {
        state,
        key: sf_ck,
        published: false,
    };

    let query_for_cache = ctx.packet.clone();

    // Drive the rule's filter chain (possibly hopping to other rules via `continue`,
    // or another rule's upstream via `forward`); `target` on return is whichever rule
    // ultimately produced the outcome, and governs cache policy/logging below.
    let (result, target) = resolve_with_filters(&ctx, state, hot, ruleset, target).await;
    let skip_cache = target.skip_cache();
    let rule_name = target.rule_name();
    let rule_arc = target.rule_name_arc();

    match result {
        Ok(StepOutcome::Response(resp, source, winner_idx)) => {
            maybe_add_response_ips(&target, ctx.info.question_end, state, resp.as_ref());
            // For a route.final Race/CidrTest fallback, the winning rule (whichever of
            // primary/secondary actually answered) reports/caches as "final->{name}"
            // instead of the generic "final".
            let winner_rule = winner_idx.and_then(|idx| hot.rules.get(idx));
            let rule_arc =
                winner_rule.map_or_else(|| rule_arc.clone(), |r| r.final_name_arc.clone());
            // Skip cache write if the routing generation advanced (ruleset hot-reload cleared
            // the cache between when we started the query and when the response arrived).
            if !skip_cache && state.hot_generation() == routing_gen {
                let (cache_policy, attribution) = match (&target, winner_rule) {
                    (RouteTarget::Rule(g, idx), _) => (g.cache_policy, RuleAttribution::Rule(*idx)),
                    (_, Some(w)) => (
                        state.cache.resolve_policy(None),
                        RuleAttribution::FinalWinner(w.index),
                    ),
                    // Winner not known (e.g. race tie-break fallback): sentinel so cache
                    // hits show the generic "final".
                    (_, None) => (
                        state.cache.resolve_policy(None),
                        RuleAttribution::FinalUnknown,
                    ),
                };
                let rule_id = attribution.to_wire();
                // `variant` was computed once above (for `ecs_in_query`/`ck`) against
                // `ctx.packet`. When ECS isn't being stripped for storage, the stored
                // query is byte-identical to `ctx.packet`, so reuse `variant` instead of
                // a second `extract_variant` pass in `DnsCache::add`; only the branch
                // where stripping actually changes the bytes needs a fresh one.
                let (cache_query, cache_variant): (bytes::Bytes, dns::QueryVariant) =
                    if ecs_in_query {
                        match dns::strip_edns_ecs(&query_for_cache) {
                            Some(stripped) => {
                                let stripped = bytes::Bytes::from(stripped);
                                let v = dns::extract_variant(&stripped, ctx.info.question_end);
                                (stripped, v)
                            }
                            None => (query_for_cache, variant),
                        }
                    } else {
                        (query_for_cache, variant)
                    };
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
                        variant: cache_variant,
                        packet: cache_packet,
                    },
                    &cache_policy,
                    rule_id,
                );
            }
            // Restore the client's original QNAME letter case (some upstreams normalise
            // it) before sending to this client and publishing to singleflight waiters.
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
                // A `filter: empty` rewrite is tagged with the same "filtered" source as
                // a `filter: drop` (see the `StepOutcome::Drop` arm below), so the
                // dashboard's "Filtered" tile/sparkline must count both — otherwise it
                // would silently undercount relative to what the query log's `filtered`
                // chip actually shows.
                if source == "filtered" {
                    state
                        .querylog
                        .counters
                        .filtered
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            emit_slow_event(&ctx, state, &resp, source, Some(rule_arc), elapsed);
            Ok(Some(resp))
        }
        Ok(StepOutcome::Drop) => {
            singleflight::publish_drop(&state.remote_inflight, &sf_ck);
            _leader.published = true;
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(&ctx, state, elapsed);
            if ctx.client().is_some() {
                state
                    .querylog
                    .counters
                    .filtered
                    .fetch_add(1, Ordering::Relaxed);
            }
            emit_slow_event(
                &ctx,
                state,
                &Bytes::new(),
                "filtered",
                Some(rule_arc),
                elapsed,
            );
            Ok(None)
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
                // Distinguish saturation of the per-upstream inflight cap from
                // other upstream failures so it is diagnosable on the dashboard.
                if err
                    .chain()
                    .any(|e| e.is::<crate::upstream::InflightCapReached>())
                {
                    state
                        .querylog
                        .counters
                        .upstream_inflight_drops
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            emit_slow_event(&ctx, state, &servfail, "upstream", Some(rule_arc), elapsed);
            Ok(Some(servfail))
        }
    }
}

/// Cap on `continue`/`forward` hops per query — fails safe (SERVFAIL) against a
/// pathological always-matching filter chain rather than looping or re-querying
/// `route.final` forever. Rule indices strictly increase on each `continue`, so a
/// well-formed chain never approaches this in practice.
const MAX_FILTER_HOPS: u32 = 8;

/// Outcome of driving a rule (and any `continue`/`forward` hops) to completion.
enum StepOutcome {
    /// A response to send/cache, tagged with the querylog `source` to report, plus
    /// the winning rule's index when this came from a `route.final` `Race`/`CidrTest`
    /// fallback (`None` for a plain rule match, `forward`, or a rewritten `filtered`
    /// response — those already have a definite rule identity via `target`).
    Response(Bytes, &'static str, Option<usize>),
    /// The rule's filter chain decided to send no reply at all.
    Drop,
}

/// Drive one target through its rule's `filter` chain (if any): every filter
/// dimension is evaluated against the resolved response (see `crate::response_filter`
/// docs), so this always queries upstream via `do_upstream_exchange` first.
///
/// `continue` swaps `target` to the next rule that matches the query (via
/// `RouteIndex::route_after`, falling back to `route.final` once no more rules
/// match) and loops. `forward` answers directly from another rule's upstream without
/// changing `target`'s identity, so caching/logging still credit the rule that
/// actually matched via routing.
///
/// Returns the final `target` alongside the result so the caller can report/cache
/// against whichever rule produced the outcome.
async fn resolve_with_filters<'a>(
    ctx: &QueryContext,
    state: &Arc<AppState>,
    hot: &'a HotState,
    ruleset: Option<&crate::ruleset::RuleSetDb>,
    mut target: RouteTarget<'a>,
) -> (Result<StepOutcome>, RouteTarget<'a>) {
    use crate::response_filter::FilterAction;

    for _ in 0..MAX_FILTER_HOPS {
        let (resp, winner_idx) = match do_upstream_exchange(ctx, state, &target).await {
            Ok(r) => r,
            Err(e) => return (Err(e), target),
        };

        if let RouteTarget::Rule(rule, idx) = target {
            if let Some(action) = crate::response_filter::first_match(
                &rule.filters,
                ruleset,
                &resp,
                ctx.info.question_end,
            ) {
                match action {
                    FilterAction::Empty => {
                        return (
                            dns::empty_reply(&ctx.packet, ctx.info.question_end)
                                .map(Bytes::from)
                                .map(|b| StepOutcome::Response(b, "filtered", None)),
                            target,
                        );
                    }
                    FilterAction::Drop => return (Ok(StepOutcome::Drop), target),
                    FilterAction::Continue => {
                        target = next_target(hot, ruleset, &ctx.info.qname, idx, ctx.info.qtype);
                        continue;
                    }
                    FilterAction::Forward(target_idx) => {
                        // Bypasses the target rule's own routing/filters/cache policy
                        // entirely — just its upstream, via the same exchange path
                        // any other rule target uses.
                        let forward_target = RouteTarget::Rule(&hot.rules[target_idx], target_idx);
                        let fresp = do_upstream_exchange(ctx, state, &forward_target).await;
                        return (
                            fresp.map(|(b, _)| StepOutcome::Response(b, "forwarded", None)),
                            target,
                        );
                    }
                }
            }
        }

        return (
            Ok(StepOutcome::Response(resp, "upstream", winner_idx)),
            target,
        );
    }
    (
        Err(anyhow!(
            "rule filter continue/forward hop limit ({MAX_FILTER_HOPS}) exceeded"
        )),
        target,
    )
}

/// The next candidate target for a `continue` filter action: the next rule (after
/// `after_idx`) that matches `qname`, or `route.final` once none do.
fn next_target<'a>(
    hot: &'a HotState,
    ruleset: Option<&crate::ruleset::RuleSetDb>,
    qname: &str,
    after_idx: usize,
    qtype: u16,
) -> RouteTarget<'a> {
    if let Some(rule) = hot
        .routing_index
        .route_after(&hot.rules, qname, ruleset, after_idx)
    {
        if let Some(t) = rule.target() {
            return t;
        }
    }
    router::classify_target(hot, qtype)
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
///
/// Returns the winning rule's index alongside the response, so callers can report the
/// query log's `rule` as `"final->{name}"` instead of the generic `"final"`.
async fn race(
    packet: Bytes,
    client_id: u16,
    client_proto: ClientProto,
    primary: &Rule,
    secondary: &Rule,
    count_hedge: bool,
) -> Result<(Bytes, usize)> {
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
                result.map(|b| (b, primary.index))
            } else {
                pick_race_winner(result, primary.index, secondary_fut.await, secondary.index)
            }
        },
        result = &mut secondary_fut => {
            if matches!(&result, Ok(r) if dns::rcode(r) != 2) {
                result.map(|b| (b, secondary.index))
            } else {
                pick_race_winner(result, secondary.index, primary_fut.await, primary.index)
            }
        },
    }
}

/// Merge two soft-fail results (SERVFAIL or network error).
/// If the second side recovered with a clean response, return it.
/// Otherwise prefer any SERVFAIL DNS response over a raw network error.
fn pick_race_winner(
    first: Result<Bytes>,
    first_idx: usize,
    second: Result<Bytes>,
    second_idx: usize,
) -> Result<(Bytes, usize)> {
    if matches!(&second, Ok(r) if dns::rcode(r) != 2) {
        return second.map(|b| (b, second_idx));
    }
    match (first, second) {
        (Ok(sf), _) => Ok((sf, first_idx)),
        (Err(_), Ok(sf)) => Ok((sf, second_idx)),
        (Err(e1), Err(e2)) => Err(anyhow!("race failed: {e1:#}; {e2:#}")),
    }
}

async fn resolve_none_rule_with_cidr(
    packet: Bytes,
    info: &dns::QueryInfo,
    client_proto: ClientProto,
    primary: &crate::server::Rule,
    secondary: &crate::server::Rule,
    state: &Arc<AppState>,
    count_hedge: bool,
) -> Result<(Bytes, usize)> {
    // Loaded once and reused for both `answer_ip_tags`/`ruleset` below and the
    // generation captured further down: sourcing them from independent atomic
    // loads (as this used to) could pair a new ruleset with an old generation
    // (or vice versa) across a hot-reload landing in between.
    let hot = state.hot.load_full();
    // Borrowed from `hot`, which is already held for this whole function (it's
    // read again below at `hot.cfg.fallback.noip_as_primary_ip`), instead of a
    // `Vec<String>` clone: this only depends on config, so nothing about a
    // per-query deep copy was ever necessary.
    let answer_ip_tags: Option<&[String]> = match &hot.cfg.fallback.target {
        FallbackTarget::Dual { answer_ip_tags, .. } if !answer_ip_tags.is_empty() => {
            Some(answer_ip_tags.as_slice())
        }
        _ => None,
    };
    let (Some(answer_ip_tags), Some(ruleset)) = (answer_ip_tags, hot.ruleset.clone()) else {
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
    // Captured before any upstream I/O so a verdict write below can be skipped if a
    // hot-reload invalidates the verdict cache while this query is still in flight
    // (mirrors the same guard the DNS response cache uses in `exchange_with_dedupe`).
    let routing_gen = hot.generation;
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
                .map(|b| (b, primary.index))
        } else {
            secondary_upstream
                .exchange_observed(packet, info.id, client_proto, count_hedge)
                .await
                .map(|b| (b, secondary.index))
        };
    }

    let primary_packet = packet.clone();
    let secondary_packet = packet;
    // Fire both upstreams concurrently. The answer-ip verdict can usually be decided
    // from the primary's answer alone (its IPs are in the set → use primary), so
    // we drive both but return the moment the primary resolves the decision,
    // without blocking on a possibly-slow secondary. The secondary query is still
    // in flight, so when its answer *is* needed there is no extra round-trip.
    let primary_query =
        primary_upstream.exchange_observed(primary_packet, info.id, client_proto, count_hedge);
    let secondary_query =
        secondary_upstream.exchange_observed(secondary_packet, info.id, client_proto, count_hedge);
    tokio::pin!(primary_query);
    tokio::pin!(secondary_query);

    // Drive both until the primary completes, stashing the secondary's result if
    // it happens to finish first (the disabled branch then stops re-polling it).
    let mut secondary_done: Option<Result<Bytes>> = None;
    let primary_resp = loop {
        tokio::select! {
            biased;
            pr = &mut primary_query => break pr,
            sr = &mut secondary_query, if secondary_done.is_none() => {
                secondary_done = Some(sr);
            }
        }
    };

    match primary_resp {
        Ok(resp) => {
            let ips = dns::answer_ips(&resp, info.question_end);
            // Pure in-memory range-set lookup, no syscalls, so it runs inline.
            let is_primary_ip = answer_ip_tags
                .iter()
                .any(|tag| ruleset.matches_any_ip(tag, &ips));
            let noip_as_primary = hot.cfg.fallback.noip_as_primary_ip;
            // Skip the write entirely if a hot-reload advanced the generation while
            // this query was in flight — the verdict cache was just invalidated and
            // this decision may be based on now-stale ruleset/ipcidr data.
            let routing_unchanged = state.hot_generation() == routing_gen;
            if ips.is_empty() {
                if noip_as_primary {
                    return Ok((resp, primary.index));
                }
            } else if is_primary_ip {
                if routing_unchanged {
                    state.verdict_cache.add(&info.qname, true);
                }
                // Decision is "use primary"; the secondary's answer is not
                // needed, so return now and let its in-flight query be dropped.
                return Ok((resp, primary.index));
            } else if routing_unchanged {
                state.verdict_cache.add(&info.qname, false);
            }
            // Decision needs the secondary's answer: use the stashed result
            // or finish awaiting the already-in-flight query.
            let secondary_resp = match secondary_done {
                Some(sr) => sr,
                None => (&mut secondary_query).await,
            };
            secondary_resp
                .map(|b| (b, secondary.index))
                .or(Ok((resp, primary.index)))
        }
        Err(primary_err) => {
            let secondary_resp = match secondary_done {
                Some(sr) => sr,
                None => (&mut secondary_query).await,
            };
            secondary_resp.map(|b| (b, secondary.index)).map_err(|secondary_err| {
                anyhow!(
                    "primary upstream failed: {primary_err:#}; secondary upstream failed: {secondary_err:#}"
                )
            })
        }
    }
}

/// Write resolved IPs from an upstream response into the configured nftset/ipset.
///
/// Called only in `exchange_with_dedupe` (upstream path). Cache hits, singleflight
/// followers, Race, and CidrTest all skip this; nftset is populated on the first
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
