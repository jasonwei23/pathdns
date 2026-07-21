//! DNS query pipeline: fast path (parse → opcode/qclass checks → cache), slow path
//! (classify → rule filter chain → upstream → cache store).
//!
//! Listener code owns sockets and framing; this module owns packet lifecycle after a DNS
//! message has been received.

use crate::cache::{cache_key_with_variant_from_qname_hash, CacheKey};
use crate::config::{FallbackTarget, FixedAnswer};
use crate::dns;
use crate::router::RouteTarget;
use crate::server::{AppState, HotState, Server};
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
/// `exchange_with_dedupe` and the decode in `upstream_name_for_rule_id` — read
/// as plain match arms instead of magic-constant bit twiddling.
#[derive(Clone, Copy)]
enum RuleAttribution {
    /// A plain `RouteTarget::Rule` match: index into `HotState::rules`.
    Rule(usize),
    /// A direct `RouteTarget::Server` match (explicit single-target
    /// `route.final`, or a `route.final` primary/secondary fallback whose
    /// winning server is known): index into `HotState::servers`.
    Final(usize),
    /// A `route.final` primary/secondary fallback whose winner is not known
    /// (e.g. both sides failed).
    FinalUnknown,
    /// No rule. Only ever produced by `from_wire` decoding a pre-existing
    /// persisted cache entry written by an older version of this sentinel
    /// format; nothing in this codebase writes it anymore.
    None,
}

impl RuleAttribution {
    /// Sentinel for `FinalUnknown`. Cannot use `u16::MAX` (65535) because that
    /// is the wire encoding of `None` (the pre-existing "no rule" sentinel,
    /// also relied on by the persisted cache file format).
    const FINAL_UNKNOWN_WIRE: u16 = 65534;
    /// Set in the wire encoding of `Final`: the low 15 bits are the server's
    /// index. Server counts are configuration-sized (never close to 2^15), so
    /// this never collides with a real index. Note the top two flagged values
    /// are taken by the sentinels: `Final(32766)`/`Final(32767)` would encode
    /// as `FINAL_UNKNOWN_WIRE`/`u16::MAX` — unreachable in any real config.
    const FINAL_FLAG: u16 = 0x8000;

    /// Encode as the `u16` stored in the cache (in-memory and persisted-to-disk).
    fn to_wire(self) -> u16 {
        match self {
            Self::Rule(idx) => idx as u16,
            Self::Final(idx) => Self::FINAL_FLAG | (idx as u16),
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
        } else if rule_id & Self::FINAL_FLAG != 0 {
            Self::Final((rule_id & !Self::FINAL_FLAG) as usize)
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

    /// Materialize the routing qname into the lazy slot if absent, returning a
    /// borrow. The packet was already validated by `parse_query_fast`, so
    /// `qname_from_question` cannot fail here; an empty fallback keeps the
    /// hot path free of unwrap/expect if that ever changes.
    fn ensure_qname(&mut self) -> &Arc<str> {
        if self.info.qname.is_none() {
            let q = dns::qname_from_question(&self.packet, self.info.question_end)
                .unwrap_or_else(|_| Arc::from(""));
            self.info.qname = Some(q);
        }
        // `is_none` was just handled above, so this is always `Some`.
        self.info.qname.as_ref().unwrap_or_else(|| unreachable!())
    }

    /// An owned clone of the qname, materializing from the packet if the lazy
    /// slot is still empty. Cheap `Arc` clone in the common (already-present)
    /// case; used at the cache-store and querylog-emit sites, which only run
    /// when the qname was already materialized by routing/guard anyway.
    fn qname_owned(&self) -> Arc<str> {
        self.info.qname.clone().unwrap_or_else(|| {
            dns::qname_from_question(&self.packet, self.info.question_end)
                .unwrap_or_else(|_| Arc::from(""))
        })
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
    /// Cache miss; full async resolution is required. `probe` carries the
    /// `QueryVariant` already parsed while checking the cache **and** the cache
    /// key(s) already computed, both reused by the slow path instead of being
    /// re-derived from the raw packet.
    Miss {
        info: dns::FastQueryInfo,
        probe: crate::cache::CacheProbe,
    },
    /// Malformed packet; drop silently, send no reply.
    Drop,
}

/// Decode a `rule_id` stored in the cache into the upstream's display name.
fn upstream_name_for_rule_id(rule_id: u16, hot: &HotState) -> Option<Arc<str>> {
    match RuleAttribution::from_wire(rule_id) {
        RuleAttribution::None => None,
        RuleAttribution::FinalUnknown => Some(crate::router::final_arc()),
        RuleAttribution::Final(idx) => Some(
            hot.servers
                .get(idx)
                .map(|s| s.final_name_arc.clone())
                .unwrap_or_else(crate::router::final_arc),
        ),
        RuleAttribution::Rule(idx) => hot.rules.get(idx).map(|rule| rule.server_arc.clone()),
    }
}

#[inline]
fn record_query_received(ql: &crate::querylog::QueryLogHandle, proto: ClientProto) {
    // The total is derived as udp + tcp at read time
    // (`QueryLogCounters::queries_total`) — a third global atomic RMW on
    // every received packet bought nothing.
    match proto {
        ClientProto::Udp => ql.counters.queries_udp.fetch_add(1, Ordering::Relaxed),
        ClientProto::Tcp => ql.counters.queries_tcp.fetch_add(1, Ordering::Relaxed),
    };
}

/// Self-renewing response arena for the fast path: each response is written
/// into the buffer and handed out as a zero-copy `Bytes` via
/// [`Self::take`] (`BytesMut::split().freeze()`); the buffer keeps serving
/// later responses from its remaining capacity and renews itself with a
/// fresh `chunk`-sized allocation once the remainder falls below a floor.
///
/// The common cache hit therefore costs one necessary copy (cache entry →
/// arena, where the ID/case/TTL patches happen) and **zero** per-hit
/// allocations — previously each hit also paid a `Bytes::copy_from_slice`
/// (malloc + full second copy) to detach the response from the reused
/// buffer. A plain reusable buffer can't hand out owned bytes without that
/// copy, and naive `split()` reuse degrades into per-hit mallocs once the
/// initial capacity is gone (which is why the copy existed); the explicit
/// chunk renewal is what makes split() safe here, amortizing one malloc
/// across `chunk / avg_response_size` responses. Handed-out `Bytes` keep
/// their (refcounted) chunk alive however long callers hold them — queued
/// in a sendmmsg batch, parked in the pending-send queue — independent of
/// the arena's own renewals.
pub(crate) struct ResponseArena {
    buf: BytesMut,
    chunk: usize,
}

impl ResponseArena {
    /// Renew when remaining capacity drops below this. A response larger than
    /// the remainder is still handled — `BytesMut` reserves a fresh buffer
    /// internally — this only tunes how often the amortized allocation happens.
    const MIN_REMAINING: usize = 2048;

    pub(crate) fn new(chunk: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(chunk),
            chunk,
        }
    }

    /// The write target for the next response (empty between responses).
    pub(crate) fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    /// Read access to the not-yet-taken response (for logging/inspection).
    fn buf(&self) -> &[u8] {
        &self.buf
    }

    /// Detach the written response zero-copy and renew the chunk if it has
    /// run low.
    pub(crate) fn take(&mut self) -> Bytes {
        let resp = self.buf.split().freeze();
        if self.buf.capacity() < Self::MIN_REMAINING {
            self.buf = BytesMut::with_capacity(self.chunk);
        }
        resp
    }
}

/// Fast path (cache hit / local rejection): writes the response into `arena`
/// and hands it out as a zero-copy `Bytes` — see [`ResponseArena`].
pub(crate) fn try_fast_path_into(
    packet: &[u8],
    peer: SocketAddr,
    proto: ClientProto,
    state: &AppState,
    arena: &mut ResponseArena,
) -> FastPathOutcome {
    let collecting = state.querylog.collecting();
    let t0 = collecting.then(Instant::now);

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

    // Cache hit: write directly into the caller-provided arena. The entry's
    // qname Arc is only cloned when detailed events are collected.
    let (hit, probe) =
        state
            .cache
            .get_into_with_ecs_fallback(packet, &fast_info, arena.buf_mut(), collecting);
    if let Some(meta) = hit {
        let ql = &state.querylog;
        ql.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
        // `meta.qname` is Some exactly when `collecting` was passed into the
        // lookup above; destructuring keeps the two in lockstep.
        if let Some(qname) = meta.qname {
            // A plain `load()` guard suffices: `h` never crosses an .await and
            // this whole path is synchronous, so the cheaper thread-local guard
            // beats `load_full()`'s refcount round-trip on every logged hit.
            let h = state.hot.load();
            ql.try_emit_with(|seq| crate::querylog::QueryLogEvent {
                seq,
                unix_micros: crate::querylog::unix_micros_now(),
                client: peer.ip(),
                client_port: peer.port(),
                qname,
                qtype: fast_info.qtype,
                rcode: dns::rcode(arena.buf()),
                elapsed_us: t0.map_or(0, |t| t.elapsed().as_micros() as u64),
                response_bytes: arena.buf().len() as u32,
                source: "cache",
                upstream: upstream_name_for_rule_id(meta.rule_id, &h),
            });
        }
        return FastPathOutcome::Response { resp: arena.take() };
    }

    FastPathOutcome::Miss {
        info: fast_info,
        probe,
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
    probe: crate::cache::CacheProbe,
    pre_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<Option<Bytes>> {
    let mut info = match dns::parse_query_from_fast(&packet, fast_info, probe.variant) {
        Ok(info) => info,
        Err(_) => return Ok(None),
    };
    // Reuse the cache key(s) the fast-path probe already computed, so the slow
    // path doesn't recompute the key-tail hash for singleflight / cache write.
    info.precomputed_cache_keys = Some((probe.regular_key, probe.stripped_key));
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

async fn resolve_query(mut ctx: QueryContext, state: &Arc<AppState>) -> Result<Option<Bytes>> {
    let hot = state.hot.load_full();
    // Borrowed straight out of the held `hot` snapshot — cloning the Arc here
    // was a per-query refcount round-trip for a reference the snapshot already
    // guarantees alive.
    let ruleset = if hot.needs_ruleset {
        hot.ruleset.as_deref()
    } else {
        None
    };

    // The qname *string* is only needed if a consumer downstream reads it: a
    // cache store keeps it on the entry, and a querylog event logs it. Routing
    // itself needs it only when the decision is name-dependent (below). When
    // none of these hold — a constant-route, cache-off, querylog-off forward —
    // the string is never built, saving an allocation per query.
    let need_qname_downstream = state.cache.is_enabled() || state.querylog.collecting();

    let target = match hot.routing_index.constant_target() {
        // Routing is constant: no qname needed to pick the target.
        Some(constant) => {
            if need_qname_downstream {
                ctx.ensure_qname();
            }
            match constant {
                Some(idx) => match hot.rules.get(idx) {
                    Some(rule) => rule.target(),
                    None => router::classify_target(&hot, ctx.info.qtype),
                },
                None => router::classify_target(&hot, ctx.info.qtype),
            }
        }
        // Name-dependent routing: materialize the qname and match on it.
        None => {
            let qname = ctx.ensure_qname().clone();
            match hot.routing_index.route(&hot.rules, &qname, ruleset) {
                Some(rule) => rule.target(),
                None => router::classify_target(&hot, ctx.info.qtype),
            }
        }
    };
    exchange_with_dedupe(ctx, state, &hot, ruleset, target).await
}

/// Run the appropriate upstream exchange for a given route target.
/// Extracted so it can be pinned and raced against a timeout.
///
/// Returns the winning server's index alongside the response when `target` is a
/// `route.final` `Race`/`CidrTest` fallback (so callers can report/cache against
/// whichever of primary/secondary actually answered, e.g. `"final->domestic-dns"`).
/// `None` for a plain `RouteTarget::Rule`/`Server`, since the caller already knows its identity.
async fn do_upstream_exchange(
    ctx: &QueryContext,
    state: &Arc<AppState>,
    hot: &HotState,
    target: &RouteTarget<'_>,
) -> Result<(Bytes, Option<usize>)> {
    match target {
        RouteTarget::Race { primary, secondary } => race(
            ctx.packet.clone(),
            ctx.info.question_end,
            ctx.info.qtype,
            ctx.info.id,
            ctx.proto,
            primary,
            secondary,
        )
        .await
        .map(|(b, idx)| (b, Some(idx))),
        RouteTarget::CidrTest { primary, secondary } => resolve_none_rule_with_cidr(
            ctx.packet.clone(),
            &ctx.info,
            ctx.proto,
            primary,
            secondary,
            state,
            hot,
        )
        .await
        .map(|(b, idx)| (b, Some(idx))),
        RouteTarget::Rule(rule, _) => exchange_kind(
            ctx.packet.clone(),
            ctx.info.question_end,
            ctx.info.qtype,
            ctx.info.id,
            ctx.proto,
            &rule.kind,
        )
        .await
        .map(|b| (b, None)),
        RouteTarget::Server(s, _) => exchange_kind(
            ctx.packet.clone(),
            ctx.info.question_end,
            ctx.info.qtype,
            ctx.info.id,
            ctx.proto,
            &s.kind,
        )
        .await
        .map(|b| (b, None)),
    }
}

/// Resolve one `ServerKind`: a real exchange against its upstream pool, or a
/// local synthesis for a fixed answer (no network I/O, never fails).
async fn exchange_kind(
    packet: Bytes,
    question_end: usize,
    qtype: u16,
    client_id: u16,
    client_proto: ClientProto,
    kind: &crate::server::ServerKind,
) -> Result<Bytes> {
    match kind {
        crate::server::ServerKind::Upstream(pool) => {
            pool.exchange_observed(packet, client_id, client_proto)
                .await
        }
        crate::server::ServerKind::Fixed(set) => {
            synth_fixed_answer(&packet, question_end, qtype, set)
        }
    }
}

/// Synthesise a response for a fixed-answer `route.servers` entry: A/AAAA
/// records, or an RCODE/empty reply. Mirrors the DNS-record-building the old
/// `route.answer` map used, minus CNAME (dropped — see `FixedAnswer`).
fn synth_fixed_answer(
    packet: &[u8],
    question_end: usize,
    qtype: u16,
    set: &crate::config::FixedAnswerSet,
) -> Result<Bytes> {
    if !set.answers.is_empty() {
        let mut a: Option<(std::net::Ipv4Addr, u32)> = None;
        let mut aaaa: Option<(std::net::Ipv6Addr, u32)> = None;
        for fa in &set.answers {
            match fa {
                FixedAnswer::A(addr, ttl) => a = Some((*addr, *ttl)),
                FixedAnswer::Aaaa(addr, ttl) => aaaa = Some((*addr, *ttl)),
            }
        }
        return match (qtype, a, aaaa) {
            (1, Some((addr, ttl)), _) => {
                dns::a_reply(packet, question_end, addr, ttl).map(Bytes::from)
            }
            (28, _, Some((addr, ttl))) => {
                dns::aaaa_reply(packet, question_end, addr, ttl).map(Bytes::from)
            }
            _ => dns::empty_reply(packet, question_end).map(Bytes::from),
        };
    }
    // RCODE entry.
    let rcode = set.rcode.unwrap_or(0);
    if rcode == 0 {
        dns::empty_reply(packet, question_end).map(Bytes::from)
    } else {
        dns::rcode_reply(packet, question_end, rcode).map(Bytes::from)
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
    // Reuse the EDNS variant the fast path already parsed while checking the
    // cache (see `dns::QueryInfo::variant`) for cache-key selection and the
    // strip-mode cache-write decision, instead of re-parsing it here.
    let variant = ctx.info.variant;
    let ecs_in_query = target.strip_ecs() && variant.ecs_src.is_some();
    // Reuse the key the fast-path probe already computed for this exact
    // (query, variant, strip) combination; recompute only if this query didn't
    // come through the fast-path miss route (then `precomputed_cache_keys` is
    // None). When `ecs_in_query`, the probe necessarily computed the stripped
    // key, so the `regular_key` fallback below is never taken in that arm.
    let ck = match ctx.info.precomputed_cache_keys {
        Some((regular_key, stripped_key)) => {
            if ecs_in_query {
                stripped_key.unwrap_or(regular_key)
            } else {
                regular_key
            }
        }
        None => cache_key_with_variant_from_qname_hash(
            &ctx.packet,
            ctx.info.question_end,
            ctx.info.qname_wire_hash,
            ctx.info.qname_wire_hash_end,
            &variant,
            ecs_in_query,
        ),
    };
    // Mix routing generation into the singleflight key so followers from a previous
    // routing generation do not join an in-flight request for a different route target.
    let sf_ck = ck ^ routing_gen.wrapping_mul(0x9e3779b97f4a7c15);
    let waiter = singleflight::register(&state.remote_inflight, sf_ck)?;

    if let Some(rx) = waiter {
        // Bound the follower wait so a panicking leader never leaves clients hung
        // forever. Must cover the leader's actual worst case, not just one bare
        // `cfg.timeout`: a hedged exchange can run `hedge_delay` before even
        // starting its (fully re-timed-out) second upstream, and a `rule.filter`'s
        // `forward` action adds one more full exchange (`MAX_EXCHANGES_PER_QUERY`).
        // Undershooting this just means followers occasionally get a spurious
        // SERVFAIL for a query the leader was about to answer correctly — this
        // only pads the panic-safety fallback, so erring generous costs nothing
        // in the (overwhelmingly common) case where the leader finishes well
        // before it.
        // Reuse the same `hot` snapshot the caller took `routing_gen`/`sf_ck` from,
        // rather than an independent `state.hot.load()` here: a concurrent
        // hot-reload between the two reads could otherwise pair this generation's
        // routing_gen with a *different* generation's `cfg.timeout`/`hedge_delay`.
        let cfg = &hot.cfg;
        let deadline = cfg.timeout * MAX_EXCHANGES_PER_QUERY
            + cfg.hedge_delay.unwrap_or_default()
            + Duration::from_secs(1);
        let published = match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(published)) => published,
            // Covers both Err(_timeout) and Ok(Err(_)) — the leader was removed
            // without publishing (upstream error or cancellation); only this
            // path needs a synthesized SERVFAIL, so it's built here instead of
            // unconditionally before the timeout on the common success path.
            _ => {
                let servfail = Bytes::from(
                    dns::servfail_reply(&ctx.packet, ctx.info.question_end).unwrap_or_default(),
                );
                let elapsed = started.elapsed().as_micros() as u64;
                record_client_latency(state, elapsed);
                record_singleflight_hit(state);
                emit_slow_event(
                    &ctx,
                    state,
                    &servfail,
                    "singleflight",
                    Some(target.upstream_name_arc()),
                    elapsed,
                );
                return Ok(Some(servfail));
            }
        };
        let Some(resp) = published else {
            // The leader's rule filter decided to drop this query (not an error);
            // followers get the same outcome instead of a synthesized SERVFAIL.
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(state, elapsed);
            record_singleflight_hit(state);
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
            record_client_latency(state, elapsed);
            record_singleflight_hit(state);
            emit_slow_event(
                &ctx,
                state,
                &servfail,
                "singleflight",
                Some(target.upstream_name_arc()),
                elapsed,
            );
            return Ok(Some(servfail));
        }
        let mut resp = BytesMut::from(resp.as_ref());
        dns::set_id(&mut resp, ctx.info.id)?;
        // Restore the client's original letter case (some upstreams normalise it).
        resp[12..ctx.info.question_end].copy_from_slice(ctx.question());
        let resp = resp.freeze();
        record_client_latency(state, elapsed);
        record_singleflight_hit(state);
        emit_slow_event(
            &ctx,
            state,
            &resp,
            "singleflight",
            Some(target.upstream_name_arc()),
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

    // Drive the rule's filter chain (if any; fires its `add-ip` side effect
    // inline on an `accept` match, or hops once to another server's upstream
    // via `forward`); `target` on return is whichever rule ultimately produced
    // the outcome, and governs cache policy/logging below.
    let (result, target) = resolve_with_filters(&ctx, state, hot, ruleset, target).await;
    let skip_cache = target.skip_cache();
    let upstream_name = target.upstream_name();
    let upstream_arc = target.upstream_name_arc();

    match result {
        Ok(StepOutcome::Response(resp, source, winner_idx, forwarded_idx)) => {
            // For a route.final Race/CidrTest fallback, the winning server (whichever of
            // primary/secondary actually answered) reports/caches as "final->{name}"
            // instead of the generic "final".
            let winner_server = winner_idx.and_then(|idx| hot.servers.get(idx));
            let upstream_arc =
                winner_server.map_or_else(|| upstream_arc.clone(), |s| s.final_name_arc.clone());
            // Skip cache write if the routing generation advanced (ruleset hot-reload cleared
            // the cache between when we started the query and when the response arrived).
            // Also gated on the cache being configured at all, so a cache-off forward
            // neither builds a `CacheInsert` nor materializes the qname it carries.
            if !skip_cache && state.cache.is_enabled() && state.hot_generation() == routing_gen {
                let (mut cache_policy, attribution) = match (&target, winner_server) {
                    (RouteTarget::Rule(rule, idx), _) => {
                        (rule.cache_policy, RuleAttribution::Rule(*idx))
                    }
                    (RouteTarget::Server(_, idx), _) => (
                        state.cache.resolve_policy(None),
                        RuleAttribution::Final(*idx),
                    ),
                    (_, Some(w)) => (
                        state.cache.resolve_policy(None),
                        RuleAttribution::Final(w.index),
                    ),
                    // Winner not known (e.g. race tie-break fallback): sentinel so cache
                    // hits show the generic "final".
                    (_, None) => (
                        state.cache.resolve_policy(None),
                        RuleAttribution::FinalUnknown,
                    ),
                };
                // A fixed `RCODE://` server (no A/AAAA records, so nothing in the
                // packet carries a TTL) caches its response for its own `?ttl=`
                // instead of the usual nodata TTL (always 0 — see
                // `CacheHandle::resolve_policy`), still clamped by whatever
                // min-ttl/max-ttl otherwise applies. An `A://`/`AAAA://` entry needs
                // no such override: its record's TTL is already in the packet and
                // read normally by `effective_ttl_and_offsets`.
                //
                // A `rule.filter`'s `forward` action still credits/caches under the
                // *original* matched rule (see `resolve_with_filters`'s doc comment),
                // so `target.resolved_kind` would report the original rule's kind, not
                // the forward target's — `forwarded_idx` (set only for "forwarded")
                // is consulted first to get the kind that was actually queried.
                let fixed_kind = match forwarded_idx.and_then(|idx| hot.servers.get(idx)) {
                    Some(s) => Some(&s.kind),
                    None => target.resolved_kind(winner_server),
                };
                if let Some(crate::server::ServerKind::Fixed(set)) = fixed_kind {
                    if set.answers.is_empty() {
                        cache_policy.nodata_ttl = set.rcode_ttl;
                    }
                }
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
                        qname: ctx.qname_owned(),
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
            // `resp` is uniquely owned here (only borrowed above), so `BytesMut::from`
            // takes it by value for a zero-copy conversion instead of a full memcpy.
            let mut resp_mut = BytesMut::from(resp);
            resp_mut[12..ctx.info.question_end].copy_from_slice(ctx.question());
            let resp = resp_mut.freeze();
            singleflight::publish_bytes(&state.remote_inflight, &sf_ck, resp.clone());
            _leader.published = true;
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(state, elapsed);
            state
                .querylog
                .counters
                .upstream_ok
                .fetch_add(1, Ordering::Relaxed);
            emit_slow_event(&ctx, state, &resp, source, Some(upstream_arc), elapsed);
            Ok(Some(resp))
        }
        Ok(StepOutcome::Drop) => {
            singleflight::publish_drop(&state.remote_inflight, &sf_ck);
            _leader.published = true;
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(state, elapsed);
            state
                .querylog
                .counters
                .filtered
                .fetch_add(1, Ordering::Relaxed);
            emit_slow_event(
                &ctx,
                state,
                &Bytes::new(),
                "filtered",
                Some(upstream_arc),
                elapsed,
            );
            Ok(None)
        }
        Err(err) => {
            crate::warn_rate_limited!(
                &UPSTREAM_FAIL_LAST_WARN,
                10,
                "dns event=upstream_failed target={} error={err:#}",
                upstream_name
            );
            let servfail = match dns::servfail_reply(&query_for_cache, ctx.info.question_end) {
                Ok(pkt) => pkt,
                Err(_) => return Err(err),
            };
            let servfail = Bytes::from(servfail);
            singleflight::publish_bytes(&state.remote_inflight, &sf_ck, servfail.clone());
            _leader.published = true;
            let elapsed = started.elapsed().as_micros() as u64;
            record_client_latency(state, elapsed);
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
            emit_slow_event(
                &ctx,
                state,
                &servfail,
                "upstream",
                Some(upstream_arc),
                elapsed,
            );
            Ok(Some(servfail))
        }
    }
}

/// Worst-case upstream exchanges a single query can trigger: the initial one,
/// plus at most one more if a `rule.filter`'s `forward` action fires. Used only
/// to size the singleflight follower deadline below.
const MAX_EXCHANGES_PER_QUERY: u32 = 2;

/// Outcome of driving a rule (and its `filter`, if any) to completion.
enum StepOutcome {
    /// A response to send/cache, tagged with the querylog `source` to report, plus:
    /// - the winning rule's index when this came from a `route.final` `Race`/
    ///   `CidrTest` fallback (`None` for a plain rule match, `forward`, or an
    ///   `accept` response — those already have a definite rule identity via
    ///   `target`);
    /// - the target server's index when this came from a `rule.filter`'s
    ///   `forward` action (`None` otherwise). Kept separate from the winner
    ///   index above: `forward` still credits/caches under the *original*
    ///   matched rule's identity (see `resolve_with_filters`'s doc comment),
    ///   but the cache-policy computation still needs to know which server
    ///   was actually queried, so a fixed (`RCODE://`) forward target's own
    ///   TTL is honored instead of the original rule's.
    Response(Bytes, &'static str, Option<usize>, Option<usize>),
    /// The rule's filter chain decided to send no reply at all.
    Drop,
}

/// Drive one target through its rule's `filter` chain (if any): every filter
/// dimension is evaluated against the resolved response (see `crate::response_filter`
/// docs), so this always queries upstream via `do_upstream_exchange` first.
///
/// `forward` answers directly from another rule's upstream without changing
/// `target`'s identity, so caching/logging still credit the rule that actually
/// matched via routing. `accept` returns the response as-is, firing its
/// `add-ip` side effect (if this filter entry has one) first.
///
/// Returns the final `target` alongside the result so the caller can report/cache
/// against whichever rule produced the outcome.
async fn resolve_with_filters<'a>(
    ctx: &QueryContext,
    state: &Arc<AppState>,
    hot: &'a HotState,
    ruleset: Option<&crate::ruleset::RuleSetDb>,
    target: RouteTarget<'a>,
) -> (Result<StepOutcome>, RouteTarget<'a>) {
    use crate::response_filter::FilterAction;

    let (resp, winner_idx) = match do_upstream_exchange(ctx, state, hot, &target).await {
        Ok(r) => r,
        Err(e) => return (Err(e), target),
    };

    if let RouteTarget::Rule(rule, idx) = target {
        if let Some((filter_idx, filter)) = crate::response_filter::first_match(
            &rule.filters,
            ruleset,
            &resp,
            ctx.info.question_end,
        ) {
            match filter.action {
                FilterAction::Drop => return (Ok(StepOutcome::Drop), target),
                FilterAction::Forward(target_idx) => {
                    // Bypasses rule-level routing/filters entirely — straight to
                    // the named server's upstream. Caching/logging still credit
                    // the original rule (see this function's doc comment above),
                    // but `target_idx` is threaded through so the caller can
                    // still honor a fixed (`RCODE://`) forward target's own TTL.
                    let forward_target = RouteTarget::Server(&hot.servers[target_idx], target_idx);
                    let fresp = do_upstream_exchange(ctx, state, hot, &forward_target).await;
                    return (
                        fresp.map(|(b, _)| {
                            StepOutcome::Response(b, "forwarded", None, Some(target_idx))
                        }),
                        target,
                    );
                }
                FilterAction::Accept => {
                    if let Some(ipset) = &state.ipset {
                        let ips = dns::answer_ips(&resp, ctx.info.question_end);
                        if !ips.is_empty() {
                            ipset.add_filter_ips(idx, filter_idx, &ips);
                        }
                    }
                }
            }
        }
    }

    (
        Ok(StepOutcome::Response(resp, "upstream", winner_idx, None)),
        target,
    )
}

#[inline]
fn record_client_latency(state: &AppState, elapsed_us: u64) {
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

fn record_singleflight_hit(state: &AppState) {
    state
        .querylog
        .counters
        .singleflight_hits
        .fetch_add(1, Ordering::Relaxed);
}

fn emit_slow_event(
    ctx: &QueryContext,
    state: &AppState,
    resp: &Bytes,
    source: &'static str,
    upstream: Option<Arc<str>>,
    elapsed_us: u64,
) {
    let peer = ctx.peer;
    let ql = &state.querylog;
    if !ql.collecting() {
        return;
    }
    ql.try_emit_with(|seq| crate::querylog::QueryLogEvent {
        seq,
        unix_micros: crate::querylog::unix_micros_now(),
        client: peer.ip(),
        client_port: peer.port(),
        qname: ctx.qname_owned(),
        qtype: ctx.info.qtype,
        rcode: dns::rcode(resp),
        elapsed_us,
        response_bytes: resp.len() as u32,
        source,
        upstream,
    });
}

/// Race primary and secondary servers.
///
/// A non-SERVFAIL response wins immediately. If the first responder returns SERVFAIL
/// or a network error, we wait for the other side: a clean response there wins, otherwise
/// we prefer any SERVFAIL over a raw network error, and only return `Err` if both sides
/// failed with network errors.
///
/// Returns the winning server's index alongside the response, so callers can report the
/// query log's `upstream` as `"final->{name}"` instead of the generic `"final"`.
async fn race(
    packet: Bytes,
    question_end: usize,
    qtype: u16,
    client_id: u16,
    client_proto: ClientProto,
    primary: &Server,
    secondary: &Server,
) -> Result<(Bytes, usize)> {
    let primary_fut = exchange_kind(
        packet.clone(),
        question_end,
        qtype,
        client_id,
        client_proto,
        &primary.kind,
    );
    let secondary_fut = exchange_kind(
        packet,
        question_end,
        qtype,
        client_id,
        client_proto,
        &secondary.kind,
    );
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

#[allow(clippy::too_many_arguments)]
async fn resolve_none_rule_with_cidr(
    packet: Bytes,
    info: &dns::QueryInfo,
    client_proto: ClientProto,
    primary: &Server,
    secondary: &Server,
    state: &Arc<AppState>,
    // The caller's own `HotState` snapshot (kept alive across this whole call),
    // so `answer_ip`/`ruleset`/`generation` all come from the same generation
    // as every other decision made for this query — and this function does not
    // pay a second `load_full` (atomic load + Arc refcount round-trip) plus a
    // ruleset Arc clone per CIDR-fallback query.
    hot: &HotState,
) -> Result<(Bytes, usize)> {
    let answer_ip: Option<&crate::config::AnswerIpMatcher> = match &hot.cfg.fallback.target {
        FallbackTarget::Dual { answer_ip, .. } if !answer_ip.is_empty() => Some(answer_ip),
        _ => None,
    };
    let (Some(answer_ip), Some(ruleset)) = (answer_ip, hot.ruleset.as_deref()) else {
        return race(
            packet,
            info.question_end,
            info.qtype,
            info.id,
            client_proto,
            primary,
            secondary,
        )
        .await;
    };
    // Captured before any upstream I/O so a verdict write below can be skipped if a
    // hot-reload invalidates the verdict cache while this query is still in flight
    // (mirrors the same guard the DNS response cache uses in `exchange_with_dedupe`).
    let routing_gen = hot.generation;

    // This path is only reached for a `CidrTest` rule target, i.e. name-dependent
    // routing, so `resolve_query` already materialized the qname. Fall back to
    // materializing from the packet defensively (keeps the verdict cache keyed
    // correctly without an unwrap if that invariant ever changes).
    let qname = info.qname.clone().unwrap_or_else(|| {
        dns::qname_from_question(&packet, info.question_end).unwrap_or_else(|_| Arc::from(""))
    });

    if let Some(is_primary_domain) = state.verdict_cache.get(&qname) {
        return if is_primary_domain {
            exchange_kind(
                packet,
                info.question_end,
                info.qtype,
                info.id,
                client_proto,
                &primary.kind,
            )
            .await
            .map(|b| (b, primary.index))
        } else {
            exchange_kind(
                packet,
                info.question_end,
                info.qtype,
                info.id,
                client_proto,
                &secondary.kind,
            )
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
    let primary_query = exchange_kind(
        primary_packet,
        info.question_end,
        info.qtype,
        info.id,
        client_proto,
        &primary.kind,
    );
    let secondary_query = exchange_kind(
        secondary_packet,
        info.question_end,
        info.qtype,
        info.id,
        client_proto,
        &secondary.kind,
    );
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
            let is_primary_ip = ruleset.matches_answer_ip(answer_ip, &ips);
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
                    state.verdict_cache.add(&qname, true);
                }
                // Decision is "use primary"; the secondary's answer is not
                // needed, so return now and let its in-flight query be dropped.
                return Ok((resp, primary.index));
            } else if routing_unchanged {
                state.verdict_cache.add(&qname, false);
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

#[cfg(test)]
mod tests {
    use super::RuleAttribution;

    /// The packed `u16` stored in the cache (and in the persisted cache file)
    /// must decode back to exactly the attribution that was encoded — the
    /// querylog `upstream` column for cache hits, and the ipset/nftset restore
    /// at startup, both depend on this roundtrip.
    #[test]
    fn rule_attribution_wire_roundtrip() {
        // 32765 is the largest server index that roundtrips: the top two
        // flagged encodings are reserved for the FinalUnknown/None sentinels
        // (see FINAL_FLAG's doc comment). Rule indexes roundtrip up to 32767.
        for idx in [0usize, 1, 7, 1000, 32765] {
            match RuleAttribution::from_wire(RuleAttribution::Rule(idx).to_wire()) {
                RuleAttribution::Rule(decoded) => assert_eq!(decoded, idx),
                _ => panic!("Rule({idx}) did not roundtrip"),
            }
        }
        for idx in [0usize, 1, 7, 1000, 32765] {
            match RuleAttribution::from_wire(RuleAttribution::Final(idx).to_wire()) {
                RuleAttribution::Final(decoded) => assert_eq!(decoded, idx),
                _ => panic!("Final({idx}) did not roundtrip"),
            }
        }
        assert!(matches!(
            RuleAttribution::from_wire(RuleAttribution::FinalUnknown.to_wire()),
            RuleAttribution::FinalUnknown
        ));
        // u16::MAX is the legacy "no rule" sentinel persisted by older cache
        // files; it must keep decoding to None, and the other sentinels must
        // never collide with it.
        assert!(matches!(
            RuleAttribution::from_wire(u16::MAX),
            RuleAttribution::None
        ));
        assert_ne!(RuleAttribution::FinalUnknown.to_wire(), u16::MAX);
    }
}
