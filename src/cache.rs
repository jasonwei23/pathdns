//! DNS response cache with RFC-compliant TTL management.
//!
//! Entries are keyed by the complete query semantics except the client ID.
//! QNAME label bytes are normalised to ASCII lowercase, while header flags and
//! additional records remain exact so ECS, DNSSEC, COOKIE, and similar variants
//! cannot share answers accidentally.
//!
//! On a cache hit, TTLs in the response packet are patched in-place to reflect remaining time.
//!
//! RFC semantics implemented:
//! - Normal responses: minimum TTL across all answer RRs (CNAME chains included).
//! - NODATA / NXDOMAIN: `min(SOA_TTL, SOA_MINIMUM)` from the authority section (RFC 2308).
//! - SERVFAIL (RCODE 2): never cached.
//! - Truncated responses (TC bit): never cached.
//! - OPT records (type 41): excluded from TTL patching (EDNS version field, not TTL).
//!
//! The cache is a plain fresh-or-miss cache: a lookup returns a hit only while the entry
//! is still fresh (`age < ttl`); expired entries are evicted and treated as a miss.

use crate::config::{CacheConfig, RuleCachePolicy};
use crate::dns;
use crate::hasher::Fnv1a;
use crate::persist::{atomic_write, read_bytes, read_u16, read_u32, read_u64};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::UnitWeighter;
use rustc_hash::FxBuildHasher;
use std::io::{BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type CacheKey = u64;

/// Hash a complete DNS query excluding its two-byte client ID, using a
/// pre-computed [`dns::QueryVariant`].
///
/// The hash covers:
/// - QNAME (ASCII-lowercased, self-delimiting label encoding)
/// - QTYPE + QCLASS (exact)
/// - EDNS semantics from the variant: RD/AD/CD flags, has_opt, DO bit, EDNS
///   version, and normalised ECS source subnet.
///
/// Raw additional-section bytes are NOT hashed so that semantically equivalent
/// queries with different OPT padding, unknown EDNS options, or varying ARCOUNT
/// always share the same cache entry.
///
/// Test-only reference implementation: every production lookup goes through
/// `cache_key_with_variant_from_qname_hash`, resuming from the QNAME hash
/// `dns::parse_query_fast` computed during query validation. This standalone
/// version hashes fresh from the wire bytes via `Fnv1a::write_qname_wire`, and
/// the equivalence tests below pin the two to always agree.
#[cfg(test)]
pub(crate) fn cache_key_with_variant(
    query: &[u8],
    question_end: usize,
    v: &dns::QueryVariant,
    strip_ecs: bool,
) -> CacheKey {
    if query.len() < 12 || question_end < 16 || question_end > query.len() {
        return invalid_shape_key(query, question_end);
    }
    let question = &query[12..question_end];
    let mut h = Fnv1a::new();
    let pos = h.write_qname_wire(question);
    finish_cache_key(h, question, pos, v, strip_ecs)
}

/// Same key as `cache_key_with_variant` would compute for this exact query,
/// but resumes from a QNAME hash already computed elsewhere instead of
/// re-hashing the QNAME bytes — used on the slow path (after
/// `dns::query::qname_from_question` has already produced one as a byproduct
/// of building the routing qname) to avoid a second scan+lowercase pass over
/// the same bytes.
///
/// `qname_hash`/`qname_hash_end` must have come from `QueryInfo` for this
/// exact `query`/`question_end` — they must not be reused across a different
/// query, and (like `Fnv1a::write_qname_wire`, which they mirror) are not
/// re-validated here. `cache::tests` pins the two code paths to always
/// produce identical keys for the same bytes.
pub(crate) fn cache_key_with_variant_from_qname_hash(
    query: &[u8],
    question_end: usize,
    qname_hash: Fnv1a,
    qname_hash_end: usize,
    v: &dns::QueryVariant,
    strip_ecs: bool,
) -> CacheKey {
    if query.len() < 12 || question_end < 16 || question_end > query.len() {
        // A qname_hash computed against a shape this function no longer
        // trusts isn't reusable; fall back exactly like cache_key_with_variant.
        return invalid_shape_key(query, question_end);
    }
    let question = &query[12..question_end];
    finish_cache_key(qname_hash, question, qname_hash_end, v, strip_ecs)
}

/// Shared fallback for the "caller skipped validation" shape check in both
/// `cache_key_with_variant` and `cache_key_with_variant_from_qname_hash`.
///
/// Every validated caller (resolver.rs's query-parsing path) already
/// guarantees the checked shape; reaching here means some caller skipped that
/// validation. Hash the raw bytes we do have instead of falling back to a
/// constant — a fixed hash would silently collapse every such query onto one
/// shared cache slot, letting unrelated malformed queries share answers. This
/// keeps the property "different input -> different slot" even in this
/// should-never-happen path.
fn invalid_shape_key(query: &[u8], question_end: usize) -> CacheKey {
    debug_assert!(
        false,
        "cache_key_with_variant: invalid query/question_end shape (len={}, question_end={question_end})",
        query.len()
    );
    let mut h = Fnv1a::new();
    h.write(query);
    h.write_sep();
    h.write(&question_end.to_le_bytes());
    h.finish()
}

/// Shared tail: QTYPE/QCLASS + EDNS semantics, appended after the QNAME
/// portion (`pos_after_qname`, the offset in `question` just past it) has
/// already been hashed into `h` by either caller above.
fn finish_cache_key(
    mut h: Fnv1a,
    question: &[u8],
    pos_after_qname: usize,
    v: &dns::QueryVariant,
    strip_ecs: bool,
) -> CacheKey {
    // QTYPE + QCLASS — exact match required.
    h.write(question.get(pos_after_qname..).unwrap_or(&[]));

    // EDNS semantics from pre-computed variant.
    h.write_byte(v.has_opt as u8);
    h.write_byte(v.do_bit as u8);
    h.write_byte(v.edns_version);
    h.write_byte(v.rd as u8);
    h.write_byte(v.ad as u8);
    h.write_byte(v.cd as u8);
    if strip_ecs {
        // Always hash 0 for ECS so all clients share one entry regardless of subnet.
        h.write_byte(0);
    } else {
        match v.ecs_src {
            None => h.write_byte(0),
            Some(ecs) => {
                h.write_byte(1);
                h.write(&ecs.addr);
                h.write_byte(ecs.prefix_len);
            }
        }
    }
    // Include the hash of any non-ECS/non-PADDING EDNS option codes (COOKIE, NSID, …)
    // so queries with different option sets do not share a cache entry.
    h.write(&v.extra_opts_hash.to_le_bytes());

    h.finish()
}

#[derive(Debug)]
struct Entry {
    packet: Bytes,
    query: Bytes,
    qname: Arc<str>,
    /// Byte offset of the first byte past the question section in `query`.
    /// Stored instead of a separate question copy: saves one Arc + data allocation per entry.
    question_end: usize,
    /// Pre-computed EDNS variant for `query`. Eliminates one `extract_variant` parse per cache
    /// hit when used in `queries_match_v` / `queries_match_strip_ecs_v`.
    variant: dns::QueryVariant,
    inserted: Instant,
    /// Effective TTL (clamped by per-rule or global min/max at write time).
    ttl: u32,
    /// Per-RR `(ttl_byte_offset_in_packet, original_clamped_ttl)` pairs.
    /// u32 offsets fit DNS packets (≤ 65535 bytes) and halve per-pair size vs (usize, u32).
    ttl_offsets: Arc<[(u32, u32)]>,
    /// Index of the routing rule that cached this entry (u16::MAX = unknown / loaded from disk).
    rule_id: u16,
}

/// Metadata returned from `get_into`; the packet bytes are written into the caller's buffer.
#[derive(Debug, Clone)]
pub struct CacheLookupMeta {
    /// The entry's qname — populated only when the caller asked for it
    /// (`collect_qname`, i.e. the querylog is collecting detailed events).
    /// An `Arc` clone is a shared refcount RMW pair; on the warm-hit path
    /// with logging off it was pure waste.
    pub qname: Option<Arc<str>>,
    /// Index of the rule that originally cached this entry (u16::MAX = unknown).
    pub rule_id: u16,
}

struct KeyedLookup<'a> {
    key: CacheKey,
    query: &'a [u8],
    question_end: usize,
    client_id: u16,
    strip_ecs: bool,
    variant: &'a dns::QueryVariant,
    /// Clone the entry's qname into the result (see `CacheLookupMeta::qname`).
    collect_qname: bool,
}

/// Byproducts of a cache probe (`get_into_with_ecs_fallback`) that the slow
/// path reuses on a miss: the parsed EDNS variant and the cache key(s) already
/// computed here, so `exchange_with_dedupe` neither re-parses the additional
/// section nor recomputes the key-tail hash.
#[derive(Debug, Clone)]
pub struct CacheProbe {
    /// The query's EDNS variant, parsed once during the probe.
    pub variant: dns::QueryVariant,
    /// Cache key with ECS included (`strip_ecs = false`). Always computed.
    pub regular_key: CacheKey,
    /// Cache key with ECS stripped (`strip_ecs = true`). `Some` only when the
    /// query carried ECS *and* the regular key missed (so the probe computed
    /// it); `None` otherwise.
    pub stripped_key: Option<CacheKey>,
}

/// Per-rule cache policy with global defaults already merged in.
///
/// Computed once at startup via [`DnsCache::resolve_policy`]; the insert path reads
/// plain fields instead of walking six `Option` chains per cached response.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolvedCachePolicy {
    /// Bypass the cache entirely for this rule.
    pub skip: bool,
    pub(crate) nodata_ttl: u32,
    pub(crate) min_ttl: u32,
    pub(crate) max_ttl: u32,
}

/// Context for a cache insert: the response packet plus the query it answers.
///
/// `query` is an owned `Bytes` (not borrowed) and `variant` is the caller's
/// already-computed [`dns::QueryVariant`] for it, so `DnsCache::add` neither
/// copies the query bytes nor re-parses EDNS/ECS from them — both were true
/// costs paid on every cacheable query before every caller already held (or
/// could cheaply produce) both values themselves.
pub struct CacheInsert<'a> {
    pub key: CacheKey,
    pub qname: Arc<str>,
    pub question_end: usize,
    pub query: Bytes,
    pub variant: dns::QueryVariant,
    pub packet: &'a [u8],
}

#[derive(Debug)]
pub struct DnsCache {
    // `CacheKey` is already a well-mixed FNV1a hash (see `cache_key_with_variant`), so
    // hashing it again through the cache's default hasher on every get/insert is pure
    // overhead. `FxBuildHasher` is the same fast, non-cryptographic hasher already used
    // for the singleflight/inflight sharded maps for the same reason.
    cache: Option<Cache<CacheKey, Arc<Entry>, UnitWeighter, FxBuildHasher>>,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(cfg: &CacheConfig) -> Self {
        // Unweighted (each entry weighs 1), so `weight_capacity` is the entry-count
        // cap (a plain entry-count limit). TTL is enforced by
        // pathdns on read/insert, not by the map, so no expiry backend is needed.
        let cache = (cfg.capacity > 0).then(|| {
            Cache::with(
                cfg.capacity,
                cfg.capacity as u64,
                UnitWeighter,
                FxBuildHasher,
                DefaultLifecycle::default(),
            )
        });
        Self {
            cache,
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl,
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.as_ref().map(|c| c.len() as u64).unwrap_or(0)
    }

    /// Whether a response cache is configured at all (`cache.size > 0`). When
    /// false, `add` is a no-op and the resolver skips building a `CacheInsert`
    /// (and materializing the qname it would carry) entirely.
    pub fn is_enabled(&self) -> bool {
        self.cache.is_some()
    }

    pub fn capacity(&self) -> u64 {
        self.cache.as_ref().map(|c| c.capacity()).unwrap_or(0)
    }

    /// Try regular lookup first; if that misses and the query has an ECS option,
    /// retry with the ECS-stripped cache key and relaxed variant matching.
    /// This lets a strip-mode rule serve all clients from one shared cache entry.
    ///
    /// Parses the EDNS variant once and reuses it for both the key derivation and the
    /// ECS-fallback check, avoiding redundant additional-section scans. The variant is
    /// also handed back to the caller (alongside a hit, or on a miss) so the slow path
    /// can reuse it instead of re-parsing the same query a second time.
    ///
    /// Takes the whole [`dns::FastQueryInfo`] rather than individual fields:
    /// both cache keys resume from `fast.qname_wire_hash`, the QNAME hash
    /// `dns::parse_query_fast` produced during its validation walk, so the
    /// QNAME bytes are never scanned a second time here.
    ///
    /// Returns a [`CacheProbe`] carrying the parsed variant and the cache
    /// key(s) computed here, so a subsequent cache miss reuses them (for
    /// singleflight and the eventual cache write) instead of recomputing the
    /// key-tail hash in the slow path — see `CacheProbe::key_for`.
    pub fn get_into_with_ecs_fallback(
        &self,
        query: &[u8],
        fast: &dns::FastQueryInfo,
        out: &mut BytesMut,
        collect_qname: bool,
    ) -> (Option<CacheLookupMeta>, CacheProbe) {
        let question_end = fast.question_end;
        let live_v = dns::extract_variant(query, question_end);
        let regular_key = cache_key_with_variant_from_qname_hash(
            query,
            question_end,
            fast.qname_wire_hash,
            fast.qname_wire_hash_end,
            &live_v,
            false,
        );
        if let Some(hit) = self.lookup_into_keyed(
            KeyedLookup {
                key: regular_key,
                query,
                question_end,
                client_id: fast.id,
                strip_ecs: false,
                variant: &live_v,
                collect_qname,
            },
            out,
        ) {
            let probe = CacheProbe {
                variant: live_v,
                regular_key,
                // Not needed on a hit; the slow path isn't reached.
                stripped_key: None,
            };
            return (Some(hit), probe);
        }
        // Miss on the regular key. If the query carries ECS, also probe the
        // ECS-stripped key (and remember it for the slow path to reuse).
        let mut stripped_key = None;
        let hit = if live_v.ecs_src.is_some() {
            let sk = cache_key_with_variant_from_qname_hash(
                query,
                question_end,
                fast.qname_wire_hash,
                fast.qname_wire_hash_end,
                &live_v,
                true,
            );
            stripped_key = Some(sk);
            self.lookup_into_keyed(
                KeyedLookup {
                    key: sk,
                    query,
                    question_end,
                    client_id: fast.id,
                    strip_ecs: true,
                    variant: &live_v,
                    collect_qname,
                },
                out,
            )
        } else {
            None
        };
        let probe = CacheProbe {
            variant: live_v,
            regular_key,
            stripped_key,
        };
        (hit, probe)
    }

    /// Merge a rule's cache policy over the global defaults.
    /// Call once per rule at startup; pass the result to every `add`.
    ///
    /// `nodata_ttl` (the fallback TTL for a negative response that carries no SOA)
    /// is `0`, so such responses fall to `min_ttl` — there is no separate nodata
    /// knob here. A fixed `RCODE://` server's own `?ttl=` overrides it at the
    /// call site instead (see `resolver::exchange_with_dedupe`).
    pub fn resolve_policy(&self, policy: Option<&RuleCachePolicy>) -> ResolvedCachePolicy {
        ResolvedCachePolicy {
            skip: policy.is_some_and(|p| p.skip),
            nodata_ttl: 0,
            min_ttl: policy.and_then(|p| p.min_ttl).unwrap_or(self.min_ttl),
            max_ttl: policy.and_then(|p| p.max_ttl).unwrap_or(self.max_ttl),
        }
    }

    pub fn add(&self, ins: CacheInsert<'_>, policy: &ResolvedCachePolicy, rule_id: u16) {
        let Some(cache) = &self.cache else {
            return;
        };
        if dns::is_truncated(ins.packet) {
            return;
        }

        // Apply min/max at write time so the stored TTL governs entry lifetime.
        let Some((raw_ttl, ttl_offsets)) = dns::effective_ttl_and_offsets(
            ins.packet,
            ins.question_end,
            policy.nodata_ttl,
            policy.min_ttl,
            policy.max_ttl,
        ) else {
            return;
        };

        let mut packet = BytesMut::from(ins.packet);
        // Normalize ID to 0 so the stored bytes are client-ID-agnostic.
        // lookup() patches the 2-byte ID field before returning a response.
        let _ = dns::set_id(&mut packet, 0);
        // Do NOT patch TTLs at write time; they are patched at read time with remaining TTL.
        let now = Instant::now();
        let frozen_packet = packet.freeze();
        let entry = Arc::new(Entry {
            packet: frozen_packet,
            query: ins.query,
            qname: ins.qname,
            question_end: ins.question_end,
            variant: ins.variant,
            inserted: now,
            ttl: raw_ttl,
            ttl_offsets: Arc::from(ttl_offsets.as_slice()),
            rule_id,
        });

        cache.insert(ins.key, entry);
    }

    /// Discard all cached entries. Called when the routing policy changes (ruleset reload)
    /// so that stale responses produced under the old rule decisions are not returned.
    pub fn invalidate_all(&self) {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }

    /// Core lookup implementation for the `_into` path: accepts a pre-computed cache key and
    /// the live query's pre-computed `QueryVariant` so neither needs to be re-derived here.
    fn lookup_into_keyed(
        &self,
        lookup: KeyedLookup<'_>,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        let cache = self.cache.as_ref()?;
        let question = lookup.query.get(12..lookup.question_end)?;
        let entry = cache.get(&lookup.key)?;
        let matched = queries_match_v(
            &entry.variant,
            lookup.variant,
            entry.question_end,
            entry.query.as_ref(),
            lookup.query,
            lookup.question_end,
            lookup.strip_ecs,
        );
        if !matched {
            return None;
        }

        let now = Instant::now();
        let age = now.saturating_duration_since(entry.inserted).as_secs();
        if age >= entry.ttl as u64 {
            cache.remove(&lookup.key);
            return None;
        }
        let elapsed = age.min(u32::MAX as u64) as u32;

        out.clear();
        out.extend_from_slice(&entry.packet);
        let _ = dns::set_id(out, lookup.client_id);
        if out.len() >= lookup.question_end {
            out[12..lookup.question_end].copy_from_slice(question);
        }
        dns::patch_ttls_at(out, &entry.ttl_offsets, elapsed);
        Some(CacheLookupMeta {
            qname: lookup.collect_qname.then(|| Arc::clone(&entry.qname)),
            rule_id: entry.rule_id,
        })
    }

    /// Iterate all live (non-expired) cache entries that were inserted by a
    /// known routing rule, calling `f(rule_id, response_packet, question_end)` for
    /// each.  Used at startup to repopulate nftset/ipset from the persisted cache.
    pub fn for_each_rule_entry<F>(&self, mut f: F)
    where
        F: FnMut(u16, &[u8], usize),
    {
        let Some(cache) = &self.cache else {
            return;
        };
        let now = Instant::now();
        for (_, entry) in cache.iter() {
            if entry.rule_id == u16::MAX {
                continue;
            }
            if now.saturating_duration_since(entry.inserted).as_secs() >= entry.ttl as u64 {
                continue;
            }
            f(entry.rule_id, &entry.packet, entry.question_end);
        }
    }

    /// Persist all live cache entries to `path` (atomic: writes to `.tmp` then renames).
    /// `fingerprint` is a hash of routing/cache config fields; written to the file so that
    /// a cache built under a different config is rejected on load rather than misapplied.
    pub fn save_to_file(&self, path: &Path, fingerprint: u64) -> Result<usize> {
        let Some(cache) = &self.cache else {
            return Ok(0);
        };

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect live (still-fresh) entries, carrying each one's remaining TTL
        // through to the write loop below instead of recomputing `Instant::elapsed()`
        // a second time per entry.
        let mut entries: Vec<(CacheKey, Arc<Entry>, u64)> = Vec::new();
        for (key, entry) in cache.iter() {
            let elapsed = entry.inserted.elapsed().as_secs();
            let remaining = (entry.ttl as u64).saturating_sub(elapsed);
            if remaining == 0 {
                continue;
            }
            entries.push((key, entry, remaining));
        }

        let count = entries.len();
        atomic_write(path, |w| {
            // Magic encodes format implicitly; change it when the on-disk layout changes.
            // Fingerprint encodes the config; a mismatch on load causes the file to be discarded.
            crate::persist::write_header(w, b"PDNSC009", fingerprint, count as u32)?;

            for (key, entry, remaining) in &entries {
                let expire_unix = now_unix + remaining;

                w.write_all(&key.to_le_bytes())?;
                w.write_all(&expire_unix.to_le_bytes())?;
                w.write_all(&entry.ttl.to_le_bytes())?;

                let question = entry.query.get(12..entry.question_end).unwrap_or_default();
                w.write_all(&(question.len() as u32).to_le_bytes())?;
                w.write_all(question)?;

                w.write_all(&(entry.packet.len() as u32).to_le_bytes())?;
                w.write_all(&entry.packet)?;

                w.write_all(&(entry.query.len() as u32).to_le_bytes())?;
                w.write_all(&entry.query)?;

                let qname = entry.qname.as_bytes();
                w.write_all(&(qname.len() as u32).to_le_bytes())?;
                w.write_all(qname)?;

                let offsets: &[(u32, u32)] = &entry.ttl_offsets;
                w.write_all(&(offsets.len() as u32).to_le_bytes())?;
                for &(off, original_ttl) in offsets {
                    w.write_all(&off.to_le_bytes())?;
                    w.write_all(&original_ttl.to_le_bytes())?;
                }

                w.write_all(&entry.rule_id.to_le_bytes())?;
            }
            Ok(())
        })?;
        Ok(count)
    }

    /// Load cache entries from `path`. Skips expired entries. Returns count loaded.
    /// `fingerprint` must match the value stored in the file; a mismatch means the
    /// cache was built under a different config and the file is rejected.
    pub fn load_from_file(&self, path: &Path, fingerprint: u64) -> Result<usize> {
        let Some(cache) = &self.cache else {
            return Ok(0);
        };

        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut r = BufReader::new(file);

        let count =
            crate::persist::read_and_check_header(&mut r, b"PDNSC009", fingerprint, "cache")?
                as usize;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let now_instant = Instant::now();

        let mut loaded = 0usize;
        for _ in 0..count {
            let key = read_u64(&mut r)?;
            let expire_unix = read_u64(&mut r)?;
            let raw_ttl = read_u32(&mut r)?;

            let question = read_bytes(&mut r)?;
            let packet = read_bytes(&mut r)?;
            let query = read_bytes(&mut r)?;
            let qname_bytes = read_bytes(&mut r)?;
            let offsets_count = read_u32(&mut r)? as usize;
            // A DNS packet's RR counts are u16 fields in the wire format, so no
            // legitimate entry has more offsets than this; reject a corrupt file
            // instead of speculatively reserving up to 32 GiB from one bad u32.
            anyhow::ensure!(
                offsets_count <= u16::MAX as usize,
                "cache file: TTL-offset count too large ({offsets_count}); file is likely corrupt"
            );
            let mut offsets: Vec<(u32, u32)> = Vec::with_capacity(offsets_count);
            for _ in 0..offsets_count {
                let off = read_u32(&mut r)?;
                let original_ttl = read_u32(&mut r)?;
                offsets.push((off, original_ttl));
            }

            let entry_rule_id = read_u16(&mut r)?;

            // Skip expired entries.
            if expire_unix <= now_unix {
                continue;
            }

            let remaining = expire_unix.saturating_sub(now_unix);
            let age_secs = (raw_ttl as u64).saturating_sub(remaining);
            // On embedded targets (e.g. OpenWrt) Instant is CLOCK_MONOTONIC and resets
            // on reboot.  If age_secs exceeds the system uptime, checked_sub underflows.
            // Re-anchor the entry: treat it as just-inserted with its wall-clock remaining
            // TTL as the nominal TTL.  All freshness maths stay correct.
            let (inserted, ttl_for_entry) =
                match now_instant.checked_sub(Duration::from_secs(age_secs)) {
                    Some(t) => (t, raw_ttl),
                    None => (now_instant, remaining.min(raw_ttl as u64) as u32),
                };

            let qname: Arc<str> = match std::str::from_utf8(&qname_bytes) {
                Ok(s) => Arc::from(s),
                Err(_) => continue,
            };

            let question_end = 12 + question.len();
            let variant = dns::extract_variant(&query, question_end);
            let entry = Arc::new(Entry {
                packet: Bytes::from(packet),
                query: Bytes::from(query),
                qname,
                question_end,
                variant,
                inserted,
                ttl: ttl_for_entry,
                ttl_offsets: Arc::from(offsets.as_slice()),
                rule_id: entry_rule_id,
            });

            cache.insert(key, entry);
            loaded += 1;
        }

        Ok(loaded)
    }
}

/// Compare two queries for cache-equivalence using pre-computed variants for both,
/// avoiding two `extract_variant` parses per cache-hit check.
///
/// When `strip_ecs` is set (the entry's rule uses `ecs=strip`), the comparison
/// ignores the variant's `ecs_src` field, so a strip-mode entry matches queries
/// regardless of their ECS option.
fn queries_match_v(
    stored_v: &dns::QueryVariant,
    live_v: &dns::QueryVariant,
    stored_question_end: usize,
    stored: &[u8],
    query: &[u8],
    question_end: usize,
    strip_ecs: bool,
) -> bool {
    if question_end > query.len()
        || stored_question_end != question_end
        || query.len() < 12
        || stored.len() < 12
    {
        return false;
    }
    if !dns::questions_match(&stored[12..question_end], &query[12..question_end]) {
        return false;
    }
    if strip_ecs {
        stored_v.has_opt == live_v.has_opt
            && stored_v.do_bit == live_v.do_bit
            && stored_v.edns_version == live_v.edns_version
            && stored_v.rd == live_v.rd
            && stored_v.ad == live_v.ad
            && stored_v.cd == live_v.cd
    } else {
        stored_v == live_v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cache_key_with_variant_from_qname_hash` (used by every real lookup,
    /// resuming from the QNAME hash `dns::parse_query_fast` produced during
    /// its validation walk) must always produce the exact same key as
    /// `cache_key_with_variant` (the reference implementation, hashing fresh
    /// from raw wire bytes via `Fnv1a::write_qname_wire`) for the same query
    /// -- otherwise lookups would use keys that `cache_key_with_variant`-based
    /// call sites and tests can never produce, silently defeating the cache.
    /// This is the equivalence the two hand-mirrored implementations
    /// (`Fnv1a::write_qname_wire` and the inline hashing in
    /// `dns::query::skip_query_question`) depend on staying in sync.
    ///
    /// Returns (fresh, fused-from-fast-path, fused-from-slow-path) keys for a
    /// caller-supplied packet.
    fn keys_for_packet(
        packet: &[u8],
        question_end: usize,
        expect_qname: &str,
        strip_ecs: bool,
    ) -> (CacheKey, CacheKey, CacheKey) {
        let variant = dns::extract_variant(packet, question_end);
        let fresh = cache_key_with_variant(packet, question_end, &variant, strip_ecs);

        let fast = dns::parse_query_fast(packet).unwrap();
        assert_eq!(fast.question_end, question_end);
        let fused_fast = cache_key_with_variant_from_qname_hash(
            packet,
            question_end,
            fast.qname_wire_hash,
            fast.qname_wire_hash_end,
            &variant,
            strip_ecs,
        );

        let info = dns::parse_query_from_fast(packet, fast, variant).unwrap();
        // qname is materialized lazily now; check the on-demand builder still
        // produces the expected normalized name from the same packet.
        let qname = dns::qname_from_question(packet, question_end).unwrap();
        assert_eq!(&*qname, expect_qname);
        let fused_slow = cache_key_with_variant_from_qname_hash(
            packet,
            question_end,
            info.qname_wire_hash,
            info.qname_wire_hash_end,
            &variant,
            strip_ecs,
        );
        (fresh, fused_fast, fused_slow)
    }

    fn keys_for(name: &str, qtype: u16, strip_ecs: bool) -> (CacheKey, CacheKey) {
        let (packet, question_end) = dns::synthetic_query(name, qtype).unwrap();
        let expect = name.to_ascii_lowercase();
        let (fresh, fused_fast, fused_slow) = keys_for_packet(
            &packet,
            question_end,
            expect.trim_end_matches('.'),
            strip_ecs,
        );
        assert_eq!(fused_fast, fused_slow, "fast/slow fused keys for {name:?}");
        (fresh, fused_fast)
    }

    #[test]
    fn fused_qname_hash_matches_fresh_hash() {
        let cases: Vec<(String, u16)> = vec![
            (String::new(), 1), // root
            ("a".to_string(), 1),
            ("example.com".to_string(), 1),
            ("a.b.c.example.com".to_string(), 28),
            ("EXAMPLE.COM".to_string(), 1), // mixed case
            ("MiXeD.CaSe.example.com".to_string(), 1),
            ("a-b-c.example.com".to_string(), 1),
            ("a".repeat(63), 1), // max-length single label
            (format!("{}.example.com", "a".repeat(63)), 1),
            ("xn--fsq.example.com".to_string(), 1), // punycode-shaped label
            // Maximum 255-byte wire QNAME: 63+63+63+61 labels -> 64*3+62+1.
            (
                format!(
                    "{}.{}.{}.{}",
                    "a".repeat(63),
                    "B".repeat(63),
                    "c".repeat(63),
                    "D".repeat(61)
                ),
                1,
            ),
        ];
        for (name, qtype) in cases {
            for strip_ecs in [false, true] {
                let (fresh, fused) = keys_for(&name, qtype, strip_ecs);
                assert_eq!(
                    fresh, fused,
                    "fresh vs fused cache key mismatch for name={name:?} qtype={qtype} strip_ecs={strip_ecs}"
                );
            }
        }
    }

    /// Same equivalence for a query carrying an EDNS OPT with an ECS option:
    /// the variant fields (has_opt, ecs_src) enter the key after the QNAME
    /// hash, so the fused key must match both with and without ECS stripping.
    #[test]
    fn fused_qname_hash_matches_fresh_hash_with_edns_ecs() {
        let (plain, question_end) = dns::synthetic_query("EcS.Example.COM", 1).unwrap();
        let packet = dns::inject_or_replace_ecs(
            &plain,
            &crate::config::EcsSubnet {
                addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 0)),
                prefix_len: 24,
            },
        )
        .expect("inject ECS");
        let variant = dns::extract_variant(&packet, question_end);
        assert!(
            variant.has_opt && variant.ecs_src.is_some(),
            "test packet must actually carry EDNS+ECS"
        );
        for strip_ecs in [false, true] {
            let (fresh, fused_fast, fused_slow) =
                keys_for_packet(&packet, question_end, "ecs.example.com", strip_ecs);
            assert_eq!(fresh, fused_fast, "fast fused key, strip_ecs={strip_ecs}");
            assert_eq!(fresh, fused_slow, "slow fused key, strip_ecs={strip_ecs}");
        }
        // The two strip modes must still produce different keys (ECS in vs out).
        let (with_ecs, _, _) = keys_for_packet(&packet, question_end, "ecs.example.com", false);
        let (stripped, _, _) = keys_for_packet(&packet, question_end, "ecs.example.com", true);
        assert_ne!(with_ecs, stripped);
    }

    /// The real UDP path holds many arena-served responses alive at once
    /// (queued for sendmmsg, parked in the pending queue) while the arena
    /// keeps renewing chunks underneath them. Hold hundreds of hits across
    /// several renewals and verify every response's ID, question, and answer
    /// bytes stayed intact.
    #[test]
    fn arena_responses_stay_intact_across_chunk_renewals() {
        let cache = DnsCache::new(&crate::config::CacheConfig {
            capacity: 64,
            min_ttl: 0,
            max_ttl: 0,
        });
        let (query, qe) = dns::synthetic_query("arena-life.example", 1).unwrap();
        let resp = dns::a_reply(&query, qe, std::net::Ipv4Addr::new(10, 0, 0, 1), 300).unwrap();
        let variant = dns::extract_variant(&query, qe);
        let key = cache_key_with_variant(&query, qe, &variant, false);
        cache.add(
            CacheInsert {
                key,
                qname: Arc::from("arena-life.example"),
                question_end: qe,
                query: Bytes::copy_from_slice(&query),
                variant,
                packet: &resp,
            },
            &cache.resolve_policy(None),
            0,
        );

        // Small chunk so 300 responses (~44 B each) span several renewals.
        let fast = dns::parse_query_fast(&query).unwrap();
        let mut arena = crate::resolver::ResponseArena::new(4096);
        let mut held: Vec<(u16, Bytes)> = Vec::new();
        for id in 0..300u16 {
            // Each lookup impersonates a different client ID via `fast.id`.
            let fast = dns::FastQueryInfo { id, ..fast };
            let (meta, _v) = cache.get_into_with_ecs_fallback(&query, &fast, arena.buf_mut(), false);
            assert!(meta.is_some(), "must be a cache hit");
            held.push((id, arena.take()));
        }

        // Every held response must still carry its own ID and the original
        // question + answer bytes. TTL fields are excluded from the byte
        // comparison: cache hits rewrite them to `original − elapsed_secs`,
        // so a test thread paused across a second boundary would see a
        // legitimate countdown, not corruption. What this test guards is
        // cross-response corruption from arena chunk renewals, so the TTLs
        // only need to decode as a plausible countdown of the original.
        let (_entry_ttl, ttl_offsets) =
            dns::effective_ttl_and_offsets(&resp, qe, 60, 0, 0).expect("reply has TTL offsets");
        let in_ttl_field = |i: usize| {
            ttl_offsets
                .iter()
                .any(|&(off, _)| (off as usize..off as usize + 4).contains(&i))
        };
        for (id, b) in &held {
            assert_eq!(&b[..2], &id.to_be_bytes(), "ID for response {id}");
            assert_eq!(b.len(), resp.len(), "length for response {id}");
            for i in 2..b.len() {
                if !in_ttl_field(i) {
                    assert_eq!(b[i], resp[i], "byte {i} of response {id}");
                }
            }
            for &(off, original) in ttl_offsets.iter() {
                let off = off as usize;
                let got = u32::from_be_bytes(b[off..off + 4].try_into().unwrap());
                assert!(
                    got <= original,
                    "TTL of response {id} must count down from {original}, got {got}"
                );
            }
        }
    }

    /// Two different qnames must not collapse onto the same key (sanity check
    /// that the test harness itself is actually exercising the QNAME bytes,
    /// not e.g. accidentally hashing a constant on both sides).
    #[test]
    fn different_qnames_produce_different_keys() {
        let (a, _) = keys_for("example.com", 1, false);
        let (b, _) = keys_for("example.org", 1, false);
        assert_ne!(a, b);
    }

    /// `save_to_file` iterates the cache immediately after `add`, with no flush
    /// step. Moka needed `run_pending_tasks()` to make just-inserted entries
    /// visible to `iter()`; quick-cache makes them visible right away. Guard
    /// that: insert, persist, reload into a fresh cache, and confirm the full
    /// set round-trips.
    #[test]
    fn persist_round_trip_sees_freshly_inserted_entries() {
        let cfg = crate::config::CacheConfig {
            capacity: 64,
            min_ttl: 0,
            max_ttl: 0,
        };
        let cache = DnsCache::new(&cfg);
        let names = ["a.test", "b.test", "c.test", "d.test"];
        for (i, n) in names.iter().enumerate() {
            let (query, qe) = dns::synthetic_query(n, 1).unwrap();
            let resp =
                dns::a_reply(&query, qe, std::net::Ipv4Addr::new(10, 0, 0, i as u8 + 1), 300)
                    .unwrap();
            let variant = dns::extract_variant(&query, qe);
            let key = cache_key_with_variant(&query, qe, &variant, false);
            cache.add(
                CacheInsert {
                    key,
                    qname: Arc::from(*n),
                    question_end: qe,
                    query: Bytes::copy_from_slice(&query),
                    variant,
                    packet: &resp,
                },
                &cache.resolve_policy(None),
                0,
            );
        }

        let path = std::env::temp_dir().join(format!("pathdns_persist_{}.bin", std::process::id()));
        let saved = cache.save_to_file(&path, 0xABCD).unwrap();
        assert_eq!(saved, names.len(), "every fresh entry must be iterated");

        let reloaded = DnsCache::new(&cfg);
        let loaded = reloaded.load_from_file(&path, 0xABCD).unwrap();
        assert_eq!(loaded, names.len());
        assert_eq!(reloaded.entry_count(), names.len() as u64);
        let _ = std::fs::remove_file(&path);
    }
}

/// Allocation-counting proof for the fast-path arena (`resolver::try_fast_path_into`).
///
/// Wall-clock benchmarks in shared/noisy environments can't reliably resolve
/// the effect of removing one small malloc+memcpy per cache hit, so this pins
/// the structural claim deterministically instead: at steady state, serving a
/// cache hit through the arena pattern (lookup → split().freeze()) performs
/// **at least one fewer heap allocation per hit** than the previous
/// copy-out pattern (lookup → Bytes::copy_from_slice). Both loops share
/// whatever incidental allocation the cache implementation itself does, so
/// the comparison isolates exactly the pattern change.
#[cfg(all(test, not(feature = "jemalloc")))]
#[allow(unsafe_code)] // the counting GlobalAlloc is inherently unsafe; test-only
mod alloc_proof {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    struct CountingAlloc;

    // Per-thread count: `cargo test` runs the other tests concurrently in the
    // same process, and a process-global counter picks up their threads'
    // allocations inside this test's measurement windows (which is exactly
    // how the first version of this test flaked in a full parallel run).
    // Const-initialized Cell<u64>: TLS access here neither allocates nor
    // re-enters the allocator.
    thread_local! {
        static TL_ALLOCS: Cell<u64> = const { Cell::new(0) };
    }

    fn thread_allocs() -> u64 {
        TL_ALLOCS.with(|c| c.get())
    }

    // SAFETY: pure pass-through to System, plus a thread-local counter bump.
    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            TL_ALLOCS.with(|c| c.set(c.get() + 1));
            // SAFETY: same contract as the caller's.
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: same contract as the caller's.
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            TL_ALLOCS.with(|c| c.set(c.get() + 1));
            // SAFETY: same contract as the caller's.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static COUNTING: CountingAlloc = CountingAlloc;

    #[test]
    fn arena_hit_path_saves_at_least_one_allocation_per_hit() {
        const ITERS: u64 = 1000;

        let cache = DnsCache::new(&crate::config::CacheConfig {
            capacity: 1024,
            min_ttl: 0,
            max_ttl: 0,
        });
        let (query, qe) = dns::synthetic_query("warm.example", 1).unwrap();
        let resp = dns::a_reply(&query, qe, std::net::Ipv4Addr::new(9, 9, 9, 9), 3600).unwrap();
        let variant = dns::extract_variant(&query, qe);
        let key = cache_key_with_variant(&query, qe, &variant, false);
        cache.add(
            CacheInsert {
                key,
                qname: Arc::from("warm.example"),
                question_end: qe,
                query: Bytes::copy_from_slice(&query),
                variant,
                packet: &resp,
            },
            &cache.resolve_policy(None),
            0,
        );

        let fast = dns::FastQueryInfo {
            id: 0x1234,
            ..dns::parse_query_fast(&query).unwrap()
        };
        let hit = |arena: &mut BytesMut| {
            let (meta, _v) = cache.get_into_with_ecs_fallback(&query, &fast, arena, false);
            assert!(meta.is_some(), "must be a cache hit");
        };

        // Arena pattern (current fast path): split + amortized chunk renewal,
        // through the exact type the fast path uses.
        let mut arena = crate::resolver::ResponseArena::new(64 * 1024);
        for _ in 0..10 {
            hit(arena.buf_mut()); // warm-up: cache internal buffers, arena chunks, etc.
            let _ = arena.take();
        }
        let before = thread_allocs();
        for _ in 0..ITERS {
            hit(arena.buf_mut());
            let b = arena.take();
            drop(b);
        }
        let arena_allocs = thread_allocs() - before;

        // Previous pattern: reusable scratch buffer + per-hit copy-out.
        let mut scratch = BytesMut::with_capacity(64 * 1024);
        let before = thread_allocs();
        for _ in 0..ITERS {
            hit(&mut scratch);
            let b = Bytes::copy_from_slice(&scratch);
            drop(b);
        }
        let copy_allocs = thread_allocs() - before;

        println!("arena: {arena_allocs} allocs / {ITERS} hits; copy-out: {copy_allocs}");
        assert!(
            arena_allocs + (ITERS * 9 / 10) <= copy_allocs,
            "arena pattern must save at least ~1 allocation per hit \
             (arena={arena_allocs}, copy={copy_allocs})"
        );
    }
}
