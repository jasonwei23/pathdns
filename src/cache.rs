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
use crate::persist::atomic_write;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use moka::sync::Cache;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type CacheKey = u64;

/// FNV-1a hash of a complete DNS query excluding its two-byte client ID.
///
/// The hash covers:
/// - QNAME (ASCII-lowercased, self-delimiting label encoding)
/// - QTYPE + QCLASS (exact)
/// - EDNS semantics extracted via [`dns::extract_variant`]: RD/AD/CD flags,
///   has_opt, DO bit, EDNS version, and normalised ECS source subnet.
///
/// Raw additional-section bytes are NOT hashed so that semantically equivalent
/// queries with different OPT padding, unknown EDNS options, or varying ARCOUNT
/// always share the same cache entry.
#[cfg(test)]
pub fn cache_key(query: &[u8], question_end: usize) -> CacheKey {
    cache_key_impl(query, question_end, false)
}

/// Like [`cache_key`] but always hashes `0` for the ECS field regardless of
/// whether the query contains an ECS option.  Used when the upstream strips ECS
/// so that all clients share a single cache entry keyed on the stripped variant.
#[cfg(test)]
pub fn cache_key_strip_ecs(query: &[u8], question_end: usize) -> CacheKey {
    cache_key_impl(query, question_end, true)
}

/// Hash a query using a pre-computed [`dns::QueryVariant`].
///
/// Callers that need the variant for other decisions can use this entry point to
/// avoid scanning the DNS additional section a second time.
pub(crate) fn cache_key_with_variant(
    query: &[u8],
    question_end: usize,
    v: &dns::QueryVariant,
    strip_ecs: bool,
) -> CacheKey {
    let mut h = Fnv1a::new();
    if query.len() < 12 || question_end < 16 || question_end > query.len() {
        return h.finish();
    }

    let question = &query[12..question_end];
    let mut pos = 0usize;

    // QNAME: hash each label with ASCII-lowercase normalisation.
    while let Some(&len) = question.get(pos) {
        h.write_byte(len);
        pos += 1;
        if len == 0 {
            break;
        }
        let end = (pos + len as usize).min(question.len());
        for &b in &question[pos..end] {
            h.write_byte(b.to_ascii_lowercase());
        }
        pos = end;
    }

    // QTYPE + QCLASS — exact match required.
    h.write(question.get(pos..).unwrap_or(&[]));

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

#[cfg(test)]
fn cache_key_impl(query: &[u8], question_end: usize, strip_ecs: bool) -> CacheKey {
    let v = dns::extract_variant(query, question_end);
    cache_key_with_variant(query, question_end, &v, strip_ecs)
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
    pub qname: Arc<str>,
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
}

/// Per-rule cache policy with global defaults already merged in.
///
/// Computed once at startup via [`DnsCache::resolve_policy`]; the insert path reads
/// plain fields instead of walking six `Option` chains per cached response.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedCachePolicy {
    /// Bypass the cache entirely for this rule.
    pub skip: bool,
    nodata_ttl: u32,
    min_ttl: u32,
    max_ttl: u32,
}

/// Borrowed context for a cache insert: the response packet plus the query it answers.
pub struct CacheInsert<'a> {
    pub key: CacheKey,
    pub qname: Arc<str>,
    pub question_end: usize,
    pub query: &'a [u8],
    pub packet: &'a [u8],
}

#[derive(Debug)]
pub struct DnsCache {
    cache: Option<Cache<CacheKey, Arc<Entry>>>,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(cfg: &CacheConfig) -> Self {
        let cache =
            (cfg.capacity > 0).then(|| Cache::builder().max_capacity(cfg.capacity as u64).build());
        Self {
            cache,
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl,
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.as_ref().map(|c| c.entry_count()).unwrap_or(0)
    }

    pub fn capacity(&self) -> u64 {
        self.cache
            .as_ref()
            .and_then(|c| c.policy().max_capacity())
            .unwrap_or(0)
    }

    /// Try regular lookup first; if that misses and the query has an ECS option,
    /// retry with the ECS-stripped cache key and relaxed variant matching.
    /// This lets a strip-mode rule serve all clients from one shared cache entry.
    ///
    /// Parses the EDNS variant once and reuses it for both the key derivation and the
    /// ECS-fallback check, avoiding redundant additional-section scans.
    pub fn get_into_with_ecs_fallback(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        let live_v = dns::extract_variant(query, question_end);
        let key = cache_key_with_variant(query, question_end, &live_v, false);
        if let Some(hit) = self.lookup_into_keyed(
            KeyedLookup {
                key,
                query,
                question_end,
                client_id,
                strip_ecs: false,
                variant: &live_v,
            },
            out,
        ) {
            return Some(hit);
        }
        if live_v.ecs_src.is_some() {
            let strip_key = cache_key_with_variant(query, question_end, &live_v, true);
            self.lookup_into_keyed(
                KeyedLookup {
                    key: strip_key,
                    query,
                    question_end,
                    client_id,
                    strip_ecs: true,
                    variant: &live_v,
                },
                out,
            )
        } else {
            None
        }
    }

    /// Merge a rule's cache policy over the global defaults.
    /// Call once per rule at startup; pass the result to every `add`.
    ///
    /// `nodata_ttl` (the fallback TTL for a negative response that carries no SOA)
    /// is `0`, so such responses fall to `min_ttl` — there is no separate nodata
    /// knob. Synthesised `route.answer` RCODEs set it via [`Self::negative_answer_policy`].
    pub fn resolve_policy(&self, policy: Option<&RuleCachePolicy>) -> ResolvedCachePolicy {
        ResolvedCachePolicy {
            skip: policy.is_some_and(|p| p.skip),
            nodata_ttl: 0,
            min_ttl: policy.and_then(|p| p.min_ttl).unwrap_or(self.min_ttl),
            max_ttl: policy.and_then(|p| p.max_ttl).unwrap_or(self.max_ttl),
        }
    }

    /// Policy for a synthesised `route.answer` response whose NODATA/RCODE form
    /// (no record, no SOA) should be cached for `nodata_ttl` seconds — the entry's
    /// `?ttl=`. `min_ttl`/`max_ttl` still clamp it.
    pub fn negative_answer_policy(&self, nodata_ttl: u32) -> ResolvedCachePolicy {
        ResolvedCachePolicy {
            skip: false,
            nodata_ttl,
            min_ttl: self.min_ttl,
            max_ttl: self.max_ttl,
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
        let variant = dns::extract_variant(ins.query, ins.question_end);
        let entry = Arc::new(Entry {
            packet: frozen_packet,
            query: Bytes::copy_from_slice(ins.query),
            qname: ins.qname,
            question_end: ins.question_end,
            variant,
            inserted: now,
            ttl: raw_ttl,
            ttl_offsets: Arc::from(ttl_offsets.as_slice()),
            rule_id,
        });

        cache.insert(ins.key, entry);
    }

    /// Discard all cached entries. Called when the routing policy changes (GeoSite reload)
    /// so that stale responses produced under the old rule decisions are not returned.
    pub fn invalidate_all(&self) {
        if let Some(cache) = &self.cache {
            cache.invalidate_all();
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
        let matched = if lookup.strip_ecs {
            queries_match_strip_ecs_v(
                &entry.variant,
                lookup.variant,
                entry.question_end,
                entry.query.as_ref(),
                lookup.query,
                lookup.question_end,
            )
        } else {
            queries_match_v(
                &entry.variant,
                lookup.variant,
                entry.question_end,
                entry.query.as_ref(),
                lookup.query,
                lookup.question_end,
            )
        };
        if !matched {
            return None;
        }

        let now = Instant::now();
        let age = now.saturating_duration_since(entry.inserted).as_secs();
        if age >= entry.ttl as u64 {
            cache.invalidate(&lookup.key);
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
            qname: entry.qname.clone(),
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
        // Flush Moka's internal write buffer so iter() sees all entries that
        // load_from_file just inserted (same pattern as save_to_file).
        cache.run_pending_tasks();
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
        cache.run_pending_tasks();

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect live (still-fresh) entries.
        let mut entries: Vec<(CacheKey, Arc<Entry>)> = Vec::new();
        for (key, entry) in cache.iter() {
            let elapsed = entry.inserted.elapsed().as_secs();
            let remaining = (entry.ttl as u64).saturating_sub(elapsed);
            if remaining == 0 {
                continue;
            }
            entries.push((*key, entry));
        }

        let count = entries.len();
        atomic_write(path, |w| {
            // Magic encodes format implicitly; change it when the on-disk layout changes.
            // Fingerprint encodes the config; a mismatch on load causes the file to be discarded.
            w.write_all(b"PDNSC009")?;
            w.write_all(&fingerprint.to_le_bytes())?;
            w.write_all(&(count as u32).to_le_bytes())?;

            for (key, entry) in &entries {
                let elapsed = entry.inserted.elapsed().as_secs();
                let remaining = (entry.ttl as u64).saturating_sub(elapsed);
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

        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).context("read magic")?;
        anyhow::ensure!(
            &magic == b"PDNSC009",
            "unrecognised cache file format (magic mismatch)"
        );

        let stored_fp = read_u64(&mut r).context("read fingerprint")?;
        anyhow::ensure!(
            stored_fp == fingerprint,
            "cache file was built with a different config (fingerprint mismatch) — discarding"
        );

        let count = read_u32(&mut r).context("read count")? as usize;
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
fn queries_match_v(
    stored_v: &dns::QueryVariant,
    live_v: &dns::QueryVariant,
    stored_question_end: usize,
    stored: &[u8],
    query: &[u8],
    question_end: usize,
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
    stored_v == live_v
}

/// Like [`queries_match_v`] but ignores the `ecs_src` field, so a strip-mode entry
/// matches queries regardless of their ECS option.
fn queries_match_strip_ecs_v(
    stored_v: &dns::QueryVariant,
    live_v: &dns::QueryVariant,
    stored_question_end: usize,
    stored: &[u8],
    query: &[u8],
    question_end: usize,
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
    stored_v.has_opt == live_v.has_opt
        && stored_v.do_bit == live_v.do_bit
        && stored_v.edns_version == live_v.edns_version
        && stored_v.rd == live_v.rd
        && stored_v.ad == live_v.ad
        && stored_v.cd == live_v.cd
}

pub(crate) fn read_u16(r: &mut impl Read) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub(crate) fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64(r: &mut impl Read) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
#[path = "tests/cache.rs"]
mod tests;
