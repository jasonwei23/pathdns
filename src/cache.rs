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
//! - SERVFAIL (RCODE 2): never cached; stale entries are served in preference to SERVFAIL.
//! - Truncated responses (TC bit): never cached.
//! - OPT records (type 41): excluded from TTL patching (EDNS version field, not TTL).
//!
//! Stale-while-revalidate:
//! - When `stale_secs > 0`, `get()` proactively serves expired entries within the stale
//!   window (returning `is_stale = true` so the caller can count them separately and
//!   trigger a background refresh).
//! - `get_stale()` is the unconditional stale accessor, used as an error fallback when
//!   upstream returns SERVFAIL or a network error.

use crate::config::{CacheConfig, GroupCachePolicy};
use crate::dns;
use crate::fnv::Fnv1a;
use crate::persist::atomic_write;
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use moka::sync::Cache;
use std::cmp::Ordering as CmpOrdering;
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
pub fn cache_key(query: &[u8], question_end: usize) -> CacheKey {
    cache_key_impl(query, question_end, false)
}

/// Like [`cache_key`] but always hashes `0` for the ECS field regardless of
/// whether the query contains an ECS option.  Used when the upstream strips ECS
/// so that all clients share a single cache entry keyed on the stripped variant.
pub fn cache_key_strip_ecs(query: &[u8], question_end: usize) -> CacheKey {
    cache_key_impl(query, question_end, true)
}

fn cache_key_impl(query: &[u8], question_end: usize, strip_ecs: bool) -> CacheKey {
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

    // EDNS semantics — semantic equality, not raw byte equality.
    let v = dns::extract_variant(query, question_end);
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
                h.write(&ecs.addr.to_be_bytes());
                h.write_byte(ecs.prefix_len);
            }
        }
    }

    h.finish()
}

#[derive(Debug)]
struct Entry {
    question: Arc<[u8]>,
    packet: Bytes,
    query: Bytes,
    qname: Arc<str>,
    inserted: Instant,
    /// Effective TTL (clamped by per-group or global min/max at write time).
    ttl: u32,
    stale_until: Instant,
    ttl_offsets: Arc<[(usize, u32)]>,
    /// Per-entry effective max TTL — used only to cap the stale advertised TTL.
    max_ttl: u32,
    /// Effective stale TTL advertised to clients when stale_ttl_reset is true.
    stale_ttl: u32,
    /// Effective refresh threshold (per-group overrides global).
    refresh_percent: Option<u32>,
    /// Index of the routing group that cached this entry (u16::MAX = unknown / loaded from disk).
    group_id: u16,
}

enum EntryFreshness {
    Fresh { remaining: u32 },
    Stale { advertised_ttl: u32 },
    Expired { evict: bool },
}

#[derive(Debug, Clone)]
pub struct CacheLookup {
    pub packet: Bytes,
    pub refresh: Option<CacheRefresh>,
    pub qname: Arc<str>,
    /// True when the entry's TTL had expired but it was within the stale window.
    /// The caller should count this as a stale hit and spawn a background refresh.
    pub is_stale: bool,
    /// Index of the group that originally cached this entry (u16::MAX = unknown).
    pub group_id: u16,
}

/// Metadata returned from `get_into`; the packet bytes are written into the caller's buffer.
#[derive(Debug, Clone)]
pub struct CacheLookupMeta {
    pub refresh: Option<CacheRefresh>,
    pub qname: Arc<str>,
    pub is_stale: bool,
    /// Index of the group that originally cached this entry (u16::MAX = unknown).
    pub group_id: u16,
}

#[derive(Debug, Clone)]
pub struct CacheRefresh {
    pub key: CacheKey,
    pub query: Bytes,
    /// Shared reference into the cache entry; cloning is a refcount bump, not a String copy.
    pub qname: Arc<str>,
    pub question_end: usize,
    pub qtype: u16,
}

/// Per-group cache policy with global defaults already merged in.
///
/// Computed once at startup via [`DnsCache::resolve_policy`]; the insert path reads
/// plain fields instead of walking six `Option` chains per cached response.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedCachePolicy {
    /// Bypass the cache entirely for this group.
    pub skip: bool,
    nodata_ttl: u32,
    stale_expire_ttl: u64,
    min_ttl: u32,
    max_ttl: u32,
    stale_ttl: u32,
    refresh_percent: Option<u32>,
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
    stale_expire_ttl: u64,
    stale_ttl: u32,
    stale_ttl_reset: bool,
    nodata_ttl: u32,
    min_ttl: u32,
    max_ttl: u32,
    refresh_percent: Option<u32>,
    refresh_min_ttl: Option<u32>,
}

impl DnsCache {
    pub fn new(cfg: &CacheConfig) -> Self {
        let cache =
            (cfg.capacity > 0).then(|| Cache::builder().max_capacity(cfg.capacity as u64).build());
        Self {
            cache,
            stale_expire_ttl: cfg.stale_expire_ttl,
            stale_ttl: cfg.stale_ttl,
            stale_ttl_reset: cfg.stale_ttl_reset,
            nodata_ttl: cfg.nodata_ttl,
            min_ttl: cfg.min_ttl,
            max_ttl: cfg.max_ttl,
            refresh_percent: cfg.refresh.map(|v| v.min(100)),
            refresh_min_ttl: cfg.refresh_min_ttl,
        }
    }

    pub fn enabled(&self) -> bool {
        self.cache.is_some()
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

    /// Look up a fresh or (when stale_secs > 0) proactively-served stale entry.
    /// Returns `CacheLookup.is_stale = true` when the entry's TTL had expired but it
    /// was still within the stale window; the caller should spawn a background refresh.
    pub fn get(&self, query: &[u8], question_end: usize, client_id: u16) -> Option<CacheLookup> {
        self.lookup(query, question_end, client_id, self.stale_expire_ttl > 0, false)
    }

    /// Look up and write the response packet into a caller-provided buffer.
    /// Returns metadata without allocating a new `Bytes` for the packet.
    pub fn get_into(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        self.lookup_into(
            query,
            question_end,
            client_id,
            self.stale_expire_ttl > 0,
            false,
            out,
        )
    }

    /// Unconditional stale lookup used as an error fallback (upstream SERVFAIL / failure).
    pub fn get_stale(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
    ) -> Option<CacheLookup> {
        self.lookup(query, question_end, client_id, true, false)
    }

    /// Try regular lookup first; if that misses and the query has an ECS option,
    /// retry with the ECS-stripped cache key and relaxed variant matching.
    /// This lets a strip-mode group serve all clients from one shared cache entry.
    pub fn get_with_ecs_fallback(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
    ) -> Option<CacheLookup> {
        if let Some(hit) = self.lookup(query, question_end, client_id, self.stale_expire_ttl > 0, false) {
            return Some(hit);
        }
        if dns::extract_variant(query, question_end).ecs_src.is_some() {
            self.lookup(query, question_end, client_id, self.stale_expire_ttl > 0, true)
        } else {
            None
        }
    }

    /// Like [`get_with_ecs_fallback`] but writes directly into `out`.
    pub fn get_into_with_ecs_fallback(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        if let Some(hit) = self.lookup_into(query, question_end, client_id, self.stale_expire_ttl > 0, false, out) {
            return Some(hit);
        }
        if dns::extract_variant(query, question_end).ecs_src.is_some() {
            self.lookup_into(query, question_end, client_id, self.stale_expire_ttl > 0, true, out)
        } else {
            None
        }
    }

    /// Merge a group's cache policy over the global defaults.
    /// Call once per group at startup; pass the result to every `add`.
    pub fn resolve_policy(&self, policy: Option<&GroupCachePolicy>) -> ResolvedCachePolicy {
        ResolvedCachePolicy {
            skip: policy.is_some_and(|p| p.skip),
            nodata_ttl: policy.and_then(|p| p.nodata_ttl).unwrap_or(self.nodata_ttl),
            stale_expire_ttl: policy
                .and_then(|p| p.stale_expire_ttl)
                .unwrap_or(self.stale_expire_ttl),
            min_ttl: policy.and_then(|p| p.min_ttl).unwrap_or(self.min_ttl),
            max_ttl: policy.and_then(|p| p.max_ttl).unwrap_or(self.max_ttl),
            stale_ttl: policy.and_then(|p| p.stale_ttl).unwrap_or(self.stale_ttl),
            refresh_percent: policy
                .and_then(|p| p.refresh_percent)
                .or(self.refresh_percent)
                .map(|v| v.min(100)),
        }
    }

    pub fn add(&self, ins: CacheInsert<'_>, policy: &ResolvedCachePolicy, group_id: u16) {
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
        let stale_until = now + Duration::from_secs(raw_ttl as u64 + policy.stale_expire_ttl);
        let question: Arc<[u8]> = Arc::from(&ins.query[12..ins.question_end]);
        let frozen_packet = packet.freeze();
        let entry = Arc::new(Entry {
            question: question.clone(),
            packet: frozen_packet,
            query: Bytes::copy_from_slice(ins.query),
            qname: ins.qname,
            inserted: now,
            ttl: raw_ttl,
            stale_until,
            ttl_offsets: Arc::from(ttl_offsets.as_slice()),
            max_ttl: policy.max_ttl,
            stale_ttl: policy.stale_ttl,
            refresh_percent: policy.refresh_percent,
            group_id,
        });

        cache.insert(ins.key, entry);
    }

    /// Number of entries currently in the cache (approximate; runs pending evictions first).
    pub fn len(&self) -> usize {
        let Some(cache) = &self.cache else {
            return 0;
        };
        cache.run_pending_tasks();
        cache.entry_count() as usize
    }

    /// Discard all cached entries. Called when the routing policy changes (GeoSite reload)
    /// so that stale responses produced under the old group decisions are not returned.
    pub fn invalidate_all(&self) {
        if let Some(cache) = &self.cache {
            cache.invalidate_all();
        }
    }

    fn lookup(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
        allow_stale: bool,
        strip_ecs: bool,
    ) -> Option<CacheLookup> {
        let cache = self.cache.as_ref()?;
        let question = query.get(12..question_end)?;
        let key = if strip_ecs {
            cache_key_strip_ecs(query, question_end)
        } else {
            cache_key(query, question_end)
        };
        let entry = cache.get(&key)?;
        let matched = if strip_ecs {
            queries_match_strip_ecs(entry.query.as_ref(), query, question_end)
        } else {
            queries_match(entry.query.as_ref(), query, question_end)
        };
        if !matched {
            return None;
        }

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(entry.inserted).as_secs().min(u32::MAX as u64) as u32;
        let (remaining, is_stale) = match self.entry_freshness(&entry, now, allow_stale) {
            EntryFreshness::Fresh { remaining } => (remaining, false),
            EntryFreshness::Stale { advertised_ttl } => (advertised_ttl, true),
            EntryFreshness::Expired { evict } => {
                if evict {
                    cache.invalidate(&key);
                }
                return None;
            }
        };

        let mut packet = BytesMut::from(entry.packet.as_ref());
        let _ = dns::set_id(&mut packet, client_id);
        if packet.len() >= question_end {
            packet[12..question_end].copy_from_slice(question);
        }
        if is_stale {
            dns::patch_ttls_uniform(&mut packet, &entry.ttl_offsets, remaining);
        } else {
            dns::patch_ttls_at(&mut packet, &entry.ttl_offsets, elapsed);
        }
        let refresh = self.refresh_for(&key, &entry, remaining, is_stale);
        Some(CacheLookup {
            packet: packet.freeze(),
            refresh,
            qname: entry.qname.clone(),
            is_stale,
            group_id: entry.group_id,
        })
    }

    fn lookup_into(
        &self,
        query: &[u8],
        question_end: usize,
        client_id: u16,
        allow_stale: bool,
        strip_ecs: bool,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        let cache = self.cache.as_ref()?;
        let question = query.get(12..question_end)?;
        let key = if strip_ecs {
            cache_key_strip_ecs(query, question_end)
        } else {
            cache_key(query, question_end)
        };
        let entry = cache.get(&key)?;
        let matched = if strip_ecs {
            queries_match_strip_ecs(entry.query.as_ref(), query, question_end)
        } else {
            queries_match(entry.query.as_ref(), query, question_end)
        };
        if !matched {
            return None;
        }

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(entry.inserted).as_secs().min(u32::MAX as u64) as u32;
        let (remaining, is_stale) = match self.entry_freshness(&entry, now, allow_stale) {
            EntryFreshness::Fresh { remaining } => (remaining, false),
            EntryFreshness::Stale { advertised_ttl } => (advertised_ttl, true),
            EntryFreshness::Expired { evict } => {
                if evict {
                    cache.invalidate(&key);
                }
                return None;
            }
        };

        out.clear();
        out.extend_from_slice(&entry.packet);
        let _ = dns::set_id(out, client_id);
        if out.len() >= question_end {
            out[12..question_end].copy_from_slice(question);
        }
        if is_stale {
            dns::patch_ttls_uniform(out, &entry.ttl_offsets, remaining);
        } else {
            dns::patch_ttls_at(out, &entry.ttl_offsets, elapsed);
        }
        let refresh = self.refresh_for(&key, &entry, remaining, is_stale);
        Some(CacheLookupMeta {
            refresh,
            qname: entry.qname.clone(),
            is_stale,
            group_id: entry.group_id,
        })
    }

    fn entry_freshness(&self, entry: &Entry, now: Instant, allow_stale: bool) -> EntryFreshness {
        let age = now.saturating_duration_since(entry.inserted).as_secs();
        match age.cmp(&(entry.ttl as u64)) {
            CmpOrdering::Less => EntryFreshness::Fresh {
                remaining: entry.ttl.saturating_sub(age as u32),
            },
            CmpOrdering::Equal | CmpOrdering::Greater => {
                // Per-entry stale window: stale_until > inserted + ttl iff stale_expire_ttl > 0
                // was set for this entry's group. Respect it even when global stale is off.
                let entry_has_stale =
                    entry.stale_until > entry.inserted + Duration::from_secs(entry.ttl as u64);
                if (allow_stale || entry_has_stale) && now <= entry.stale_until {
                    let advertised_ttl = if self.stale_ttl_reset {
                        match entry.max_ttl {
                            0 => entry.stale_ttl,
                            max => entry.stale_ttl.min(max),
                        }
                    } else {
                        entry.stale_until.saturating_duration_since(now).as_secs() as u32
                    };
                    EntryFreshness::Stale { advertised_ttl }
                } else {
                    EntryFreshness::Expired {
                        evict: now > entry.stale_until,
                    }
                }
            }
        }
    }

    fn refresh_for(
        &self,
        key: &CacheKey,
        entry: &Entry,
        remaining: u32,
        stale: bool,
    ) -> Option<CacheRefresh> {
        let needs_refresh = stale
            || entry.refresh_percent.is_some_and(|pct| {
                pct > 0 && remaining.saturating_mul(100) <= entry.ttl.saturating_mul(pct)
            })
            || self
                .refresh_min_ttl
                .is_some_and(|min| min > 0 && remaining <= min);
        if needs_refresh {
            let q = &entry.question;
            let question_end = 12 + q.len();
            let qtype = if q.len() >= 4 {
                u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]])
            } else {
                1
            };
            Some(CacheRefresh {
                key: *key,
                query: entry.query.clone(),
                qname: entry.qname.clone(),
                question_end,
                qtype,
            })
        } else {
            None
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

        let now_instant = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect live entries.
        let mut entries: Vec<(CacheKey, Arc<Entry>)> = Vec::new();
        for (key, entry) in cache.iter() {
            let stale_remaining = entry
                .stale_until
                .saturating_duration_since(now_instant)
                .as_secs();
            let elapsed = entry.inserted.elapsed().as_secs();
            let remaining = (entry.ttl as u64).saturating_sub(elapsed);
            if remaining == 0 && stale_remaining == 0 {
                continue;
            }
            entries.push((*key, entry));
        }

        let count = entries.len();
        atomic_write(path, |w| {
            // Magic encodes format implicitly; change it when the on-disk layout changes.
            // Fingerprint encodes the config; a mismatch on load causes the file to be discarded.
            w.write_all(b"PDNSC007")?;
            w.write_all(&fingerprint.to_le_bytes())?;
            w.write_all(&(count as u32).to_le_bytes())?;

            for (key, entry) in &entries {
                let elapsed = entry.inserted.elapsed().as_secs();
                let remaining = (entry.ttl as u64).saturating_sub(elapsed);
                let stale_remaining = entry
                    .stale_until
                    .saturating_duration_since(now_instant)
                    .as_secs();
                let expire_unix = now_unix + remaining;
                let stale_until_unix = now_unix + stale_remaining;

                w.write_all(&key.to_le_bytes())?;
                w.write_all(&expire_unix.to_le_bytes())?;
                w.write_all(&stale_until_unix.to_le_bytes())?;
                w.write_all(&entry.ttl.to_le_bytes())?;

                let question: &[u8] = &entry.question;
                w.write_all(&(question.len() as u32).to_le_bytes())?;
                w.write_all(question)?;

                w.write_all(&(entry.packet.len() as u32).to_le_bytes())?;
                w.write_all(&entry.packet)?;

                w.write_all(&(entry.query.len() as u32).to_le_bytes())?;
                w.write_all(&entry.query)?;

                let qname = entry.qname.as_bytes();
                w.write_all(&(qname.len() as u32).to_le_bytes())?;
                w.write_all(qname)?;

                let offsets: &[(usize, u32)] = &entry.ttl_offsets;
                w.write_all(&(offsets.len() as u32).to_le_bytes())?;
                for &(off, original_ttl) in offsets {
                    w.write_all(&(off as u32).to_le_bytes())?;
                    w.write_all(&original_ttl.to_le_bytes())?;
                }

                w.write_all(&entry.max_ttl.to_le_bytes())?;
                w.write_all(&entry.stale_ttl.to_le_bytes())?;
                // refresh_percent: u32::MAX encodes None.
                w.write_all(&entry.refresh_percent.unwrap_or(u32::MAX).to_le_bytes())?;
                w.write_all(&entry.group_id.to_le_bytes())?;
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
            &magic == b"PDNSC007",
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
            let stale_until_unix = read_u64(&mut r)?;
            let raw_ttl = read_u32(&mut r)?;

            let question = read_bytes(&mut r)?;
            let packet = read_bytes(&mut r)?;
            let query = read_bytes(&mut r)?;
            let qname_bytes = read_bytes(&mut r)?;
            let offsets_count = read_u32(&mut r)? as usize;
            let mut offsets: Vec<(usize, u32)> = Vec::with_capacity(offsets_count);
            for _ in 0..offsets_count {
                let off = read_u32(&mut r)? as usize;
                let original_ttl = read_u32(&mut r)?;
                offsets.push((off, original_ttl));
            }

            let entry_max_ttl = read_u32(&mut r)?;
            let entry_stale_ttl = read_u32(&mut r)?;
            let rp_raw = read_u32(&mut r)?;
            let entry_refresh_percent = (rp_raw != u32::MAX).then_some(rp_raw);
            let entry_group_id = read_u16(&mut r)?;

            // Skip fully expired entries.
            if expire_unix <= now_unix && stale_until_unix <= now_unix {
                continue;
            }

            let remaining = expire_unix.saturating_sub(now_unix);
            let age_secs = (raw_ttl as u64).saturating_sub(remaining);
            let inserted = now_instant - Duration::from_secs(age_secs);
            let stale_remaining = stale_until_unix.saturating_sub(now_unix);
            let stale_until = now_instant + Duration::from_secs(stale_remaining);

            let qname: Arc<str> = match std::str::from_utf8(&qname_bytes) {
                Ok(s) => Arc::from(s),
                Err(_) => continue,
            };

            let question_arc: Arc<[u8]> = Arc::from(question.as_slice());
            let entry = Arc::new(Entry {
                question: question_arc.clone(),
                packet: Bytes::from(packet),
                query: Bytes::from(query),
                qname,
                inserted,
                ttl: raw_ttl,
                stale_until,
                ttl_offsets: Arc::from(offsets.as_slice()),
                max_ttl: entry_max_ttl,
                stale_ttl: entry_stale_ttl,
                refresh_percent: entry_refresh_percent,
                group_id: entry_group_id,
            });

            cache.insert(key, entry);
            loaded += 1;
        }

        Ok(loaded)
    }
}

fn queries_match(stored: &[u8], query: &[u8], question_end: usize) -> bool {
    if question_end > query.len() || query.len() < 12 || stored.len() < 12 {
        return false;
    }
    let Some(stored_question_end) = dns::question_end(stored) else {
        return false;
    };
    if stored_question_end != question_end {
        return false;
    }
    if !dns::questions_match(&stored[12..question_end], &query[12..question_end]) {
        return false;
    }
    // Compare EDNS semantics instead of raw additional-section bytes so that
    // equivalent queries differing only in OPT padding share cache entries.
    dns::extract_variant(stored, stored_question_end) == dns::extract_variant(query, question_end)
}

/// Like [`queries_match`] but ignores the `ecs_src` field when comparing variants.
/// Used when the stored entry was cached with ECS stripped, so we only require the
/// non-ECS EDNS semantics to match.
fn queries_match_strip_ecs(stored: &[u8], query: &[u8], question_end: usize) -> bool {
    if question_end > query.len() || query.len() < 12 || stored.len() < 12 {
        return false;
    }
    let Some(stored_question_end) = dns::question_end(stored) else {
        return false;
    };
    if stored_question_end != question_end {
        return false;
    }
    if !dns::questions_match(&stored[12..question_end], &query[12..question_end]) {
        return false;
    }
    let sv = dns::extract_variant(stored, stored_question_end);
    let qv = dns::extract_variant(query, question_end);
    sv.has_opt == qv.has_opt
        && sv.do_bit == qv.do_bit
        && sv.edns_version == qv.edns_version
        && sv.rd == qv.rd
        && sv.ad == qv.ad
        && sv.cd == qv.cd
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
mod tests {
    use super::*;
    use crate::config::{CacheConfig, GroupCachePolicy};

    fn base_cache_config() -> CacheConfig {
        CacheConfig {
            capacity: 256,
            stale_expire_ttl: 0,
            stale_ttl: 30,
            stale_ttl_reset: true,
            nodata_ttl: 0,
            min_ttl: 0,
            max_ttl: 0,
            refresh: None,
            refresh_min_ttl: None,
        }
    }

    fn no_override_policy() -> GroupCachePolicy {
        GroupCachePolicy {
            skip: false,
            stale_expire_ttl: None,
            stale_ttl: None,
            nodata_ttl: None,
            min_ttl: None,
            max_ttl: None,
            refresh_percent: None,
        }
    }

    /// Build a minimal DNS A-record response + matching query for "test.local".
    /// Returns (response_packet, query_packet, question_end).
    fn make_test_packets(ttl: u32) -> (Vec<u8>, Vec<u8>, usize) {
        // qname: \x04test\x05local\x00 (12 bytes)
        let qname: &[u8] = b"\x04test\x05local\x00";

        let mut query = vec![
            0x00, 0x01, // ID = 1
            0x01, 0x00, // QR=0, RD=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        query.extend_from_slice(qname);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
        let question_end = query.len(); // 12 + 12 + 4 = 28

        let mut response = vec![
            0x00, 0x01, // ID = 1
            0x81, 0x80, // QR=1, RD=1, RA=1, RCODE=0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, 0x00, 0x00,
        ];
        // Question section
        response.extend_from_slice(qname);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer RR: name + type + class + TTL + rdlength + rdata
        // TTL offset in this packet = 28 (question_end) + 12 (qname) + 4 (type+class) = 44
        response.extend_from_slice(qname);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x04, 1, 2, 3, 4]);

        (response, query, question_end)
    }

    /// Read the wire TTL from the first answer record of a packet produced by
    /// `make_test_packets`. The TTL sits at offset 44 in that layout.
    fn read_wire_ttl(pkt: &[u8]) -> u32 {
        u32::from_be_bytes(pkt[44..48].try_into().unwrap())
    }

    fn add_to_cache(
        cache: &DnsCache,
        ttl: u32,
        policy: Option<&GroupCachePolicy>,
    ) -> (Vec<u8>, usize) {
        let (response, query, question_end) = make_test_packets(ttl);
        let key = cache_key(&query, question_end);
        let resolved = cache.resolve_policy(policy);
        cache.add(
            CacheInsert {
                key,
                qname: Arc::from("test.local"),
                question_end,
                query: &query,
                packet: &response,
            },
            &resolved,
            0u16,
        );
        (query, question_end)
    }

    #[test]
    fn per_group_min_ttl_raises_wire_ttl() {
        let cache = DnsCache::new(&base_cache_config());
        let policy = GroupCachePolicy {
            min_ttl: Some(60),
            ..no_override_policy()
        };
        let (query, question_end) = add_to_cache(&cache, 10, Some(&policy));
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        // DNS said 10s, group min_ttl=60 → wire TTL must be at least 60.
        assert_eq!(read_wire_ttl(&hit.packet), 60);
    }

    #[test]
    fn per_group_max_ttl_caps_wire_ttl() {
        let cache = DnsCache::new(&base_cache_config());
        let policy = GroupCachePolicy {
            max_ttl: Some(300),
            ..no_override_policy()
        };
        let (query, question_end) = add_to_cache(&cache, 3600, Some(&policy));
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        // DNS said 3600s, group max_ttl=300 → wire TTL must not exceed 300.
        assert_eq!(read_wire_ttl(&hit.packet), 300);
    }

    #[test]
    fn global_min_ttl_applied_as_fallback() {
        let mut cfg = base_cache_config();
        cfg.min_ttl = 45;
        let cache = DnsCache::new(&cfg);
        let (query, question_end) = add_to_cache(&cache, 5, None);
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        assert_eq!(read_wire_ttl(&hit.packet), 45);
    }

    #[test]
    fn global_max_ttl_applied_as_fallback() {
        let mut cfg = base_cache_config();
        cfg.max_ttl = 120;
        let cache = DnsCache::new(&cfg);
        let (query, question_end) = add_to_cache(&cache, 86400, None);
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        assert_eq!(read_wire_ttl(&hit.packet), 120);
    }

    #[test]
    fn per_group_refresh_percent_triggers_refresh() {
        let cache = DnsCache::new(&base_cache_config());
        // refresh_percent=100 means: trigger when remaining*100 <= ttl*100, i.e. always.
        let policy = GroupCachePolicy {
            refresh_percent: Some(100),
            ..no_override_policy()
        };
        let (query, question_end) = add_to_cache(&cache, 100, Some(&policy));
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        assert!(
            hit.refresh.is_some(),
            "expected a refresh request with refresh_percent=100"
        );
    }

    #[test]
    fn no_refresh_without_policy() {
        let cache = DnsCache::new(&base_cache_config());
        let (query, question_end) = add_to_cache(&cache, 100, None);
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        assert!(
            hit.refresh.is_none(),
            "expected no refresh when no policy is set"
        );
    }

    #[test]
    fn per_group_policy_overrides_global_min_ttl() {
        // Global min=30, group min=5. Group should win: wire TTL = max(ttl, 5) not max(ttl, 30).
        let mut cfg = base_cache_config();
        cfg.min_ttl = 30;
        let cache = DnsCache::new(&cfg);
        let policy = GroupCachePolicy {
            min_ttl: Some(5),
            ..no_override_policy()
        };
        let (query, question_end) = add_to_cache(&cache, 10, Some(&policy));
        let hit = cache
            .get(&query, question_end, 1)
            .expect("expected cache hit");
        // With group min_ttl=5 taking precedence, wire TTL = 10 (the DNS TTL, since 10 > 5).
        assert_eq!(read_wire_ttl(&hit.packet), 10);
    }

    #[test]
    fn edns_variant_does_not_share_cache_entry() {
        let cache = DnsCache::new(&base_cache_config());
        let (response, query, question_end) = make_test_packets(100);
        let resolved = cache.resolve_policy(None);
        cache.add(
            CacheInsert {
                key: cache_key(&query, question_end),
                qname: Arc::from("test.local"),
                question_end,
                query: &query,
                packet: &response,
            },
            &resolved,
            0,
        );

        let mut edns_query = query.clone();
        edns_query[11] = 1; // ARCOUNT = 1
        edns_query.extend_from_slice(&[
            0x00, // root owner name
            0x00, 0x29, // OPT
            0x10, 0x00, // UDP payload size
            0x00, 0x00, 0x80, 0x00, // DO flag
            0x00, 0x00, // RDLEN
        ]);

        assert!(cache.get(&edns_query, question_end, 2).is_none());
    }

    /// Build a query packet that includes an EDNS OPT record.
    fn make_edns_query(do_bit: bool) -> (Vec<u8>, usize) {
        let (_, mut query, question_end) = make_test_packets(100);
        query[11] = 1; // ARCOUNT = 1
        let do_byte: u8 = if do_bit { 0x80 } else { 0x00 };
        query.extend_from_slice(&[
            0x00,             // root owner name
            0x00, 0x29,       // type OPT (41)
            0x10, 0x00,       // UDP payload size = 4096
            0x00, 0x00,       // ext-rcode, EDNS version 0
            do_byte, 0x00,    // flags — DO bit in high byte
            0x00, 0x00,       // RDLEN = 0
        ]);
        (query, question_end)
    }

    /// Build a query with an EDNS OPT record containing an ECS option.
    /// `src_ip_last_octet` varies the source address (/24 prefix).
    fn make_ecs_query(src_ip_last_octet: u8) -> (Vec<u8>, usize) {
        let (_, mut query, question_end) = make_test_packets(100);
        // ECS OPTION-DATA: FAMILY=1 (IPv4), SOURCE-PREFIX-LENGTH=24, SCOPE=0, ADDRESS=1.2.X.0
        let ecs_data: [u8; 7] = [
            0x00, 0x01,          // FAMILY = 1
            24,                  // SOURCE-PREFIX-LENGTH
            0x00,                // SCOPE-PREFIX-LENGTH
            1, 2, src_ip_last_octet, // Address — 3 bytes for /24
        ];
        let opt_rdata_len: u16 = 4 + ecs_data.len() as u16; // code(2) + len(2) + data
        query[11] = 1; // ARCOUNT = 1
        query.extend_from_slice(&[
            0x00,       // root owner name
            0x00, 0x29, // type OPT
            0x10, 0x00, // UDP payload size
            0x00, 0x00, // ext-rcode, version
            0x00, 0x00, // flags
        ]);
        query.extend_from_slice(&opt_rdata_len.to_be_bytes()); // RDLEN
        query.extend_from_slice(&[0x00, 0x0b]);                // OPTION-CODE = 11 (ECS)
        query.extend_from_slice(&(ecs_data.len() as u16).to_be_bytes()); // OPTION-LENGTH
        query.extend_from_slice(&ecs_data);
        (query, question_end)
    }

    #[test]
    fn do_bit_zero_and_one_use_separate_cache_entries() {
        let cache = DnsCache::new(&base_cache_config());
        let (response, _, _) = make_test_packets(100);
        let resolved = cache.resolve_policy(None);

        // Cache a response under a DO=0 EDNS query.
        let (query_do0, question_end) = make_edns_query(false);
        cache.add(
            CacheInsert {
                key: cache_key(&query_do0, question_end),
                qname: Arc::from("test.local"),
                question_end,
                query: &query_do0,
                packet: &response,
            },
            &resolved,
            0,
        );

        // A DO=1 query must not hit the DO=0 entry.
        let (query_do1, _) = make_edns_query(true);
        assert!(
            cache.get(&query_do1, question_end, 1).is_none(),
            "DO=1 query must not share a DO=0 cache entry"
        );

        // After caching a DO=1 response, that same DO=1 query must hit.
        cache.add(
            CacheInsert {
                key: cache_key(&query_do1, question_end),
                qname: Arc::from("test.local"),
                question_end,
                query: &query_do1,
                packet: &response,
            },
            &resolved,
            0,
        );
        assert!(
            cache.get(&query_do1, question_end, 1).is_some(),
            "DO=1 query must hit its own cache entry"
        );
    }

    #[test]
    fn ecs_source_subnet_isolates_cache_entries() {
        let cache = DnsCache::new(&base_cache_config());
        let (response, _, _) = make_test_packets(100);
        let resolved = cache.resolve_policy(None);

        // Cache a response for ECS subnet 1.2.3.0/24.
        let (query_a, question_end) = make_ecs_query(3);
        cache.add(
            CacheInsert {
                key: cache_key(&query_a, question_end),
                qname: Arc::from("test.local"),
                question_end,
                query: &query_a,
                packet: &response,
            },
            &resolved,
            0,
        );

        // A query from a different /24 subnet must miss.
        let (query_b, _) = make_ecs_query(4);
        assert!(
            cache.get(&query_b, question_end, 1).is_none(),
            "ECS 1.2.4.0/24 must not share an entry cached for 1.2.3.0/24"
        );

        // The original subnet must still hit.
        assert!(
            cache.get(&query_a, question_end, 1).is_some(),
            "ECS 1.2.3.0/24 query must still hit its own entry"
        );
    }

    #[test]
    fn cache_key_strip_ecs_matches_no_ecs_query() {
        // With no ECS, strip_ecs key should equal normal key
        let (_, query, question_end) = make_test_packets(100);
        assert_eq!(cache_key(&query, question_end), cache_key_strip_ecs(&query, question_end));
    }

    #[test]
    fn ecs_fallback_lookup_finds_strip_ecs_entry() {
        let cache = DnsCache::new(&base_cache_config());
        let (response, _, _) = make_test_packets(100);
        let resolved = cache.resolve_policy(None);

        // Cache a response with an ECS query from one subnet, using strip_ecs key
        let (query_a, question_end) = make_ecs_query(3);
        let stripped = dns::strip_edns_ecs(&query_a).unwrap();
        let key = cache_key_strip_ecs(&query_a, question_end);
        cache.add(
            CacheInsert {
                key,
                qname: Arc::from("test.local"),
                question_end,
                query: &stripped,
                packet: &response,
            },
            &resolved,
            0,
        );

        // A different ECS subnet should find the strip_ecs cached entry via fallback
        let (query_b, _) = make_ecs_query(77);
        assert!(
            cache.get_with_ecs_fallback(&query_b, question_end, 1).is_some(),
            "ECS fallback should find the strip-ecs cached entry"
        );
    }

    #[test]
    fn cache_hit_restores_current_question_case() {
        let cache = DnsCache::new(&base_cache_config());
        let (query, question_end) = add_to_cache(&cache, 100, None);
        let mut mixed_case_query = query;
        mixed_case_query[13..17].copy_from_slice(b"TeSt");
        mixed_case_query[18..23].copy_from_slice(b"LoCaL");

        let hit = cache
            .get(&mixed_case_query, question_end, 2)
            .expect("expected case-insensitive cache hit");

        assert_eq!(
            &hit.packet[12..question_end],
            &mixed_case_query[12..question_end]
        );
    }
}
