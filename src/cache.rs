//! DNS response cache with RFC-compliant TTL management.
//!
//! Entries are keyed by FNV-1a hash of the DNS question section (qname + qtype + qclass).
//! qname label bytes are normalised to ASCII lowercase during hashing so that
//! `www.EXAMPLE.com` and `www.example.com` produce the same key (RFC 4343).
//! qtype and qclass are hashed without case folding.
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
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use moka::sync::Cache;
use std::cmp::Ordering as CmpOrdering;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type CacheKey = u64;

/// FNV-1a hash of DNS question bytes with qname label bytes normalised to lowercase.
pub fn cache_key(question: &[u8]) -> CacheKey {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut h = FNV_OFFSET;
    let mut pos = 0;

    loop {
        let Some(&len) = question.get(pos) else {
            break;
        };
        h ^= len as u64;
        h = h.wrapping_mul(FNV_PRIME);
        pos += 1;
        if len == 0 {
            break;
        }
        let end = (pos + len as usize).min(question.len());
        for &b in &question[pos..end] {
            h ^= b.to_ascii_lowercase() as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        pos = end;
    }

    for &b in question.get(pos..).unwrap_or(&[]) {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Sentinel key for NXDOMAIN cross-qtype caching.
/// Derived from the qname-only hash by XOR with a fixed pattern.
fn nxdomain_key(qname_hash: CacheKey) -> CacheKey {
    qname_hash ^ 0xFFFF_FFFF_FFFF_FFFF
}

/// Compute a hash of just the qname portion of a DNS question (excluding qtype/qclass).
fn qname_only_hash(question: &[u8]) -> CacheKey {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut h = FNV_OFFSET;
    let mut pos = 0;

    loop {
        let Some(&len) = question.get(pos) else { break };
        h ^= len as u64;
        h = h.wrapping_mul(FNV_PRIME);
        pos += 1;
        if len == 0 {
            break;
        }
        let end = (pos + len as usize).min(question.len());
        for &b in &question[pos..end] {
            h ^= b.to_ascii_lowercase() as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        pos = end;
    }
    h
}

/// Compare qname portions (up to and including the 0x00 terminator) of two DNS questions,
/// ignoring qtype/qclass. Case-insensitive on label bytes.
fn qname_eq_nocase(a: &[u8], b: &[u8]) -> bool {
    let mut pos = 0;
    loop {
        let len_a = *a.get(pos).unwrap_or(&0);
        let len_b = *b.get(pos).unwrap_or(&0);
        if len_a != len_b {
            return false;
        }
        pos += 1;
        if len_a == 0 {
            return true;
        }
        let end_a = pos + len_a as usize;
        let end_b = pos + len_b as usize;
        if end_a > a.len() || end_b > b.len() {
            return false;
        }
        for i in 0..len_a as usize {
            if a[pos + i].to_ascii_lowercase() != b[pos + i].to_ascii_lowercase() {
                return false;
            }
        }
        pos += len_a as usize;
    }
}

/// Case-insensitive comparison for DNS question wire bytes.
/// Label bytes are compared lowercase; qtype and qclass are compared exactly.
fn question_eq_nocase(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut pos = 0;
    loop {
        let Some(&len_a) = a.get(pos) else {
            break;
        };
        let Some(&len_b) = b.get(pos) else {
            return false;
        };
        if len_a != len_b {
            return false;
        }
        pos += 1;
        if len_a == 0 {
            break;
        }
        let end = pos + len_a as usize;
        if end > a.len() || end > b.len() {
            return false;
        }
        for i in pos..end {
            if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
                return false;
            }
        }
        pos = end;
    }
    a.get(pos..) == b.get(pos..)
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
    ttl_offsets: Arc<[usize]>,
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

    /// Look up a fresh or (when stale_secs > 0) proactively-served stale entry.
    /// Returns `CacheLookup.is_stale = true` when the entry's TTL had expired but it
    /// was still within the stale window; the caller should spawn a background refresh.
    pub fn get(&self, question: &[u8], client_id: u16) -> Option<CacheLookup> {
        self.lookup(question, client_id, self.stale_expire_ttl > 0)
    }

    /// Look up and write the response packet into a caller-provided buffer.
    /// Returns metadata without allocating a new `Bytes` for the packet.
    pub fn get_into(
        &self,
        question: &[u8],
        client_id: u16,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        self.lookup_into(question, client_id, self.stale_expire_ttl > 0, out)
    }

    /// Unconditional stale lookup used as an error fallback (upstream SERVFAIL / failure).
    pub fn get_stale(&self, question: &[u8], client_id: u16) -> Option<CacheLookup> {
        self.lookup(question, client_id, true)
    }

    pub fn add(
        &self,
        key: CacheKey,
        qname: std::sync::Arc<str>,
        question_end: usize,
        query: &[u8],
        packet: &[u8],
        policy: Option<&GroupCachePolicy>,
        group_id: u16,
    ) {
        let Some(cache) = &self.cache else {
            return;
        };
        if dns::is_truncated(packet) {
            return;
        }

        // Derive effective settings by merging group policy over global defaults.
        let nodata_ttl = policy.and_then(|p| p.nodata_ttl).unwrap_or(self.nodata_ttl);
        let stale_expire_ttl = policy
            .and_then(|p| p.stale_expire_ttl)
            .unwrap_or(self.stale_expire_ttl);
        let effective_min_ttl = policy.and_then(|p| p.min_ttl).unwrap_or(self.min_ttl);
        let effective_max_ttl = policy.and_then(|p| p.max_ttl).unwrap_or(self.max_ttl);
        let effective_stale_ttl = policy.and_then(|p| p.stale_ttl).unwrap_or(self.stale_ttl);
        let effective_refresh_percent = policy
            .and_then(|p| p.refresh_percent)
            .or(self.refresh_percent)
            .map(|v| v.min(100));

        // Apply min/max at write time so the stored TTL governs entry lifetime.
        let Some((raw_ttl, ttl_offsets)) = dns::effective_ttl_and_offsets(
            packet,
            question_end,
            nodata_ttl,
            effective_min_ttl,
            effective_max_ttl,
        ) else {
            return;
        };

        let mut packet = BytesMut::from(packet);
        // Normalize ID to 0 so the stored bytes are client-ID-agnostic.
        // lookup() patches the 2-byte ID field before returning a response.
        let _ = dns::set_id(&mut packet, 0);
        // Do NOT patch TTLs at write time; they are patched at read time with remaining TTL.
        let now = Instant::now();
        let stale_until = now + Duration::from_secs(raw_ttl as u64 + stale_expire_ttl);
        let question: Arc<[u8]> = Arc::from(&query[12..question_end]);
        let frozen_packet = packet.freeze();
        let entry = Arc::new(Entry {
            question: question.clone(),
            packet: frozen_packet,
            query: Bytes::copy_from_slice(query),
            qname,
            inserted: now,
            ttl: raw_ttl,
            stale_until,
            ttl_offsets: Arc::from(ttl_offsets.as_slice()),
            max_ttl: effective_max_ttl,
            stale_ttl: effective_stale_ttl,
            refresh_percent: effective_refresh_percent,
            group_id,
        });

        // If this response is NXDOMAIN, also store a sentinel under the qname-only key
        // so future queries for the same name with any qtype can be served an NXDOMAIN.
        if dns::rcode(entry.packet.as_ref()) == 3 {
            let question_bytes: &[u8] = &question;
            let nx_key = nxdomain_key(qname_only_hash(question_bytes));
            cache.insert(nx_key, entry.clone());
        }

        cache.insert(key, entry);
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

    fn lookup(&self, question: &[u8], client_id: u16, allow_stale: bool) -> Option<CacheLookup> {
        let cache = self.cache.as_ref()?;
        let key = cache_key(question);
        let (entry, evict_key, is_sentinel) = match cache.get(&key) {
            Some(e) if question_eq_nocase(e.question.as_ref(), question) => (e, key, false),
            _ => {
                // Cache miss: check NXDOMAIN sentinel for any-qtype NXDOMAIN.
                let nx_key = nxdomain_key(qname_only_hash(question));
                let nx_entry = cache.get(&nx_key)?;
                // Verify qname matches (ignore qtype, but require same qclass).
                if !qname_eq_nocase(nx_entry.question.as_ref(), question) {
                    return None;
                }
                let qlen = question.len();
                let eq_len = nx_entry.question.len();
                if qlen < 2
                    || eq_len < 2
                    || question[qlen - 2..] != nx_entry.question.as_ref()[eq_len - 2..]
                {
                    return None;
                }
                (nx_entry, nx_key, true)
            }
        };

        let now = Instant::now();
        let (remaining, is_stale) = match self.entry_freshness(&entry, now, allow_stale) {
            EntryFreshness::Fresh { remaining } => (remaining, false),
            EntryFreshness::Stale { advertised_ttl } => (advertised_ttl, true),
            EntryFreshness::Expired { evict } => {
                if evict {
                    cache.invalidate(&evict_key);
                }
                return None;
            }
        };

        // TTL was clamped at write time; remaining already reflects that.
        // No re-clamping here — that would freeze the countdown.
        let wire_ttl = remaining;

        let mut packet = BytesMut::from(entry.packet.as_ref());
        let _ = dns::set_id(&mut packet, client_id);
        if is_sentinel {
            // Patch qtype in the Question section to match the incoming query.
            let qlen = question.len();
            if qlen >= 4 {
                let qtype_off = 12 + qlen - 4;
                if qtype_off + 2 <= packet.len() {
                    packet[qtype_off..qtype_off + 2].copy_from_slice(&question[qlen - 4..qlen - 2]);
                }
            }
        }
        dns::patch_ttls_at(&mut packet, &entry.ttl_offsets, wire_ttl);
        let refresh = self.refresh_for(&key, &entry, remaining, is_stale);
        Some(CacheLookup {
            packet: packet.freeze(),
            refresh,
            is_stale,
            group_id: entry.group_id,
        })
    }

    fn lookup_into(
        &self,
        question: &[u8],
        client_id: u16,
        allow_stale: bool,
        out: &mut BytesMut,
    ) -> Option<CacheLookupMeta> {
        let cache = self.cache.as_ref()?;
        let key = cache_key(question);
        let (entry, evict_key, is_sentinel) = match cache.get(&key) {
            Some(e) if question_eq_nocase(e.question.as_ref(), question) => (e, key, false),
            _ => {
                let nx_key = nxdomain_key(qname_only_hash(question));
                let nx_entry = cache.get(&nx_key)?;
                if !qname_eq_nocase(nx_entry.question.as_ref(), question) {
                    return None;
                }
                let qlen = question.len();
                let eq_len = nx_entry.question.len();
                if qlen < 2
                    || eq_len < 2
                    || question[qlen - 2..] != nx_entry.question.as_ref()[eq_len - 2..]
                {
                    return None;
                }
                (nx_entry, nx_key, true)
            }
        };

        let now = Instant::now();
        let (remaining, is_stale) = match self.entry_freshness(&entry, now, allow_stale) {
            EntryFreshness::Fresh { remaining } => (remaining, false),
            EntryFreshness::Stale { advertised_ttl } => (advertised_ttl, true),
            EntryFreshness::Expired { evict } => {
                if evict {
                    cache.invalidate(&evict_key);
                }
                return None;
            }
        };

        let wire_ttl = remaining;

        out.clear();
        out.extend_from_slice(&entry.packet);
        let _ = dns::set_id(out, client_id);
        if is_sentinel {
            let qlen = question.len();
            if qlen >= 4 {
                let qtype_off = 12 + qlen - 4;
                if qtype_off + 2 <= out.len() {
                    out[qtype_off..qtype_off + 2].copy_from_slice(&question[qlen - 4..qlen - 2]);
                }
            }
        }
        dns::patch_ttls_at(out, &entry.ttl_offsets, wire_ttl);
        let refresh = self.refresh_for(&key, &entry, remaining, is_stale);
        Some(CacheLookupMeta {
            refresh,
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

        let tmp = path.with_extension("tmp");
        let file =
            std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        let mut w = BufWriter::new(file);

        // Collect live, non-sentinel entries.
        // Sentinel entries (NXDOMAIN cross-qtype keys) are excluded: they are re-derived
        // automatically on load when the canonical NXDOMAIN entry is inserted.
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
            // Skip sentinel entries; they are identified by key == nxdomain_key(qname_only_hash).
            if *key == nxdomain_key(qname_only_hash(&entry.question)) {
                continue;
            }
            entries.push((*key, entry));
        }

        // Magic encodes format implicitly; change it when the on-disk layout changes.
        // Fingerprint encodes the config; a mismatch on load causes the file to be discarded.
        w.write_all(b"PDNSC004")?;
        w.write_all(&fingerprint.to_le_bytes())?;
        w.write_all(&(entries.len() as u32).to_le_bytes())?;

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

            let offsets: &[usize] = &entry.ttl_offsets;
            w.write_all(&(offsets.len() as u32).to_le_bytes())?;
            for &off in offsets {
                w.write_all(&(off as u32).to_le_bytes())?;
            }

            w.write_all(&entry.max_ttl.to_le_bytes())?;
            w.write_all(&entry.stale_ttl.to_le_bytes())?;
            // refresh_percent: u32::MAX encodes None.
            w.write_all(&entry.refresh_percent.unwrap_or(u32::MAX).to_le_bytes())?;
            w.write_all(&entry.group_id.to_le_bytes())?;
        }

        w.flush()?;
        drop(w);
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(entries.len())
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
            &magic == b"PDNSC004",
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
            let mut offsets: Vec<usize> = Vec::with_capacity(offsets_count);
            for _ in 0..offsets_count {
                offsets.push(read_u32(&mut r)? as usize);
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

            // Re-derive NXDOMAIN sentinel if needed.
            if dns::rcode(entry.packet.as_ref()) == 3 {
                let nx_key = nxdomain_key(qname_only_hash(&question_arc));
                cache.insert(nx_key, entry.clone());
            }
            cache.insert(key, entry);
            loaded += 1;
        }

        Ok(loaded)
    }
}

fn read_u16(r: &mut impl Read) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(r: &mut impl Read) -> Result<u64> {
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
        let question = &query[12..question_end];
        let key = cache_key(question);
        cache.add(
            key,
            Arc::from("test.local"),
            question_end,
            &query,
            &response,
            policy,
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
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
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
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
        // DNS said 3600s, group max_ttl=300 → wire TTL must not exceed 300.
        assert_eq!(read_wire_ttl(&hit.packet), 300);
    }

    #[test]
    fn global_min_ttl_applied_as_fallback() {
        let mut cfg = base_cache_config();
        cfg.min_ttl = 45;
        let cache = DnsCache::new(&cfg);
        let (query, question_end) = add_to_cache(&cache, 5, None);
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
        assert_eq!(read_wire_ttl(&hit.packet), 45);
    }

    #[test]
    fn global_max_ttl_applied_as_fallback() {
        let mut cfg = base_cache_config();
        cfg.max_ttl = 120;
        let cache = DnsCache::new(&cfg);
        let (query, question_end) = add_to_cache(&cache, 86400, None);
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
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
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
        assert!(
            hit.refresh.is_some(),
            "expected a refresh request with refresh_percent=100"
        );
    }

    #[test]
    fn no_refresh_without_policy() {
        let cache = DnsCache::new(&base_cache_config());
        let (query, question_end) = add_to_cache(&cache, 100, None);
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
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
        let question = &query[12..question_end];
        let hit = cache.get(question, 1).expect("expected cache hit");
        // With group min_ttl=5 taking precedence, wire TTL = 10 (the DNS TTL, since 10 > 5).
        assert_eq!(read_wire_ttl(&hit.packet), 10);
    }
}
