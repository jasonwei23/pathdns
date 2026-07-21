//! Verdict cache for `fallback: none` routing decisions.
//!
//! ## When this cache is active
//! Entries are added only when ALL of these conditions hold simultaneously:
//!   1. `fallback.default-rule` is `"none"` with an ipset configured.
//!   2. The query type is A (1) or AAAA (28).
//!   3. The domain is NOT matched by any custom rule rule.
//!
//! If routing is fully covered by rule rules, virtually no domain reaches the
//! `none` fallback and the verdict cache correctly stays empty.
//!
//! ## What is cached
//! After racing both primary and secondary upstreams and testing the primary's
//! response IPs against the configured ipset, the result is one of:
//!   - `PrimaryIp`: cached as `true`  (route future queries to primary upstream)
//!   - `SecondaryIp`: cached as `false` (route future queries to secondary upstream)
//!   - `NoIpFound` / `OtherCase`: NOT cached (uncertain; re-races next time)
//!
//! ## Implementation
//! Uses a `quick_cache::sync::Cache` with a capacity bound; TTL is enforced
//! lazily on read (see `is_expired`). `get` is on the hot path and avoids allocation.
//!
//! ## Persistence
//! When `cache-persist-path` is configured, verdicts are saved alongside the DNS
//! cache to `<cache-persist-path>.verdict` (same magic + config-fingerprint scheme;
//! see `save_to_file`).  Each entry carries its original insert time so reloaded
//! verdicts expire at their original deadline rather than getting a fresh TTL.

use crate::config::VerdictCacheConfig;
use crate::persist::atomic_write;
use anyhow::{Context, Result};
use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::UnitWeighter;
use rustc_hash::FxBuildHasher;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk format magic; bump when the layout changes.
const PERSIST_MAGIC: &[u8; 8] = b"PDNSV001";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Sibling path for the verdict persist file: `<cache_persist_path>.verdict`.
pub fn persist_path_for(cache_path: &Path) -> PathBuf {
    let mut os = cache_path.as_os_str().to_os_string();
    os.push(".verdict");
    PathBuf::from(os)
}

/// Cached verdict plus its insert time (epoch seconds) for expiry on reload.
#[derive(Debug, Clone, Copy)]
struct VerdictEntry {
    is_primary: bool,
    inserted_unix: u64,
}

#[derive(Debug, Clone)]
pub struct VerdictCache {
    inner: Option<Arc<Cache<String, VerdictEntry, UnitWeighter, FxBuildHasher>>>,
    /// TTL in seconds; 0 = entries never expire.
    ttl_secs: u64,
}

impl VerdictCache {
    pub fn new(cfg: Option<&VerdictCacheConfig>) -> Self {
        let Some(cfg) = cfg else {
            return Self {
                inner: None,
                ttl_secs: 0,
            };
        };
        if cfg.capacity == 0 {
            return Self {
                inner: None,
                ttl_secs: 0,
            };
        }

        // TTL is enforced only by the manual `is_expired` check below, not by the
        // cache map: a reload-from-disk carries each entry's original
        // `inserted_unix` deadline, which a map-level TTL clock (re-anchored at
        // reload) would diverge from anyway, so tracking it in the map too would
        // be pure overhead. (quick-cache has no map-level TTL regardless.)
        //
        // `FxBuildHasher` instead of the cache's default hasher: qnames are not
        // attacker-controlled in a way that matters here (worst case is uneven
        // cache distribution, not a DoS), matching `DnsCache` and the route
        // cache in `route_index.rs`.
        let cache = Cache::with(
            cfg.capacity,
            cfg.capacity as u64,
            UnitWeighter,
            FxBuildHasher,
            DefaultLifecycle::default(),
        );
        Self {
            inner: Some(Arc::new(cache)),
            ttl_secs: cfg.ttl.as_secs(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// `true` when an entry inserted at `inserted_unix` is past its deadline.
    /// Every entry (in-process or reloaded) is expired lazily here on read,
    /// against its own original `inserted_unix` deadline.
    fn is_expired(&self, inserted_unix: u64, now: u64) -> bool {
        self.ttl_secs > 0 && now >= inserted_unix.saturating_add(self.ttl_secs)
    }

    /// Look up a routing verdict for a domain name.
    ///
    /// `qname` must already be normalized (lowercase, no trailing dot).
    pub fn get(&self, qname: &str) -> Option<bool> {
        let entry = self.inner.as_ref()?.get(qname)?;
        if self.is_expired(entry.inserted_unix, now_unix()) {
            return None;
        }
        Some(entry.is_primary)
    }

    /// Invalidate all cached routing decisions.
    ///
    /// Routing configuration and ipset-backed policy can change independently of
    /// the cached DNS responses, so callers must clear verdicts whenever routing
    /// state is reloaded.
    pub fn invalidate_all(&self) {
        if let Some(cache) = &self.inner {
            cache.clear();
        }
    }

    /// `qname` must already be normalized (lowercase, no trailing dot) — same
    /// contract as [`Self::get`]. Every call site derives it from
    /// `dns::qname_from_question`, which already lowercases and bounds it to the
    /// DNS wire limit, so re-validating with `domain::normalize_domain` here
    /// would just be a second allocating pass over a value already known-good.
    pub fn add(&self, qname: &str, is_primary_domain: bool) {
        let Some(cache) = &self.inner else {
            return;
        };
        cache.insert(
            qname.to_string(),
            VerdictEntry {
                is_primary: is_primary_domain,
                inserted_unix: now_unix(),
            },
        );
    }

    /// Save live verdicts to `path` (atomic tmp + rename).
    ///
    /// `fingerprint` is the same config hash used by the DNS cache persist file;
    /// a verdict cache built under a different rule/fallback config is rejected
    /// on load rather than misapplied.
    pub fn save_to_file(&self, path: &Path, fingerprint: u64) -> Result<usize> {
        let Some(cache) = &self.inner else {
            return Ok(0);
        };
        let now = now_unix();

        let mut entries: Vec<(String, VerdictEntry)> = Vec::new();
        for (k, v) in cache.iter() {
            if self.is_expired(v.inserted_unix, now) {
                continue;
            }
            entries.push((k, v));
        }

        let count = entries.len();
        atomic_write(path, |w| {
            crate::persist::write_header(w, PERSIST_MAGIC, fingerprint, count as u32)?;
            for (qname, entry) in &entries {
                w.write_all(&entry.inserted_unix.to_le_bytes())?;
                w.write_all(&[entry.is_primary as u8])?;
                let b = qname.as_bytes();
                w.write_all(&(b.len() as u16).to_le_bytes())?;
                w.write_all(b)?;
            }
            Ok(())
        })?;
        Ok(count)
    }

    /// Load verdicts from `path`, skipping entries past their original deadline.
    /// Returns the number of entries loaded.
    pub fn load_from_file(&self, path: &Path, fingerprint: u64) -> Result<usize> {
        let Some(cache) = &self.inner else {
            return Ok(0);
        };

        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut r = BufReader::new(file);

        let count = crate::persist::read_and_check_header(
            &mut r,
            PERSIST_MAGIC,
            fingerprint,
            "verdict cache",
        )? as usize;
        let now = now_unix();
        let mut loaded = 0usize;
        for _ in 0..count {
            let inserted_unix = crate::persist::read_u64(&mut r)?;
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let qname_len = crate::persist::read_u16(&mut r)? as usize;
            let mut qname_bytes = vec![0u8; qname_len];
            r.read_exact(&mut qname_bytes)?;

            if self.is_expired(inserted_unix, now) {
                continue;
            }
            let Ok(qname) = String::from_utf8(qname_bytes) else {
                continue;
            };
            cache.insert(
                qname,
                VerdictEntry {
                    is_primary: flag[0] != 0,
                    inserted_unix,
                },
            );
            loaded += 1;
        }
        Ok(loaded)
    }
}

// Tests.
