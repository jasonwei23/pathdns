//! Verdict cache for `fallback: none` routing decisions.
//!
//! ## When this cache is active
//! Entries are added only when ALL of these conditions hold simultaneously:
//!   1. `fallback.default-group` is `"none"` with an ipset configured.
//!   2. The query type is A (1) or AAAA (28).
//!   3. The domain is NOT matched by any custom group rule.
//!
//! If routing is fully covered by group rules, virtually no domain reaches the
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
//! Uses a `moka::sync::Cache` with configurable TTL and capacity.
//! `get` is on the hot path and avoids allocation.
//!
//! ## Persistence
//! When `cache-persist-path` is configured, verdicts are saved alongside the DNS
//! cache to `<cache-persist-path>.verdict` (same magic + config-fingerprint scheme;
//! see `save_to_file`).  Each entry carries its original insert time so reloaded
//! verdicts expire at their original deadline rather than getting a fresh TTL.

use crate::config::VerdictCacheConfig;
use crate::persist::atomic_write;
use anyhow::{Context, Result};
use moka::sync::Cache;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    inner: Option<Arc<Cache<String, VerdictEntry>>>,
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

        let ttl = if cfg.ttl == Duration::ZERO {
            None
        } else {
            Some(cfg.ttl)
        };
        let mut builder = Cache::builder().max_capacity(cfg.capacity as u64);
        if let Some(t) = ttl {
            builder = builder.time_to_live(t);
        }
        Self {
            inner: Some(Arc::new(builder.build())),
            ttl_secs: cfg.ttl.as_secs(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// `true` when an entry inserted at `inserted_unix` is past its deadline.
    /// Only relevant for reloaded entries: in-process entries are expired by the
    /// moka TTL at the same boundary, but a reload restarts the moka clock, so the
    /// original deadline is enforced here.
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
            cache.invalidate_all();
        }
    }

    pub fn add(&self, qname: &str, is_primary_domain: bool) {
        let Some(cache) = &self.inner else {
            return;
        };
        let Some(qname) = crate::domain::normalize_domain(qname) else {
            return;
        };
        cache.insert(
            qname,
            VerdictEntry {
                is_primary: is_primary_domain,
                inserted_unix: now_unix(),
            },
        );
    }

    /// Save live verdicts to `path` (atomic tmp + rename).
    ///
    /// `fingerprint` is the same config hash used by the DNS cache persist file;
    /// a verdict cache built under a different group/fallback config is rejected
    /// on load rather than misapplied.
    pub fn save_to_file(&self, path: &Path, fingerprint: u64) -> Result<usize> {
        let Some(cache) = &self.inner else {
            return Ok(0);
        };
        cache.run_pending_tasks();
        let now = now_unix();

        let mut entries: Vec<(Arc<String>, VerdictEntry)> = Vec::new();
        for (k, v) in cache.iter() {
            if self.is_expired(v.inserted_unix, now) {
                continue;
            }
            entries.push((k, v));
        }

        let count = entries.len();
        atomic_write(path, |w| {
            w.write_all(PERSIST_MAGIC)?;
            w.write_all(&fingerprint.to_le_bytes())?;
            w.write_all(&(count as u32).to_le_bytes())?;
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

        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).context("read magic")?;
        anyhow::ensure!(
            &magic == PERSIST_MAGIC,
            "unrecognised verdict cache file format (magic mismatch)"
        );

        let stored_fp = crate::cache::read_u64(&mut r).context("read fingerprint")?;
        anyhow::ensure!(
            stored_fp == fingerprint,
            "verdict cache file was built with a different config (fingerprint mismatch) — discarding"
        );

        let count = crate::cache::read_u32(&mut r).context("read count")? as usize;
        let now = now_unix();
        let mut loaded = 0usize;
        for _ in 0..count {
            let inserted_unix = crate::cache::read_u64(&mut r)?;
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let qname_len = crate::cache::read_u16(&mut r)? as usize;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache(ttl_secs: u64) -> VerdictCache {
        VerdictCache::new(Some(&VerdictCacheConfig {
            capacity: 1000,
            ttl: Duration::from_secs(ttl_secs),
        }))
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pathdns-test-{}-{}", std::process::id(), name))
    }

    #[test]
    fn save_load_roundtrip() {
        let path = temp_path("roundtrip");
        let a = make_cache(3600);
        a.add("primary.example.com", true);
        a.add("secondary.example.com", false);
        let saved = a.save_to_file(&path, 42).unwrap();
        assert_eq!(saved, 2);

        let b = make_cache(3600);
        let loaded = b.load_from_file(&path, 42).unwrap();
        assert_eq!(loaded, 2);
        assert_eq!(b.get("primary.example.com"), Some(true));
        assert_eq!(b.get("secondary.example.com"), Some(false));
        assert_eq!(b.get("unknown.example.com"), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fingerprint_mismatch_rejected() {
        let path = temp_path("fp-mismatch");
        let a = make_cache(3600);
        a.add("example.com", true);
        a.save_to_file(&path, 1).unwrap();

        let b = make_cache(3600);
        assert!(b.load_from_file(&path, 2).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_entries_skipped_on_load() {
        let path = temp_path("expired");
        // ttl=1s: write an entry whose deadline has already passed by crafting the
        // file via a cache whose entries are saved, then loading after expiry.
        let a = make_cache(1);
        a.add("example.com", true);
        a.save_to_file(&path, 7).unwrap();

        std::thread::sleep(Duration::from_millis(1100));
        let b = make_cache(1);
        let loaded = b.load_from_file(&path, 7).unwrap();
        assert_eq!(loaded, 0);
        assert_eq!(b.get("example.com"), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn zero_ttl_never_expires() {
        let path = temp_path("zero-ttl");
        let a = make_cache(0);
        a.add("example.com", false);
        a.save_to_file(&path, 9).unwrap();

        let b = make_cache(0);
        let loaded = b.load_from_file(&path, 9).unwrap();
        assert_eq!(loaded, 1);
        assert_eq!(b.get("example.com"), Some(false));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invalidate_all_removes_cached_verdicts() {
        let cache = make_cache(0);
        cache.add("example.com", true);
        assert_eq!(cache.get("example.com"), Some(true));

        cache.invalidate_all();

        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn disabled_cache_saves_nothing() {
        let c = VerdictCache::new(None);
        assert_eq!(c.save_to_file(Path::new("/nonexistent"), 0).unwrap(), 0);
    }
}
