//! Cache for `route.final.answer-ip` decisions on unmatched A and AAAA queries.
//!
//! The key includes the question and DNS response variant, so IPv4/IPv6
//! answers and client subnets can route independently. Only decisions based
//! on a primary answer containing IP addresses are cached.
//!
//! Verdicts save beside the DNS response cache at `<persist.path>.verdict`.
//! Their original timestamps are retained across restarts.

use crate::config::VerdictCacheConfig;
use crate::dns::QueryVariant;
use crate::persist::atomic_write;
use anyhow::{Context, Result};
use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::UnitWeighter;
use rustc_hash::FxBuildHasher;
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk format magic; bump when the layout changes.
const PERSIST_MAGIC: &[u8; 8] = b"PDNSV002";

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct VerdictKey {
    pub qname: Arc<str>,
    pub qtype: u16,
    pub qclass: u16,
    pub variant: QueryVariant,
}

#[derive(Debug)]
pub struct VerdictCache {
    inner: Option<Cache<VerdictKey, VerdictEntry, UnitWeighter, FxBuildHasher>>,
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
        let cache = Cache::with(
            cfg.capacity,
            cfg.capacity as u64,
            UnitWeighter,
            FxBuildHasher,
            DefaultLifecycle::default(),
        );
        Self {
            inner: Some(cache),
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

    pub(crate) fn get(&self, key: &VerdictKey) -> Option<bool> {
        let entry = self.inner.as_ref()?.get(key)?;
        if self.is_expired(entry.inserted_unix, now_unix()) {
            return None;
        }
        Some(entry.is_primary)
    }

    pub(crate) fn add(&self, key: VerdictKey, is_primary: bool) {
        if let Some(cache) = &self.inner {
            cache.insert(
                key,
                VerdictEntry {
                    is_primary,
                    inserted_unix: now_unix(),
                },
            );
        }
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

        let mut entries = Vec::new();
        for (k, v) in cache.iter() {
            if self.is_expired(v.inserted_unix, now) {
                continue;
            }
            entries.push((k, v));
        }

        let count = entries.len();
        atomic_write(path, |w| {
            crate::persist::write_header(w, PERSIST_MAGIC, fingerprint, count as u32)?;
            for (key, entry) in &entries {
                w.write_all(&entry.inserted_unix.to_le_bytes())?;
                w.write_all(&[entry.is_primary as u8])?;
                let key_bytes = rmp_serde::to_vec(key).context("encode verdict key")?;
                w.write_all(&(key_bytes.len() as u32).to_le_bytes())?;
                w.write_all(&key_bytes)?;
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
            let key_bytes = crate::persist::read_bytes(&mut r)?;

            if self.is_expired(inserted_unix, now) {
                continue;
            }
            let key = rmp_serde::from_slice(&key_bytes).context("decode verdict key")?;
            cache.insert(
                key,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EcsSubnet;
    use crate::dns;

    #[test]
    fn persistence_keeps_question_type_and_ecs_family_separate() {
        let (query, question_end) = dns::synthetic_query("cache.test", 1).unwrap();
        let key = |qtype, addr: &str| {
            let subnet = EcsSubnet {
                addr: addr.parse().unwrap(),
                prefix_len: 0,
            };
            let query = dns::inject_or_replace_ecs(&query, &subnet).unwrap();
            VerdictKey {
                qname: Arc::from("cache.test"),
                qtype,
                qclass: 1,
                variant: dns::extract_variant(&query, question_end),
            }
        };
        let config = VerdictCacheConfig {
            capacity: 8,
            ttl: std::time::Duration::ZERO,
        };
        let a_v4 = key(1, "0.0.0.0");
        let a_v6 = key(1, "::");
        let aaaa_v4 = key(28, "0.0.0.0");
        assert_eq!(a_v4.variant.ecs_src.unwrap().family, 1);
        assert_eq!(a_v6.variant.ecs_src.unwrap().family, 2);

        let cache = VerdictCache::new(Some(&config));
        cache.add(a_v4.clone(), true);
        cache.add(a_v6.clone(), false);
        cache.add(aaaa_v4.clone(), false);
        let path = std::env::temp_dir().join(format!(
            "pathdns-verdict-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        assert_eq!(cache.save_to_file(&path, 11).unwrap(), 3);

        let restored = VerdictCache::new(Some(&config));
        assert_eq!(restored.load_from_file(&path, 11).unwrap(), 3);
        assert_eq!(restored.get(&a_v4), Some(true));
        assert_eq!(restored.get(&a_v6), Some(false));
        assert_eq!(restored.get(&aaaa_v4), Some(false));

        std::fs::write(&path, b"PDNSV001").unwrap();
        assert!(restored.load_from_file(&path, 11).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
