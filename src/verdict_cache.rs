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

use crate::config::VerdictCacheConfig;
use moka::sync::Cache;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VerdictCache {
    inner: Option<Arc<Cache<String, bool>>>,
}

impl VerdictCache {
    pub fn new(cfg: Option<&VerdictCacheConfig>) -> Self {
        let Some(cfg) = cfg else {
            return Self { inner: None };
        };
        if cfg.capacity == 0 {
            return Self { inner: None };
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
        }
    }

    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub fn len(&self) -> usize {
        let Some(cache) = self.inner.as_ref() else {
            return 0;
        };
        cache.run_pending_tasks();
        cache.entry_count() as usize
    }

    /// Look up a routing verdict for a domain name.
    ///
    /// `qname` must already be normalized (lowercase, no trailing dot).
    pub fn get(&self, qname: &str) -> Option<bool> {
        self.inner.as_ref()?.get(qname)
    }

    pub fn add(&self, qname: &str, is_primary_domain: bool) {
        let Some(cache) = &self.inner else {
            return;
        };
        let Some(qname) = crate::domain::normalize_domain(qname) else {
            return;
        };
        cache.insert(qname, is_primary_domain);
    }
}
