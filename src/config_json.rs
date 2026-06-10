//! JSON configuration file support (`-c path.json`).
//!
//! `JsonConfig` is the raw deserialised representation of the config file.
//! It is parsed once at startup and consumed by `Config::from_json` in
//! `config.rs`, which validates it and builds the `Config` struct.
//!
//! # Minimal example – default-group is a named group
//!
//! ```json
//! {
//!   "bind":          "0.0.0.0:53",
//!   "geosite-file":  ["/etc/pathdns/geosite.dat"],
//!   "group": [
//!     { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
//!     { "name": "overseas", "tag": ["!cn"], "upstream": ["tcp://1.1.1.1"] }
//!   ],
//!   "fallback": { "default-group": "domestic" },
//!   "cache": { "size": 10000 }
//! }
//! ```
//!
//! # Example – default-group "none" with primary/secondary and ipset
//!
//! ```json
//! {
//!   "bind":         "0.0.0.0:53",
//!   "geosite-file": ["/etc/pathdns/geosite.dat"],
//!   "group": [
//!     { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"],
//!       "add-ip": "mainroute,mainroute6" },
//!     { "name": "overseas", "tag": ["!cn"], "upstream": ["tcp://1.1.1.1"] }
//!   ],
//!   "fallback": {
//!     "default-group": "none",
//!     "primary":       "domestic",
//!     "secondary":     "overseas",
//!     "ipset-name4":   "mainroute",
//!     "ipset-name6":   "mainroute6"
//!   },
//!   "cache": { "size": 10000 }
//! }
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Group-level cache overrides.  Only per-entry behavior may be configured here;
/// runtime/instance settings (`persist`, `stale-client-timeout`, `refresh-min-ttl`,
/// `stale-ttl-reset`) are global-only.  `size` only accepts `0` (skip cache).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonGroupCacheSection {
    /// Only `0` is accepted — disables caching for this group.
    pub(crate) size: Option<usize>,
    pub(crate) stale_expire_ttl: Option<u64>,
    pub(crate) stale_ttl: Option<u32>,
    pub(crate) nodata_ttl: Option<u32>,
    pub(crate) min_ttl: Option<u32>,
    pub(crate) max_ttl: Option<u32>,
    pub(crate) refresh: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonConfig {
    // Listener
    pub(crate) bind: Option<String>,
    pub(crate) worker_threads: Option<usize>,
    pub(crate) verbose: Option<bool>,
    pub(crate) metrics_addr: Option<String>,

    // Upstreams / transport
    pub(crate) timeout: Option<u64>,
    pub(crate) udp_buf_size: Option<usize>,
    pub(crate) upstream_udp_sockets: Option<usize>,
    pub(crate) upstream_max_inflight: Option<usize>,
    pub(crate) max_inflight: Option<usize>,
    pub(crate) inflight_queue_ms: Option<u64>,
    pub(crate) hedge_delay_ms: Option<u64>,

    // GeoSite
    pub(crate) geosite_file: Option<Vec<String>>,

    // Cache
    pub(crate) cache: Option<JsonCacheSection>,

    // Verdict cache
    pub(crate) verdict_cache: Option<JsonVerdictCacheSection>,

    // ipset / nftset – add operations only (test sets live in fallback)
    pub(crate) no_ipset_blacklist: Option<bool>,

    // Groups
    /// Custom routing groups (matched top-to-bottom).
    pub(crate) group: Option<Vec<JsonGroupEntry>>,

    /// Fallback routing when no group matches. Required.
    pub(crate) fallback: Option<JsonFallbackSection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonFallbackSection {
    /// `"none"` | `"null"` | a group name defined in `group`.
    pub(crate) default_group: String,
    /// Required when `default-group` is `"none"`: primary upstream group name.
    pub(crate) primary: Option<String>,
    /// Required when `default-group` is `"none"`: secondary upstream group name.
    pub(crate) secondary: Option<String>,
    /// IPv4 nftset/ipset name for IP-based routing in `"none"` fallback.
    pub(crate) ipset_name4: Option<String>,
    /// IPv6 nftset/ipset name for IP-based routing in `"none"` fallback.
    pub(crate) ipset_name6: Option<String>,
    /// Treat NODATA primary replies as primary IPs for routing decisions.
    pub(crate) noip_as_primary_ip: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonCacheSection {
    pub(crate) size: Option<usize>,
    pub(crate) stale_expire_ttl: Option<u64>,
    pub(crate) stale_ttl: Option<u32>,
    pub(crate) stale_ttl_reset: Option<bool>,
    pub(crate) stale_client_timeout: Option<u64>,
    pub(crate) nodata_ttl: Option<u32>,
    pub(crate) min_ttl: Option<u32>,
    pub(crate) max_ttl: Option<u32>,
    pub(crate) refresh: Option<u32>,
    pub(crate) refresh_min_ttl: Option<u32>,
    pub(crate) persist: Option<JsonPersistSection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonPersistSection {
    pub(crate) path: String,
    pub(crate) interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonVerdictCacheSection {
    pub(crate) size: Option<usize>,
    pub(crate) ttl: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonGroupEntry {
    pub(crate) name: String,
    pub(crate) tag: Option<Vec<String>>,
    pub(crate) upstream: Option<Vec<String>>,
    /// Add resolved IPs from responses to this nftset/ipset pair (`"v4set,v6set"`).
    pub(crate) add_ip: Option<String>,
    pub(crate) cache: Option<JsonGroupCacheSection>,
    /// Accept both integer and array of integers.
    pub(crate) filter_qtype: Option<serde_json::Value>,
}

/// Parse a JSON config file and return the `JsonConfig` struct.
pub(crate) fn load_json_config(path: &Path) -> Result<JsonConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse config file: {}", path.display()))
}
