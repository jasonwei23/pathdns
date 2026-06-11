//! JSON configuration file support (`-c path.json`).
//!
//! `JsonConfig` is the raw deserialised representation of the config file.
//! It is parsed once at startup and consumed by `Config::from_json` in
//! `config.rs`, which validates it and builds the `Config` struct.
//!
//! # Minimal example – fallback routes to a named group
//!
//! ```json
//! {
//!   "bind":          ["0.0.0.0:53", "[::]:53"],
//!   "geosite-file":  ["/etc/pathdns/geosite.dat"],
//!   "group": [
//!     { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
//!     { "name": "overseas", "tag": ["!cn"], "upstream": ["tcp://1.1.1.1"] }
//!   ],
//!   "fallback": "domestic",
//!   "cache": { "size": 10000 }
//! }
//! ```
//!
//! # Example – racing fallback (primary/secondary with ipset test)
//!
//! ```json
//! {
//!   "bind":         ["0.0.0.0:53", "[::]:53"],
//!   "geosite-file": ["/etc/pathdns/geosite.dat"],
//!   "group": [
//!     { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"],
//!       "add-ip": "mainroute,mainroute6" },
//!     { "name": "overseas", "tag": ["!cn"], "upstream": ["tcp://1.1.1.1"] }
//!   ],
//!   "fallback": {
//!     "primary":       "domestic",
//!     "secondary":     "overseas",
//!     "ipset-name4":   "mainroute",
//!     "ipset-name6":   "mainroute6"
//!   },
//!   "cache": { "size": 10000 }
//! }
//! ```
//!
//! Legacy spellings `{"default-group": "<name>"}`, `{"default-group": "none", ...}`
//! and `{"default-group": "null"}` remain accepted.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Group-level cache overrides.  Only per-entry behavior may be configured here;
/// runtime/instance settings (`persist`, `stale-client-timeout-ms`, `refresh-min-ttl`,
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
    // Listener — accepts a single address string or an array of address strings.
    pub(crate) bind: Option<serde_json::Value>,
    pub(crate) worker_threads: Option<usize>,

    // Query log / dashboard
    pub(crate) querylog: Option<JsonQueryLogSection>,

    // Upstreams / transport
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) udp_buf_size: Option<usize>,
    pub(crate) upstream_udp_sockets: Option<usize>,
    pub(crate) upstream_max_inflight: Option<usize>,
    pub(crate) upstream_max_response_bytes: Option<usize>,
    pub(crate) max_inflight: Option<usize>,
    pub(crate) inflight_queue_ms: Option<u64>,
    pub(crate) hedge_delay_ms: Option<u64>,
    /// Maximum concurrent TCP client connections. 0 = unlimited.
    pub(crate) tcp_max_connections: Option<usize>,
    /// Timeout (ms) for reading the DNS message body after the 2-byte length prefix. 0 = disabled.
    pub(crate) tcp_read_timeout_ms: Option<u64>,
    /// Timeout (ms) for receiving the next request on an idle TCP connection. 0 = disabled.
    pub(crate) tcp_idle_timeout_ms: Option<u64>,

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
    /// Either a string (group name, or `"null"` for empty responses) or an
    /// object (see `JsonFallbackSection`).
    pub(crate) fallback: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonFallbackSection {
    /// Legacy selector: `"none"` | `"null"` | a group name defined in `group`.
    /// Optional — when omitted, a `primary`/`secondary` pair selects racing
    /// mode, and `"fallback": "<group>"` (string form) routes to a group.
    pub(crate) default_group: Option<String>,
    /// Racing mode: primary upstream group name.
    pub(crate) primary: Option<String>,
    /// Racing mode: secondary upstream group name.
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
    pub(crate) stale_client_timeout_ms: Option<u64>,
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

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonQueryLogSection {
    /// HTTP API listen address(es): a string or an array of strings
    /// (e.g. `["0.0.0.0:8080", "[::]:8080"]` for dual-stack).
    pub(crate) bind: Option<serde_json::Value>,
    pub(crate) token: Option<String>,
    /// In-memory ring capacity. 0 = disable event collection (counters still active).
    pub(crate) memory: Option<usize>,
    /// mpsc channel depth.
    pub(crate) channel: Option<usize>,
    /// Extract A/AAAA answer IPs into each event. Disabled by default.
    pub(crate) answer_ips: Option<bool>,
    pub(crate) file: Option<JsonQueryLogFile>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonQueryLogFile {
    pub(crate) dir: Option<String>,
    pub(crate) max_mb: Option<u64>,
    pub(crate) max_segments: Option<usize>,
    /// Maximum events to accumulate before one write call (default 256).
    pub(crate) batch_size: Option<usize>,
    /// How often the worker flushes the OS buffer in ms (default 500).
    pub(crate) flush_interval_ms: Option<u64>,
    /// Delete compressed segments older than this many days.
    pub(crate) retention_days: Option<u32>,
    /// Gzip-compress segments after rotation (default true).
    pub(crate) compress: Option<bool>,
}

/// Parse a JSON config file and return the `JsonConfig` struct.
pub(crate) fn load_json_config(path: &Path) -> Result<JsonConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse config file: {}", path.display()))
}
