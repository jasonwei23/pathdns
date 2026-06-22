//! JSON configuration file support (`-c path.json`).
//!
//! `JsonConfig` is the raw deserialised representation of the config file.
//! It is parsed once at startup and consumed by `Config::from_json` in
//! `config.rs`, which validates it and builds the `Config` struct.
//!
//! # Minimal example – route.final as a rule name
//!
//! ```json
//! {
//!   "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
//!   "cache": { "size": 10000 },
//!   "route": {
//!     "geosite": ["/etc/pathdns/geosite.dat"],
//!     "rules": [
//!       { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
//!       { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://dns.google?bootstrap=119.29.29.29"] }
//!     ],
//!     "final": "domestic"
//!   }
//! }
//! ```
//!
//! # Example – ipset-test final (upstream decided by ipset membership)
//!
//! The primary's answer IPs are tested against the ipset: in the set → use the
//! primary's answer; not in the set → use the secondary's. Both rules are
//! queried concurrently only to hide latency — this is IP-policy routing, not
//! a race, so `ipset4`/`ipset6` are required in this form.
//!
//! ```json
//! {
//!   "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
//!   "cache": { "size": 10000 },
//!   "route": {
//!     "geosite": ["/etc/pathdns/geosite.dat"],
//!     "rules": [
//!       { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"],
//!         "add-ip": "mainroute,mainroute6" },
//!       { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://dns.google?bootstrap=119.29.29.29"] }
//!     ],
//!     "final": {
//!       "primary":       "domestic",
//!       "secondary":     "overseas",
//!       "ipset4":        "mainroute",
//!       "ipset6":        "mainroute6",
//!       "verdict-cache": { "size": 4096, "ttl": 3600 }
//!     }
//!   }
//! }
//! ```
//!
//! # Example – nftset with prefix-mask routing
//!
//! Use `family@table@set` to target an nftset instead of an ipset.
//! An optional fourth `@N` segment applies a prefix mask before insertion
//! (e.g. `inet@fw4@mainroute@24` inserts the /24 network address for each
//! resolved IPv4 address, useful for route tables keyed on prefixes).
//! The v4 and v6 set names are separated by a comma in `add-ip`;
//! use `"null"` to skip one address family.
//!
//! ```json
//! {
//!   "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
//!   "route": {
//!     "geosite": ["/etc/pathdns/geosite.dat"],
//!     "rules": [
//!       { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"],
//!         "add-ip": "inet@fw4@mainroute@24,inet@fw4@mainroute6@48" },
//!       { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://dns.google?bootstrap=119.29.29.29"] }
//!     ],
//!     "final": {
//!       "primary":   "domestic",
//!       "secondary": "overseas",
//!       "ipset4":    "inet@fw4@mainroute",
//!       "ipset6":    "inet@fw4@mainroute6"
//!     }
//!   }
//! }
//! ```
//!
//! ## Set name formats
//!
//! | Format | Meaning |
//! |--------|---------|
//! | `"myset"` | ipset named `myset` |
//! | `"myset/24"` | ipset named `myset`, IP masked to /24 before insertion |
//! | `"inet@fw4@myset"` | nftset: family `inet`, table `fw4`, set `myset` |
//! | `"inet@fw4@myset@24"` | same nftset, IP masked to /24 before insertion |
//!
//! The mask variants are useful with nftset `interval` sets: pathdns queries
//! the kernel for the `NFT_SET_INTERVAL` flag at startup and automatically
//! writes masked entries as prefix ranges (e.g. `1.2.3.0-1.2.3.255`).
//!

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Rule-level cache overrides.  Only per-entry behavior may be configured here;
/// runtime/instance settings (`persist`) are global-only.  `size` only accepts `0`
/// (skip cache).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonRuleCacheSection {
    /// Only `0` is accepted — disables caching for this rule.
    pub(crate) size: Option<usize>,
    pub(crate) min_ttl: Option<u32>,
    pub(crate) max_ttl: Option<u32>,
}

/// Optional runtime / protocol tuning knobs.
/// All fields have sensible auto-derived defaults; omit the entire section
/// (or individual fields within it) if the defaults are acceptable.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonRuntimeSection {
    // Concurrency
    pub(crate) worker_threads: Option<usize>,
    pub(crate) max_inflight: Option<usize>,
    pub(crate) inflight_queue_ms: Option<u64>,
    pub(crate) upstream_max_inflight: Option<usize>,
    pub(crate) upstream_udp_sockets: Option<usize>,
    // Timeouts
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) hedge_delay_ms: Option<u64>,
    pub(crate) tcp_max_connections: Option<usize>,
    pub(crate) tcp_read_timeout_ms: Option<u64>,
    pub(crate) tcp_idle_timeout_ms: Option<u64>,
    // UDP I/O
    pub(crate) udp_buf_size: Option<usize>,
    /// io_uring provided-buffer-ring depth per shard (receive burst headroom vs
    /// memory). Rounded up to a power of two. Default 256.
    pub(crate) uring_recv_buffers: Option<usize>,
    // Upstream health / selection
    pub(crate) upstream_max_response_bytes: Option<usize>,
}

/// DNS listener configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonBindSection {
    /// IP address(es) to listen on.  String or array of IP strings (without port).
    /// Defaults to `"127.0.0.1"` when omitted.
    pub(crate) addr: Option<serde_json::Value>,
    /// UDP/TCP port to listen on.  Defaults to 65353 when omitted.
    pub(crate) port: Option<u16>,
    /// Protocol: `"udp"`, `"tcp"`, or absent for both (default).
    pub(crate) proto: Option<String>,
    /// Network interface filter: `["eth0","br-lan"]` to allow only named
    /// interfaces, `["!wan"]` to accept from all except the listed ones, or
    /// absent/`[]` to bind all interfaces (default).  Applied via SO_BINDTODEVICE.
    pub(crate) interface: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonConfig {
    // Listener
    pub(crate) bind: Option<JsonBindSection>,

    // Dashboard (query log + HTTP API)
    pub(crate) dashboard: Option<JsonDashboardSection>,

    // Cache
    pub(crate) cache: Option<JsonCacheSection>,

    // Runtime / protocol tuning (all fields have auto-derived defaults)
    pub(crate) runtime: Option<JsonRuntimeSection>,

    /// Routing section: geosite data sources, rule rules, and final routing target.
    pub(crate) route: Option<JsonRouteSection>,
}

/// Routing section — rules all routing-related config in one place.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonRouteSection {
    /// GeoSite data files used by rule tag matching.
    pub(crate) geosite: Option<Vec<String>>,
    /// Ordered list of routing rules (matched top-to-bottom).
    pub(crate) rules: Option<Vec<JsonRuleEntry>>,
    /// Domain → fixed-answer map, consulted before `rules`. Keys are domain
    /// patterns (`full:`, `domain:`, `keyword:`, `regexp:`, or bare = suffix);
    /// values are a single `A://`/`AAAA://`/`CNAME://`/`RCODE://` URL or an
    /// array of them (e.g. one `A://` plus one `AAAA://`).
    pub(crate) answer: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    /// Target when no rule matches. Either a string (rule name) or a
    /// `JsonFinalSection` object for ipset-test mode. Omit to fall back to the
    /// last rule.
    #[serde(rename = "final")]
    pub(crate) route_final: Option<serde_json::Value>,
}

/// The object form of `route.final` configures **ipset-test mode**: both rules
/// are queried concurrently (for latency), but the answer that is returned is
/// decided by ipset membership — if the primary's answer IPs are found in the
/// configured ipset, the primary's answer is used, otherwise the secondary's.
/// At least one of `ipset4`/`ipset6` is required.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonFinalSection {
    /// Rule whose answer is preferred when its IPs are in the ipset.
    pub(crate) primary: Option<String>,
    /// Rule whose answer is used when the primary's IPs are NOT in the ipset.
    pub(crate) secondary: Option<String>,
    /// IPv4 nftset/ipset name the primary's answer IPs are tested against.
    pub(crate) ipset4: Option<String>,
    /// IPv6 nftset/ipset name the primary's answer IPs are tested against.
    pub(crate) ipset6: Option<String>,
    /// Treat NODATA primary replies as primary IPs for routing decisions.
    pub(crate) noip_as_primary_ip: Option<bool>,
    /// Verdict cache for ipset-test results.  Co-located here because it only
    /// applies when ipset-test mode is active.
    pub(crate) verdict_cache: Option<JsonVerdictCacheSection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonCacheSection {
    pub(crate) size: Option<usize>,
    pub(crate) min_ttl: Option<u32>,
    pub(crate) max_ttl: Option<u32>,
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
pub(crate) struct JsonRuleEntry {
    pub(crate) name: String,
    pub(crate) tag: Option<Vec<String>>,
    pub(crate) upstream: Option<Vec<String>>,
    /// Add resolved IPs from responses to this nftset/ipset pair (`"v4set,v6set"`).
    pub(crate) add_ip: Option<String>,
    pub(crate) cache: Option<JsonRuleCacheSection>,
    /// Accept both integer and array of integers.
    pub(crate) filter_qtype: Option<serde_json::Value>,
    /// Collapse CNAME chains in A/AAAA answers to a single record at the query name.
    pub(crate) collapse: Option<bool>,
}

/// Dashboard (query log viewer + HTTP API) configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonDashboardSection {
    /// HTTP API listen port.  Derives IP addresses from `bind.addr` with the port
    /// substituted, respecting the `bind.interface` filter.
    /// Omit to disable the dashboard entirely.
    pub(crate) port: Option<u16>,
    pub(crate) token: Option<String>,
    /// In-memory ring capacity.  0 = disable event collection (counters still active).
    pub(crate) memory: Option<usize>,
    /// mpsc channel depth.
    pub(crate) channel: Option<usize>,
    /// Extract A/AAAA answer IPs into each event.  Disabled by default.
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
