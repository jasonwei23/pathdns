//! JSON configuration file support (`-c path.json`).
//!
//! `JsonConfig` is the raw deserialised representation of the config file.
//! It is parsed once at startup and consumed by `Config::from_json` in
//! `config.rs`, which validates it and builds the `Config` struct.
//!
//! # Minimal example – route.final as a server name
//!
//! ```json
//! {
//!   "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
//!   "cache": { "size": 10000 },
//!   "route": {
//!     "servers": { "domestic-dns": "119.29.29.29", "overseas-dns": "tls://dns.google?bootstrap=domestic-dns" },
//!     "ruleset": [{ "tag": "cn", "format": "mrs", "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" }],
//!     "rules": [
//!       { "matcher": ["tag:cn"],  "upstream": "domestic-dns" },
//!       { "matcher": ["tag:!cn"], "upstream": "overseas-dns" }
//!     ],
//!     "final": "domestic-dns"
//!   }
//! }
//! ```
//!
//! # Example – answer-ip test final (upstream decided by IP-CIDR membership)
//!
//! The primary's answer IPs are tested against the `answer-ip`-tagged
//! `route.ruleset` entry: in the set → use the primary's answer; not in the
//! set → use the secondary's. Both servers are queried concurrently only to
//! hide latency — this is IP-policy routing, not a race, so `answer-ip` is
//! required in this form. `rule.filter`'s `answer-ip` match criterion (see
//! `crate::response_filter`) references `route.ruleset` ipcidr tags the same way.
//!
//! ```json
//! {
//!   "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
//!   "cache": { "size": 10000 },
//!   "route": {
//!     "servers": { "domestic-dns": "119.29.29.29", "overseas-dns": "tls://dns.google?bootstrap=domestic-dns" },
//!     "ruleset": [
//!       { "tag": "cn",    "format": "mrs",  "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" },
//!       { "tag": "cn-ip", "format": "text", "behavior": "ipcidr", "path": "/etc/pathdns/cn-ip.list" }
//!     ],
//!     "rules": [
//!       {
//!         "matcher": ["tag:cn"], "upstream": "domestic-dns",
//!         "filter": [
//!           { "response-type": "A",    "action": "accept", "add-ip": "mainroute" },
//!           { "response-type": "AAAA", "action": "accept", "add-ip": "mainroute6" }
//!         ]
//!       },
//!       { "matcher": ["tag:!cn"], "upstream": "overseas-dns" }
//!     ],
//!     "final": {
//!       "primary":       "domestic-dns",
//!       "secondary":     "overseas-dns",
//!       "answer-ip":     "cn-ip",
//!       "verdict-cache": { "size": 4096, "ttl": 3600 }
//!     }
//!   }
//! }
//! ```
//!
//! # Example – nftset with prefix-mask add-ip
//!
//! `add-ip` targets ipset/nftset directly (unrelated to `route.final`'s
//! answer-ip test above). Use `family@table@set` to target an nftset instead of
//! an ipset. An optional fourth `@N` segment applies a prefix mask before
//! insertion (e.g. `inet@fw4@mainroute@24` inserts the /24 network address for
//! each resolved IPv4 address, useful for route tables keyed on prefixes).
//! `add-ip` is only valid on an `"accept"` filter entry whose `response-type`
//! is pinned to exactly one of `A`/`AAAA` — that's what makes a single set
//! name unambiguous (a query only ever gets one record type back).
//!
//! ```json
//! {
//!   "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
//!   "route": {
//!     "servers": { "domestic-dns": "119.29.29.29", "overseas-dns": "tls://dns.google?bootstrap=domestic-dns" },
//!     "ruleset": [{ "tag": "cn", "format": "mrs", "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" }],
//!     "rules": [
//!       {
//!         "matcher": ["tag:cn"], "upstream": "domestic-dns",
//!         "filter": [
//!           { "response-type": "A",    "action": "accept", "add-ip": "inet@fw4@mainroute@24" },
//!           { "response-type": "AAAA", "action": "accept", "add-ip": "inet@fw4@mainroute6@48" }
//!         ]
//!       },
//!       { "matcher": ["tag:!cn"], "upstream": "overseas-dns" }
//!     ],
//!     "final": "domestic-dns"
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

/// Accept either a single value or an array of them; both normalize to a `Vec`
/// via [`OneOrMany::into_vec`]. Lets fields like `answer-ip`, `response-type`,
/// and `bind.addr` be written as a bare scalar instead of a one-element array.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub(crate) fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v],
            OneOrMany::Many(v) => v,
        }
    }
}

/// A DNS field value written as either a numeric code or a symbolic name —
/// e.g. `"A"` or `1`, `"NXDOMAIN"` or `3`. Used for `response-type`,
/// `response-rcode`, and `response-qclass`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum NameOrNumber {
    Number(i64),
    Name(String),
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
    /// Per-datagram UDP socket diagnostics: "off", "basic" (SO_RXQ_OVFL drop
    /// accounting + SO_MEMINFO sampling) or "full" (adds SO_TIMESTAMPNS
    /// kernel→userspace latency; the default).
    pub(crate) udp_diagnostics: Option<String>,
    // Upstream health / selection
    pub(crate) upstream_max_response_bytes: Option<usize>,
}

/// DNS listener configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonBindSection {
    /// IP address(es) to listen on.  String or array of IP strings (without port).
    /// Defaults to `"127.0.0.1"` when omitted.
    pub(crate) addr: Option<OneOrMany<String>>,
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

    /// Routing section: ruleset data sources, rule rules, and final routing target.
    pub(crate) route: Option<JsonRouteSection>,
}

/// Routing section — rules all routing-related config in one place.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonRouteSection {
    /// Named upstream resolvers, referenced by name from `rules[].upstream`,
    /// `final`, and `rule.filter[].forward`. Each value is a single upstream
    /// URL string, or an array of them (multiple nodes in one pool, hedged/
    /// raced the same way `rules[].upstream` used to support directly) —
    /// or a synthesised fixed answer: a single `A://`/`AAAA://`/`RCODE://`
    /// URL, or an array of them (e.g. one `A://` plus one `AAAA://`), never
    /// mixed with real upstream URLs in the same entry.
    pub(crate) servers: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    /// Rule-set data sources used by rule tag matching.
    pub(crate) ruleset: Option<Vec<JsonRuleSetEntry>>,
    /// Ordered list of routing rules (matched top-to-bottom).
    pub(crate) rules: Option<Vec<JsonRuleEntry>>,
    /// Target when no rule matches. Either a string (rule name) or a
    /// `JsonFinalSection` object for answer-ip test mode. Omit to fall back to
    /// the last rule.
    #[serde(rename = "final")]
    pub(crate) route_final: Option<serde_json::Value>,
}

/// One `route.ruleset` entry: a mihomo-compatible rule-set file bound to an
/// explicit tag. See `crate::ruleset` for the format/behavior semantics.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonRuleSetEntry {
    /// Tag name referenced by `rule.matcher`'s `tag:` expressions.
    pub(crate) tag: String,
    /// `"text"` (mihomo plain-text rule-set) or `"mrs"` (mihomo binary rule-set).
    pub(crate) format: String,
    /// `"domain"` or `"ipcidr"` — see `crate::ruleset` module docs.
    pub(crate) behavior: String,
    /// Path to the rule-set file.
    pub(crate) path: String,
}

/// The object form of `route.final` configures **answer-ip test mode**: both
/// servers are queried concurrently (for latency), but the answer that is
/// returned is decided by IP-CIDR membership — if the primary's answer IPs are
/// found in the `answer-ip`-tagged `route.ruleset` entry, the primary's answer
/// is used, otherwise the secondary's. `answer-ip` is required. Same tag
/// reference convention as `rule.filter`'s `answer-ip` criterion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonFinalSection {
    /// `route.servers` name whose answer is preferred when its IPs are in `answer-ip`.
    pub(crate) primary: Option<String>,
    /// `route.servers` name whose answer is used when the primary's IPs are NOT in `answer-ip`.
    pub(crate) secondary: Option<String>,
    /// `route.ruleset` tag(s) (`behavior: ipcidr`) the primary's answer IPs are
    /// tested against — a single tag name or array of them, same as
    /// `rule.filter`'s `answer-ip`.
    pub(crate) answer_ip: Option<OneOrMany<String>>,
    /// Treat NODATA primary replies as primary IPs for routing decisions.
    pub(crate) noip_as_primary_ip: Option<bool>,
    /// Verdict cache for answer-ip test results.  Co-located here because it
    /// only applies when answer-ip test mode is active.
    pub(crate) verdict_cache: Option<JsonVerdictCacheSection>,
}

/// `size`, `min-ttl`, and `max-ttl` are global (the cache is one shared
/// resource). Per-server tweaks all live in one place — `overrides`, a map keyed
/// by `route.servers` name — instead of being spread across the ttl fields and a
/// separate `no-cache` list, e.g.:
///
/// ```json
/// "cache": {
///   "size": 10000, "min-ttl": 0, "max-ttl": 3600,
///   "overrides": {
///     "domestic-dns": { "min-ttl": 30 },
///     "ads-blocked":  { "no-cache": true }
///   }
/// }
/// ```
///
/// See `crate::config::parse::apply_cache_field_overrides`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonCacheSection {
    pub(crate) size: Option<usize>,
    pub(crate) min_ttl: Option<u32>,
    pub(crate) max_ttl: Option<u32>,
    pub(crate) persist: Option<JsonPersistSection>,
    pub(crate) overrides: Option<std::collections::BTreeMap<String, JsonCacheOverride>>,
}

/// Per-server cache policy under `cache.overrides.<server-name>`. Each field is
/// optional; `no-cache: true` disables caching for that server and cannot be
/// combined with a `min-ttl`/`max-ttl` override.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonCacheOverride {
    pub(crate) min_ttl: Option<u32>,
    pub(crate) max_ttl: Option<u32>,
    pub(crate) no_cache: Option<bool>,
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
    /// Each entry is either a domain pattern (bare/`+.`/`.`/`*.`) or a
    /// `tag:cn,!gfw` ruleset-tag expression. The rule matches if ANY entry
    /// matches; omit for a catch-all rule.
    pub(crate) matcher: Option<Vec<String>>,
    /// Name of a `route.servers` entry this rule resolves through.
    pub(crate) upstream: Option<String>,
    /// Ordered match-criteria + action entries — see `crate::response_filter`.
    pub(crate) filter: Option<Vec<JsonRuleFilterEntry>>,
}

/// One `rule.filter` entry: AND-ed match criteria plus an action.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct JsonRuleFilterEntry {
    /// `route.ruleset` tag(s) (`behavior: ipcidr`) — a single tag name or array of
    /// them. Matches if any resolved answer IP falls in any of the referenced
    /// tags' ranges. The same tag-reference convention as `route.final`'s `answer-ip`.
    pub(crate) answer_ip: Option<OneOrMany<String>>,
    /// RR type name(s) (`"CNAME"`, `"A"`, …) or number(s) present in the answer section.
    pub(crate) response_type: Option<OneOrMany<NameOrNumber>>,
    /// RCODE name(s) (`"NXDOMAIN"`, …) or number(s).
    pub(crate) response_rcode: Option<OneOrMany<NameOrNumber>>,
    /// QCLASS name(s) (`"IN"`, …) or number(s).
    pub(crate) response_qclass: Option<OneOrMany<NameOrNumber>>,
    /// `"accept"` | `"drop"` | `"forward"`.
    pub(crate) action: String,
    /// Target `route.servers` name; required (and only valid) when `action` is `"forward"`.
    pub(crate) forward: Option<String>,
    /// nftset/ipset target to populate with this entry's resolved IPs; valid
    /// only with `action: "accept"` and a `response-type` pinned to exactly one
    /// of `A`/`AAAA` (see `crate::response_filter`).
    pub(crate) add_ip: Option<String>,
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
