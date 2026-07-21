//! CLI argument parsing and configuration validation.
//!
//! `Config` is the validated, fully-resolved configuration struct consumed by
//! the rest of the program.  It is built by `parse_args()`, which accepts only
//! two CLI flags (`-c`, `-h`) and delegates all configuration to the
//! JSON file loaded with `-c`.
//!
//! Validation catches: unknown rule names in `route.final`, and invalid
//! filter/ipset config.
//! All errors are returned as `anyhow::Error` so they print cleanly at startup.

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

mod bootstrap;
mod fingerprint;
pub(crate) mod json;
mod parse;
mod upstream_url;
use self::json::JsonConfig;
use self::upstream_url::{parse_rcode_name, parse_upstreams};
use crate::ruleset::RuleSetSpec;
pub use fingerprint::cache_fingerprint;

// ── Public types ────────────────────────────────────────────────────────────

/// A fixed DNS answer record returned locally without contacting any upstream.
/// Configured via `A://` or `AAAA://` as a `route.servers` value. Each record
/// carries its own TTL (settable per entry via `?ttl=N`, default [`DEFAULT_ANSWER_TTL`]).
#[derive(Debug, Clone)]
pub enum FixedAnswer {
    /// Return an A record with the given IPv4 address and TTL.
    A(Ipv4Addr, u32),
    /// Return an AAAA record with the given IPv6 address and TTL.
    Aaaa(Ipv6Addr, u32),
}

/// A `route.servers` entry synthesised locally instead of queried from a real
/// upstream: either up to one `A://` + one `AAAA://` record (`answers`), or a
/// fixed `RCODE://` response (`rcode`) — the two are mutually exclusive
/// (validated at parse time).
#[derive(Debug, Clone, Default)]
pub struct FixedAnswerSet {
    /// Fixed RCODE to return without any answer records.
    pub rcode: Option<u8>,
    /// Cache TTL for the `RCODE://` / NODATA response. Only meaningful when
    /// `rcode` is `Some`; record TTLs for A/AAAA live in `answers`.
    pub rcode_ttl: u32,
    /// Synthesised A/AAAA records. May hold at most one A and one AAAA combined.
    pub answers: Vec<FixedAnswer>,
}

/// A `route.servers` entry: either a real upstream pool, or a locally
/// synthesised fixed answer.
#[derive(Debug, Clone)]
pub enum ServerSpec {
    Upstream(Vec<UpstreamEndpoint>),
    Fixed(FixedAnswerSet),
}

/// Default TTL (seconds) for a fixed-answer `route.servers` record when no
/// `?ttl=` is given.
pub const DEFAULT_ANSWER_TTL: u32 = 60;

/// An IP prefix used in a fixed ECS option injected into outbound queries.
#[derive(Debug, Clone)]
pub struct EcsSubnet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

/// Per-upstream EDNS Client Subnet handling mode.
#[derive(Debug, Clone)]
pub enum EcsMode {
    Strip,
    Forward,
    Fixed(EcsSubnet),
}

/// How much per-datagram UDP diagnostics the listen sockets collect
/// (`runtime.udp-diagnostics`). Ordered: each level includes the previous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UdpDiagnostics {
    /// No socket-level diagnostics at all: no cmsgs requested, no per-packet
    /// control-area parsing, no SO_MEMINFO sampling.
    Off,
    /// Drop accounting only: `SO_RXQ_OVFL` (kernel receive-drop counter cmsg)
    /// plus the ~1 Hz `SO_MEMINFO` receive-buffer occupancy sample.
    Basic,
    /// Everything: adds `SO_TIMESTAMPNS`, giving the per-second peak
    /// kernel→userspace receive latency — one cmsg per datagram plus a clock
    /// read and latency computation per drain batch. The default (matches
    /// the previous unconditional behavior).
    Full,
}

/// All cache parameters bundled together; passed to `DnsCache::new`.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub capacity: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
}

/// Shared transport settings passed to every `UpstreamPool`.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub timeout: Duration,
    pub udp_sockets: usize,
    pub udp_buf_size: usize,
    pub upstream_max_inflight: usize,
    /// Enables hedging when set; also the fallback delay used until a node has
    /// an RTT sample (or right after a failure) — see `UpstreamNode::hedge_delay`.
    pub hedge_delay: Option<Duration>,
    /// Reject upstream TCP/TLS responses larger than this (bytes). 0 = no limit.
    pub upstream_max_response_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProto {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    H3,
}

#[derive(Debug, Clone)]
pub struct UpstreamEndpoint {
    pub proto: UpstreamProto,
    pub addr: SocketAddr,
    pub server_name: Option<String>,
    pub path: Option<String>,
    pub no_sni: bool,
    pub ecs_mode: Option<EcsMode>,
    /// Linux `SO_MARK` (fwmark) applied to this upstream's egress socket(s) for
    /// policy routing (`ip rule`/`ip route`). `None` = unmarked. Set via `?mark=`.
    pub mark: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RuleCachePolicy {
    pub skip: bool,
    pub min_ttl: Option<u32>,
    pub max_ttl: Option<u32>,
}

/// One `rule.matcher` entry: either a domain pattern (same conventions as
/// `route.ruleset`'s `domain`-behavior patterns) or a `tag:` ruleset-tag
/// expression. A rule matches a query if ANY of its `matcher` entries match
/// (empty `matcher` = catch-all).
#[derive(Debug, Clone)]
pub enum RuleMatcher {
    /// Domain pattern: bare (exact), `+.`/`.` (suffix), or `*.` (single-label
    /// wildcard) — see `crate::domain::classify_pattern`. Stored as the
    /// original (trimmed) pattern string; classified/compiled when the
    /// routing index is built.
    Domain(String),
    /// `tag:cn,!gfw` expression. `include` may be empty (an exclude-only
    /// "everything except" pattern, e.g. `tag:!gfw`) but `include`/`exclude`
    /// are never both empty (rejected at parse time).
    Tag {
        include: Vec<String>,
        exclude: Vec<String>,
    },
}

/// A `route.ruleset` ipcidr-tag reference used by `answer-ip`, with optional
/// `!` exclusion per entry — same include/exclude convention as
/// `rule.matcher`'s `tag:` expressions, but evaluated against a resolved
/// response's answer IPs instead of a domain name. Matches when any answer IP
/// falls in an include tag's range (or there are no include tags) AND no
/// answer IP falls in any exclude tag's range — `!tag` alone (no include) is
/// a valid "none of the answer IPs are in this range" pattern. `include`/
/// `exclude` are never both empty (rejected at parse time).
#[derive(Debug, Clone, Default)]
pub struct AnswerIpMatcher {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

impl AnswerIpMatcher {
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Empty = catch-all (matches every query not already matched by an
    /// earlier rule).
    pub matcher: Vec<RuleMatcher>,
    /// Name of the `route.servers` entry this rule resolves through.
    /// Validated against `Config::servers` in `Config::from_json`.
    pub server: String,
    pub cache_policy: Option<RuleCachePolicy>,
    pub filters: Vec<RuleFilterSpec>,
}

/// One `rule.filter` entry: an ordered set of AND-ed match criteria plus an action.
/// See `crate::response_filter` for match/action semantics.
#[derive(Debug, Clone)]
pub struct RuleFilterSpec {
    /// `route.ruleset` ipcidr tag(s) to test resolved answer IPs against, with
    /// optional `!` exclusion — see `AnswerIpMatcher`.
    pub answer_ip: AnswerIpMatcher,
    pub response_type: Vec<u16>,
    pub response_rcode: Vec<u8>,
    pub response_qclass: Vec<u16>,
    pub action: RuleFilterActionSpec,
    /// nftset/ipset target (`"v4set"`, `"v6set/24"`, `"inet@fw4@set@24"`, …) to
    /// populate with this entry's resolved IPs. Only valid on `Accept` (checked
    /// at parse time) — `Drop`/`Forward` have no response of their own to pull
    /// IPs from, and only `Accept` requires `response-type` be pinned to exactly
    /// one of `A`/`AAAA`, which is what makes a single set name unambiguous.
    pub add_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RuleFilterActionSpec {
    /// Return the response as-is; see `RuleFilterSpec::add_ip` for the optional
    /// ipset/nftset side effect.
    Accept,
    Drop,
    /// Target `route.servers` name; resolved to an index when rules are built.
    Forward(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetConfig {
    /// Add targets, keyed by `(rule_idx, filter_idx)` — a rule's position in
    /// `Config::rules`, and that filter entry's position in the rule's own
    /// `filter` list (rules and filter entries have no name of their own).
    /// The `bool` is `true` for an AAAA (IPv6) target, `false` for A (IPv4) —
    /// mirroring the filter entry's `response-type`, which `add_ip` requires
    /// to be pinned to exactly one of the two — so the mask suffix (`/N` or
    /// `@N`) can be validated against the right address family's bit width.
    pub add_rules: Vec<(usize, usize, String, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictCacheConfig {
    pub capacity: usize,
    pub ttl: Duration,
}

/// What happens when no rule matches a query.
#[derive(Debug, Clone)]
pub enum FallbackTarget {
    /// `route.final` was omitted: fall back to the last configured rule,
    /// regardless of that rule's own tags — its cache policy/filters/add-ip
    /// still apply.
    LastRule,
    /// Route unconditionally to a named `route.servers` entry, bypassing
    /// rule-level cache overrides/filters/add-ip (global cache policy applies).
    Server(String),
    /// IP-based routing: test primary's response IPs against one or more
    /// ipcidr-behavior `route.ruleset` tags to pick primary vs secondary. When
    /// `answer_ip` is empty, both are queried in race mode (first valid wins).
    Dual {
        primary: String,
        secondary: String,
        /// Tested against the primary's answer IPs — primary wins if it
        /// matches, secondary wins otherwise. Empty means race (no IP testing).
        answer_ip: AnswerIpMatcher,
    },
}

#[derive(Debug, Clone)]
pub struct FallbackConfig {
    pub target: FallbackTarget,
    pub noip_as_primary_ip: bool,
}

/// Configuration for the dashboard (query log viewer + HTTP API), parsed from the `dashboard` JSON section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardConfig {
    /// Whether the dashboard section was present in the configuration.
    pub enabled: bool,
    /// HTTP API listeners: `(addr, iface)` pairs derived from the main `bind` config
    /// with the port substituted. Empty = no HTTP listener.
    pub bind: Vec<(SocketAddr, Option<String>)>,
    /// Bearer token for API auth. `None` = no auth required.
    pub token: Option<String>,
    /// Ring buffer capacity. 0 = event collection disabled (counters only).
    pub memory: usize,
    /// mpsc channel capacity.
    pub channel: usize,
    pub file: Option<DashboardFileConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardFileConfig {
    pub dir: PathBuf,
    /// Rotate when the active segment exceeds this size in MiB.
    pub max_mb: u64,
    /// Maximum number of completed (compressed) segments to retain.
    pub max_segments: usize,
    /// Maximum events to accumulate before one write call.
    pub batch_size: usize,
    /// How often the worker flushes its OS buffer (milliseconds).
    pub flush_interval_ms: u64,
    /// Delete compressed segments older than this many days. `None` = no age limit.
    pub retention_days: Option<u32>,
    /// Gzip-compress segments after rotation.
    pub compress: bool,
}

/// Network interface filter, resolved from the `interface` JSON field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InterfaceFilter {
    /// Accept on all interfaces (default; no SO_BINDTODEVICE applied).
    #[default]
    All,
    /// Accept only on the listed interfaces.
    Only(Vec<String>),
    /// Accept on all interfaces except the listed ones.
    Except(Vec<String>),
}

/// One DNS listen address with its enabled protocols (from an optional
/// `@udp`/`@tcp` suffix; both when no suffix is given).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindEndpoint {
    pub addr: SocketAddr,
    pub udp: bool,
    pub tcp: bool,
}

/// Configuration fields are grouped into two hot-reload categories:
///
/// **Truly hot-reloadable** (take effect for new requests without restarting):
/// upstreams, routing rules, fixed answers, fallback policy, per-rule cache policy,
/// upstream timeouts/hedging, and TCP read/idle timeouts.
///
/// **Startup-only** (a reload logs `restart_required`): listeners and worker sizing,
/// io_uring/listener buffers, global inflight/TCP connection limits, cache and
/// persistence construction, ipset/verdict-cache managers, dashboard/querylog, and
/// the ruleset watcher file list.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: Vec<BindEndpoint>,
    pub interface: InterfaceFilter,
    pub timeout: Duration,
    pub max_inflight: usize,
    /// 0 = hard-drop immediately; >0 = queue for up to this many ms before dropping.
    pub inflight_queue_ms: u64,
    /// Listener-start-only: changing this requires a restart.
    pub worker_threads: usize,
    pub fallback: FallbackConfig,
    pub cache_size: usize,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub cache_persist_path: Option<PathBuf>,
    pub cache_persist_interval: u64,
    /// Listener-start-only: changing this requires a restart.
    pub udp_buf_size: usize,
    /// io_uring provided-buffer-ring depth per shard (power of two).
    /// Listener-start-only: changing this requires a restart.
    pub uring_recv_buffers: usize,
    /// Socket-level UDP diagnostics level (cmsg options are set at bind time).
    /// Listener-start-only: changing this requires a restart.
    pub udp_diagnostics: UdpDiagnostics,
    /// Rebuilt with upstream pools during a successful hot reload.
    pub upstream_udp_sockets: usize,
    /// Maximum concurrent TCP client connections. 0 = unlimited.
    pub tcp_max_connections: usize,
    /// Timeout for reading the DNS message body. 0 = disabled.
    pub tcp_read_timeout_ms: u64,
    /// Timeout for waiting for the next request on an idle TCP connection. 0 = disabled.
    pub tcp_idle_timeout_ms: u64,
    pub dashboard: DashboardConfig,
    /// Named upstream resolvers (`route.servers`), in declaration order. Each
    /// is either a real upstream pool or a locally synthesised fixed answer.
    /// Referenced by name from `rules[].server` (and, once resolved, `final`/
    /// `forward` targets too).
    pub servers: Vec<(String, ServerSpec)>,
    pub rules: Vec<RuleSpec>,
    pub ipset: Option<IpSetConfig>,
    pub verdict_cache: Option<VerdictCacheConfig>,
    pub ruleset_specs: Vec<RuleSetSpec>,
    pub upstream_max_inflight: usize,
    /// Enables hedging when set; also the fallback delay used until a node has
    /// an RTT sample (or right after a failure) — see `UpstreamNode::hedge_delay`.
    pub hedge_delay: Option<Duration>,
    /// Reject upstream TCP/TLS responses larger than this (bytes). 0 = no limit.
    pub upstream_max_response_bytes: usize,
}

impl Config {
    pub fn cache_config(&self) -> CacheConfig {
        CacheConfig {
            capacity: self.cache_size,
            min_ttl: self.cache_min_ttl,
            max_ttl: self.cache_max_ttl,
        }
    }

    pub fn upstream_config(&self) -> UpstreamConfig {
        UpstreamConfig {
            timeout: self.timeout,
            udp_sockets: self.upstream_udp_sockets,
            udp_buf_size: self.udp_buf_size,
            upstream_max_inflight: self.upstream_max_inflight,
            hedge_delay: self.hedge_delay,
            upstream_max_response_bytes: self.upstream_max_response_bytes,
        }
    }

    pub fn parse_args() -> Result<(Self, PathBuf)> {
        let config_path = parse_cli()?;
        let json = json::load_json_config(&config_path)?;
        let mut cfg = Self::from_json(json)?;
        cfg.anchor_paths(&config_base_dir(&config_path));
        Ok((cfg, config_path))
    }

    /// Resolve every relative file path inside the config against `base` (the
    /// config file's own directory — see [`config_base_dir`]), so behavior
    /// doesn't depend on the process working directory a service manager,
    /// container, or shell happened to start pathdns from. Applied at startup
    /// and again on every config hot-reload with the same base, so the two
    /// always agree. Absolute paths pass through untouched.
    pub(crate) fn anchor_paths(&mut self, base: &std::path::Path) {
        fn anchor(path: &mut PathBuf, base: &std::path::Path) {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        for spec in &mut self.ruleset_specs {
            anchor(&mut spec.path, base);
        }
        if let Some(path) = &mut self.cache_persist_path {
            anchor(path, base);
        }
        if let Some(file) = &mut self.dashboard.file {
            anchor(&mut file.dir, base);
        }
    }

    pub(crate) fn from_json(mut json: JsonConfig) -> Result<Self> {
        let (bind_addrs, interface) = parse::parse_bind_config(json.bind)?;

        let t = json.runtime.unwrap_or_default();

        let worker_threads = t.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
        });
        let max_inflight = t.max_inflight.unwrap_or(worker_threads * 1024);
        if max_inflight < 1 {
            return Err(anyhow!("runtime.max-inflight must be at least 1"));
        }
        let inflight_queue_ms = t.inflight_queue_ms.unwrap_or(0);

        // Per-upstream concurrent in-flight cap. Scales with the worker count
        // (like the global `max_inflight`) so high-QPS boxes are not bottlenecked
        // by a fixed small value, with a 1024 floor that still bounds outstanding
        // work to one upstream. By Little's law this caps a single upstream at
        // roughly `cap / RTT` queries/s; raise it for very high QPS to few upstreams.
        let upstream_max_inflight = t
            .upstream_max_inflight
            .unwrap_or_else(|| (worker_threads * 256).max(1024));
        let hedge_delay_ms = t.hedge_delay_ms.unwrap_or(0);

        let route = json.route.unwrap_or_default();
        let mut servers = parse::parse_servers(route.servers.unwrap_or_default())?;
        let mut rules = parse::parse_rules(route.rules.unwrap_or_default(), &servers)?;

        // Every rule's `server` must reference a real `route.servers` entry.
        for (idx, spec) in rules.iter().enumerate() {
            if !servers.iter().any(|(name, _)| name == &spec.server) {
                return Err(anyhow!(
                    "rule #{idx}: upstream \"{}\": no such route.servers entry",
                    spec.server
                ));
            }
        }

        // Apply ECS strip default to all real-upstream servers' endpoints
        // (meaningless for a fixed-answer server, which never queries anything).
        for (_, spec) in servers.iter_mut() {
            if let ServerSpec::Upstream(endpoints) = spec {
                for ep in endpoints.iter_mut() {
                    if ep.ecs_mode.is_none() {
                        ep.ecs_mode = Some(EcsMode::Strip);
                    }
                }
            }
        }

        // Parse route.final section; omitting it uses the last rule as the fallback.
        let (fallback, verdict_cache) = if let Some(json_final) = route.route_final {
            parse::parse_final_config(json_final, &servers)?
        } else {
            if rules.is_empty() {
                return Err(anyhow!("route.final is required when route.rules is empty"));
            }
            (
                FallbackConfig {
                    target: FallbackTarget::LastRule,
                    noip_as_primary_ip: false,
                },
                None,
            )
        };

        // Build ipset config: add targets come from each rule's filter entries.
        let ipset = parse::parse_ipset_config(&rules)?;

        // cache.size / min-ttl / max-ttl are global; per-server tweaks live in
        // cache.overrides — see JsonCacheSection's doc comment.
        let cache_size = json.cache.as_ref().and_then(|c| c.size).unwrap_or(10000);
        let cache_min_ttl = json.cache.as_ref().and_then(|c| c.min_ttl).unwrap_or(0);
        let cache_max_ttl = json.cache.as_ref().and_then(|c| c.max_ttl).unwrap_or(0);
        if cache_max_ttl > 0 && cache_min_ttl > cache_max_ttl {
            return Err(anyhow!(
                "cache.min-ttl {cache_min_ttl} cannot exceed cache.max-ttl {cache_max_ttl}"
            ));
        }
        let cache_overrides = json
            .cache
            .as_mut()
            .and_then(|c| c.overrides.take())
            .unwrap_or_default();
        parse::apply_cache_field_overrides(cache_overrides, &mut rules)?;

        let udp_diagnostics = match t.udp_diagnostics.as_deref() {
            None | Some("full") => UdpDiagnostics::Full,
            Some("basic") => UdpDiagnostics::Basic,
            Some("off") => UdpDiagnostics::Off,
            Some(other) => {
                return Err(anyhow!(
                    "runtime.udp-diagnostics: expected \"off\", \"basic\" or \"full\", got \"{other}\""
                ))
            }
        };
        let udp_buf_size = t.udp_buf_size.unwrap_or(4 * 1024 * 1024);
        // Provided buffer-ring depth: power of two, clamped to a sane range. The ring
        // index is a u16, so the kernel caps it at 32768; we cap lower for memory.
        let uring_recv_buffers = t
            .uring_recv_buffers
            .unwrap_or(256)
            .clamp(16, 8192)
            .next_power_of_two();
        let upstream_udp_sockets = t
            .upstream_udp_sockets
            .unwrap_or(worker_threads.max(32))
            .max(1);

        // Parse dashboard section.
        let dashboard = parse::parse_dashboard_config(json.dashboard, &bind_addrs, &interface)?;

        let tcp_max_connections = t.tcp_max_connections.unwrap_or(1024);
        let tcp_read_timeout_ms = t.tcp_read_timeout_ms.unwrap_or(5000);
        let tcp_idle_timeout_ms = t.tcp_idle_timeout_ms.unwrap_or(30_000);

        Ok(Self {
            bind: bind_addrs,
            interface,
            timeout: Duration::from_millis(t.timeout_ms.unwrap_or(3000)),
            max_inflight,
            inflight_queue_ms,
            worker_threads,
            fallback,
            dashboard,
            tcp_max_connections,
            tcp_read_timeout_ms,
            tcp_idle_timeout_ms,
            cache_size,
            cache_min_ttl,
            cache_max_ttl,
            cache_persist_path: json
                .cache
                .as_ref()
                .and_then(|c| c.persist.as_ref())
                .map(|p| PathBuf::from(&p.path)),
            cache_persist_interval: json
                .cache
                .as_ref()
                .and_then(|c| c.persist.as_ref())
                .and_then(|p| p.interval)
                .unwrap_or(0),
            udp_buf_size,
            uring_recv_buffers,
            udp_diagnostics,
            upstream_udp_sockets,
            servers,
            rules,
            ipset,
            verdict_cache,
            ruleset_specs: parse::parse_ruleset_specs(route.ruleset.unwrap_or_default())?,
            upstream_max_inflight,
            hedge_delay: (hedge_delay_ms > 0).then(|| Duration::from_millis(hedge_delay_ms)),
            upstream_max_response_bytes: t.upstream_max_response_bytes.unwrap_or(0),
        })
    }
}

/// The directory all relative paths inside a config file resolve against: the
/// config file's own directory, made absolute via the current working
/// directory when the config path itself is relative.
pub(crate) fn config_base_dir(config_path: &std::path::Path) -> PathBuf {
    let abs = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(config_path)
    };
    abs.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}

// ── CLI parsing ─────────────────────────────────────────────────────────────

fn parse_cli() -> Result<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    let mut config: Option<PathBuf> = None;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                let path = args
                    .get(i)
                    .ok_or_else(|| anyhow!("-c requires a config file path"))?;
                config = Some(PathBuf::from(path));
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(anyhow!("unknown option: {other}\nUse -h for help."));
            }
        }
        i += 1;
    }
    let config = config
        .ok_or_else(|| anyhow!("Error: configuration file not specified.\nUse -h for help."))?;
    Ok(config)
}

fn print_help() {
    println!(
        "Usage: pathdns -c <config.json> [-h]\n\
         \n\
         Options:\n\
           -c <config.json>   Load configuration file (required)\n\
           -h                 Show this help message\n\
         \n\
         All configuration is read from the JSON file specified with -c."
    );
}

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use crate::ruleset::{RuleSetBehavior, RuleSetFormat};

    #[test]
    fn relative_paths_anchor_to_config_dir_absolute_pass_through() {
        let mut cfg_paths = (
            vec![RuleSetSpec {
                tag: "cn".into(),
                format: RuleSetFormat::Text,
                behavior: RuleSetBehavior::Domain,
                path: PathBuf::from("rules/cn.list"),
            }],
            Some(PathBuf::from("cache.bin")),
            Some(PathBuf::from("/var/log/querylog")),
        );
        // Exercise the same anchor logic through a minimal Config would need a
        // full parse; anchor the fields directly through a throwaway Config.
        let mut cfg = Config {
            bind: Vec::new(),
            interface: InterfaceFilter::All,
            timeout: Duration::from_secs(1),
            max_inflight: 1,
            inflight_queue_ms: 0,
            worker_threads: 1,
            fallback: FallbackConfig {
                target: FallbackTarget::LastRule,
                noip_as_primary_ip: false,
            },
            cache_size: 0,
            cache_min_ttl: 0,
            cache_max_ttl: 0,
            cache_persist_path: cfg_paths.1.take(),
            cache_persist_interval: 0,
            udp_buf_size: 0,
            uring_recv_buffers: 16,
            udp_diagnostics: UdpDiagnostics::Full,
            upstream_udp_sockets: 1,
            tcp_max_connections: 0,
            tcp_read_timeout_ms: 0,
            tcp_idle_timeout_ms: 0,
            dashboard: DashboardConfig {
                enabled: true,
                bind: Vec::new(),
                token: None,
                memory: 0,
                channel: 64,
                file: Some(DashboardFileConfig {
                    dir: cfg_paths.2.take().unwrap(),
                    max_mb: 1,
                    max_segments: 1,
                    batch_size: 1,
                    flush_interval_ms: 50,
                    retention_days: None,
                    compress: false,
                }),
            },
            servers: Vec::new(),
            rules: Vec::new(),
            ipset: None,
            verdict_cache: None,
            ruleset_specs: std::mem::take(&mut cfg_paths.0),
            upstream_max_inflight: 0,
            hedge_delay: None,
            upstream_max_response_bytes: 0,
        };

        cfg.anchor_paths(std::path::Path::new("/etc/pathdns"));
        assert_eq!(
            cfg.ruleset_specs[0].path,
            PathBuf::from("/etc/pathdns/rules/cn.list")
        );
        assert_eq!(
            cfg.cache_persist_path.as_deref(),
            Some(std::path::Path::new("/etc/pathdns/cache.bin"))
        );
        // Absolute paths pass through untouched.
        assert_eq!(
            cfg.dashboard.file.as_ref().unwrap().dir,
            PathBuf::from("/var/log/querylog")
        );
    }

    #[test]
    fn config_base_dir_is_absolute_for_relative_config_paths() {
        let base = config_base_dir(std::path::Path::new("config.json"));
        assert!(base.is_absolute());
        assert_eq!(
            config_base_dir(std::path::Path::new("/etc/pathdns/config.json")),
            PathBuf::from("/etc/pathdns")
        );
    }
}
