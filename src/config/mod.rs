//! CLI argument parsing and configuration validation.
//!
//! `Config` is the validated, fully-resolved configuration struct consumed by
//! the rest of the program.  It is built by `parse_args()`, which accepts only
//! three CLI flags (`-c`, `-v`, `-h`) and delegates all configuration to the
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
pub use fingerprint::cache_fingerprint;
use self::json::JsonConfig;
use self::upstream_url::{parse_rcode_name, parse_upstreams};
use crate::ruleset::RuleSetSpec;

// ── Public types ────────────────────────────────────────────────────────────

/// A fixed DNS answer record returned locally without contacting any upstream.
/// Configured via `A://`, `AAAA://`, or `CNAME://` in `route.answer`. Each record
/// carries its own TTL (settable per entry via `?ttl=N`, default [`DEFAULT_ANSWER_TTL`]).
#[derive(Debug, Clone)]
pub enum FixedAnswer {
    /// Return an A record with the given IPv4 address and TTL.
    A(Ipv4Addr, u32),
    /// Return an AAAA record with the given IPv6 address and TTL.
    Aaaa(Ipv6Addr, u32),
    /// Return a CNAME record pointing to the given (already-lowercased) domain, with TTL.
    Cname(String, u32),
}

/// Default TTL (seconds) for a `route.answer` record when no `?ttl=` is given.
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

#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub name: String,
    pub ruleset_include: Vec<String>,
    pub ruleset_exclude: Vec<String>,
    pub upstream: Vec<UpstreamEndpoint>,
    /// nftset/ipset pair (`"v4set,v6set"`) to populate with resolved IPs.
    pub add_ip: Option<String>,
    pub cache_policy: Option<RuleCachePolicy>,
    pub filters: Vec<RuleFilterSpec>,
}

/// One `rule.filter` entry: an ordered set of AND-ed match criteria plus an action.
/// See `crate::response_filter` for match/action semantics.
#[derive(Debug, Clone)]
pub struct RuleFilterSpec {
    /// `route.ruleset` tags (`behavior: ipcidr`), lowercased.
    pub answer_ip: Vec<String>,
    pub response_type: Vec<u16>,
    pub response_rcode: Vec<u8>,
    pub response_qclass: Vec<u16>,
    pub action: RuleFilterActionSpec,
}

#[derive(Debug, Clone)]
pub enum RuleFilterActionSpec {
    Empty,
    Drop,
    Continue,
    /// Target rule name; resolved to an index when rules are built.
    Forward(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetPair {
    pub v4: Option<String>,
    pub v6: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetConfig {
    /// Per-rule add sets, keyed by rule name.
    pub add_rules: Vec<(String, IpSetPair)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictCacheConfig {
    pub capacity: usize,
    pub ttl: Duration,
}

/// What happens when no rule matches a query.
#[derive(Debug, Clone)]
pub enum FallbackTarget {
    /// Route to a named rule unconditionally.
    Rule(String),
    /// IP-based routing: test primary's response IPs against one or more
    /// ipcidr-behavior `route.ruleset` tags to pick primary vs secondary. When
    /// `answer_ip_tags` is empty, both are queried in race mode (first valid wins).
    Dual {
        primary: String,
        secondary: String,
        /// `route.ruleset` tags (`behavior: ipcidr`) to test against — primary
        /// wins if its answer IPs are in any of them. Empty means race (no IP
        /// testing).
        answer_ip_tags: Vec<String>,
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
    /// Extract A/AAAA answer IPs into detailed events.
    pub answer_ips: bool,
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
    /// Rebuilt with upstream pools during a successful hot reload.
    pub upstream_udp_sockets: usize,
    /// Maximum concurrent TCP client connections. 0 = unlimited.
    pub tcp_max_connections: usize,
    /// Timeout for reading the DNS message body. 0 = disabled.
    pub tcp_read_timeout_ms: u64,
    /// Timeout for waiting for the next request on an idle TCP connection. 0 = disabled.
    pub tcp_idle_timeout_ms: u64,
    pub dashboard: DashboardConfig,
    pub rules: Vec<RuleSpec>,
    /// Domain → fixed-answer map consulted before `rules` at query time.
    pub answer_map: crate::answer_map::AnswerMap,
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
        Ok((Self::from_json(json)?, config_path))
    }

    pub(crate) fn from_json(json: JsonConfig) -> Result<Self> {
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
        let mut rules = parse::parse_rules(route.rules.unwrap_or_default())?;

        // Parse the domain → fixed-answer map (consulted before `rules`).
        let answer_map = parse::parse_answer_map(route.answer.unwrap_or_default())?;

        // Apply ECS strip default to all rule upstreams.
        for spec in rules.iter_mut() {
            for ep in spec.upstream.iter_mut() {
                if ep.ecs_mode.is_none() {
                    ep.ecs_mode = Some(EcsMode::Strip);
                }
            }
        }

        // Parse route.final section; omitting it uses the last rule as the fallback.
        let (fallback, verdict_cache) = if let Some(json_final) = route.route_final {
            parse::parse_final_config(json_final, &rules)?
        } else {
            let last = rules
                .last()
                .ok_or_else(|| anyhow!("route.final is required when route.rules is empty"))?;
            (
                FallbackConfig {
                    target: FallbackTarget::Rule(last.name.clone()),
                    noip_as_primary_ip: false,
                },
                None,
            )
        };

        // Build ipset config: test pair from fallback (if None target), add pairs from rules.
        let ipset = parse::parse_ipset_config(&rules)?;

        let cache_min_ttl = json.cache.as_ref().and_then(|c| c.min_ttl).unwrap_or(0);
        let cache_max_ttl = json.cache.as_ref().and_then(|c| c.max_ttl).unwrap_or(0);
        if cache_max_ttl > 0 && cache_min_ttl > cache_max_ttl {
            return Err(anyhow!(
                "cache.min-ttl {cache_min_ttl} cannot exceed cache.max-ttl {cache_max_ttl}"
            ));
        }

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
        let dashboard = if let Some(ql) = json.dashboard {
            let bind: Vec<(SocketAddr, Option<String>)> = if let Some(port) = ql.port {
                if port == 0 {
                    return Err(anyhow!("dashboard.port must be between 1 and 65535"));
                }
                match &interface {
                    InterfaceFilter::Only(ifaces) => {
                        let mut seen = std::collections::HashSet::new();
                        let unique_ips: Vec<_> = bind_addrs
                            .iter()
                            .filter(|ep| seen.insert(ep.addr.ip()))
                            .map(|ep| ep.addr.ip())
                            .collect();
                        unique_ips
                            .iter()
                            .flat_map(|&ip| {
                                ifaces.iter().map(move |iface| {
                                    (SocketAddr::new(ip, port), Some(iface.clone()))
                                })
                            })
                            .collect()
                    }
                    _ => {
                        let mut seen = std::collections::HashSet::new();
                        bind_addrs
                            .iter()
                            .filter(|ep| seen.insert(ep.addr.ip()))
                            .map(|ep| (SocketAddr::new(ep.addr.ip(), port), None))
                            .collect()
                    }
                }
            } else {
                vec![]
            };
            if ql
                .token
                .as_deref()
                .is_some_and(|token| token.trim().is_empty())
            {
                return Err(anyhow!("dashboard.token must not be empty"));
            }
            let channel = ql.channel.unwrap_or(4096);
            if channel == 0 {
                return Err(anyhow!("dashboard.channel must be at least 1"));
            }
            if channel > 1_000_000 {
                return Err(anyhow!("dashboard.channel must not exceed 1000000"));
            }
            let memory = ql.memory.unwrap_or(1000);
            if memory > 10_000_000 {
                return Err(anyhow!("dashboard.memory must not exceed 10000000"));
            }
            let file = if let Some(f) = ql.file {
                let dir = PathBuf::from(f.dir.unwrap_or_else(|| "./querylog".to_string()));
                let max_mb = f.max_mb.unwrap_or(8);
                let max_segments = f.max_segments.unwrap_or(3);
                if max_mb == 0 {
                    return Err(anyhow!("dashboard.file.max-mb must be at least 1"));
                }
                if max_segments == 0 {
                    return Err(anyhow!("dashboard.file.max-segments must be at least 1"));
                }
                let batch_size = f.batch_size.unwrap_or(256).max(1);
                let flush_interval_ms = f.flush_interval_ms.unwrap_or(500).max(50);
                let retention_days = f.retention_days;
                let compress = f.compress.unwrap_or(true);
                Some(DashboardFileConfig {
                    dir,
                    max_mb,
                    max_segments,
                    batch_size,
                    flush_interval_ms,
                    retention_days,
                    compress,
                })
            } else {
                None
            };
            DashboardConfig {
                enabled: true,
                bind,
                token: ql.token,
                memory,
                channel,
                answer_ips: ql.answer_ips.unwrap_or(false),
                file,
            }
        } else {
            DashboardConfig {
                enabled: false,
                bind: Vec::new(),
                token: None,
                memory: 0,
                channel: 4096,
                answer_ips: false,
                file: None,
            }
        };

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
            answer_map,
            tcp_max_connections,
            tcp_read_timeout_ms,
            tcp_idle_timeout_ms,
            cache_size: json.cache.as_ref().and_then(|c| c.size).unwrap_or(10000),
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
            upstream_udp_sockets,
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
