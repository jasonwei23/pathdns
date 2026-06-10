//! CLI argument parsing and configuration validation.
//!
//! `Config` is the validated, fully-resolved configuration struct consumed by
//! the rest of the program.  It is built by `parse_args()`, which accepts only
//! three CLI flags (`-c`, `-v`, `-h`) and delegates all configuration to the
//! JSON file loaded with `-c`.
//!
//! Validation catches: unknown group names in `fallback`, unknown names in
//! `group-no-cache`, and invalid filter/ipset config.
//! All errors are returned as `anyhow::Error` so they print cleanly at startup.

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use crate::config_json::{JsonConfig, JsonGroupCacheSection, JsonGroupEntry};

// ── Public types ────────────────────────────────────────────────────────────

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
    pub stale_expire_ttl: u64,
    pub stale_ttl: u32,
    pub stale_ttl_reset: bool,
    pub nodata_ttl: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub refresh: Option<u32>,
    pub refresh_min_ttl: Option<u32>,
}

/// Shared transport settings passed to every `UpstreamPool`.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub timeout: Duration,
    pub udp_pool_size: usize,
    pub udp_buf_size: usize,
    pub upstream_max_inflight: usize,
    pub hedge_delay: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProto {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    H3,
    UdpIncoming,
    TcpIncoming,
}

#[derive(Debug, Clone)]
pub struct UpstreamEndpoint {
    pub proto: UpstreamProto,
    pub addr: SocketAddr,
    pub server_name: Option<String>,
    pub path: Option<String>,
    pub no_sni: bool,
    pub ecs_mode: Option<EcsMode>,
}

#[derive(Debug, Clone)]
pub struct GroupCachePolicy {
    pub skip: bool,
    pub stale_expire_ttl: Option<u64>,
    pub stale_ttl: Option<u32>,
    pub nodata_ttl: Option<u32>,
    pub min_ttl: Option<u32>,
    pub max_ttl: Option<u32>,
    pub refresh_percent: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct GroupSpec {
    pub name: String,
    pub geosite_include: Vec<String>,
    pub geosite_exclude: Vec<String>,
    pub upstream: Vec<UpstreamEndpoint>,
    /// nftset/ipset pair (`"v4set,v6set"`) to populate with resolved IPs.
    pub add_ip: Option<String>,
    pub cache_policy: Option<GroupCachePolicy>,
    pub filter_qtype: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpSetPair {
    pub v4: Option<String>,
    pub v6: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IpSetConfig {
    /// Test sets used for IP-based primary/secondary routing in `FallbackTarget::None`.
    /// `None` when the fallback is not `"none"` or no ipset names were configured.
    pub test: Option<IpSetPair>,
    /// Per-group add sets, keyed by group name.
    pub add_groups: Vec<(String, IpSetPair)>,
    pub blacklist: bool,
}

#[derive(Debug, Clone)]
pub struct VerdictCacheConfig {
    pub capacity: usize,
    pub ttl: Duration,
}

/// What happens when no group matches a query.
#[derive(Debug, Clone)]
pub enum FallbackTarget {
    /// Route to a named group unconditionally.
    Group(String),
    /// IP-based routing: test primary's response IPs against ipset to pick primary vs secondary.
    None {
        primary: String,
        secondary: String,
        /// Test ipset pair; `None` means race (no ipset testing).
        ipset: Option<IpSetPair>,
    },
    /// Return an empty (NXDOMAIN) response.
    Null,
}

#[derive(Debug, Clone)]
pub struct FallbackConfig {
    pub target: FallbackTarget,
    pub noip_as_primary_ip: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub listen_udp: bool,
    pub listen_tcp: bool,
    pub timeout: Duration,
    pub max_inflight: usize,
    /// 0 = hard-drop immediately; >0 = queue for up to this many ms before dropping.
    pub inflight_queue_ms: u64,
    pub worker_threads: usize,
    pub fallback: FallbackConfig,
    pub verbose: bool,
    pub cache_size: usize,
    pub cache_stale_expire_ttl: u64,
    pub cache_stale_ttl: u32,
    pub cache_stale_ttl_reset: bool,
    pub cache_stale_client_timeout: u64,
    pub cache_nodata_ttl: u32,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub cache_refresh: Option<u32>,
    pub cache_refresh_min_ttl: Option<u32>,
    pub cache_persist_path: Option<PathBuf>,
    pub cache_persist_interval: u64,
    pub udp_buf_size: usize,
    pub udp_pool_size: usize,
    pub metrics_addr: Option<SocketAddr>,
    pub groups: Vec<GroupSpec>,
    pub ipset: Option<IpSetConfig>,
    pub verdict_cache: Option<VerdictCacheConfig>,
    pub geosite_files: Vec<PathBuf>,
    pub upstream_max_inflight: usize,
    pub hedge_delay: Option<Duration>,
}

impl Config {
    pub fn cache_config(&self) -> CacheConfig {
        CacheConfig {
            capacity: self.cache_size,
            stale_expire_ttl: self.cache_stale_expire_ttl,
            stale_ttl: self.cache_stale_ttl,
            stale_ttl_reset: self.cache_stale_ttl_reset,
            nodata_ttl: self.cache_nodata_ttl,
            min_ttl: self.cache_min_ttl,
            max_ttl: self.cache_max_ttl,
            refresh: self.cache_refresh,
            refresh_min_ttl: self.cache_refresh_min_ttl,
        }
    }

    pub fn upstream_config(&self) -> UpstreamConfig {
        UpstreamConfig {
            timeout: self.timeout,
            udp_pool_size: self.udp_pool_size,
            udp_buf_size: self.udp_buf_size,
            upstream_max_inflight: self.upstream_max_inflight,
            hedge_delay: self.hedge_delay,
        }
    }

    pub fn parse_args() -> Result<Self> {
        let (config_path, verbose) = parse_cli()?;
        let json = crate::config_json::load_json_config(&config_path)?;
        Self::from_json(json, verbose)
    }

    pub(crate) fn from_json(json: JsonConfig, cli_verbose: bool) -> Result<Self> {
        let bind_raw = json.bind.as_deref().unwrap_or("127.0.0.1:65353");
        let (listen_udp, listen_tcp) = resolve_bind_proto(bind_raw)?;
        let bind_addr = {
            let addr_part = bind_raw.split_once('@').map_or(bind_raw, |(a, _)| a);
            let normalized = normalize_addr_with_default_port(addr_part, 65353);
            parse_addr(&normalized).with_context(|| format!("invalid bind address: {addr_part}"))?
        };

        let worker_threads = json.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
        });
        let max_inflight = json.max_inflight.unwrap_or(worker_threads * 1024);
        if max_inflight < 1 {
            return Err(anyhow!("max-inflight must be at least 1"));
        }
        let inflight_queue_ms = json.inflight_queue_ms.unwrap_or(0);

        let upstream_max_inflight = json.upstream_max_inflight.unwrap_or(256);
        let hedge_delay_ms = json.hedge_delay_ms.unwrap_or(0);

        let mut groups = parse_groups(json.group.unwrap_or_default())?;

        // Apply ECS strip default to all group upstreams.
        for spec in groups.iter_mut() {
            for ep in spec.upstream.iter_mut() {
                if ep.ecs_mode.is_none() {
                    ep.ecs_mode = Some(EcsMode::Strip);
                }
            }
        }

        // Parse fallback section (required).
        let json_fallback = json
            .fallback
            .ok_or_else(|| anyhow!("fallback section is required"))?;
        let fallback = parse_fallback_config(json_fallback, &groups)?;

        // Build ipset config: test pair from fallback (if None target), add pairs from groups.
        let ipset =
            parse_ipset_config(&fallback, &groups, json.no_ipset_blacklist.unwrap_or(false))?;

        let verdict_cache = json.verdict_cache.and_then(|vc| {
            vc.size
                .filter(|&c| c > 0)
                .map(|capacity| VerdictCacheConfig {
                    capacity,
                    ttl: Duration::from_secs(vc.ttl.unwrap_or(3600)),
                })
        });

        let cache_min_ttl = json.cache.as_ref().and_then(|c| c.min_ttl).unwrap_or(0);
        let cache_max_ttl = json.cache.as_ref().and_then(|c| c.max_ttl).unwrap_or(0);
        if cache_max_ttl > 0 && cache_min_ttl > cache_max_ttl {
            return Err(anyhow!(
                "cache.min-ttl {cache_min_ttl} cannot exceed cache.max-ttl {cache_max_ttl}"
            ));
        }

        let udp_buf_size = json.udp_buf_size.unwrap_or(4 * 1024 * 1024);
        let udp_pool_size = json.upstream_udp_sockets.unwrap_or(worker_threads).max(1);

        Ok(Self {
            bind: bind_addr,
            listen_udp,
            listen_tcp,
            timeout: Duration::from_secs(json.timeout.unwrap_or(5)),
            max_inflight,
            inflight_queue_ms,
            worker_threads,
            fallback,
            verbose: json.verbose.unwrap_or(false) || cli_verbose,
            cache_size: json.cache.as_ref().and_then(|c| c.size).unwrap_or(10000),
            cache_stale_expire_ttl: json
                .cache
                .as_ref()
                .and_then(|c| c.stale_expire_ttl)
                .unwrap_or(0),
            cache_stale_ttl: json.cache.as_ref().and_then(|c| c.stale_ttl).unwrap_or(30),
            cache_stale_ttl_reset: json
                .cache
                .as_ref()
                .and_then(|c| c.stale_ttl_reset)
                .unwrap_or(true),
            cache_stale_client_timeout: json
                .cache
                .as_ref()
                .and_then(|c| c.stale_client_timeout)
                .unwrap_or(0),
            cache_nodata_ttl: json.cache.as_ref().and_then(|c| c.nodata_ttl).unwrap_or(60),
            cache_min_ttl,
            cache_max_ttl,
            cache_refresh: json.cache.as_ref().and_then(|c| c.refresh),
            cache_refresh_min_ttl: json.cache.as_ref().and_then(|c| c.refresh_min_ttl),
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
            udp_pool_size,
            metrics_addr: json.metrics_addr.as_deref().map(parse_addr).transpose()?,
            groups,
            ipset,
            verdict_cache,
            geosite_files: json
                .geosite_file
                .unwrap_or_default()
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            upstream_max_inflight,
            hedge_delay: (hedge_delay_ms > 0).then(|| Duration::from_millis(hedge_delay_ms)),
        })
    }
}

// ── CLI parsing ─────────────────────────────────────────────────────────────

fn parse_cli() -> Result<(PathBuf, bool)> {
    let args: Vec<String> = std::env::args().collect();
    let mut config: Option<PathBuf> = None;
    let mut verbose = false;
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
            "-v" => verbose = true,
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
    Ok((config, verbose))
}

fn print_help() {
    println!(
        "Usage: pathdns -c <config.json> [-v] [-h]\n\
         \n\
         Options:\n\
           -c <config.json>   Load configuration file (required)\n\
           -v                 Enable verbose output\n\
           -h                 Show this help message\n\
         \n\
         All configuration is read from the JSON file specified with -c."
    );
}

// ── Config parsing helpers ───────────────────────────────────────────────────

fn parse_fallback_config(
    jf: crate::config_json::JsonFallbackSection,
    groups: &[GroupSpec],
) -> Result<FallbackConfig> {
    let group_exists = |name: &str| groups.iter().any(|g| g.name == name);

    let target = match jf.default_group.as_str() {
        "null" => FallbackTarget::Null,
        "none" => {
            let primary = jf
                .primary
                .ok_or_else(|| anyhow!("fallback: default-group \"none\" requires \"primary\""))?;
            let secondary = jf.secondary.ok_or_else(|| {
                anyhow!("fallback: default-group \"none\" requires \"secondary\"")
            })?;
            if !group_exists(&primary) {
                return Err(anyhow!("fallback.primary \"{primary}\": no such group"));
            }
            if !group_exists(&secondary) {
                return Err(anyhow!("fallback.secondary \"{secondary}\": no such group"));
            }
            if primary == secondary {
                return Err(anyhow!(
                    "fallback.primary and fallback.secondary must be different groups"
                ));
            }
            let ipset = match (jf.ipset_name4, jf.ipset_name6) {
                (None, None) => None,
                (v4, v6) => {
                    let pair = IpSetPair {
                        v4: v4.filter(|s| !s.is_empty() && s != "null"),
                        v6: v6.filter(|s| !s.is_empty() && s != "null"),
                    };
                    if pair.v4.is_none() && pair.v6.is_none() {
                        None
                    } else {
                        Some(pair)
                    }
                }
            };
            FallbackTarget::None {
                primary,
                secondary,
                ipset,
            }
        }
        name => {
            if !group_exists(name) {
                return Err(anyhow!("fallback.default-group \"{name}\": no such group"));
            }
            FallbackTarget::Group(name.to_string())
        }
    };

    Ok(FallbackConfig {
        target,
        noip_as_primary_ip: jf.noip_as_primary_ip.unwrap_or(false),
    })
}

fn parse_ipset_config(
    fallback: &FallbackConfig,
    groups: &[GroupSpec],
    no_blacklist: bool,
) -> Result<Option<IpSetConfig>> {
    // Test pair comes from fallback.None ipset fields.
    let test = if let FallbackTarget::None { ipset, .. } = &fallback.target {
        ipset.clone()
    } else {
        None
    };

    // Add pairs come from group.add_ip entries.
    let mut add_groups: Vec<(String, IpSetPair)> = Vec::new();
    for group in groups {
        if let Some(raw) = &group.add_ip {
            add_groups.push((group.name.clone(), parse_ipset_pair(raw)?));
        }
    }

    if test.is_some() || !add_groups.is_empty() {
        Ok(Some(IpSetConfig {
            test,
            add_groups,
            blacklist: !no_blacklist,
        }))
    } else {
        Ok(None)
    }
}

fn parse_group_tag_entry(value: &str) -> Result<GroupTagEntry> {
    let value = value.trim();
    if let Some(tag) = value.strip_prefix('!') {
        if tag.is_empty() || is_invalid_geosite_tag(tag) {
            return Err(anyhow!("group tag: expected !TAG, got: {value}"));
        }
        Ok(GroupTagEntry::Exclude(tag.to_lowercase()))
    } else {
        if value.is_empty() || is_invalid_geosite_tag(value) {
            return Err(anyhow!("group tag: expected TAG or !TAG, got: {value}"));
        }
        Ok(GroupTagEntry::Include(value.to_lowercase()))
    }
}

fn is_invalid_geosite_tag(value: &str) -> bool {
    value.contains(':') || value.contains('/') || value.contains('\\')
}

enum GroupTagEntry {
    Include(String),
    Exclude(String),
}

fn parse_group_cache_policy(
    cache: Option<JsonGroupCacheSection>,
) -> Result<Option<GroupCachePolicy>> {
    let Some(c) = cache else {
        return Ok(None);
    };

    // Check for conflicting fields when size: 0 disables the cache.
    let has_other_fields = c.stale_expire_ttl.is_some()
        || c.stale_ttl.is_some()
        || c.nodata_ttl.is_some()
        || c.min_ttl.is_some()
        || c.max_ttl.is_some()
        || c.refresh.is_some();

    match c.size {
        Some(0) => {
            if has_other_fields {
                return Err(anyhow!(
                    "group cache.size: 0 disables caching for this group; \
                     other cache fields are meaningless alongside it and must be removed"
                ));
            }
            return Ok(Some(GroupCachePolicy {
                skip: true,
                stale_expire_ttl: None,
                stale_ttl: None,
                nodata_ttl: None,
                min_ttl: None,
                max_ttl: None,
                refresh_percent: None,
            }));
        }
        Some(n) => {
            return Err(anyhow!(
                "group cache.size must be 0 (skip cache) or omitted; \
                 set the cache capacity with the global cache.size (got {n})"
            ));
        }
        None => {}
    }

    // Validate min_ttl ≤ max_ttl when both are set and non-zero.
    if let (Some(min), Some(max)) = (c.min_ttl, c.max_ttl) {
        if min > 0 && max > 0 && min > max {
            return Err(anyhow!(
                "group cache.min-ttl ({min}) must not be greater than cache.max-ttl ({max})"
            ));
        }
    }

    // Validate refresh percentage.
    if let Some(r) = c.refresh {
        if r > 100 {
            return Err(anyhow!("group cache.refresh must be in 0–100 (got {r})"));
        }
    }

    Ok(Some(GroupCachePolicy {
        skip: false,
        stale_expire_ttl: c.stale_expire_ttl,
        stale_ttl: c.stale_ttl,
        nodata_ttl: c.nodata_ttl,
        min_ttl: c.min_ttl,
        max_ttl: c.max_ttl,
        refresh_percent: c.refresh,
    }))
}

fn parse_group_filter_qtype(value: Option<serde_json::Value>) -> Result<Vec<u16>> {
    fn check_qtype(n: u64) -> Result<u16> {
        if n > 65535 {
            Err(anyhow!(
                "filter-qtype value {n} is out of range (DNS QTYPE is 16-bit: 0–65535)"
            ))
        } else {
            Ok(n as u16)
        }
    }
    match value {
        None | Some(serde_json::Value::Null) => Ok(vec![]),
        Some(serde_json::Value::Number(n)) => {
            let qt = n.as_u64().ok_or_else(|| {
                anyhow!("filter-qtype must be a positive integer or array of positive integers")
            })?;
            Ok(vec![check_qtype(qt)?])
        }
        Some(serde_json::Value::Array(arr)) => {
            let mut qtypes = Vec::with_capacity(arr.len());
            for v in arr {
                let n = v.as_u64().ok_or_else(|| {
                    anyhow!("filter-qtype must be a positive integer or array of positive integers")
                })?;
                qtypes.push(check_qtype(n)?);
            }
            Ok(qtypes)
        }
        _ => Err(anyhow!(
            "filter-qtype must be a positive integer or array of positive integers"
        )),
    }
}

fn parse_json_group(jg: JsonGroupEntry) -> Result<GroupSpec> {
    let name = jg.name.trim();
    if name.is_empty() {
        return Err(anyhow!("group name cannot be empty"));
    }
    let mut geosite_include = Vec::new();
    let mut geosite_exclude = Vec::new();
    for tags in jg.tag.iter().flatten() {
        for entry in crate::domain::split_csv(tags) {
            match parse_group_tag_entry(entry)? {
                GroupTagEntry::Include(t) => geosite_include.push(t),
                GroupTagEntry::Exclude(t) => geosite_exclude.push(t),
            }
        }
    }
    let upstream = if name == "null" {
        Vec::new()
    } else {
        let urls = jg.upstream.as_deref().unwrap_or(&[]);
        if urls.is_empty() {
            return Err(anyhow!("group \"{name}\" requires an upstream"));
        }
        parse_upstreams(urls)?
    };
    let cache_policy = parse_group_cache_policy(jg.cache)?;
    let filter_qtype = parse_group_filter_qtype(jg.filter_qtype)?;
    Ok(GroupSpec {
        name: name.to_string(),
        geosite_include,
        geosite_exclude,
        upstream,
        add_ip: jg.add_ip.filter(|s| !s.is_empty()),
        cache_policy,
        filter_qtype,
    })
}

fn parse_groups(json_groups: Vec<JsonGroupEntry>) -> Result<Vec<GroupSpec>> {
    let mut groups = Vec::new();
    for jg in json_groups {
        groups.push(parse_json_group(jg)?);
    }

    // Reject duplicate group names.
    let mut seen = std::collections::HashSet::new();
    for g in &groups {
        if !seen.insert(g.name.as_str()) {
            return Err(anyhow!("duplicate group name: \"{}\"", g.name));
        }
    }

    Ok(groups)
}

fn resolve_bind_proto(raw: &str) -> Result<(bool, bool)> {
    let Some((_, proto)) = raw.split_once('@') else {
        return Ok((true, true));
    };
    match proto {
        "udp" => Ok((true, false)),
        "tcp" => Ok((false, true)),
        other => Err(anyhow!(
            "invalid bind protocol '@{other}'; expected @udp or @tcp"
        )),
    }
}

fn normalize_addr_with_default_port(s: &str, default_port: u16) -> String {
    if s.starts_with('[') {
        if s.rsplit_once(']')
            .is_some_and(|(_, tail)| tail.starts_with(':') && tail[1..].parse::<u16>().is_ok())
        {
            return s.to_string();
        }
        return format!("{s}:{default_port}");
    }
    let colon_count = s.as_bytes().iter().filter(|&&b| b == b':').count();
    if colon_count >= 2 {
        return format!("[{s}]:{default_port}");
    }
    if s.rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        s.to_string()
    } else {
        format!("{s}:{default_port}")
    }
}

fn normalize_addr(s: &str) -> String {
    normalize_addr_with_default_port(s, 53)
}

fn parse_addr(s: &str) -> Result<SocketAddr> {
    let s = normalize_addr(s);
    s.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("failed to resolve address: {s}"))
}

fn parse_upstreams(items: &[String]) -> Result<Vec<UpstreamEndpoint>> {
    let mut out = Vec::new();
    for item in items {
        out.extend(parse_upstream(item)?);
    }
    if out.is_empty() {
        return Err(anyhow!("at least one upstream DNS is required"));
    }
    Ok(out)
}

/// FNV-1a hash of the routing/cache-affecting config fields.
///
/// Written to the cache persistence file so that a stale cache from a previous config
/// is automatically rejected instead of bypassing the new routing or cache policy.
/// Covers: groups (name, tags, filter_qtype, cache policy), fallback routing, global
/// cache TTL settings, and GeoSite file paths.
pub fn cache_fingerprint(cfg: &Config) -> u64 {
    let mut h = crate::fnv::Fnv1a::new();
    macro_rules! feed {
        ($bytes:expr) => {
            h.write($bytes)
        };
    }
    macro_rules! sep {
        () => {
            h.write_sep()
        };
    }

    for g in &cfg.groups {
        feed!(g.name.as_bytes());
        sep!();

        let mut include = g.geosite_include.clone();
        include.sort_unstable();
        for t in &include {
            feed!(t.as_bytes());
            sep!();
        }
        let mut exclude = g.geosite_exclude.clone();
        exclude.sort_unstable();
        for t in &exclude {
            feed!(b"!");
            feed!(t.as_bytes());
            sep!();
        }

        let mut qtypes = g.filter_qtype.clone();
        qtypes.sort_unstable();
        for qt in qtypes {
            feed!(&qt.to_le_bytes());
        }
        sep!();

        if let Some(p) = &g.cache_policy {
            feed!(&[p.skip as u8]);
            feed!(&p.min_ttl.unwrap_or(0).to_le_bytes());
            feed!(&p.max_ttl.unwrap_or(0).to_le_bytes());
            feed!(&p.nodata_ttl.unwrap_or(0).to_le_bytes());
            feed!(&p.stale_ttl.unwrap_or(0).to_le_bytes());
            feed!(&p.stale_expire_ttl.unwrap_or(0).to_le_bytes());
            feed!(&p.refresh_percent.unwrap_or(u32::MAX).to_le_bytes());
        }
        sep!();
    }

    match &cfg.fallback.target {
        FallbackTarget::Group(name) => {
            feed!(b"group");
            feed!(name.as_bytes());
        }
        FallbackTarget::None {
            primary, secondary, ..
        } => {
            feed!(b"none");
            feed!(primary.as_bytes());
            feed!(secondary.as_bytes());
        }
        FallbackTarget::Null => feed!(b"null"),
    }
    sep!();

    feed!(&cfg.cache_min_ttl.to_le_bytes());
    feed!(&cfg.cache_max_ttl.to_le_bytes());
    feed!(&cfg.cache_nodata_ttl.to_le_bytes());
    feed!(&cfg.cache_stale_ttl.to_le_bytes());
    feed!(&cfg.cache_stale_expire_ttl.to_le_bytes());
    feed!(&cfg.cache_refresh.unwrap_or(0).to_le_bytes());
    sep!();

    for path in &cfg.geosite_files {
        feed!(path.to_string_lossy().as_bytes());
        // Include mtime+size so a same-path file replacement invalidates the cache.
        if let Ok(meta) = std::fs::metadata(path) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            feed!(&mtime.to_le_bytes());
            feed!(&meta.len().to_le_bytes());
        }
        sep!();
    }

    h.finish()
}

fn parse_ipset_pair(value: &str) -> Result<IpSetPair> {
    let mut parts = value.splitn(2, ',').map(str::trim);
    let v4 = normalize_ipset_name(parts.next().unwrap_or_default());
    let v6 = normalize_ipset_name(parts.next().unwrap_or_default());
    if v4.is_none() && v6.is_none() {
        return Err(anyhow!("invalid ipset/nftset pair: {value}"));
    }
    Ok(IpSetPair { v4, v6 })
}

fn normalize_ipset_name(value: &str) -> Option<String> {
    if value.is_empty() || value == "null" {
        None
    } else {
        Some(value.to_string())
    }
}

fn parse_upstream(raw: &str) -> Result<Vec<UpstreamEndpoint>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("upstream cannot be empty"));
    }
    if raw.contains('#') {
        return Err(anyhow!(
            "invalid upstream '{raw}': '#' port syntax is not supported; use udp://host:port or tcp://host:port"
        ));
    }
    if let Some((host, addr)) = raw.rsplit_once('@') {
        return Err(anyhow!(
            "upstream host@addr syntax is not supported: {host}@{addr}"
        ));
    }

    let Some((scheme, rest)) = raw.split_once("://") else {
        let addr = parse_addr_with_default_port(raw, 53)?;
        return Ok(vec![
            endpoint(UpstreamProto::UdpIncoming, addr, None, None, false, None),
            endpoint(UpstreamProto::TcpIncoming, addr, None, None, false, None),
        ]);
    };

    let proto = parse_upstream_scheme(scheme)?;
    let (rest_no_query, query) = rest.split_once('?').map_or((rest, ""), |(a, q)| (a, q));
    let no_sni = query.split('&').any(|p| p == "no-sni");
    let sni_override = query
        .split('&')
        .find_map(|p| p.strip_prefix("sni="))
        .map(str::to_string);
    let ecs_param = query.split('&').find_map(|p| p.strip_prefix("ecs="));
    let ecs_mode: Option<EcsMode> = match ecs_param {
        None => None,
        Some("strip") => Some(EcsMode::Strip),
        Some("forward") => Some(EcsMode::Forward),
        Some(val) => Some(EcsMode::Fixed(
            parse_ecs_subnet(val)
                .with_context(|| format!("invalid upstream '{raw}': ?ecs={val}"))?,
        )),
    };

    for param in query.split('&').filter(|p| !p.is_empty()) {
        if param != "no-sni" && !param.starts_with("sni=") && !param.starts_with("ecs=") {
            return Err(anyhow!(
                "invalid upstream '{raw}': unknown query parameter '{param}'"
            ));
        }
    }
    if no_sni && !matches!(proto, UpstreamProto::Tls) {
        return Err(anyhow!(
            "invalid upstream '{raw}': ?no-sni is only valid for tls:// upstreams"
        ));
    }
    if sni_override.is_some() && !proto.uses_tls_name() {
        return Err(anyhow!(
            "invalid upstream '{raw}': ?sni= is only valid for TLS-based upstreams"
        ));
    }

    let (authority, path) = split_upstream_path(rest_no_query)?;
    let port = proto.default_port();
    let (host, addr) = parse_authority(authority, port)?;
    let server_name = sni_override.or_else(|| {
        proto
            .uses_tls_name()
            .then(|| strip_ipv6_brackets(host).to_string())
    });
    let path = match proto {
        UpstreamProto::Https | UpstreamProto::H3 => {
            Some(path.unwrap_or(DEFAULT_DOH_PATH).to_string())
        }
        _ if path.is_some() => {
            return Err(anyhow!(
                "invalid upstream '{raw}': path is only valid for https://, doh://, h3://"
            ));
        }
        _ => None,
    };

    Ok(vec![endpoint(
        proto,
        addr,
        server_name,
        path,
        no_sni,
        ecs_mode,
    )])
}

const DEFAULT_DOH_PATH: &str = "/dns-query";

fn endpoint(
    proto: UpstreamProto,
    addr: SocketAddr,
    server_name: Option<String>,
    path: Option<String>,
    no_sni: bool,
    ecs_mode: Option<EcsMode>,
) -> UpstreamEndpoint {
    UpstreamEndpoint {
        proto,
        addr,
        server_name,
        path,
        no_sni,
        ecs_mode,
    }
}

fn parse_ecs_subnet(s: &str) -> Result<EcsSubnet> {
    if let Some((addr_str, prefix_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str
            .parse()
            .with_context(|| format!("invalid address '{addr_str}'"))?;
        let prefix_len: u8 = prefix_str
            .parse()
            .with_context(|| format!("invalid prefix length '{prefix_str}'"))?;
        let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
        if prefix_len > max {
            return Err(anyhow!("prefix length {prefix_len} exceeds maximum {max}"));
        }
        Ok(EcsSubnet { addr, prefix_len })
    } else {
        let addr: IpAddr = s
            .parse()
            .with_context(|| format!("expected IP address or CIDR prefix, got '{s}'"))?;
        let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
        Ok(EcsSubnet { addr, prefix_len })
    }
}

fn parse_upstream_scheme(scheme: &str) -> Result<UpstreamProto> {
    match scheme.to_ascii_lowercase().as_str() {
        "udp" => Ok(UpstreamProto::Udp),
        "tcp" => Ok(UpstreamProto::Tcp),
        "tls" => Ok(UpstreamProto::Tls),
        "https" | "doh" => Ok(UpstreamProto::Https),
        "quic" | "doq" => Ok(UpstreamProto::Quic),
        "h3" => Ok(UpstreamProto::H3),
        other => Err(anyhow!("unsupported upstream scheme '{other}'")),
    }
}

fn split_upstream_path(rest: &str) -> Result<(&str, Option<&str>)> {
    let (authority, path) = rest.split_once('/').map_or((rest, None), |(a, p)| {
        let path = if p.is_empty() { "/" } else { &rest[a.len()..] };
        (a, Some(path))
    });
    if authority.is_empty() {
        return Err(anyhow!("upstream URL is missing a host"));
    }
    Ok((authority, path))
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(&str, SocketAddr)> {
    let addr = parse_addr_with_default_port(authority, default_port)?;
    let host = authority_host(authority)?;
    Ok((host, addr))
}

fn authority_host(authority: &str) -> Result<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(anyhow!("invalid IPv6 upstream authority: {authority}"));
        };
        if !tail.is_empty() && !tail.starts_with(':') {
            return Err(anyhow!("invalid upstream authority: {authority}"));
        }
        return Ok(host);
    }
    Ok(authority
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(authority, |(host, _)| host))
}

fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

fn parse_addr_with_default_port(s: &str, default_port: u16) -> Result<SocketAddr> {
    let s = normalize_addr_with_default_port(s, default_port);
    s.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("failed to resolve address: {s}"))
}

impl UpstreamProto {
    fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp | Self::UdpIncoming | Self::TcpIncoming => 53,
            Self::Tls | Self::Quic => 853,
            Self::Https | Self::H3 => 443,
        }
    }

    fn uses_tls_name(self) -> bool {
        matches!(self, Self::Tls | Self::Https | Self::Quic | Self::H3)
    }
}
