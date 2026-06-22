//! Application state and listener orchestration.
//!
//! Query lifecycle logic lives in `resolver`; listener sockets live in `listener`.

use crate::cache::DnsCache;
use crate::config::{Config, EcsMode, FallbackTarget, InterfaceFilter};
use crate::geosite::GeoSiteDb;
use crate::ipset::IpSetManager;
use crate::listener;
use crate::route_index::RouteIndex;
use crate::singleflight;
use crate::upstream::UpstreamPool;
use crate::verdict_cache::VerdictCache;
use anyhow::{anyhow, Context, Result};
use arc_swap::{ArcSwap, ArcSwapOption};
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::Semaphore;

const RELOAD_RETRIES: usize = 5;
const RELOAD_RETRY_DELAY: Duration = Duration::from_millis(100);

/// How the fallback target was resolved at startup (rule indices into `HotState::rules`).
pub enum ResolvedFallback {
    /// Route unmatched queries to a fixed rule.
    Rule(usize),
    /// Race primary vs secondary; first valid response wins (no ipset).
    Race { primary: usize, secondary: usize },
    /// IP-test primary vs secondary using the configured ipset.
    IpSetTest { primary: usize, secondary: usize },
}

/// Hot-reloadable state: rebuilt from the config file on every reload.
/// Wrapped in `ArcSwap` so query-handling tasks can load a snapshot cheaply
/// without blocking writers (config reloads).
pub struct HotState {
    pub cfg: Config,
    pub rules: Vec<Rule>,
    pub needs_geosite: bool,
    pub fallback: ResolvedFallback,
    pub routing_index: RouteIndex,
}

pub struct AppState {
    /// Hot-reloadable routing + config state.  Load with `state.hot.load()` (sync/fast)
    /// or `state.hot.load_full()` (returns Arc, safe to hold across .await).
    pub hot: ArcSwap<HotState>,
    /// Path to the config file, used to watch for changes.
    pub config_path: Option<PathBuf>,
    pub limit: Arc<Semaphore>,
    /// Connection-level semaphore for TCP. `None` = unlimited.
    pub tcp_conn_limit: Option<Arc<Semaphore>>,
    pub cache: DnsCache,
    pub(crate) remote_inflight: singleflight::InflightTable,
    pub ipset: Option<Arc<IpSetManager>>,
    pub verdict_cache: VerdictCache,
    pub geosite: ArcSwapOption<GeoSiteDb>,
    pub querylog: crate::querylog::QueryLogHandle,
    /// Incremented on every hot-reload. Used to prevent stale upstream responses
    /// (resolved under the old routing) from being inserted into the freshly-cleared cache.
    pub routing_generation: AtomicU64,
}

pub struct Rule {
    pub name: String,
    /// Pre-interned Arc of `name`; clone is a refcount bump, no allocation per query.
    pub name_arc: Arc<str>,
    /// Index of this rule in `HotState::rules`; carried in `RouteTarget::Rule`.
    pub index: usize,
    pub upstream: Option<UpstreamPool>,
    /// Rule cache policy merged over global defaults at startup.
    pub cache_policy: crate::cache::ResolvedCachePolicy,
    pub filter_qtype: std::collections::HashSet<u16>,
    pub geosite_include: Vec<String>,
    pub geosite_exclude: Vec<String>,
    /// True when every upstream in this rule strips ECS (mode is Strip or unset).
    /// Used to share a single cache entry across all clients rather than one per subnet.
    pub strip_ecs: bool,
    /// Collapse CNAME chains in A/AAAA answers to a single record at the query name.
    pub collapse: bool,
}

impl Rule {
    pub fn target(&self) -> Option<crate::router::RouteTarget<'_>> {
        self.upstream
            .is_some()
            .then_some(crate::router::RouteTarget::Rule(self, self.index))
    }
}

impl AppState {
    pub async fn new(
        cfg: Config,
        config_path: Option<PathBuf>,
        querylog: crate::querylog::QueryLogHandle,
    ) -> Result<Self> {
        // Cache is created first so each rule's cache policy can be resolved
        // against the global defaults inside build_hot_state.
        let cache = DnsCache::new(&cfg.cache_config());

        if let Some(path) = &cfg.cache_persist_path {
            let fp = crate::config::cache_fingerprint(&cfg);
            match cache.load_from_file(path, fp) {
                Ok(n) if n > 0 => crate::startup!("cache persist=loaded entries={n}"),
                Ok(_) => {}
                Err(e) => crate::startup!("cache persist=load_failed error={e:#}"),
            }
        }

        let ipset = cfg
            .ipset
            .as_ref()
            .map(IpSetManager::new)
            .transpose()?
            .map(Arc::new);

        let verdict_cache = VerdictCache::new(cfg.verdict_cache.as_ref());
        if verdict_cache.enabled() {
            if let Some(path) = &cfg.cache_persist_path {
                let vpath = crate::verdict_cache::persist_path_for(path);
                if vpath.exists() {
                    let fp = crate::config::cache_fingerprint(&cfg);
                    match verdict_cache.load_from_file(&vpath, fp) {
                        Ok(n) if n > 0 => {
                            crate::startup!("verdict_cache persist=loaded entries={n}")
                        }
                        Ok(_) => {}
                        Err(e) => crate::startup!("verdict_cache persist=load_failed error={e:#}"),
                    }
                }
            }
        }

        let (hot, geosite) = build_hot_state(cfg, &querylog, &cache).await?;

        // Restore ipset/nftset entries from the persisted DNS cache so that policy
        // routing rules are active immediately after a restart without waiting for
        // each domain to be queried again.
        if let Some(ref ipset_mgr) = ipset {
            // Collect IPs per rule so we can batch, deduplicate, and send in one
            // netlink message per set rather than one per cache entry.
            let mut rule_ips: HashMap<usize, (String, Vec<std::net::IpAddr>)> = HashMap::new();
            cache.for_each_rule_entry(|rule_id, packet, question_end| {
                if let Some(rule) = hot.rules.get(rule_id as usize) {
                    let ips = crate::dns::answer_ips(packet, question_end);
                    if !ips.is_empty() {
                        rule_ips
                            .entry(rule_id as usize)
                            .or_insert_with(|| (rule.name.clone(), Vec::new()))
                            .1
                            .extend_from_slice(&ips);
                    }
                }
            });
            if !rule_ips.is_empty() {
                let rules_count = rule_ips.len();
                for (name, ips) in rule_ips.values() {
                    ipset_mgr.add_rule_ips(name, ips);
                }
                crate::startup!("add_ip persist=restore_queued rules={rules_count}");
            }
        }

        let max = hot.cfg.max_inflight;
        let tcp_conn_limit = (hot.cfg.tcp_max_connections > 0)
            .then(|| Arc::new(Semaphore::new(hot.cfg.tcp_max_connections)));

        Ok(Self {
            hot: ArcSwap::new(hot),
            config_path,
            limit: Arc::new(Semaphore::new(max)),
            tcp_conn_limit,
            cache,
            remote_inflight: singleflight::InflightTable::new(),
            ipset,
            verdict_cache,
            geosite: ArcSwapOption::new(geosite),
            querylog,
            routing_generation: AtomicU64::new(0),
        })
    }

    pub fn geosite_snapshot(&self) -> Option<Arc<GeoSiteDb>> {
        self.geosite.load_full()
    }
}

/// Build a `HotState` from a validated config.
///
/// Returns the `Arc<HotState>` and the loaded `GeoSiteDb` (if any tags are
/// needed). The GeoSite database is stored separately in `AppState::geosite`
/// rather than inside `HotState` so it can be hot-reloaded independently.
async fn build_hot_state(
    cfg: Config,
    querylog: &crate::querylog::QueryLogHandle,
    cache: &DnsCache,
) -> Result<(Arc<HotState>, Option<Arc<GeoSiteDb>>)> {
    let upstream_cfg = cfg.upstream_config();
    let rules = build_rules(&cfg, &upstream_cfg, querylog, cache).await?;
    let fallback = resolve_fallback(&cfg, &rules)?;
    let needed_tags = needed_geosite_tags(&cfg);
    let needs_geosite = !needed_tags.is_empty();
    let geosite = load_geosite(&cfg, &needed_tags)?;
    let routing_index = RouteIndex::build(&rules);
    if !cfg.answer_map.is_empty() {
        crate::startup!("answer map entries={}", cfg.answer_map.len());
    }
    let hot = Arc::new(HotState {
        cfg,
        rules,
        needs_geosite,
        fallback,
        routing_index,
    });
    Ok((hot, geosite))
}

/// Build the list of `Rule` from a parsed config.
async fn build_rules(
    cfg: &Config,
    upstream_cfg: &crate::config::UpstreamConfig,
    querylog: &crate::querylog::QueryLogHandle,
    cache: &DnsCache,
) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for (idx, spec) in cfg.rules.iter().enumerate() {
        // Rules always forward to a real upstream; fixed answers live in route.answer.
        let upstream = Some(
            UpstreamPool::new(
                &format!("rule-{}", spec.name),
                &spec.upstream,
                upstream_cfg,
                Some(querylog.counters.clone()),
            )
            .await?,
        );
        let strip_ecs = spec
            .upstream
            .iter()
            .all(|ep| matches!(ep.ecs_mode, Some(EcsMode::Strip) | None));
        rules.push(Rule {
            name: spec.name.clone(),
            name_arc: Arc::from(spec.name.as_str()),
            index: idx,
            upstream,
            cache_policy: cache.resolve_policy(spec.cache_policy.as_ref()),
            filter_qtype: spec.filter_qtype.iter().copied().collect(),
            geosite_include: spec.geosite_include.clone(),
            geosite_exclude: spec.geosite_exclude.clone(),
            strip_ecs,
            collapse: spec.collapse,
        });
    }
    Ok(rules)
}

/// Resolve fallback rule names to indices in `rules`.
fn resolve_fallback(cfg: &Config, rules: &[Rule]) -> Result<ResolvedFallback> {
    let find = |name: &str| -> Result<usize> {
        rules
            .iter()
            .position(|g| g.name == name)
            .ok_or_else(|| anyhow!("fallback rule not found: {name}"))
    };
    Ok(match &cfg.fallback.target {
        FallbackTarget::Rule(name) => ResolvedFallback::Rule(find(name)?),
        FallbackTarget::Dual {
            primary,
            secondary,
            ipset,
        } => {
            let p = find(primary)?;
            let s = find(secondary)?;
            if ipset.is_some() {
                ResolvedFallback::IpSetTest {
                    primary: p,
                    secondary: s,
                }
            } else {
                ResolvedFallback::Race {
                    primary: p,
                    secondary: s,
                }
            }
        }
    })
}

pub(crate) fn needed_geosite_tags(cfg: &Config) -> HashSet<String> {
    cfg.rules
        .iter()
        .flat_map(|spec| spec.geosite_include.iter().chain(&spec.geosite_exclude))
        .map(String::as_str)
        .chain(cfg.answer_map.referenced_tags())
        .map(String::from)
        .collect()
}

fn load_geosite(cfg: &Config, needed_tags: &HashSet<String>) -> Result<Option<Arc<GeoSiteDb>>> {
    if needed_tags.is_empty() {
        return Ok(None);
    }
    if cfg.geosite_files.is_empty() {
        return Err(anyhow!(
            "GeoSite tags referenced in config but no geosite-file specified"
        ));
    }
    let db = GeoSiteDb::load(&cfg.geosite_files, needed_tags)
        .context("failed to load GeoSite database")?;
    Ok(Some(Arc::new(db)))
}

fn listeners_summary(cfg: &Config) -> String {
    let iface_suffix = match &cfg.interface {
        InterfaceFilter::All => String::new(),
        InterfaceFilter::Only(ifaces) => format!(" (iface={})", ifaces.join(",")),
        InterfaceFilter::Except(excluded) => format!(" (iface=!{})", excluded.join(",!")),
    };
    cfg.bind
        .iter()
        .map(|ep| {
            let proto = match (ep.udp, ep.tcp) {
                (true, true) => "udp+tcp",
                (true, false) => "udp",
                (false, true) => "tcp",
                (false, false) => "none",
            };
            format!("{proto}://{}{iface_suffix}", ep.addr)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn spawn_reload_watchers(state: Arc<AppState>) {
    for watcher in ReloadWatcher::for_state(&state) {
        spawn_reload_watcher(state.clone(), watcher);
    }
}

#[derive(Clone)]
enum ReloadWatcher {
    Geosite {
        paths: Vec<PathBuf>,
        tags: HashSet<String>,
    },
    Config {
        path: PathBuf,
        handle: tokio::runtime::Handle,
    },
}

impl ReloadWatcher {
    fn for_state(state: &AppState) -> Vec<Self> {
        let hot = state.hot.load();
        let mut watchers = Vec::new();
        let tags = needed_geosite_tags(&hot.cfg);
        if !tags.is_empty() {
            watchers.push(Self::Geosite {
                paths: hot.cfg.geosite_files.clone(),
                tags,
            });
        }
        if let Some(path) = &state.config_path {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                watchers.push(Self::Config {
                    path: path.clone(),
                    handle,
                });
            }
        }
        watchers
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Geosite { .. } => "geosite",
            Self::Config { .. } => "config",
        }
    }

    fn paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Geosite { paths, .. } => paths.clone(),
            Self::Config { path, .. } => vec![path.clone()],
        }
    }

    fn reload(&self, state: &AppState) -> Result<()> {
        match self {
            Self::Geosite { tags, .. } => reload_geosite(state, tags),
            Self::Config { handle, .. } => handle.block_on(reload_config(state)),
        }
    }
}

fn spawn_reload_watcher(state: Arc<AppState>, watcher: ReloadWatcher) {
    thread::spawn(move || {
        let mut backoff = Duration::from_secs(1);
        loop {
            let t0 = std::time::Instant::now();
            let name = watcher.name();
            let reload_watcher = watcher.clone();
            let state2 = state.clone();
            let result = watch_files(watcher.paths(), name, move || {
                reload_watcher.reload(&state2)
            });
            if let Err(err) = result {
                crate::warn!(
                    "reload watcher={} status=restart backoff={}s error={err:#}",
                    name,
                    backoff.as_secs()
                );
            } else {
                crate::warn!(
                    "reload watcher={} status=restart reason=channel_closed",
                    name
                );
            }
            if t0.elapsed() > Duration::from_secs(60) {
                backoff = Duration::from_secs(1);
            } else {
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
            thread::sleep(backoff);
        }
    });
}

fn reload_geosite(state: &AppState, needed_tags: &HashSet<String>) -> Result<()> {
    let (geosite_files_len, db) = {
        let hot = state.hot.load();
        let db = load_geosite(&hot.cfg, needed_tags)?;
        (hot.cfg.geosite_files.len(), db)
    };
    state.geosite.store(db);
    state.hot.load().routing_index.invalidate();
    // Increment generation before clearing the cache so in-flight queries that recorded
    // the old generation will skip the cache write and not re-pollute the fresh cache.
    state.routing_generation.fetch_add(1, Ordering::Release);
    state.cache.invalidate_all();
    state.verdict_cache.invalidate_all();
    crate::startup!(
        "reload event=geosite status=ok files={} tags={}",
        geosite_files_len,
        needed_tags.len()
    );
    Ok(())
}

async fn reload_config(state: &AppState) -> Result<()> {
    let config_path = match &state.config_path {
        Some(p) => p.clone(),
        None => return Ok(()),
    };
    let json = crate::config::json::load_json_config(&config_path)?;
    let cfg = Config::from_json(json)?;

    // Detect listener-start-only fields that changed but cannot take effect
    // without a full restart.  Warn clearly rather than silently ignoring them.
    let restart_required = {
        let old = state.hot.load();
        let mut changed: Vec<&'static str> = Vec::new();
        if old.cfg.bind != cfg.bind || old.cfg.interface != cfg.interface {
            changed.push("bind");
        }
        if old.cfg.worker_threads != cfg.worker_threads {
            changed.push("runtime.worker-threads");
        }
        if old.cfg.udp_buf_size != cfg.udp_buf_size {
            changed.push("runtime.udp-buf-size");
        }
        if old.cfg.uring_recv_buffers != cfg.uring_recv_buffers {
            changed.push("runtime.uring-recv-buffers");
        }
        if old.cfg.max_inflight != cfg.max_inflight {
            changed.push("runtime.max-inflight");
        }
        if old.cfg.tcp_max_connections != cfg.tcp_max_connections {
            changed.push("runtime.tcp-max-connections");
        }
        if old.cfg.cache_size != cfg.cache_size
            || old.cfg.cache_min_ttl != cfg.cache_min_ttl
            || old.cfg.cache_max_ttl != cfg.cache_max_ttl
            || old.cfg.cache_persist_path != cfg.cache_persist_path
            || old.cfg.cache_persist_interval != cfg.cache_persist_interval
        {
            changed.push("cache");
        }
        if old.cfg.ipset != cfg.ipset {
            changed.push("route ipset/add-ip");
        }
        if old.cfg.verdict_cache != cfg.verdict_cache {
            changed.push("route.final.verdict-cache");
        }
        if old.cfg.dashboard != cfg.dashboard {
            changed.push("dashboard");
        }
        if old.cfg.geosite_files != cfg.geosite_files {
            changed.push("route.geosite watcher");
        }
        if !changed.is_empty() {
            crate::warn!(
                "reload event=config fields=[{}] status=restart_required \
                 reason=startup_state_already_constructed",
                changed.join(",")
            );
        }
        !changed.is_empty()
    };
    // Reload is transactional: never apply only the hot half of a configuration
    // whose startup-owned resources no longer match. Keep the old snapshot intact.
    if restart_required {
        return Ok(());
    }

    let (hot, geosite) = build_hot_state(cfg, &state.querylog, &state.cache).await?;
    state.hot.store(hot);
    state.geosite.store(geosite);
    state.routing_generation.fetch_add(1, Ordering::Release);
    state.cache.invalidate_all();
    state.verdict_cache.invalidate_all();
    crate::startup!("reload event=config status=ok");
    Ok(())
}

fn watch_files<F>(paths: Vec<PathBuf>, name: &'static str, mut reload: F) -> notify::Result<()>
where
    F: FnMut() -> Result<()> + Send + 'static,
{
    if paths.is_empty() {
        return Ok(());
    }

    let dir_watches = watched_dirs(&paths);
    let target_filenames: HashSet<OsString> = dir_watches
        .values()
        .flat_map(|v| v.iter().cloned())
        .collect();

    let (tx, rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, NotifyConfig::default())?;
    for dir in dir_watches.keys() {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
    }

    // Minimum interval between successive reloads.  inotify emits multiple raw
    // events (MODIFY, CLOSE_WRITE, MOVED_TO …) for a single file save; without a
    // cooldown each save triggers 2-3 full GeoSite parses.
    const DEBOUNCE: Duration = Duration::from_millis(500);
    let mut last_reload = std::time::Instant::now()
        .checked_sub(DEBOUNCE)
        .unwrap_or(std::time::Instant::now());

    for res in rx {
        match res {
            Ok(event) => {
                if !is_reload_event(&event.kind) {
                    continue;
                }
                if !event.paths.iter().any(|p| {
                    p.file_name()
                        .is_some_and(|file| target_filenames.contains(file))
                }) {
                    continue;
                }
                if last_reload.elapsed() < DEBOUNCE {
                    continue;
                }

                let mut retries = RELOAD_RETRIES;
                loop {
                    match reload() {
                        Ok(()) => {
                            last_reload = std::time::Instant::now();
                            break;
                        }
                        Err(err) => {
                            retries -= 1;
                            if retries == 0 {
                                crate::warn!("reload event={} status=failed error={err:#}", name);
                                break;
                            }
                            thread::sleep(RELOAD_RETRY_DELAY);
                        }
                    }
                }
            }
            Err(err) => {
                crate::warn!("reload watcher={} status=event_error error={err}", name);
            }
        }
    }
    Ok(())
}

fn watched_dirs(paths: &[PathBuf]) -> HashMap<PathBuf, Vec<OsString>> {
    let mut dirs = HashMap::new();
    for path in paths {
        let parent = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let file = path.file_name().map(OsString::from).unwrap_or_default();
        dirs.entry(parent).or_insert_with(Vec::new).push(file);
    }
    dirs
}

fn is_reload_event(kind: &EventKind) -> bool {
    kind.is_modify() || kind.is_create()
}

pub async fn serve(state: Arc<AppState>) -> Result<()> {
    let (bind, ifaces) = {
        let hot = state.hot.load();
        if !hot.cfg.bind.iter().any(|ep| ep.udp || ep.tcp) {
            return Err(anyhow!("at least one bind protocol is required"));
        }
        let ifaces: Vec<Option<String>> = match &hot.cfg.interface {
            InterfaceFilter::All => vec![None],
            InterfaceFilter::Only(names) => names.iter().map(|n| Some(n.clone())).collect(),
            InterfaceFilter::Except(excluded) => {
                let all = listener::list_interface_names()
                    .context("failed to enumerate network interfaces")?;
                let filtered: Vec<Option<String>> = all
                    .into_iter()
                    .filter(|n| !excluded.contains(n))
                    .map(Some)
                    .collect();
                if filtered.is_empty() {
                    return Err(anyhow!(
                        "interface filter excludes all available network interfaces; \
                         no sockets will be created"
                    ));
                }
                filtered
            }
        };
        crate::log_info!("listening dns=[{}]", listeners_summary(&hot.cfg));
        (hot.cfg.bind.clone(), ifaces)
    };

    let mut set = tokio::task::JoinSet::new();
    for ep in &bind {
        let ep = *ep;
        for iface in &ifaces {
            if ep.udp {
                let s = state.clone();
                let iface = iface.clone();
                set.spawn(async move { listener::serve_udp(ep.addr, iface.as_deref(), s).await });
            }
            if ep.tcp {
                let s = state.clone();
                let iface = iface.clone();
                set.spawn(async move { listener::serve_tcp(ep.addr, iface.as_deref(), s).await });
            }
        }
    }
    // Return as soon as any listener exits (error or unexpected shutdown).
    match set.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(anyhow!("listener task panicked: {e}")),
        None => Ok(()),
    }
}
