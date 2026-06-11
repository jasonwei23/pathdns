//! Application state and listener orchestration.
//!
//! Query lifecycle logic lives in `pipeline`; listener sockets live in `listener`.

use crate::cache::{CacheKey, DnsCache};
use crate::config::{Config, FallbackTarget};
use crate::geosite::GeoSiteDb;
use crate::ipset::IpSetManager;
#[cfg(unix)]
use crate::listener;
use crate::router::RouteTarget;
use crate::routing_index::RouteIndex;
use crate::singleflight;
use crate::upstream::UpstreamPool;
use crate::verdict_cache::VerdictCache;
use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwapOption;
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::sync::Semaphore;

const RELOAD_RETRIES: usize = 5;
const RELOAD_RETRY_DELAY: Duration = Duration::from_millis(100);

/// How the fallback target was resolved at startup (group indices into `AppState::groups`).
pub enum ResolvedFallback {
    /// Route unmatched queries to a fixed group.
    Group(usize),
    /// Race primary vs secondary; first valid response wins (no ipset).
    Race { primary: usize, secondary: usize },
    /// IP-test primary vs secondary using the configured ipset.
    NoneIpSet { primary: usize, secondary: usize },
    /// Return empty response.
    Null,
}

pub struct AppState {
    pub cfg: Config,
    pub limit: Arc<Semaphore>,
    /// Connection-level semaphore for TCP. `None` = unlimited.
    pub tcp_conn_limit: Option<Arc<Semaphore>>,
    pub cache: DnsCache,
    pub groups: Vec<CustomGroup>,
    pub(crate) remote_inflight: singleflight::InflightTable,
    pub refresh_gate: RefreshGate,
    pub refresh_tx: tokio::sync::mpsc::Sender<crate::cache::CacheRefresh>,
    pub ipset: Option<Arc<IpSetManager>>,
    pub verdict_cache: VerdictCache,
    pub needs_geosite: bool,
    pub geosite: ArcSwapOption<GeoSiteDb>,
    pub routing_index: RouteIndex,
    pub fallback: ResolvedFallback,
    pub stale_client_timeout_ms: u64,
    pub querylog: crate::querylog::QueryLogHandle,
}

pub struct RefreshGate {
    active: Mutex<HashSet<CacheKey>>,
    bloom: [AtomicU64; 4],
}

pub struct CustomGroup {
    pub name: String,
    pub upstream: Option<UpstreamPool>,
    /// Group cache policy merged over global defaults at startup.
    pub cache_policy: crate::cache::ResolvedCachePolicy,
    pub filter_qtype: std::collections::HashSet<u16>,
    pub geosite_include: Vec<String>,
    pub geosite_exclude: Vec<String>,
}

impl CustomGroup {
    pub fn target(&self) -> Option<RouteTarget<'_>> {
        self.upstream.is_some().then_some(RouteTarget::Group(self))
    }
}

impl AppState {
    pub async fn new(
        cfg: Config,
        querylog: crate::querylog::QueryLogHandle,
    ) -> Result<(
        Self,
        tokio::sync::mpsc::Receiver<crate::cache::CacheRefresh>,
    )> {
        let upstream_cfg = cfg.upstream_config();

        // Cache is created before the groups so each group's cache policy can be
        // resolved against the global defaults once, at startup.
        let cache = DnsCache::new(&cfg.cache_config());

        // Build custom group pools.
        let mut groups = Vec::new();
        for spec in &cfg.groups {
            let upstream = if spec.name == "null" {
                None
            } else {
                Some(
                    UpstreamPool::new(
                        &format!("group-{}", spec.name),
                        &spec.upstream,
                        &upstream_cfg,
                        Some(querylog.counters.clone()),
                    )
                    .await?,
                )
            };
            groups.push(CustomGroup {
                name: spec.name.clone(),
                upstream,
                cache_policy: cache.resolve_policy(spec.cache_policy.as_ref()),
                filter_qtype: spec.filter_qtype.iter().copied().collect(),
                geosite_include: spec.geosite_include.clone(),
                geosite_exclude: spec.geosite_exclude.clone(),
            });
        }

        // Resolve fallback group indices.
        let fallback = resolve_fallback(&cfg, &groups)?;

        if let Some(path) = &cfg.cache_persist_path {
            let fp = crate::config::cache_fingerprint(&cfg);
            match cache.load_from_file(path, fp) {
                Ok(n) if n > 0 => crate::startup!("cache persist=loaded entries={n}"),
                Ok(_) => {}
                Err(e) => crate::startup!("cache persist=load_failed error={e:#}"),
            }
        }

        #[cfg(target_os = "linux")]
        let ipset = cfg
            .ipset
            .as_ref()
            .map(IpSetManager::new)
            .transpose()?
            .map(Arc::new);
        #[cfg(not(target_os = "linux"))]
        let ipset: Option<Arc<IpSetManager>> = None;
        let verdict_cache = VerdictCache::new(cfg.verdict_cache.as_ref());
        if verdict_cache.enabled() {
            if let Some(path) = &cfg.cache_persist_path {
                let vpath = crate::verdict_cache::persist_path_for(path);
                if vpath.exists() {
                    let fp = crate::config::cache_fingerprint(&cfg);
                    match verdict_cache.load_from_file(&vpath, fp) {
                        Ok(n) if n > 0 => crate::startup!("verdict_cache persist=loaded entries={n}"),
                        Ok(_) => {}
                        Err(e) => crate::startup!("verdict_cache persist=load_failed error={e:#}"),
                    }
                }
            }
        }

        let needed_tags = needed_geosite_tags(&cfg);
        let needs_geosite = !needed_tags.is_empty();
        let geosite = load_geosite(&cfg, &needed_tags)?;
        let routing_index = RouteIndex::build(&groups);

        let max = cfg.max_inflight;
        let tcp_conn_limit = (cfg.tcp_max_connections > 0)
            .then(|| Arc::new(Semaphore::new(cfg.tcp_max_connections)));
        let stale_client_timeout_ms = cfg.cache_stale_client_timeout;
        let (refresh_tx, refresh_rx) = tokio::sync::mpsc::channel::<crate::cache::CacheRefresh>(64);
        Ok((
            Self {
                cfg,
                limit: Arc::new(Semaphore::new(max)),
                tcp_conn_limit,
                cache,
                groups,
                remote_inflight: singleflight::InflightTable::new(),
                refresh_gate: RefreshGate::new(),
                refresh_tx,
                ipset,
                verdict_cache,
                needs_geosite,
                geosite: ArcSwapOption::new(geosite),
                routing_index,
                fallback,
                stale_client_timeout_ms,
                querylog,
            },
            refresh_rx,
        ))
    }

    pub fn geosite_snapshot(&self) -> Option<Arc<GeoSiteDb>> {
        self.geosite.load_full()
    }
}

/// Resolve fallback group names to indices in `groups`.
fn resolve_fallback(cfg: &Config, groups: &[CustomGroup]) -> Result<ResolvedFallback> {
    let find = |name: &str| -> Result<usize> {
        groups
            .iter()
            .position(|g| g.name == name)
            .ok_or_else(|| anyhow!("fallback group not found: {name}"))
    };
    Ok(match &cfg.fallback.target {
        FallbackTarget::Null => ResolvedFallback::Null,
        FallbackTarget::Group(name) => ResolvedFallback::Group(find(name)?),
        FallbackTarget::None {
            primary,
            secondary,
            ipset,
        } => {
            let p = find(primary)?;
            let s = find(secondary)?;
            if ipset.is_some() {
                ResolvedFallback::NoneIpSet {
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

fn needed_geosite_tags(cfg: &Config) -> HashSet<String> {
    cfg.groups
        .iter()
        .flat_map(|spec| spec.geosite_include.iter().chain(&spec.geosite_exclude))
        .cloned()
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
    let mut total = 0usize;
    for (_tag, count) in db.tag_counts() {
        total += count;
    }
    crate::startup!(
        "geosite files={} tags={} matchers={}",
        cfg.geosite_files.len(),
        needed_tags.len(),
        total
    );
    Ok(Some(Arc::new(db)))
}

fn listeners_summary(cfg: &Config) -> &'static str {
    match (cfg.listen_udp, cfg.listen_tcp) {
        (true, true) => "udp,tcp",
        (true, false) => "udp",
        (false, true) => "tcp",
        (false, false) => "none",
    }
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
}

impl ReloadWatcher {
    fn for_state(state: &AppState) -> Vec<Self> {
        let mut watchers = Vec::new();
        let tags = needed_geosite_tags(&state.cfg);
        if !tags.is_empty() {
            watchers.push(Self::Geosite {
                paths: state.cfg.geosite_files.clone(),
                tags,
            });
        }
        watchers
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Geosite { .. } => "geosite",
        }
    }

    fn paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Geosite { paths, .. } => paths.clone(),
        }
    }

    fn reload(&self, state: &AppState) -> Result<()> {
        match self {
            Self::Geosite { tags, .. } => reload_geosite(state, tags),
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
    let db = load_geosite(&state.cfg, needed_tags)?;
    state.geosite.store(db);
    state.routing_index.invalidate();
    state.cache.invalidate_all();
    crate::startup!(
        "reload event=geosite status=ok files={} tags={}",
        state.cfg.geosite_files.len(),
        needed_tags.len()
    );
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

                let mut retries = RELOAD_RETRIES;
                loop {
                    match reload() {
                        Ok(()) => break,
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

impl RefreshGate {
    pub(crate) fn new() -> Self {
        Self {
            active: Mutex::new(HashSet::new()),
            bloom: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    pub(crate) fn begin(&self, key: &CacheKey) -> bool {
        let bit_idx = key & 63;
        let word_idx = (key >> 6) & 3;
        let bit = 1u64 << bit_idx;
        let old = self.bloom[word_idx as usize].fetch_or(bit, Ordering::Relaxed);
        let Ok(mut active) = self.active.lock() else {
            return false;
        };
        if old & bit != 0 && active.contains(key) {
            return false;
        }
        active.insert(*key)
    }

    pub(crate) fn end(&self, key: &CacheKey) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(key);
            if active.is_empty() {
                for w in &self.bloom {
                    w.store(0, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(unix)]
pub async fn serve(state: Arc<AppState>) -> Result<()> {
    if !state.cfg.listen_udp && !state.cfg.listen_tcp {
        return Err(anyhow!("at least one bind protocol is required"));
    }
    let proto = listeners_summary(&state.cfg);
    let addrs = state.cfg.bind.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(" ");
    crate::startup!("listening dns=[{addrs}] proto={proto}");
    let mut set = tokio::task::JoinSet::new();
    for &addr in &state.cfg.bind {
        if state.cfg.listen_udp {
            let s = state.clone();
            set.spawn(async move { listener::serve_udp(addr, s).await });
        }
        if state.cfg.listen_tcp {
            let s = state.clone();
            set.spawn(async move { listener::serve_tcp(addr, s).await });
        }
    }
    // Return as soon as any listener exits (error or unexpected shutdown).
    match set.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(anyhow!("listener task panicked: {e}")),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
pub async fn serve(_state: Arc<AppState>) -> Result<()> {
    anyhow::bail!("listener not available on non-unix")
}
