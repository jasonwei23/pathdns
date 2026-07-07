//! Application state and listener orchestration.
//!
//! Query lifecycle logic lives in `resolver`; listener sockets live in `listener`.

use crate::cache::DnsCache;
use crate::config::{Config, EcsMode, FallbackTarget, InterfaceFilter};
use crate::ipset::IpSetManager;
use crate::listener;
use crate::route_index::RouteIndex;
use crate::ruleset::RuleSetDb;
use crate::singleflight;
use crate::upstream::UpstreamPool;
use crate::verdict_cache::VerdictCache;
use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
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
    /// Race primary vs secondary; first valid response wins (no IP test).
    Race { primary: usize, secondary: usize },
    /// IP-test primary vs secondary against an ipcidr-behavior ruleset tag
    /// (looked up from `HotState::cfg.fallback.target` at query time).
    CidrTest { primary: usize, secondary: usize },
}

/// Config + derived rule state. Expensive to rebuild (spins up real upstream
/// connections in `build_rules`), so it's shared unchanged (via `Arc`) between
/// `HotState` generations that only reload the ruleset — a full config.json
/// reload always rebuilds this whole struct fresh.
pub struct RoutingConfig {
    pub cfg: Config,
    pub rules: Vec<Rule>,
    pub needs_ruleset: bool,
    pub fallback: ResolvedFallback,
}

/// Hot-reloadable state: routing config, the ruleset database, and the routing
/// index derived from both, swapped in as a single atomic unit on every reload
/// (config or ruleset). This is what closes the reload race: a query snapshots
/// one `Arc<HotState>` via `state.hot.load_full()` and every field it reads
/// back out of that snapshot is guaranteed to be from the same reload
/// generation, never a mix of an old and a new one.
pub struct HotState {
    routing: Arc<RoutingConfig>,
    pub ruleset: Option<Arc<RuleSetDb>>,
    pub routing_index: RouteIndex,
    /// Monotonically increasing per-reload identity, baked into this same
    /// struct rather than tracked via a separate `AtomicU64` — reading it back
    /// out of an already-loaded `HotState` snapshot is a plain field access,
    /// never a second independently-timed atomic load that could race the swap.
    pub generation: u64,
}

impl std::ops::Deref for HotState {
    type Target = RoutingConfig;
    fn deref(&self) -> &RoutingConfig {
        &self.routing
    }
}

pub struct AppState {
    /// Hot-reloadable routing + config + ruleset state.  Load with
    /// `state.hot.load()` (sync/fast) or `state.hot.load_full()` (returns Arc,
    /// safe to hold across .await).
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
    pub querylog: crate::querylog::QueryLogHandle,
    /// Serializes `reload_ruleset`/`reload_config`: each does a plain
    /// read-`hot`/compute/`store`-`hot` sequence with no CAS, so two reloads
    /// racing (a ruleset file and config.json changing close together, each
    /// watched on its own OS thread) could otherwise interleave — the slower
    /// one's `store` would silently discard the faster one's already-published
    /// result, and both would mint the same `generation` for structurally
    /// different `HotState`s, breaking every `routing_gen` staleness check
    /// downstream. Held for the full read/compute/store/invalidate sequence in
    /// both reload paths, not just around the `store` call.
    reload_lock: tokio::sync::Mutex<()>,
}

pub struct Rule {
    pub name: String,
    /// Pre-interned Arc of `name`; clone is a refcount bump, no allocation per query.
    pub name_arc: Arc<str>,
    /// Pre-interned `"final->{name}"`, used when this rule wins a `route.final`
    /// primary/secondary race — precomputed here so reporting it (querylog, cache
    /// replay) is a refcount bump, never a per-query format!().
    pub final_name_arc: Arc<str>,
    /// Index of this rule in `HotState::rules`; carried in `RouteTarget::Rule`.
    pub index: usize,
    pub upstream: Option<UpstreamPool>,
    /// Rule cache policy merged over global defaults at startup.
    pub cache_policy: crate::cache::ResolvedCachePolicy,
    /// Evaluated against the resolved response — see `crate::response_filter` docs.
    pub filters: Vec<crate::response_filter::ResponseFilter>,
    pub ruleset_include: Vec<String>,
    pub ruleset_exclude: Vec<String>,
    /// True when every upstream in this rule strips ECS (mode is Strip or unset).
    /// Used to share a single cache entry across all clients rather than one per subnet.
    pub strip_ecs: bool,
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

        let hot = build_hot_state(cfg, &querylog, &cache, 0).await?;

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
            querylog,
            reload_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Opaque per-reload identity: differs from a previously captured value iff
    /// `state.hot` has been swapped since (i.e. a reload happened).
    pub fn hot_generation(&self) -> u64 {
        self.hot.load().generation
    }
}

/// Build a `HotState` from a validated config: rules (and their upstream
/// connections), fallback resolution, ruleset database, and routing index are
/// all constructed here and wrapped in one `Arc<HotState>`, so callers always
/// swap in a fully consistent generation.
async fn build_hot_state(
    cfg: Config,
    querylog: &crate::querylog::QueryLogHandle,
    cache: &DnsCache,
    generation: u64,
) -> Result<Arc<HotState>> {
    let upstream_cfg = cfg.upstream_config();
    let rules = build_rules(&cfg, &upstream_cfg, querylog, cache).await?;
    let fallback = resolve_fallback(&cfg, &rules)?;
    let domain_tags = needed_ruleset_domain_tags(&cfg);
    let ipcidr_tags = needed_ruleset_ipcidr_tags(&cfg);
    let needs_ruleset = !domain_tags.is_empty() || !ipcidr_tags.is_empty();
    let ruleset = load_ruleset(cfg.ruleset_specs.clone(), domain_tags, ipcidr_tags).await?;
    let routing_index = RouteIndex::build(&rules);
    if !cfg.answer_map.is_empty() {
        crate::startup!("answer map entries={}", cfg.answer_map.len());
    }
    let routing = Arc::new(RoutingConfig {
        cfg,
        rules,
        needs_ruleset,
        fallback,
    });
    Ok(Arc::new(HotState {
        routing,
        ruleset,
        routing_index,
        generation,
    }))
}

/// Build the list of `Rule` from a parsed config.
async fn build_rules(
    cfg: &Config,
    upstream_cfg: &crate::config::UpstreamConfig,
    querylog: &crate::querylog::QueryLogHandle,
    cache: &DnsCache,
) -> Result<Vec<Rule>> {
    // Forward-target rule names may be defined later in the list, so the full
    // name -> index map is built upfront (config parsing already validated that
    // every forward target names a real rule).
    let name_to_idx: HashMap<&str, usize> = cfg
        .rules
        .iter()
        .enumerate()
        .map(|(i, s)| (s.name.as_str(), i))
        .collect();

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
        let filters = build_response_filters(&spec.filters, &name_to_idx)?;
        let cache_policy = cache.resolve_policy(spec.cache_policy.as_ref());
        // A rule overriding only one of min-ttl/max-ttl inherits the other from the
        // global cache config; config-parse-time validation only cross-checks a
        // pair set on the *same* scope, so an inconsistent effective pair (e.g. a
        // rule's min-ttl above the global max-ttl) would otherwise silently clamp
        // every cached entry to the smaller value instead of erroring.
        if cache_policy.min_ttl > 0
            && cache_policy.max_ttl > 0
            && cache_policy.min_ttl > cache_policy.max_ttl
        {
            return Err(anyhow!(
                "rule \"{}\": effective cache.min-ttl ({}) exceeds effective cache.max-ttl ({}) \
                 once inherited from the global cache config",
                spec.name,
                cache_policy.min_ttl,
                cache_policy.max_ttl
            ));
        }
        rules.push(Rule {
            name: spec.name.clone(),
            name_arc: Arc::from(spec.name.as_str()),
            final_name_arc: Arc::from(format!("final->{}", spec.name)),
            index: idx,
            upstream,
            cache_policy,
            filters,
            ruleset_include: spec.ruleset_include.clone(),
            ruleset_exclude: spec.ruleset_exclude.clone(),
            strip_ecs,
        });
    }
    Ok(rules)
}

/// Compile config-level `RuleFilterSpec`s into runtime `ResponseFilter`s, resolving
/// each `forward` target's rule name to an index via `name_to_idx`.
fn build_response_filters(
    specs: &[crate::config::RuleFilterSpec],
    name_to_idx: &HashMap<&str, usize>,
) -> Result<Vec<crate::response_filter::ResponseFilter>> {
    use crate::config::RuleFilterActionSpec;
    use crate::response_filter::{FilterAction, ResponseFilter};

    specs
        .iter()
        .map(|spec| {
            let action = match &spec.action {
                RuleFilterActionSpec::Empty => FilterAction::Empty,
                RuleFilterActionSpec::Drop => FilterAction::Drop,
                RuleFilterActionSpec::Continue => FilterAction::Continue,
                RuleFilterActionSpec::Forward(name) => {
                    let idx = *name_to_idx
                        .get(name.as_str())
                        .ok_or_else(|| anyhow!("filter forward target \"{name}\": no such rule"))?;
                    FilterAction::Forward(idx)
                }
            };
            Ok(ResponseFilter {
                answer_ip: spec.answer_ip.clone(),
                response_type: spec.response_type.iter().copied().collect(),
                response_rcode: spec.response_rcode.iter().copied().collect(),
                response_qclass: spec.response_qclass.iter().copied().collect(),
                action,
            })
        })
        .collect()
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
            answer_ip_tags,
        } => {
            let p = find(primary)?;
            let s = find(secondary)?;
            if !answer_ip_tags.is_empty() {
                ResolvedFallback::CidrTest {
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

/// Ruleset tags needed for domain-based tag matching (`rule.tag` / `route.answer`'s `tag:`).
pub(crate) fn needed_ruleset_domain_tags(cfg: &Config) -> HashSet<String> {
    cfg.rules
        .iter()
        .flat_map(|spec| spec.ruleset_include.iter().chain(&spec.ruleset_exclude))
        .map(String::as_str)
        .chain(cfg.answer_map.referenced_tags())
        .map(String::from)
        .collect()
}

/// Ruleset tags needed for ipcidr matching: `route.final`'s fallback test, if
/// configured, plus every tag referenced by a `rule.filter`'s `answer-ip`.
pub(crate) fn needed_ruleset_ipcidr_tags(cfg: &Config) -> HashSet<String> {
    let mut tags: HashSet<String> = match &cfg.fallback.target {
        FallbackTarget::Dual { answer_ip_tags, .. } => answer_ip_tags.iter().cloned().collect(),
        _ => HashSet::new(),
    };
    for spec in &cfg.rules {
        for filter in &spec.filters {
            tags.extend(filter.answer_ip.iter().cloned());
        }
    }
    tags
}

/// Load the ruleset database, offloading the (potentially slow: large `.mrs`
/// files, zstd decompression, regex compilation) blocking file I/O onto
/// tokio's blocking-task pool rather than running it inline on the calling
/// task — the same pattern used for the ipset netlink test this fallback
/// mechanism replaced (see git history) and for the periodic cache-persist
/// save in `main.rs`.
async fn load_ruleset(
    ruleset_specs: Vec<crate::ruleset::RuleSetSpec>,
    domain_tags: HashSet<String>,
    ipcidr_tags: HashSet<String>,
) -> Result<Option<Arc<RuleSetDb>>> {
    if domain_tags.is_empty() && ipcidr_tags.is_empty() {
        return Ok(None);
    }
    if ruleset_specs.is_empty() {
        return Err(anyhow!(
            "ruleset tags referenced in config but route.ruleset has no entries"
        ));
    }
    let db = tokio::task::spawn_blocking(move || {
        RuleSetDb::load(&ruleset_specs, &domain_tags, &ipcidr_tags)
    })
    .await
    .map_err(|e| anyhow!("ruleset load task failed: {e}"))?
    .context("failed to load ruleset database")?;
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
    RuleSet {
        paths: Vec<PathBuf>,
        domain_tags: HashSet<String>,
        ipcidr_tags: HashSet<String>,
        handle: tokio::runtime::Handle,
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
        let domain_tags = needed_ruleset_domain_tags(&hot.cfg);
        let ipcidr_tags = needed_ruleset_ipcidr_tags(&hot.cfg);
        if !domain_tags.is_empty() || !ipcidr_tags.is_empty() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                watchers.push(Self::RuleSet {
                    paths: hot
                        .cfg
                        .ruleset_specs
                        .iter()
                        .map(|s| s.path.clone())
                        .collect(),
                    domain_tags,
                    ipcidr_tags,
                    handle,
                });
            }
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
            Self::RuleSet { .. } => "ruleset",
            Self::Config { .. } => "config",
        }
    }

    fn paths(&self) -> Vec<PathBuf> {
        match self {
            Self::RuleSet { paths, .. } => paths.clone(),
            Self::Config { path, .. } => vec![path.clone()],
        }
    }

    fn reload(&self, state: &AppState) -> Result<()> {
        match self {
            Self::RuleSet {
                domain_tags,
                ipcidr_tags,
                handle,
                ..
            } => handle.block_on(reload_ruleset(state, domain_tags, ipcidr_tags)),
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

async fn reload_ruleset(
    state: &AppState,
    domain_tags: &HashSet<String>,
    ipcidr_tags: &HashSet<String>,
) -> Result<()> {
    // Serialized against `reload_config` — see `AppState::reload_lock` docs:
    // without this, a concurrent config reload could land its `store` between
    // this function's own read and store, and get silently overwritten below.
    let _reload_guard = state.reload_lock.lock().await;
    // The config/rules (and their live upstream connections) are unaffected by a
    // ruleset-only reload, so the existing `RoutingConfig` is reused as-is (a
    // cheap Arc clone, no upstream teardown/rebuild).
    let (routing, ruleset_specs, ruleset_specs_len, generation) = {
        let hot = state.hot.load();
        (
            hot.routing.clone(),
            hot.cfg.ruleset_specs.clone(),
            hot.cfg.ruleset_specs.len(),
            hot.generation.wrapping_add(1),
        )
    };
    let db = load_ruleset(ruleset_specs, domain_tags.clone(), ipcidr_tags.clone()).await?;
    // RouteIndex::build is a pure function of `rules` alone (unchanged here), so
    // rebuilding it fresh is just cheap tag re-interning; the side effect of a
    // guaranteed-empty route cache comes from construction, not a separate
    // invalidate() mutation.
    let routing_index = RouteIndex::build(&routing.rules);
    // Single atomic swap: the new ruleset, its fresh (empty) routing index, and the
    // config/rules they were derived from all become visible to concurrent queries
    // together — no window where a query can see one but not the others.
    state.hot.store(Arc::new(HotState {
        routing,
        ruleset: db,
        routing_index,
        generation,
    }));
    // Two-part invalidation, not redundant with each other: this clears
    // whatever was already cached under the *old* generation; the per-query
    // `routing_gen` check in `resolver.rs::exchange_with_dedupe` (and
    // `resolve_none_rule_with_cidr`) is the other half, stopping a query that
    // was already in flight under the old generation from writing a fresh
    // entry into the cache *after* this clear using now-stale routing
    // decisions. Store-then-clear ordering matters: a query reading `hot`
    // after the store but before this clear still sees its own write cleared
    // rather than left stale.
    state.cache.invalidate_all();
    state.verdict_cache.invalidate_all();
    crate::startup!(
        "reload event=ruleset status=ok files={} tags={}",
        ruleset_specs_len,
        domain_tags.len() + ipcidr_tags.len()
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

    // Serialized against `reload_ruleset` — see `AppState::reload_lock` docs.
    let _reload_guard = state.reload_lock.lock().await;

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
            changed.push("route add-ip");
        }
        if old.cfg.verdict_cache != cfg.verdict_cache {
            changed.push("route.final.verdict-cache");
        }
        if old.cfg.dashboard != cfg.dashboard {
            changed.push("dashboard");
        }
        if old.cfg.ruleset_specs != cfg.ruleset_specs {
            changed.push("route.ruleset watcher");
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

    let old_hot = state.hot.load_full();
    let generation = old_hot.generation.wrapping_add(1);
    let hot = build_hot_state(cfg, &state.querylog, &state.cache, generation).await?;
    state.hot.store(hot);
    // Same two-part invalidation as `reload_ruleset` above: this clears the
    // old generation's entries, `resolver.rs`'s `routing_gen` check stops a
    // still-in-flight old-generation query from writing a fresh stale one.
    state.cache.invalidate_all();
    state.verdict_cache.invalidate_all();
    // `build_hot_state` just built entirely new `UpstreamPool`s (fresh UDP
    // sockets and recv/send tasks included) for every rule, so `old_hot`'s
    // pools are now orphaned. UDP's recv-supervisor tasks have no self-timeout
    // and would otherwise block on their sockets forever, leaking FDs and
    // tasks on every single reload — see `UpstreamPool::shutdown`. Retiring
    // them is deferred rather than immediate: a query that captured `old_hot`
    // (via `state.hot.load_full()`) just before this store is still legitimately
    // exchanging with them, and each such query is itself bounded by
    // `old_hot.cfg.timeout` — so waiting comfortably past that bound before
    // tearing down guarantees no still-in-flight query gets its upstream pulled
    // out from under it.
    schedule_upstream_shutdown(old_hot);
    crate::startup!("reload event=config status=ok");
    Ok(())
}

/// Retire a superseded `HotState` generation's UDP upstream sockets/tasks
/// after a grace period bounding how long a query that grabbed a strong ref to
/// it just before the reload could still legitimately be in flight. `old_hot`
/// is moved into the spawned task so it (and everything it owns) stays alive
/// for the wait, then dropped alongside the shutdown call.
fn schedule_upstream_shutdown(old_hot: Arc<HotState>) {
    let grace = old_hot.cfg.timeout + Duration::from_secs(5);
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        for rule in &old_hot.rules {
            if let Some(pool) = &rule.upstream {
                pool.shutdown();
            }
        }
    });
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
    // cooldown each save triggers 2-3 full ruleset parses.
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
