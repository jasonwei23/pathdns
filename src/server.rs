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
use inotify::{Inotify, WatchMask};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::Semaphore;

const RELOAD_RETRIES: usize = 5;
const RELOAD_RETRY_DELAY: Duration = Duration::from_millis(100);

/// How the fallback target was resolved at startup.
pub enum ResolvedFallback {
    /// `route.final` was omitted: fall back to the last configured rule
    /// (index into `HotState::rules`).
    Rule(usize),
    /// Explicit `route.final: "<server>"`: route straight to that server
    /// (index into `HotState::servers`).
    Server(usize),
    /// Race primary vs secondary; first valid response wins (no IP test).
    /// Indices into `HotState::servers`.
    Race { primary: usize, secondary: usize },
    /// IP-test primary vs secondary against an ipcidr-behavior ruleset tag
    /// (looked up from `HotState::cfg.fallback.target` at query time).
    /// Indices into `HotState::servers`.
    CidrTest { primary: usize, secondary: usize },
}

/// Config + derived rule state. Expensive to rebuild (spins up real upstream
/// connections in `build_rules`), so it's shared unchanged (via `Arc`) between
/// `HotState` generations that only reload the ruleset — a full config.json
/// reload always rebuilds this whole struct fresh.
pub struct RoutingConfig {
    pub cfg: Config,
    /// Named upstream pools (`route.servers`), shared by every rule that
    /// references one via `RuleSpec::server`, and directly targetable from
    /// `route.final`/`rule.filter`'s `forward`.
    pub servers: Vec<Server>,
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

/// Reload outcome bookkeeping, surfaced through the dashboard's `/api/stats`.
///
/// This exists because the reload paths' `warn!`/`startup!` logging is
/// compiled out: without it, a hot reload that keeps failing — or one that
/// silently requires a restart — is indistinguishable from one that applied,
/// and the operator only finds out when stale routing shows up in answers.
pub struct ReloadStats {
    /// Reloads (config or ruleset) that were fully applied.
    pub applied: AtomicU64,
    /// Failed reload *attempts* (the watcher retries each event up to
    /// `RELOAD_RETRIES` times, and each failing attempt counts).
    pub failed_attempts: AtomicU64,
    /// Config reloads rejected because a startup-only field changed.
    pub restart_required: AtomicU64,
    /// Unix seconds of the most recent applied reload. 0 = none yet.
    pub last_applied_unix: AtomicU64,
    /// Most recent failure or restart-required description; cleared by the
    /// next applied reload.
    last_error: std::sync::Mutex<Option<String>>,
}

impl ReloadStats {
    fn new() -> Self {
        Self {
            applied: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            restart_required: AtomicU64::new(0),
            last_applied_unix: AtomicU64::new(0),
            last_error: std::sync::Mutex::new(None),
        }
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn set_last_error(&self, msg: Option<String>) {
        *self
            .last_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = msg;
    }

    fn record_applied(&self) {
        self.applied.fetch_add(1, Ordering::Relaxed);
        self.last_applied_unix
            .store(Self::now_unix(), Ordering::Relaxed);
        self.set_last_error(None);
    }

    fn record_failed_attempt(&self, err: &anyhow::Error) {
        self.failed_attempts.fetch_add(1, Ordering::Relaxed);
        self.set_last_error(Some(format!("{err:#}")));
    }

    fn record_restart_required(&self, fields: &[&'static str]) {
        self.restart_required.fetch_add(1, Ordering::Relaxed);
        self.set_last_error(Some(format!(
            "config change not applied; restart required for: {}",
            fields.join(",")
        )));
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
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
    /// Hot-reload outcome counters + last error, for `/api/stats`.
    pub reload: ReloadStats,
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

/// What a `route.servers` entry (or a rule/final/forward target referencing
/// one) actually resolves to at query time.
#[derive(Clone)]
pub enum ServerKind {
    /// A real, shared upstream connection pool.
    Upstream(Arc<UpstreamPool>),
    /// Synthesised locally — no network I/O at all.
    Fixed(crate::config::FixedAnswerSet),
}

/// A `route.servers` entry. Every rule referencing this name via
/// `RuleSpec::server` clones `kind` (an `Arc<UpstreamPool>` clone is a
/// refcount bump; a `FixedAnswerSet` clone is a cheap small-data copy);
/// `route.final` and `rule.filter`'s `forward` can also target a server
/// directly, bypassing rule-level cache overrides/filters/add-ip.
pub struct Server {
    pub name: String,
    /// Pre-interned Arc of `name`; clone is a refcount bump, no allocation per query.
    pub name_arc: Arc<str>,
    /// Pre-interned `"final->{name}"`, used when this server wins a `route.final`
    /// primary/secondary race, or is targeted directly by a single-target
    /// `route.final` — precomputed here so reporting it (querylog, cache
    /// replay) is a refcount bump, never a per-query format!().
    pub final_name_arc: Arc<str>,
    /// Index of this server in `HotState::servers`.
    pub index: usize,
    pub kind: ServerKind,
    /// True when every upstream endpoint strips ECS (mode is Strip or unset),
    /// or this is a fixed answer (always ECS-independent).
    /// Used to share a single cache entry across all clients rather than one per subnet.
    pub strip_ecs: bool,
}

pub struct Rule {
    /// Index of this rule in `HotState::rules`; carried in `RouteTarget::Rule`.
    pub index: usize,
    /// Name of the `route.servers` entry this rule resolves through.
    pub server: String,
    /// Pre-interned Arc of `server`; clone is a refcount bump, no allocation
    /// per query — shared with the `Server`'s own `name_arc`.
    pub server_arc: Arc<str>,
    pub kind: ServerKind,
    /// Rule cache policy merged over global defaults at startup.
    pub cache_policy: crate::cache::ResolvedCachePolicy,
    /// Evaluated against the resolved response — see `crate::response_filter` docs.
    pub filters: Vec<crate::response_filter::ResponseFilter>,
    /// Empty = catch-all. See `crate::config::RuleMatcher`.
    pub matcher: Vec<crate::config::RuleMatcher>,
    /// True when every upstream in this rule strips ECS (mode is Strip or unset).
    /// Used to share a single cache entry across all clients rather than one per subnet.
    pub strip_ecs: bool,
}

impl Rule {
    pub fn target(&self) -> crate::router::RouteTarget<'_> {
        crate::router::RouteTarget::Rule(self, self.index)
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
        // each domain to be queried again. Re-runs each cached response through its
        // rule's filter chain to find which `accept`+`add-ip` entry (if any) would
        // have matched it — mirroring the live path, where `add-ip` only fires on an
        // explicit filter match rather than unconditionally per rule.
        if let Some(ref ipset_mgr) = ipset {
            // Collect IPs per (rule, filter) so we can batch, deduplicate, and send
            // in one netlink message per set rather than one per cache entry.
            let mut filter_ips: HashMap<(usize, usize), Vec<std::net::IpAddr>> = HashMap::new();
            let ruleset = hot.ruleset.as_deref();
            cache.for_each_rule_entry(|rule_id, packet, question_end| {
                let Some(rule) = hot.rules.get(rule_id as usize) else {
                    return;
                };
                let Some((filter_idx, filter)) = crate::response_filter::first_match(
                    &rule.filters,
                    ruleset,
                    packet,
                    question_end,
                ) else {
                    return;
                };
                if !matches!(filter.action, crate::response_filter::FilterAction::Accept) {
                    return;
                }
                let ips = crate::dns::answer_ips(packet, question_end);
                if !ips.is_empty() {
                    filter_ips
                        .entry((rule_id as usize, filter_idx))
                        .or_default()
                        .extend_from_slice(&ips);
                }
            });
            if !filter_ips.is_empty() {
                let count = filter_ips.len();
                for ((rule_idx, filter_idx), ips) in &filter_ips {
                    ipset_mgr.add_filter_ips(*rule_idx, *filter_idx, ips);
                }
                crate::startup!("add_ip persist=restore_queued filters={count}");
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
            reload: ReloadStats::new(),
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
    let servers = build_servers(&cfg, &upstream_cfg, querylog).await?;
    let rules = build_rules(&cfg, &servers, cache).await?;
    let fallback = resolve_fallback(&cfg, &rules, &servers)?;
    let domain_tags = needed_ruleset_domain_tags(&cfg);
    let ipcidr_tags = needed_ruleset_ipcidr_tags(&cfg);
    let needs_ruleset = !domain_tags.is_empty() || !ipcidr_tags.is_empty();
    let ruleset = load_ruleset(cfg.ruleset_specs.clone(), domain_tags, ipcidr_tags, None).await?;
    let routing_index = RouteIndex::build(&rules, cfg.cache_size);
    let routing = Arc::new(RoutingConfig {
        cfg,
        servers,
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

/// Build one shared `Server` per `route.servers` entry: a real `Arc<UpstreamPool>`
/// for an upstream entry, or a `FixedAnswerSet` (no network I/O) for a
/// synthesised one. Every rule referencing the same server name (via
/// `RuleSpec::server`) clones the same pool `Arc`, so upstream servers share
/// one connection pool instead of opening independent sockets per rule.
async fn build_servers(
    cfg: &Config,
    upstream_cfg: &crate::config::UpstreamConfig,
    querylog: &crate::querylog::QueryLogHandle,
) -> Result<Vec<Server>> {
    use crate::config::ServerSpec;

    let mut servers = Vec::with_capacity(cfg.servers.len());
    for (idx, (name, spec)) in cfg.servers.iter().enumerate() {
        let (kind, strip_ecs) = match spec {
            ServerSpec::Upstream(endpoints) => {
                let pool = UpstreamPool::new(
                    name,
                    endpoints,
                    upstream_cfg,
                    Some(querylog.counters.clone()),
                )
                .await?;
                let strip_ecs = endpoints
                    .iter()
                    .all(|ep| matches!(ep.ecs_mode, Some(EcsMode::Strip) | None));
                (ServerKind::Upstream(Arc::new(pool)), strip_ecs)
            }
            // Fixed answers are the same for every client, so they're always
            // ECS-independent — one shared cache entry regardless of subnet.
            ServerSpec::Fixed(set) => (ServerKind::Fixed(set.clone()), true),
        };
        servers.push(Server {
            name: name.clone(),
            name_arc: Arc::from(name.as_str()),
            final_name_arc: Arc::from(format!("final->{name}")),
            index: idx,
            kind,
            strip_ecs,
        });
    }
    Ok(servers)
}

/// Build the list of `Rule` from a parsed config.
async fn build_rules(cfg: &Config, servers: &[Server], cache: &DnsCache) -> Result<Vec<Rule>> {
    // Config parsing already validated every rule's `server` (and every filter
    // `forward` target) names a real `route.servers` entry, so lookups below
    // can't miss.
    let server_by_name: HashMap<&str, &Server> =
        servers.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut rules = Vec::new();
    for (idx, spec) in cfg.rules.iter().enumerate() {
        let server = server_by_name[spec.server.as_str()];
        let kind = server.kind.clone();
        let strip_ecs = server.strip_ecs;
        let filters = build_response_filters(&spec.filters, &server_by_name)?;
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
                "rule #{idx}: effective cache.min-ttl ({}) exceeds effective cache.max-ttl ({}) \
                 once inherited from the global cache config",
                cache_policy.min_ttl,
                cache_policy.max_ttl
            ));
        }
        rules.push(Rule {
            index: idx,
            server: spec.server.clone(),
            server_arc: Arc::clone(&server.name_arc),
            kind,
            cache_policy,
            filters,
            matcher: spec.matcher.clone(),
            strip_ecs,
        });
    }
    Ok(rules)
}

/// Compile config-level `RuleFilterSpec`s into runtime `ResponseFilter`s, resolving
/// each `forward` target's server name to an index via `server_by_name`.
fn build_response_filters(
    specs: &[crate::config::RuleFilterSpec],
    server_by_name: &HashMap<&str, &Server>,
) -> Result<Vec<crate::response_filter::ResponseFilter>> {
    use crate::config::RuleFilterActionSpec;
    use crate::response_filter::{FilterAction, ResponseFilter};

    specs
        .iter()
        .map(|spec| {
            let action = match &spec.action {
                RuleFilterActionSpec::Accept => FilterAction::Accept,
                RuleFilterActionSpec::Drop => FilterAction::Drop,
                RuleFilterActionSpec::Forward(name) => {
                    let idx = server_by_name
                        .get(name.as_str())
                        .ok_or_else(|| {
                            anyhow!("filter forward target \"{name}\": no such route.servers entry")
                        })?
                        .index;
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

/// Resolve the fallback target to indices: `LastRule`/an explicit rule-list
/// index (only ever the last one) into `rules`, or a `route.servers` name
/// into `servers`.
fn resolve_fallback(cfg: &Config, rules: &[Rule], servers: &[Server]) -> Result<ResolvedFallback> {
    let find_server = |name: &str| -> Result<usize> {
        servers
            .iter()
            .position(|s| s.name == name)
            .ok_or_else(|| anyhow!("fallback server not found: {name}"))
    };
    Ok(match &cfg.fallback.target {
        FallbackTarget::LastRule => {
            let idx = rules
                .len()
                .checked_sub(1)
                .ok_or_else(|| anyhow!("route.final is required when route.rules is empty"))?;
            ResolvedFallback::Rule(idx)
        }
        FallbackTarget::Server(name) => ResolvedFallback::Server(find_server(name)?),
        FallbackTarget::Dual {
            primary,
            secondary,
            answer_ip,
        } => {
            let p = find_server(primary)?;
            let s = find_server(secondary)?;
            if !answer_ip.is_empty() {
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

/// Ruleset tags needed for domain-based tag matching (`rule.matcher`'s `tag:` entries).
pub(crate) fn needed_ruleset_domain_tags(cfg: &Config) -> HashSet<String> {
    cfg.rules
        .iter()
        .flat_map(|spec| &spec.matcher)
        .filter_map(|m| match m {
            crate::config::RuleMatcher::Tag { include, exclude } => {
                Some(include.iter().chain(exclude))
            }
            crate::config::RuleMatcher::Domain(_) => None,
        })
        .flatten()
        .cloned()
        .collect()
}

/// Ruleset tags needed for ipcidr matching: `route.final`'s fallback test, if
/// configured, plus every tag referenced by a `rule.filter`'s `answer-ip`.
pub(crate) fn needed_ruleset_ipcidr_tags(cfg: &Config) -> HashSet<String> {
    let mut tags: HashSet<String> = HashSet::new();
    if let FallbackTarget::Dual { answer_ip, .. } = &cfg.fallback.target {
        tags.extend(answer_ip.include.iter().cloned());
        tags.extend(answer_ip.exclude.iter().cloned());
    }
    for spec in &cfg.rules {
        for filter in &spec.filters {
            tags.extend(filter.answer_ip.include.iter().cloned());
            tags.extend(filter.answer_ip.exclude.iter().cloned());
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
/// `reuse`, when set, is `(previous_db, changed_paths)` — see
/// `RuleSetDb::load`'s doc comment. Only `reload_ruleset` (a single ruleset
/// file changing) passes this; startup and a full config reload always load
/// every referenced tag fresh.
async fn load_ruleset(
    ruleset_specs: Vec<crate::ruleset::RuleSetSpec>,
    domain_tags: HashSet<String>,
    ipcidr_tags: HashSet<String>,
    reuse: Option<(Arc<RuleSetDb>, HashSet<PathBuf>)>,
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
        RuleSetDb::load(
            &ruleset_specs,
            &domain_tags,
            &ipcidr_tags,
            reuse.as_ref().map(|(db, changed)| (db.as_ref(), changed)),
        )
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
        // Watch ruleset files whenever any are configured — NOT only when the
        // startup config references a tag. A config hot-reload can introduce
        // the first tag reference later, and the watcher set is never rebuilt,
        // so gating on the startup tag set would leave those later references
        // without file-change reloads. Which tags to (re)load is decided per
        // reload from the then-current config — see `reload_ruleset`.
        if !hot.cfg.ruleset_specs.is_empty() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                watchers.push(Self::RuleSet {
                    paths: hot
                        .cfg
                        .ruleset_specs
                        .iter()
                        .map(|s| s.path.clone())
                        .collect(),
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

    /// `changed` is the set of watched files (normalized full paths — see
    /// `normalized_watch_path`) that changed since the last successful reload.
    /// `Config`'s reload always re-reads everything regardless, so it ignores this.
    fn reload(&self, state: &AppState, changed: &HashSet<PathBuf>) -> Result<()> {
        let result = match self {
            Self::RuleSet { handle, .. } => handle.block_on(reload_ruleset(state, changed)),
            Self::Config { handle, .. } => handle.block_on(reload_config(state)),
        };
        if let Err(err) = &result {
            state.reload.record_failed_attempt(err);
        }
        result
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
            let result = watch_files(watcher.paths(), name, move |changed: &HashSet<PathBuf>| {
                reload_watcher.reload(&state2, changed)
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

async fn reload_ruleset(state: &AppState, changed_paths: &HashSet<PathBuf>) -> Result<()> {
    // Serialized against `reload_config` — see `AppState::reload_lock` docs:
    // without this, a concurrent config reload could land its `store` between
    // this function's own read and store, and get silently overwritten below.
    let _reload_guard = state.reload_lock.lock().await;
    // The config/rules (and their live upstream connections) are unaffected by a
    // ruleset-only reload, so the existing `RoutingConfig` is reused as-is (a
    // cheap Arc clone, no upstream teardown/rebuild).
    //
    // The tag sets are recomputed here from the *current* config, under the
    // same snapshot as everything else — never carried over from watcher
    // construction time. A config hot-reload can change which tags the rules
    // reference; a watcher-held snapshot would rebuild the ruleset DB for the
    // old tags and silently turn every newer tag reference into "never
    // matches".
    let (routing, ruleset_specs, ruleset_specs_len, generation, previous_db, domain_tags, ipcidr_tags) = {
        let hot = state.hot.load();
        (
            hot.routing.clone(),
            hot.cfg.ruleset_specs.clone(),
            hot.cfg.ruleset_specs.len(),
            hot.generation.wrapping_add(1),
            hot.ruleset.clone(),
            needed_ruleset_domain_tags(&hot.cfg),
            needed_ruleset_ipcidr_tags(&hot.cfg),
        )
    };
    // Nothing in the current config references ruleset data: the file change
    // is irrelevant to routing, so skip the swap (and the cache invalidation
    // it would force). If a later config reload introduces tag references, it
    // performs its own full fresh ruleset load.
    if domain_tags.is_empty() && ipcidr_tags.is_empty() {
        return Ok(());
    }
    // Only the file(s) in `changed_paths` are actually re-read/re-parsed;
    // every other referenced ruleset tag is reused as-is from `previous_db` — see
    // `RuleSetDb::load`'s doc comment.
    let reuse = previous_db.map(|db| (db, changed_paths.clone()));
    let db = load_ruleset(ruleset_specs, domain_tags, ipcidr_tags, reuse).await?;
    // RouteIndex::build is a pure function of `rules`/`cache_size` alone
    // (unchanged here), so rebuilding it fresh is just cheap tag
    // re-interning; the side effect of a guaranteed-empty route cache comes
    // from construction, not a separate invalidate() mutation.
    let routing_index = RouteIndex::build(&routing.rules, routing.cfg.cache_size);
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
    state.reload.record_applied();
    crate::log_info!(
        "reload event=ruleset status=ok files={ruleset_specs_len} generation={generation}"
    );
    Ok(())
}

async fn reload_config(state: &AppState) -> Result<()> {
    let config_path = match &state.config_path {
        Some(p) => p.clone(),
        None => return Ok(()),
    };
    let json = crate::config::json::load_json_config(&config_path)?;
    let mut cfg = Config::from_json(json)?;
    // Same path anchoring as startup (`Config::parse_args`), so the
    // startup-only-change comparison below never sees a spurious diff from
    // one side being anchored and the other not.
    cfg.anchor_paths(&crate::config::config_base_dir(&config_path));

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
        if old.cfg.udp_diagnostics != cfg.udp_diagnostics {
            changed.push("runtime.udp-diagnostics");
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
            // Always printed: silently swallowing this leaves the operator
            // believing the edit took effect (the watcher reports success and
            // clears the pending events).
            crate::log_error!(
                "reload event=config fields=[{}] status=restart_required \
                 reason=startup_state_already_constructed",
                changed.join(",")
            );
            state.reload.record_restart_required(&changed);
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
    // pools are now orphaned once the last reference drops. No explicit
    // teardown is scheduled here: each `UpstreamNode`'s `Drop` impl (see
    // `upstream/mod.rs`) shuts down its UDP recv tasks/sockets when the pool
    // is dropped, which happens exactly when the last in-flight query still
    // holding `old_hot` finishes — never earlier (a fixed grace period could
    // undershoot a hedged + filter-forwarded query's true worst case) and
    // never leaked (a query can't hold the old generation forever, being
    // bounded by its own timeouts).
    drop(old_hot);
    state.reload.record_applied();
    crate::log_info!("reload event=config status=ok generation={generation}");
    Ok(())
}

/// Watch mask covering every raw inotify event a config/ruleset file save can
/// produce: a plain in-place write (MODIFY, CLOSE_WRITE) and an atomic
/// editor-style replace, i.e. write-to-temp-then-rename-over-original
/// (CREATE, MOVED_TO — the new inode lands under the watched directory).
/// Scoping the watch to just these means the kernel never wakes us for
/// unrelated activity in the directory (ACCESS, OPEN, ATTRIB, …), unlike
/// `notify`'s cross-platform API, which reports everything and leaves
/// filtering to the caller.
const RELOAD_WATCH_MASK: WatchMask = WatchMask::MODIFY
    .union(WatchMask::CREATE)
    .union(WatchMask::CLOSE_WRITE)
    .union(WatchMask::MOVED_TO);

fn watch_files<F>(paths: Vec<PathBuf>, name: &'static str, mut reload: F) -> Result<()>
where
    F: FnMut(&HashSet<PathBuf>) -> Result<()> + Send + 'static,
{
    if paths.is_empty() {
        return Ok(());
    }

    let dir_watches = watched_dirs(&paths);
    // Full normalized paths (see `normalized_watch_path`) rather than bare
    // file names: two watched directories may each contain a file with the
    // same name (e.g. /a/cn.mrs and /b/cn.mrs), and name-only matching would
    // report both as changed when either one is touched.
    let targets: HashSet<PathBuf> = paths.iter().map(|p| normalized_watch_path(p)).collect();

    // Watching the parent directory (not the file itself) survives an editor
    // that saves via write-to-temp-then-rename: renaming over the original
    // changes its inode, which would silently drop a watch placed on the file
    // directly.
    let mut inotify = Inotify::init().context("failed to initialize inotify")?;
    let mut wd_dirs: HashMap<inotify::WatchDescriptor, PathBuf> = HashMap::new();
    for dir in dir_watches.keys() {
        let wd = inotify
            .add_watch(dir, RELOAD_WATCH_MASK)
            .with_context(|| format!("failed to watch {}", dir.display()))?;
        wd_dirs.insert(wd, dir.clone());
    }

    // Minimum interval between successive reloads.  inotify emits multiple raw
    // events (MODIFY, CLOSE_WRITE, MOVED_TO …) for a single file save; without a
    // cooldown each save triggers 2-3 full ruleset parses.
    const DEBOUNCE: Duration = Duration::from_millis(500);
    let mut last_reload = std::time::Instant::now()
        .checked_sub(DEBOUNCE)
        .unwrap_or(std::time::Instant::now());

    // Normalized full paths of watched files that changed since the last
    // successful reload. Accumulated across the debounce window so a reload
    // always sees every file that changed since it last ran, even if several
    // changed within one window and only the last event's arrival actually
    // triggers the call.
    let mut changed_paths: HashSet<PathBuf> = HashSet::new();
    let mut buffer = [0u8; 4096];

    loop {
        // A blocking read on the inotify fd; genuinely fatal (fd closed, etc.)
        // rather than a per-event condition, so it propagates via `?` and lets
        // the caller's retry-with-backoff loop re-establish the watch from
        // scratch instead of busy-looping on a broken fd here.
        let events = inotify
            .read_events_blocking(&mut buffer)
            .context("failed to read inotify events")?;
        if !collect_changed_paths(events, &wd_dirs, &targets, &mut changed_paths) {
            continue;
        }
        // Debounce by waiting out the remainder of the window rather than
        // skipping: `continue`-ing here would leave the just-accumulated
        // changes unapplied until some unrelated future event arrives — for a
        // file saved with multiple in-place writes, the first (possibly
        // partial) content would be the one that sticks. Sleeping preserves
        // the "at most one reload per DEBOUNCE" rate limit while guaranteeing
        // every accumulated change is eventually applied.
        let since_last = last_reload.elapsed();
        if since_last < DEBOUNCE {
            thread::sleep(DEBOUNCE - since_last);
            // Coalesce events that arrived during the sleep into this same
            // reload (the fd is non-blocking, so an empty queue is just
            // `WouldBlock`) instead of letting each schedule its own
            // debounce-delayed reload of the same file.
            if let Ok(events) = inotify.read_events(&mut buffer) {
                collect_changed_paths(events, &wd_dirs, &targets, &mut changed_paths);
            }
        }

        let mut retries = RELOAD_RETRIES;
        loop {
            match reload(&changed_paths) {
                Ok(()) => {
                    last_reload = std::time::Instant::now();
                    changed_paths.clear();
                    break;
                }
                Err(err) => {
                    retries -= 1;
                    if retries == 0 {
                        crate::log_error!("reload event={} status=failed error={err:#}", name);
                        break;
                    }
                    thread::sleep(RELOAD_RETRY_DELAY);
                }
            }
        }
    }
}

/// Fold one batch of inotify events into `changed`, matching by full
/// normalized path via the event's watch descriptor. Returns `true` when this
/// batch was relevant (a watched file changed, or the kernel reported a queue
/// overflow).
///
/// `Q_OVERFLOW` means the kernel dropped events, so which files changed is no
/// longer knowable — every watched file is conservatively marked changed
/// (turning the next ruleset reload into a full re-read instead of an
/// incremental one).
fn collect_changed_paths(
    events: inotify::Events<'_>,
    wd_dirs: &HashMap<inotify::WatchDescriptor, PathBuf>,
    targets: &HashSet<PathBuf>,
    changed: &mut HashSet<PathBuf>,
) -> bool {
    let mut relevant = false;
    for event in events {
        if event.mask.contains(inotify::EventMask::Q_OVERFLOW) {
            changed.extend(targets.iter().cloned());
            relevant = true;
            continue;
        }
        let Some(name) = event.name else { continue };
        let Some(dir) = wd_dirs.get(&event.wd) else {
            continue;
        };
        let full = dir.join(name);
        if targets.contains(&full) {
            changed.insert(full);
            relevant = true;
        }
    }
    relevant
}

fn watched_dirs(paths: &[PathBuf]) -> HashMap<PathBuf, Vec<OsString>> {
    let mut dirs = HashMap::new();
    for path in paths {
        let file = path.file_name().map(OsString::from).unwrap_or_default();
        dirs.entry(watch_parent(path)).or_insert_with(Vec::new).push(file);
    }
    dirs
}

/// Directory whose inotify watch covers `path`. For a bare relative file name
/// ("config.json"), `parent()` returns `Some("")` — not `None` — and
/// `inotify_add_watch("")` fails with ENOENT, which would silently kill the
/// watcher (the retry loop's warning macro is compiled out); both cases map
/// to ".".
fn watch_parent(path: &std::path::Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// `path` in the exact form watcher events reproduce it: the watch directory
/// (see `watch_parent`) joined with the file name. Both sides of every
/// changed-path comparison — the watcher's event-derived paths and a
/// `RuleSetSpec`'s configured path — go through this, so they always compare
/// equal regardless of how the configured path was spelled.
pub(crate) fn normalized_watch_path(path: &std::path::Path) -> PathBuf {
    watch_parent(path).join(path.file_name().unwrap_or_default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn disabled_querylog() -> crate::querylog::QueryLogHandle {
        let (handle, _worker, _qps, _stats, _shutdown) =
            crate::querylog::build(crate::querylog::QueryLogConfig {
                enabled: false,
                memory: 0,
                channel: 64,
                shards: 1,
                file: None,
            });
        handle
    }

    async fn state_from_config_file(config_path: &std::path::Path) -> Arc<AppState> {
        let json = crate::config::json::load_json_config(config_path).unwrap();
        let cfg = Config::from_json(json).unwrap();
        Arc::new(
            AppState::new(cfg, Some(config_path.to_path_buf()), disabled_querylog())
                .await
                .unwrap(),
        )
    }

    /// A config hot-reload can change which ruleset tags the rules reference.
    /// A subsequent ruleset-file reload must use the *current* config's tags,
    /// not the set captured when the watcher was created — otherwise the new
    /// tag silently stops matching after the first ruleset file change.
    #[tokio::test]
    async fn ruleset_reload_uses_tags_from_the_current_config() {
        let dir = std::env::temp_dir().join(format!(
            "pathdns-watcher-tags-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.list");
        let b = dir.join("b.list");
        std::fs::write(&a, "+.aaa.test\n").unwrap();
        std::fs::write(&b, "+.bbb.test\n").unwrap();
        let config_path = dir.join("config.json");

        let config_json = |tag: &str| {
            serde_json::json!({
                "route": {
                    "servers": { "blocked": "RCODE://NXDOMAIN" },
                    "ruleset": [
                        { "tag": "a", "format": "text", "behavior": "domain",
                          "path": a.to_str().unwrap() },
                        { "tag": "b", "format": "text", "behavior": "domain",
                          "path": b.to_str().unwrap() }
                    ],
                    "rules": [
                        { "matcher": [format!("tag:{tag}")], "upstream": "blocked" }
                    ],
                    "final": "blocked"
                }
            })
            .to_string()
        };

        std::fs::write(&config_path, config_json("a")).unwrap();
        let state = state_from_config_file(&config_path).await;
        assert!(state
            .hot
            .load()
            .ruleset
            .as_ref()
            .unwrap()
            .matches("a", "x.aaa.test"));

        // Config hot-reload switches the rule from tag:a to tag:b.
        std::fs::write(&config_path, config_json("b")).unwrap();
        reload_config(&state).await.unwrap();
        assert!(state
            .hot
            .load()
            .ruleset
            .as_ref()
            .unwrap()
            .matches("b", "x.bbb.test"));

        // Ruleset file b changes afterwards: the reload must load {b} (the
        // current config's tag set). A watcher-held stale {a} would produce a
        // db without b, silently turning tag:b into never-matches.
        std::fs::write(&b, "+.bbb.test\n+.newly-added.test\n").unwrap();
        let mut changed = HashSet::new();
        changed.insert(normalized_watch_path(&b));
        reload_ruleset(&state, &changed).await.unwrap();
        let hot = state.hot.load();
        let db = hot.ruleset.as_ref().expect("ruleset db present");
        assert!(
            db.matches("b", "x.newly-added.test"),
            "tag introduced by a config reload must survive a ruleset reload"
        );
        drop(hot);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The ruleset watcher must exist whenever ruleset files are configured,
    /// even if the startup config references no tags yet — a config
    /// hot-reload can introduce the first tag reference later, and the
    /// watcher set is never rebuilt.
    #[tokio::test]
    async fn ruleset_watcher_created_without_startup_tag_references() {
        let dir = std::env::temp_dir().join(format!(
            "pathdns-watcher-notags-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.list");
        std::fs::write(&a, "+.aaa.test\n").unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            serde_json::json!({
                "route": {
                    "servers": { "blocked": "RCODE://NXDOMAIN" },
                    "ruleset": [
                        { "tag": "a", "format": "text", "behavior": "domain",
                          "path": a.to_str().unwrap() }
                    ],
                    "rules": [
                        { "matcher": ["example.com"], "upstream": "blocked" }
                    ],
                    "final": "blocked"
                }
            })
            .to_string(),
        )
        .unwrap();

        let state = state_from_config_file(&config_path).await;
        assert!(
            state.hot.load().ruleset.is_none(),
            "no tags referenced at startup"
        );
        let watchers = ReloadWatcher::for_state(&state);
        assert!(
            watchers
                .iter()
                .any(|w| matches!(w, ReloadWatcher::RuleSet { .. })),
            "ruleset watcher must exist whenever ruleset files are configured"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A bare relative file name has `parent() == Some("")`; the watcher must
    /// map that to "." — `inotify_add_watch("")` fails with ENOENT, which
    /// silently killed the reload watcher for any relative config/ruleset path.
    #[test]
    fn bare_relative_paths_watch_the_current_directory() {
        let dirs = watched_dirs(&[PathBuf::from("config.json")]);
        assert_eq!(dirs.len(), 1);
        let (dir, files) = dirs.iter().next().unwrap();
        assert_eq!(dir, &PathBuf::from("."));
        assert_eq!(files, &vec![std::ffi::OsString::from("config.json")]);
    }

    #[test]
    fn paths_group_by_parent_directory() {
        let dirs = watched_dirs(&[
            PathBuf::from("/etc/pathdns/a.list"),
            PathBuf::from("/etc/pathdns/b.list"),
            PathBuf::from("rel/c.list"),
        ]);
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[&PathBuf::from("/etc/pathdns")].len(), 2);
        assert_eq!(
            dirs[&PathBuf::from("rel")],
            vec![std::ffi::OsString::from("c.list")]
        );
    }
}
