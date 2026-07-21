// pathdns is Linux-only by construction: io_uring multishot recvmsg, netlink
// (ipset/nftset), SO_REUSEPORT and other Linux APIs are used unconditionally.
// Fail with one clear message instead of a cascade of unresolved-symbol errors.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![cfg_attr(not(test), warn(clippy::expect_used, clippy::unwrap_used))]

#[cfg(not(target_os = "linux"))]
compile_error!("pathdns only builds on Linux (requires io_uring, netlink, SO_REUSEPORT, ...).");

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// The whole application lives here as a library (with a thin `main.rs` binary
// on top) so that `fuzz/` can link against it and call directly into the
// wire-format parsers (`dns`, `mrs`, ...) without going through a process.
pub mod cache;
pub mod config;
pub mod dns;
pub mod domain;
pub mod hasher;
pub mod iprange;
pub mod ipset;
pub mod listener;
pub mod log;
pub mod mrs;
pub mod persist;
pub mod querylog;
pub mod resolver;
pub mod response_filter;
pub mod route_index;
pub mod router;
pub mod ruleset;
pub mod server;
pub mod singleflight;
pub mod stats;
#[allow(unsafe_code)]
pub mod sys;
pub mod udp_send;
#[allow(unsafe_code)]
pub mod udp_uring;
pub mod upstream;
pub mod verdict_cache;

use anyhow::Result;
use config::Config;
use std::sync::Arc;

pub fn main() {
    if let Err(err) = run() {
        log_error!("startup status=failed error={err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let (cfg, config_path) = Config::parse_args()?;
    let worker_threads = cfg.worker_threads.max(1);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        // Name each worker thread (pthread_setname_np → prctl(PR_SET_NAME)) so the
        // SO_REUSEPORT shards are individually visible in `top -H`, `/proc/<pid>/task`
        // and perf. Kept under the 15-char comm limit.
        .thread_name_fn(|| {
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("pathdns-w{id}")
        })
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async_main(cfg, config_path))
}

async fn async_main(cfg: Config, config_path: std::path::PathBuf) -> Result<()> {
    // Build querylog handle before AppState so it can be threaded in.
    let ql_cfg = crate::querylog::QueryLogConfig {
        enabled: cfg.dashboard.enabled,
        memory: cfg.dashboard.memory,
        channel: cfg.dashboard.channel,
        // One producer channel shard per worker thread so runtime threads never
        // contend on a shared channel head (clamped in `querylog::build`).
        shards: cfg.worker_threads.max(1),
        file: cfg
            .dashboard
            .file
            .as_ref()
            .map(|f| crate::querylog::QueryLogFileConfig {
                dir: f.dir.clone(),
                max_mb: f.max_mb,
                max_segments: f.max_segments,
                batch_size: f.batch_size,
                flush_interval_ms: f.flush_interval_ms,
                retention_days: f.retention_days,
                compress: f.compress,
            }),
    };
    let (ql_handle, ql_worker, qps_ring, stats_ring, ql_shutdown) = crate::querylog::build(ql_cfg);

    let app_state = server::AppState::new(cfg, Some(config_path), ql_handle.clone()).await?;
    let state = Arc::new(app_state);
    let (querylog_bind, querylog_token) = {
        let hot = state.hot.load();
        (
            hot.cfg.dashboard.bind.clone(),
            hot.cfg.dashboard.token.clone(),
        )
    };
    if querylog_bind
        .iter()
        .any(|(addr, _)| !addr.ip().is_loopback())
        && querylog_token.is_none()
    {
        eprintln!("warn: web dashboard is exposed without authentication");
    }
    server::spawn_reload_watchers(state.clone());

    let mut ql_worker_task = None;
    if let Some(ws) = ql_worker {
        let api_ring = ws.ring.clone();

        ql_worker_task = Some(tokio::spawn(crate::querylog::worker::run(
            ws.rxs,
            ws.ring,
            ws.counters,
            ws.file_cfg,
            ws.shutdown,
        )));

        spawn_dashboard_listeners(
            &querylog_bind,
            &querylog_token,
            api_ring,
            &qps_ring,
            &stats_ring,
            &ql_handle,
            &state,
        )?;
    } else if !querylog_bind.is_empty() {
        // No collection (memory=0) but still serve API for stats.
        let api_ring = std::sync::Arc::new(crate::querylog::ring::EventRing::new(0));
        spawn_dashboard_listeners(
            &querylog_bind,
            &querylog_token,
            api_ring,
            &qps_ring,
            &stats_ring,
            &ql_handle,
            &state,
        )?;
    }

    let qps_task = (!querylog_bind.is_empty()).then(|| {
        tokio::spawn(crate::querylog::worker::run_qps_sampler(
            qps_ring.clone(),
            stats_ring.clone(),
            ql_handle.counters.clone(),
            ql_shutdown.subscribe(),
        ))
    });

    let (cache_persist_interval, cache_persist_path) = {
        let hot = state.hot.load();
        (
            hot.cfg.cache_persist_interval,
            hot.cfg.cache_persist_path.clone(),
        )
    };
    let cache_persist_lock = Arc::new(std::sync::Mutex::new(()));
    let mut cache_persist_task = None;
    if cache_persist_interval > 0 {
        if let Some(path) = cache_persist_path {
            let s = state.clone();
            let vpath = verdict_cache::persist_path_for(&path);
            let persist_lock = cache_persist_lock.clone();
            cache_persist_task = Some(tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(cache_persist_interval));
                ticker.tick().await; // skip immediate first tick
                loop {
                    ticker.tick().await;
                    let save_state = s.clone();
                    let save_path = path.clone();
                    let save_vpath = vpath.clone();
                    let save_lock = persist_lock.clone();
                    // Recomputed on every tick (not captured once at startup): a
                    // hot-reload since the last save changes what the live cache
                    // content actually corresponds to, and tagging saves with a
                    // stale fingerprint would make the next startup reject a
                    // perfectly fresh, post-reload cache as stale.
                    let fp = config::cache_fingerprint(&save_state.hot.load().cfg);
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        let _guard = save_lock
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        save_caches(&save_state, &save_path, &save_vpath, fp);
                    })
                    .await
                    {
                        crate::warn!("cache persist=task_failed error={e}");
                    }
                }
            }));
        }
    }

    // Capture the listener result without `?` so the cache save below always runs,
    // even when the listener exits with an error.
    let serve_result: Result<()> = tokio::select! {
        result = server::serve(state.clone()) => result,
        _ = shutdown_signal() => {
            startup!("shutdown signal=received");
            Ok(())
        }
    };

    let _ = ql_shutdown.send(true);
    if let Some(mut task) = ql_worker_task.take() {
        if tokio::time::timeout(std::time::Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
    }
    if let Some(mut task) = qps_task {
        if tokio::time::timeout(std::time::Duration::from_secs(1), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
    }
    if let Some(task) = cache_persist_task {
        task.abort();
        let _ = task.await;
    }

    {
        // A spawn_blocking save already in progress cannot be cancelled.  Serialise
        // the final save with it so both writers never share the same `.tmp` path.
        let _guard = cache_persist_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hot = state.hot.load();
        if let Some(path) = &hot.cfg.cache_persist_path {
            let fp = config::cache_fingerprint(&hot.cfg);
            let vpath = verdict_cache::persist_path_for(path);
            save_caches(&state, path, &vpath, fp);
        }
    }

    startup!("shutdown status=ok");

    serve_result
}

/// Bind the dashboard's HTTP API on every `(addr, iface)` pair and spawn a
/// `querylog::api::serve` task for each. Shared by the "collecting" and
/// "stats-only" (memory=0) dashboard startup paths, which differ only in
/// which `api_ring` they pass through.
fn spawn_dashboard_listeners(
    querylog_bind: &[(std::net::SocketAddr, Option<String>)],
    querylog_token: &Option<String>,
    api_ring: Arc<crate::querylog::ring::EventRing>,
    qps_ring: &Arc<crate::querylog::ring::QpsRing>,
    stats_ring: &Arc<crate::querylog::ring::StatsRing>,
    ql_handle: &crate::querylog::QueryLogHandle,
    state: &Arc<server::AppState>,
) -> Result<()> {
    // Grouped by addr so multiple interfaces sharing one addr collapse into a
    // single "(iface=a,b)" suffix, matching the dns listener summary's style.
    let mut summary: Vec<(std::net::SocketAddr, Vec<String>)> = Vec::new();
    for (addr, iface) in querylog_bind {
        let api_listener = crate::listener::bind_tcp_listener(*addr, iface.as_deref())
            .map_err(|e| anyhow::anyhow!("web: failed to bind {addr}: {e}"))?;
        match summary.iter_mut().find(|(a, _)| a == addr) {
            Some((_, ifaces)) => ifaces.extend(iface.clone()),
            None => summary.push((*addr, iface.iter().cloned().collect())),
        }
        tokio::spawn(crate::querylog::api::serve(
            api_listener,
            querylog_token.clone(),
            api_ring.clone(),
            qps_ring.clone(),
            stats_ring.clone(),
            ql_handle.clone(),
            state.clone(),
        ));
    }
    if !summary.is_empty() {
        let joined = summary
            .iter()
            .map(|(addr, ifaces)| {
                if ifaces.is_empty() {
                    format!("http://{addr}")
                } else {
                    format!("http://{addr} (iface={})", ifaces.join(","))
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        log_info!("listening web=[{joined}]");
    }
    Ok(())
}

/// Save the main DNS cache and (if enabled) the verdict cache to disk, logging
/// the outcome of each. Shared by the periodic persist task and the final
/// shutdown save.
fn save_caches(state: &server::AppState, path: &std::path::Path, vpath: &std::path::Path, fp: u64) {
    match state.cache.save_to_file(path, fp) {
        Ok(n) => startup!("cache persist=saved entries={n}"),
        Err(e) => startup!("cache persist=save_failed error={e:#}"),
    }
    if state.verdict_cache.enabled() {
        match state.verdict_cache.save_to_file(vpath, fp) {
            Ok(n) => startup!("verdict_cache persist=saved entries={n}"),
            Err(e) => startup!("verdict_cache persist=save_failed error={e:#}"),
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}
