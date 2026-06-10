#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod cache;
mod config;
mod config_json;
mod dns;
mod domain;
mod fnv;
mod geosite;
mod ipset;
#[cfg(unix)]
mod listener;
mod log;
mod persist;
mod pipeline;
mod querylog;
mod router;
mod routing_index;
mod server;
mod singleflight;
mod stats;
mod upstream;
mod verdict_cache;

use anyhow::Result;
use config::Config;
use std::sync::Arc;

fn main() {
    if let Err(err) = run() {
        log_error!("startup status=failed error={err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cfg = Config::parse_args()?;
    let worker_threads = cfg.worker_threads.max(1);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async_main(cfg))
}

async fn async_main(cfg: Config) -> Result<()> {
    // Build querylog handle before AppState so it can be threaded in.
    let ql_cfg = crate::querylog::QueryLogConfig {
        enabled: cfg.querylog.enabled,
        memory: cfg.querylog.memory,
        channel: cfg.querylog.channel,
        answer_ips: cfg.querylog.answer_ips,
        file: cfg
            .querylog
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

    let (app_state, refresh_rx) = server::AppState::new(cfg, ql_handle.clone()).await?;
    let state = Arc::new(app_state);
    if state
        .cfg
        .querylog
        .bind
        .is_some_and(|addr| !addr.ip().is_loopback())
        && state.cfg.querylog.token.is_none()
    {
        eprintln!("warn: web dashboard is exposed without authentication");
    }
    pipeline::spawn_refresh_worker(state.clone(), refresh_rx);
    server::spawn_reload_watchers(state.clone());

    let mut ql_worker_task = None;
    if let Some(ws) = ql_worker {
        let ring = ws.ring.clone();
        let api_ring = ring.clone();
        let api_qps = qps_ring.clone();
        let api_handle = ql_handle.clone();
        let api_state = state.clone();
        let api_token = state.cfg.querylog.token.clone();
        let api_bind = state.cfg.querylog.bind;

        ql_worker_task = Some(tokio::spawn(crate::querylog::worker::run(
            ws.rx,
            ws.ring,
            ws.counters,
            ws.file_cfg,
            ws.shutdown,
        )));

        if let Some(addr) = api_bind {
            let api_listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("web: failed to bind {addr}: {e}"))?;
            startup!("listening web=http://{addr}");
            let api_stats = stats_ring.clone();
            tokio::spawn(crate::querylog::api::serve(
                api_listener, api_token, api_ring, api_qps, api_stats, api_handle, api_state,
            ));
        }
    } else if let Some(addr) = state.cfg.querylog.bind {
        // No collection (memory=0) but still serve API for stats.
        let api_listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("web: failed to bind {addr}: {e}"))?;
        startup!("listening web=http://{addr}");
        let api_ring = std::sync::Arc::new(crate::querylog::ring::EventRing::new(0));
        tokio::spawn(crate::querylog::api::serve(
            api_listener,
            state.cfg.querylog.token.clone(),
            api_ring,
            qps_ring.clone(),
            stats_ring.clone(),
            ql_handle.clone(),
            state.clone(),
        ));
    }

    let qps_task = state.cfg.querylog.bind.map(|_| {
        tokio::spawn(crate::querylog::worker::run_qps_sampler(
            qps_ring.clone(),
            stats_ring.clone(),
            ql_handle.counters.clone(),
            ql_shutdown.subscribe(),
        ))
    });

    if state.cfg.cache_persist_interval > 0 {
        if let Some(path) = state.cfg.cache_persist_path.clone() {
            let s = state.clone();
            let fp = config::cache_fingerprint(&s.cfg);
            let vpath = verdict_cache::persist_path_for(&path);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    s.cfg.cache_persist_interval,
                ));
                ticker.tick().await; // skip immediate first tick
                loop {
                    ticker.tick().await;
                    let save_state = s.clone();
                    let save_path = path.clone();
                    let save_vpath = vpath.clone();
                    if let Err(e) = tokio::task::spawn_blocking(move || {
                        match save_state.cache.save_to_file(&save_path, fp) {
                            Ok(n) => startup!("cache persist=saved entries={n}"),
                            Err(e) => startup!("cache persist=save_failed error={e:#}"),
                        }
                        if save_state.verdict_cache.enabled() {
                            match save_state.verdict_cache.save_to_file(&save_vpath, fp) {
                                Ok(n) => startup!("verdict_cache persist=saved entries={n}"),
                                Err(e) => {
                                    startup!("verdict_cache persist=save_failed error={e:#}")
                                }
                            }
                        }
                    })
                    .await
                    {
                        crate::warn!("cache persist=task_failed error={e}");
                    }
                }
            });
        }
    }

    // Load verdict cache from disk on startup if DNS cache persistence is configured.
    if let Some(path) = &state.cfg.cache_persist_path {
        if state.verdict_cache.enabled() {
            let fp = config::cache_fingerprint(&state.cfg);
            let vpath = verdict_cache::persist_path_for(path);
            if vpath.exists() {
                match state.verdict_cache.load_from_file(&vpath, fp) {
                    Ok(n) => startup!("verdict_cache persist=loaded entries={n}"),
                    Err(e) => startup!("verdict_cache persist=load_failed error={e:#}"),
                }
            }
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

    if let Some(path) = &state.cfg.cache_persist_path {
        let fp = config::cache_fingerprint(&state.cfg);
        match state.cache.save_to_file(path, fp) {
            Ok(n) => startup!("cache persist=saved entries={n}"),
            Err(e) => startup!("cache persist=save_failed error={e:#}"),
        }
        if state.verdict_cache.enabled() {
            let vpath = verdict_cache::persist_path_for(path);
            match state.verdict_cache.save_to_file(&vpath, fp) {
                Ok(n) => startup!("verdict_cache persist=saved entries={n}"),
                Err(e) => startup!("verdict_cache persist=save_failed error={e:#}"),
            }
        }
    }

    startup!("shutdown status=ok");

    serve_result
}

#[cfg(unix)]
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

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
