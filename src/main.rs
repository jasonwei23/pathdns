#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod cache;
mod config;
mod config_file;
mod dns;
mod domain;
mod geosite;
mod hasher;
mod ipset;
mod listener;
mod log;
mod persist;
mod querylog;
mod resolver;
mod route_table;
mod router;
mod server;
mod singleflight;
mod stats;
mod udp_batch;
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
    let (cfg, config_path) = Config::parse_args()?;
    let worker_threads = cfg.worker_threads.max(1);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async_main(cfg, config_path))
}

async fn async_main(cfg: Config, config_path: std::path::PathBuf) -> Result<()> {
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

    let (app_state, refresh_rx) =
        server::AppState::new(cfg, Some(config_path), ql_handle.clone()).await?;
    let state = Arc::new(app_state);
    let (querylog_bind, querylog_token) = {
        let hot = state.hot.load();
        (
            hot.cfg.querylog.bind.clone(),
            hot.cfg.querylog.token.clone(),
        )
    };
    if querylog_bind.iter().any(|addr| !addr.ip().is_loopback()) && querylog_token.is_none() {
        eprintln!("warn: web dashboard is exposed without authentication");
    }
    resolver::spawn_refresh_worker(state.clone(), refresh_rx);
    server::spawn_reload_watchers(state.clone());

    let mut ql_worker_task = None;
    if let Some(ws) = ql_worker {
        let ring = ws.ring.clone();
        let api_ring = ring.clone();

        ql_worker_task = Some(tokio::spawn(crate::querylog::worker::run(
            ws.rx,
            ws.ring,
            ws.counters,
            ws.file_cfg,
            ws.shutdown,
        )));

        for &addr in &querylog_bind {
            let api_listener = crate::listener::bind_tcp_listener(addr)
                .map_err(|e| anyhow::anyhow!("web: failed to bind {addr}: {e}"))?;
            log_info!("listening web=http://{addr}");
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
    } else if !querylog_bind.is_empty() {
        // No collection (memory=0) but still serve API for stats.
        let api_ring = std::sync::Arc::new(crate::querylog::ring::EventRing::new(0));
        for &addr in &querylog_bind {
            let api_listener = crate::listener::bind_tcp_listener(addr)
                .map_err(|e| anyhow::anyhow!("web: failed to bind {addr}: {e}"))?;
            log_info!("listening web=http://{addr}");
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
    }

    let qps_task = (!querylog_bind.is_empty()).then(|| {
        tokio::spawn(crate::querylog::worker::run_qps_sampler(
            qps_ring.clone(),
            stats_ring.clone(),
            ql_handle.counters.clone(),
            ql_shutdown.subscribe(),
        ))
    });

    let cache_persist_interval = state.hot.load().cfg.cache_persist_interval;
    let cache_persist_path = state.hot.load().cfg.cache_persist_path.clone();
    if cache_persist_interval > 0 {
        if let Some(path) = cache_persist_path {
            let s = state.clone();
            let fp = config::cache_fingerprint(&s.hot.load().cfg);
            let vpath = verdict_cache::persist_path_for(&path);
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(cache_persist_interval));
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

    {
        let hot = state.hot.load();
        if let Some(path) = &hot.cfg.cache_persist_path {
            let fp = config::cache_fingerprint(&hot.cfg);
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
    }

    startup!("shutdown status=ok");

    serve_result
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
