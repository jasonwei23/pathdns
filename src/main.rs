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
mod metrics;
mod pipeline;
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
    log::configure(cfg.verbose);
    let worker_threads = cfg.worker_threads.max(1);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_io()
        .enable_time()
        .build()?;

    rt.block_on(async_main(cfg))
}

async fn async_main(cfg: Config) -> Result<()> {
    let (app_state, refresh_rx) = server::AppState::new(cfg).await?;
    let state = Arc::new(app_state);
    pipeline::spawn_refresh_worker(state.clone(), refresh_rx);
    server::spawn_reload_watchers(state.clone());

    if let Some(addr) = state.cfg.metrics_addr {
        let s = state.clone();
        tokio::spawn(async move {
            metrics::serve_metrics(addr, s).await;
        });
    }

    if state.cfg.cache_persist_interval > 0 {
        if let Some(path) = state.cfg.cache_persist_path.clone() {
            let s = state.clone();
            let fp = config::cache_fingerprint(&s.cfg);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    s.cfg.cache_persist_interval,
                ));
                ticker.tick().await; // skip immediate first tick
                let vpath = verdict_cache::persist_path_for(&path);
                loop {
                    ticker.tick().await;
                    match s.cache.save_to_file(&path, fp) {
                        Ok(n) => startup!("cache persist=saved entries={n}"),
                        Err(e) => startup!("cache persist=save_failed error={e:#}"),
                    }
                    if s.verdict_cache.enabled() {
                        match s.verdict_cache.save_to_file(&vpath, fp) {
                            Ok(n) => startup!("verdict_cache persist=saved entries={n}"),
                            Err(e) => startup!("verdict_cache persist=save_failed error={e:#}"),
                        }
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
