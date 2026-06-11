//! Query log background worker.
//!
//! Drains the mpsc channel, pushes events to the in-memory ring, and
//! optionally appends MessagePack-encoded events to rotating segment files.
//! QPS history is sampled once per second by a separate lightweight task.
//!
//! ## File format
//! Each active segment is `querylog-{unix_micros:020}.msgpack` — a sequence of
//! concatenated MessagePack maps, one per event, written with named keys.
//! On rotation the segment is gzip-compressed to `querylog-{ts}.msgpack.gz`
//! in a blocking thread-pool task so the worker never stalls.
//!
//! ## Reading historical files
//! `read_history_file` decodes a `.msgpack.gz` (or plain `.msgpack`) segment
//! and returns up to `limit` matching `DecodedEvent` values.  It is designed
//! to be called from `tokio::task::spawn_blocking` inside the HTTP API handler.

use super::{DecodedEvent, QpsRing, QueryLogCounters, QueryLogEvent, QueryLogFileConfig};
use crate::querylog::ring::{EventRing, StatsRing};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, Duration, MissedTickBehavior};

// ── QPS sampler ───────────────────────────────────────────────────────────────

pub async fn run_qps_sampler(
    qps_ring: Arc<QpsRing>,
    stats_ring: Arc<StatsRing>,
    counters: Arc<QueryLogCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    use super::ring::PerSecondSnapshot;
    let mut ticker = interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    macro_rules! load {
        ($field:ident) => { counters.$field.load(Ordering::Relaxed) };
    }
    // Capture initial absolute values; deltas are computed each tick.
    let mut prev_queries    = load!(queries_total);
    let mut prev_cache      = load!(cache_hits);
    let mut prev_up_ok      = load!(upstream_ok);
    let mut prev_up_err     = load!(upstream_err);
    let mut prev_null       = load!(null_responses);
    let mut prev_stale      = load!(stale_served);
    let mut prev_filtered   = load!(filtered);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let cur_queries  = load!(queries_total);
                let cur_cache    = load!(cache_hits);
                let cur_up_ok    = load!(upstream_ok);
                let cur_up_err   = load!(upstream_err);
                let cur_null     = load!(null_responses);
                let cur_stale    = load!(stale_served);
                let cur_filtered = load!(filtered);

                let snap = PerSecondSnapshot {
                    unix_secs:      now_secs,
                    queries:        cur_queries .saturating_sub(prev_queries),
                    cache_hits:     cur_cache   .saturating_sub(prev_cache),
                    upstream_ok:    cur_up_ok   .saturating_sub(prev_up_ok),
                    upstream_err:   cur_up_err  .saturating_sub(prev_up_err),
                    null_responses: cur_null    .saturating_sub(prev_null),
                    stale_served:   cur_stale   .saturating_sub(prev_stale),
                    filtered:       cur_filtered.saturating_sub(prev_filtered),
                };
                qps_ring.push(snap.queries);
                stats_ring.push(snap);

                prev_queries  = cur_queries;
                prev_cache    = cur_cache;
                prev_up_ok    = cur_up_ok;
                prev_up_err   = cur_up_err;
                prev_null     = cur_null;
                prev_stale    = cur_stale;
                prev_filtered = cur_filtered;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
            }
        }
    }
}

// ── Main worker loop ──────────────────────────────────────────────────────────

pub async fn run(
    mut rx: mpsc::Receiver<QueryLogEvent>,
    ring: Arc<EventRing>,
    counters: Arc<QueryLogCounters>,
    file_cfg: Option<QueryLogFileConfig>,
    mut shutdown: watch::Receiver<bool>,
) {
    let batch_size = file_cfg
        .as_ref()
        .map(|c| c.batch_size)
        .unwrap_or(256)
        .max(1);
    let flush_ms = file_cfg
        .as_ref()
        .map(|c| c.flush_interval_ms)
        .unwrap_or(500)
        .max(50);

    let mut file_state: Option<MsgpackFileState> = None;

    if let Some(cfg) = &file_cfg {
        match MsgpackFileState::open(cfg).await {
            Ok(fs) => file_state = Some(fs),
            Err(e) => {
                counters.file_write_errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("warn: querylog file=open_failed error={e:#}");
            }
        }
    }

    let mut flush_ticker = interval(Duration::from_millis(flush_ms));
    flush_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            Some(ev) = rx.recv() => {
                let mut batch = Vec::with_capacity(batch_size);
                batch.push(ev);
                while batch.len() < batch_size {
                    match rx.try_recv() {
                        Ok(next) => batch.push(next),
                        Err(_) => break,
                    }
                }
                process_batch(batch, &ring, &counters, &file_cfg, &mut file_state).await;
            }
            _ = flush_ticker.tick() => {
                if let Some(fs) = &mut file_state {
                    if let Err(e) = fs.flush().await {
                        counters.file_write_errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("warn: querylog file=flush_failed error={e:#}");
                        file_state = None;
                    }
                } else if let Some(cfg) = &file_cfg {
                    match MsgpackFileState::open(cfg).await {
                        Ok(fs) => file_state = Some(fs),
                        Err(_) => {}
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    // Drain all remaining events before returning.
                    while let Ok(ev) = rx.try_recv() {
                        let mut batch = vec![ev];
                        while batch.len() < batch_size {
                            match rx.try_recv() {
                                Ok(next) => batch.push(next),
                                Err(_) => break,
                            }
                        }
                        process_batch(batch, &ring, &counters, &file_cfg, &mut file_state).await;
                    }
                    if let Some(fs) = &mut file_state {
                        let _ = fs.flush().await;
                    }
                    return;
                }
            }
            else => break,
        }
    }
}

// ── Batch processing ──────────────────────────────────────────────────────────

async fn process_batch(
    batch: Vec<QueryLogEvent>,
    ring: &EventRing,
    counters: &QueryLogCounters,
    file_cfg: &Option<QueryLogFileConfig>,
    file_state: &mut Option<MsgpackFileState>,
) {
    counters
        .events_processed
        .fetch_add(batch.len() as u64, Ordering::Relaxed);

    // Wrap each event in Arc; push to the ring.
    let mut arc_batch: Vec<Arc<QueryLogEvent>> = Vec::with_capacity(batch.len());
    for ev in batch {
        let ev = Arc::new(ev);
        if ring.enabled() {
            if ring.push(ev.clone()) {
                counters.ring_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        arc_batch.push(ev);
    }

    // Batch-serialize and write to the msgpack segment.
    let result = match (file_state.as_mut(), file_cfg.as_ref()) {
        (Some(fs), Some(cfg)) => fs.append_batch(&arc_batch, cfg).await,
        _ => return,
    };

    if let Err(e) = result {
        counters.file_write_errors.fetch_add(1, Ordering::Relaxed);
        eprintln!("warn: querylog file=write_failed error={e:#}");
        *file_state = None;
    }
}

// ── MessagePack file state ────────────────────────────────────────────────────

struct MsgpackFileState {
    file: BufWriter<tokio::fs::File>,
    path: PathBuf,
    bytes_written: u64,
}

impl MsgpackFileState {
    async fn open(cfg: &QueryLogFileConfig) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(&cfg.dir).await?;
        let name = segment_name();
        let path = cfg.dir.join(&name);
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        let bytes_written = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        prune_old_files(cfg).await.ok();
        Ok(Self {
            file: BufWriter::with_capacity(64 * 1024, file),
            path,
            bytes_written,
        })
    }

    /// Serialize `batch` into a single in-memory buffer and write it atomically.
    async fn append_batch(
        &mut self,
        batch: &[Arc<QueryLogEvent>],
        cfg: &QueryLogFileConfig,
    ) -> anyhow::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        // Encode all events into a local buffer before touching the async writer.
        let mut buf: Vec<u8> = Vec::with_capacity(batch.len() * 128);
        for ev in batch {
            rmp_serde::encode::write_named(&mut buf, ev.as_ref())
                .map_err(|e| anyhow::anyhow!("msgpack encode: {e}"))?;
        }

        self.file.write_all(&buf).await?;
        self.bytes_written += buf.len() as u64;

        // Rotate if the active segment has grown past the size limit.
        if self.bytes_written >= cfg.max_mb * 1_048_576 {
            self.rotate(cfg).await?;
        }

        Ok(())
    }

    /// Flush, compress the closed segment, then open a fresh one.
    async fn rotate(&mut self, cfg: &QueryLogFileConfig) -> anyhow::Result<()> {
        self.file.flush().await?;

        // Fire-and-forget gzip compression in the blocking thread pool.
        let old_path = self.path.clone();
        let compress = cfg.compress;
        if compress {
            tokio::task::spawn_blocking(move || {
                if let Err(e) = compress_to_gz(&old_path) {
                    eprintln!(
                        "warn: querylog compress=failed path={} error={e:#}",
                        old_path.display()
                    );
                }
            });
            // Do not await — compression runs concurrently while the worker
            // continues draining the channel into the new segment.
        }

        // Open a new segment immediately.
        let name = segment_name();
        let new_path = cfg.dir.join(&name);
        let f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&new_path)
            .await?;
        self.file = BufWriter::with_capacity(64 * 1024, f);
        self.path = new_path;
        self.bytes_written = 0;

        prune_old_files(cfg).await.ok();
        Ok(())
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        self.file.flush().await?;
        Ok(())
    }
}

// ── Gzip compression (blocking) ───────────────────────────────────────────────

fn compress_to_gz(path: &Path) -> std::io::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::BufReader;

    let gz_path = PathBuf::from(format!("{}.gz", path.display()));
    let src = std::fs::File::open(path)?;
    let dst = std::fs::File::create(&gz_path)?;
    let mut encoder = GzEncoder::new(std::io::BufWriter::new(dst), Compression::default());
    std::io::copy(&mut BufReader::new(src), &mut encoder)?;
    encoder.finish()?;
    std::fs::remove_file(path)?;
    Ok(())
}

// ── Segment naming ────────────────────────────────────────────────────────────

fn segment_name() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    format!("querylog-{micros:020}.msgpack")
}

// ── Pruning ───────────────────────────────────────────────────────────────────

async fn prune_old_files(cfg: &QueryLogFileConfig) -> anyhow::Result<()> {
    let mut entries = tokio::fs::read_dir(&cfg.dir).await?;
    let mut files: Vec<String> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let n = entry.file_name().to_string_lossy().into_owned();
        if n.starts_with("querylog-")
            && (n.ends_with(".msgpack") || n.ends_with(".msgpack.gz"))
        {
            files.push(n);
        }
    }
    // Name-based sort = chronological order (timestamp prefix).
    files.sort();

    // Age-based removal using the timestamp embedded in the file name.
    if let Some(days) = cfg.retention_days {
        let now_micros = super::unix_micros_now();
        let cutoff = now_micros.saturating_sub(days as u64 * 86_400 * 1_000_000);
        let mut keep = Vec::with_capacity(files.len());
        for name in files {
            let ts = extract_file_timestamp(&name).unwrap_or(u64::MAX);
            if ts < cutoff {
                let _ = tokio::fs::remove_file(cfg.dir.join(&name)).await;
            } else {
                keep.push(name);
            }
        }
        files = keep;
    }

    // Count-based removal: retain only the `max_segments` most recent.
    let max = cfg.max_segments.max(1);
    if files.len() > max {
        for old_name in &files[..files.len() - max] {
            let _ = tokio::fs::remove_file(cfg.dir.join(old_name)).await;
        }
    }

    Ok(())
}

/// Extract the Unix-microsecond timestamp from a segment file name.
/// Names are `querylog-{20_digits}.msgpack` or `querylog-{20_digits}.msgpack.gz`.
fn extract_file_timestamp(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("querylog-")?;
    let end = rest.find('.')?;
    rest[..end].parse::<u64>().ok()
}

// ── Historical file reader ────────────────────────────────────────────────────

/// List historical segments in `dir`, newest-last.
/// Returns `(file_name, size_bytes)` pairs.
/// Includes both gzip-compressed (`.msgpack.gz`) and plain (`.msgpack`) segments.
/// The most-recently-named plain `.msgpack` file is excluded because it is the
/// active segment currently being written to.
pub fn list_history_files(dir: &Path) -> Vec<(String, u64)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut gz_files: Vec<(String, u64)> = Vec::new();
    let mut plain_files: Vec<(String, u64)> = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        if name.starts_with("querylog-") {
            if name.ends_with(".msgpack.gz") {
                gz_files.push((name, size));
            } else if name.ends_with(".msgpack") {
                plain_files.push((name, size));
            }
        }
    }
    // The lexicographically largest plain `.msgpack` name is the active segment.
    plain_files.sort_by(|a, b| a.0.cmp(&b.0));
    if !plain_files.is_empty() {
        plain_files.pop(); // drop the active segment
    }
    let mut files: Vec<(String, u64)> = gz_files.into_iter().chain(plain_files).collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

/// Decode up to `limit` events from a historical MessagePack segment.
/// Accepts both `.msgpack.gz` (gzip-compressed) and plain `.msgpack` files.
/// Call this inside `tokio::task::spawn_blocking` — file I/O is synchronous.
pub fn read_history_file(
    path: &Path,
    limit: usize,
    filter: Option<&str>,
) -> anyhow::Result<Vec<DecodedEvent>> {
    use std::io::BufReader;

    let file = std::fs::File::open(path)?;
    let limit = limit.min(10_000).max(1);

    let events = if path.to_str().map_or(false, |s| s.ends_with(".gz")) {
        let gz = flate2::read::GzDecoder::new(file);
        decode_msgpack_stream(BufReader::new(gz), limit, filter)
    } else {
        decode_msgpack_stream(BufReader::new(file), limit, filter)
    };

    Ok(events)
}

fn decode_msgpack_stream<R: std::io::Read>(
    reader: R,
    limit: usize,
    filter: Option<&str>,
) -> Vec<DecodedEvent> {
    let mut de = rmp_serde::Deserializer::new(reader);
    let mut events = Vec::new();
    loop {
        let result: Result<DecodedEvent, _> = serde::de::Deserialize::deserialize(&mut de);
        match result {
            Ok(ev) => {
                if filter.map_or(true, |f| f.is_empty() || ev.qname.contains(f)) {
                    events.push(ev);
                    if events.len() >= limit {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    events
}

// ── Timestamp formatting (also used by api.rs) ────────────────────────────────

/// Convert Unix microseconds to an RFC3339 timestamp string (UTC, µs precision).
pub fn micros_to_rfc3339(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let frac = micros % 1_000_000;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{frac:06}Z")
}

fn days_to_ymd(mut days: u64) -> (u32, u32, u32) {
    days += 719468;
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}
