//! Query log background worker.
//!
//! Drains the mpsc channel, pushes events to the in-memory ring, and
//! optionally appends MessagePack-encoded events to rotating segment files.
//! QPS history is sampled once per second by a separate lightweight task.
//!
//! ## File format
//! Each active segment is `querylog-{unix_micros:020}.msgpack` — a sequence of
//! concatenated MessagePack maps, one per event, written with named keys.
//! A compact `.index.json` sidecar stores entry counts, time ranges, and sparse
//! byte offsets. Rotated segments are written as concatenated independent gzip
//! members, one per index block, so history queries only decompress the blocks
//! they need.
//!
//! ## Reading historical files
//! `read_history_page` queries a `.msgpack.gz` (or plain `.msgpack`) segment
//! through its sparse sidecar index and returns one bounded result page. It is
//! designed to run in `tokio::task::spawn_blocking` inside the HTTP API handler.

use super::{DecodedEvent, QpsRing, QueryLogCounters, QueryLogEvent, QueryLogFileConfig};
use crate::querylog::ring::{EventRing, StatsRing};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, Duration, MissedTickBehavior};

const HISTORY_INDEX_VERSION: u8 = 1;
/// Target entries per index block; consecutive small batches are merged until
/// this limit is reached before starting a new block.
const HISTORY_INDEX_STRIDE: u64 = 512;
/// Hard cap on page size returned by the history API.
const HISTORY_PAGE_MAX: usize = 200;

// ── Index structures ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryBlock {
    offset: u64,
    len: u64,
    first_entry: u64,
    entries: u32,
    start_micros: u64,
    end_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryIndex {
    version: u8,
    /// True when the segment file contains independent gzip members (one per
    /// block) rather than plain msgpack.
    compressed_blocks: bool,
    total_entries: u64,
    start_micros: Option<u64>,
    end_micros: Option<u64>,
    blocks: Vec<HistoryBlock>,
}

impl HistoryIndex {
    fn empty() -> Self {
        Self {
            version: HISTORY_INDEX_VERSION,
            compressed_blocks: false,
            total_entries: 0,
            start_micros: None,
            end_micros: None,
            blocks: Vec::new(),
        }
    }

    /// Record a freshly-written batch at byte range `[offset, offset+len)`.
    /// Small batches are merged into the last block until `HISTORY_INDEX_STRIDE`
    /// is reached; a new block is started when the stride fills.
    fn append_batch(&mut self, offset: u64, len: u64, batch: &[Arc<QueryLogEvent>]) {
        let Some(first) = batch.first() else {
            return;
        };
        let end_micros = batch.last().map_or(first.unix_micros, |ev| ev.unix_micros);
        let count = batch.len() as u64;
        self.start_micros.get_or_insert(first.unix_micros);
        self.end_micros = Some(end_micros);

        // Merge into the last block if it is still below the stride limit and
        // the byte ranges are contiguous (they always should be for sequential writes).
        if let Some(last) = self.blocks.last_mut() {
            if last.first_entry + u64::from(last.entries) == self.total_entries
                && u64::from(last.entries) + count <= HISTORY_INDEX_STRIDE
                && last.offset + last.len == offset
            {
                last.len += len;
                last.entries += count as u32;
                last.end_micros = end_micros;
                self.total_entries += count;
                return;
            }
        }

        self.blocks.push(HistoryBlock {
            offset,
            len,
            first_entry: self.total_entries,
            entries: count as u32,
            start_micros: first.unix_micros,
            end_micros,
        });
        self.total_entries += count;
    }
}

// ── Public types for the API layer ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HistoryFileInfo {
    pub name: String,
    pub size_bytes: u64,
    pub total_entries: Option<u64>,
    pub start_micros: Option<u64>,
    pub end_micros: Option<u64>,
    pub indexed: bool,
}

#[derive(Debug)]
pub struct HistoryQuery {
    pub limit: usize,
    /// Ordinal of the first entry to consider; `None` means start from the
    /// beginning of the effective time window.
    pub cursor: Option<u64>,
    pub from_micros: Option<u64>,
    pub to_micros: Option<u64>,
    pub qname: Option<String>,
    pub rcode: Option<u8>,
    pub source: Option<String>,
}

#[derive(Serialize)]
pub struct HistoryPage {
    pub events: Vec<DecodedEvent>,
    /// `None` for legacy files that have no index.
    pub total_entries: Option<u64>,
    pub start_micros: Option<u64>,
    pub end_micros: Option<u64>,
    /// The cursor to supply on the next request; `None` when `has_more` is false.
    pub next_cursor: Option<u64>,
    pub has_more: bool,
    pub indexed: bool,
}

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
        ($field:ident) => {
            counters.$field.load(Ordering::Relaxed)
        };
    }
    // Capture initial absolute values; deltas are computed each tick.
    let mut prev_queries = load!(queries_total);
    let mut prev_cache = load!(cache_hits);
    let mut prev_up_ok = load!(upstream_ok);
    let mut prev_up_err = load!(upstream_err);
    let mut prev_null = load!(local_responses);
    let mut prev_filtered = load!(filtered);

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
                let cur_null     = load!(local_responses);
                let cur_filtered = load!(filtered);

                let snap = PerSecondSnapshot {
                    unix_secs:      now_secs,
                    queries:        cur_queries .saturating_sub(prev_queries),
                    cache_hits:     cur_cache   .saturating_sub(prev_cache),
                    upstream_ok:    cur_up_ok   .saturating_sub(prev_up_ok),
                    upstream_err:   cur_up_err  .saturating_sub(prev_up_err),
                    local_responses: cur_null    .saturating_sub(prev_null),
                    filtered:       cur_filtered.saturating_sub(prev_filtered),
                };
                qps_ring.push(snap.queries);
                stats_ring.push(snap);

                // Publish the last second's peak receive-buffer occupancy and reset
                // the accumulator so the next window starts fresh (gauge, not counter).
                let rmem_peak = counters.udp_rmem_pct_acc.swap(0, Ordering::Relaxed);
                counters.udp_rmem_pct.store(rmem_peak, Ordering::Relaxed);
                // Same for the peak kernel→userspace receive latency.
                let lat_peak = counters.udp_recv_lat_us_acc.swap(0, Ordering::Relaxed);
                counters.udp_recv_lat_us.store(lat_peak, Ordering::Relaxed);

                prev_queries  = cur_queries;
                prev_cache    = cur_cache;
                prev_up_ok    = cur_up_ok;
                prev_up_err   = cur_up_err;
                prev_null     = cur_null;
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
                    if let Ok(fs) = MsgpackFileState::open(cfg).await {
                        file_state = Some(fs);
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
        if ring.enabled() && ring.push(ev.clone()) {
            counters.ring_evictions.fetch_add(1, Ordering::Relaxed);
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
    index: HistoryIndex,
    index_dirty: bool,
}

impl MsgpackFileState {
    async fn open(cfg: &QueryLogFileConfig) -> anyhow::Result<Self> {
        tokio::fs::create_dir_all(&cfg.dir).await?;

        // Reuse the most-recent plain segment if it is still below the size
        // limit.  This avoids creating a new file on every restart, which
        // would exhaust max_segments slots with empty / tiny files.
        let reusable = find_resumable_segment(&cfg.dir, cfg.max_mb).await;
        let (path, index) =
            reusable.unwrap_or_else(|| (cfg.dir.join(segment_name()), HistoryIndex::empty()));

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
            index,
            index_dirty: false,
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

        let offset = self.bytes_written;
        self.file.write_all(&buf).await?;
        self.bytes_written += buf.len() as u64;
        self.index.append_batch(offset, buf.len() as u64, batch);
        self.index_dirty = true;

        // Rotate if the active segment has grown past the size limit.
        if self.bytes_written >= cfg.max_mb * 1_048_576 {
            self.rotate(cfg).await?;
        }

        Ok(())
    }

    /// Flush, compress the closed segment, then open a fresh one.
    async fn rotate(&mut self, cfg: &QueryLogFileConfig) -> anyhow::Result<()> {
        self.flush().await?;

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
        self.index = HistoryIndex::empty();
        self.index_dirty = false;

        prune_old_files(cfg).await.ok();
        Ok(())
    }

    async fn flush(&mut self) -> anyhow::Result<()> {
        self.file.flush().await?;
        if self.index_dirty {
            let data = serde_json::to_vec(&self.index)?;
            tokio::fs::write(index_path(&self.path), data).await?;
            self.index_dirty = false;
        }
        Ok(())
    }
}

// ── Gzip compression (blocking) ───────────────────────────────────────────────

/// Compress `path` to `{path}.gz` using the sidecar index when available.
///
/// When an index exists the file is split into independent gzip members (one per
/// block) so history reads can seek directly to the relevant block.  Falls back
/// to a single-member gzip for legacy/unindexed files.
///
/// A `.tmp` intermediate prevents the reader from seeing a partial `.gz` file.
fn compress_to_gz(path: &Path) -> std::io::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{BufReader, BufWriter, Write};

    let gz_path = PathBuf::from(format!("{}.gz", path.display()));
    let temp_path = PathBuf::from(format!("{}.tmp", gz_path.display()));
    let index = load_index(path).ok();
    let mut src = std::fs::File::open(path)?;

    if let Some(index) = index.filter(|idx| !idx.blocks.is_empty()) {
        let mut dst = BufWriter::new(std::fs::File::create(&temp_path)?);
        let source_blocks = index.blocks.clone();
        let mut compressed_index = HistoryIndex {
            compressed_blocks: true,
            blocks: Vec::with_capacity(source_blocks.len()),
            ..index
        };
        let mut output_offset = 0u64;

        for block in &source_blocks {
            src.seek(SeekFrom::Start(block.offset))?;
            let mut plain = vec![0u8; block.len as usize];
            src.read_exact(&mut plain)?;
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&plain)?;
            let compressed = encoder.finish()?;
            dst.write_all(&compressed)?;
            compressed_index.blocks.push(HistoryBlock {
                offset: output_offset,
                len: compressed.len() as u64,
                ..block.clone()
            });
            output_offset += compressed.len() as u64;
        }
        dst.flush()?;
        write_index(&temp_path, &compressed_index)?;
    } else {
        let dst = BufWriter::new(std::fs::File::create(&temp_path)?);
        let mut encoder = GzEncoder::new(dst, Compression::fast());
        std::io::copy(&mut BufReader::new(src), &mut encoder)?;
        encoder.finish()?;
    }

    // Atomic rename of data file, then index file (best-effort).
    // If the process crashes between the two renames, load_index will fail on
    // the .gz and the reader will use the MultiGzDecoder legacy path.
    std::fs::rename(&temp_path, &gz_path)?;
    let temp_index = index_path(&temp_path);
    if temp_index.exists() {
        std::fs::rename(temp_index, index_path(&gz_path))?;
    }
    std::fs::remove_file(path)?;
    let _ = std::fs::remove_file(index_path(path));
    Ok(())
}

// ── Segment naming ────────────────────────────────────────────────────────────

/// Return the path and index of the most-recent plain `.msgpack` segment if it
/// is still below the rotation threshold, so the worker can append to it on
/// restart rather than creating a new file.
async fn find_resumable_segment(dir: &Path, max_mb: u64) -> Option<(PathBuf, HistoryIndex)> {
    let mut entries = tokio::fs::read_dir(dir).await.ok()?;
    let mut candidates: Vec<String> = Vec::new();
    while let Some(e) = entries.next_entry().await.ok()? {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("querylog-") && name.ends_with(".msgpack") {
            candidates.push(name);
        }
    }
    // Lexicographic sort = chronological; take the newest.
    candidates.sort();
    let name = candidates.into_iter().next_back()?;
    let path = dir.join(&name);
    let size = tokio::fs::metadata(&path).await.ok()?.len();
    // Only resume if the file is still below the rotation threshold and has a
    // valid index that covers it exactly (guards against crash-truncated indexes).
    let index = load_index(&path).ok()?;
    if size < max_mb * 1_048_576 {
        Some((path, index))
    } else {
        None
    }
}

fn segment_name() -> String {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    format!("querylog-{micros:020}.msgpack")
}

// ── Index helpers ─────────────────────────────────────────────────────────────

fn index_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.index.json", path.display()))
}

fn load_index(path: &Path) -> anyhow::Result<HistoryIndex> {
    let data = std::fs::read(index_path(path))?;
    let index: HistoryIndex = serde_json::from_slice(&data)?;
    anyhow::ensure!(
        index.version == HISTORY_INDEX_VERSION,
        "unsupported history index version"
    );
    let file_size = std::fs::metadata(path)?.len();
    let mut expected_offset = 0u64;
    let mut expected_entry = 0u64;
    for block in &index.blocks {
        anyhow::ensure!(
            block.offset == expected_offset && block.first_entry == expected_entry,
            "non-contiguous history index"
        );
        anyhow::ensure!(block.len > 0 && block.entries > 0, "empty history block");
        expected_offset = expected_offset
            .checked_add(block.len)
            .ok_or_else(|| anyhow::anyhow!("history index byte offset overflow"))?;
        expected_entry = expected_entry
            .checked_add(u64::from(block.entries))
            .ok_or_else(|| anyhow::anyhow!("history index entry overflow"))?;
    }
    anyhow::ensure!(
        expected_offset == file_size && expected_entry == index.total_entries,
        "history index does not cover the complete segment"
    );
    Ok(index)
}

fn write_index(path: &Path, index: &HistoryIndex) -> std::io::Result<()> {
    let data = serde_json::to_vec(index).map_err(std::io::Error::other)?;
    std::fs::write(index_path(path), data)
}

// ── Pruning ───────────────────────────────────────────────────────────────────

async fn prune_old_files(cfg: &QueryLogFileConfig) -> anyhow::Result<()> {
    let mut entries = tokio::fs::read_dir(&cfg.dir).await?;
    let mut files: Vec<String> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let n = entry.file_name().to_string_lossy().into_owned();
        if n.starts_with("querylog-") && (n.ends_with(".msgpack") || n.ends_with(".msgpack.gz")) {
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
                remove_segment(&cfg.dir.join(&name)).await;
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
            remove_segment(&cfg.dir.join(old_name)).await;
        }
    }

    Ok(())
}

/// Remove a segment file and its sidecar index (best-effort).
async fn remove_segment(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
    let _ = tokio::fs::remove_file(index_path(path)).await;
}

/// Extract the Unix-microsecond timestamp from a segment file name.
/// Names are `querylog-{20_digits}.msgpack` or `querylog-{20_digits}.msgpack.gz`.
fn extract_file_timestamp(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("querylog-")?;
    let end = rest.find('.')?;
    rest[..end].parse::<u64>().ok()
}

// ── Historical file listing ───────────────────────────────────────────────────

/// List historical segments in `dir`, sorted oldest-first.
///
/// Includes both gzip-compressed (`.msgpack.gz`) and plain (`.msgpack`)
/// segments. During the compression window both forms of the same segment can
/// briefly coexist; the plain `.msgpack` is suppressed when its `.gz`
/// counterpart already exists.
pub fn list_history_files(dir: &Path) -> Vec<HistoryFileInfo> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut files: Vec<HistoryFileInfo> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("querylog-")
                && (name.ends_with(".msgpack.gz") || name.ends_with(".msgpack"))
            {
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                let path = e.path();
                let index = load_index(&path).ok();
                Some(HistoryFileInfo {
                    name,
                    size_bytes: size,
                    total_entries: index.as_ref().map(|idx| idx.total_entries),
                    start_micros: index.as_ref().and_then(|idx| idx.start_micros),
                    end_micros: index.as_ref().and_then(|idx| idx.end_micros),
                    indexed: index.is_some(),
                })
            } else {
                None
            }
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));

    // During the compression window both querylog-T.msgpack and
    // querylog-T.msgpack.gz can coexist.  Drop the plain form when its
    // compressed counterpart is already visible.
    let gz_stems: std::collections::HashSet<String> = files
        .iter()
        .filter(|f| f.name.ends_with(".msgpack.gz"))
        .map(|f| f.name.trim_end_matches(".msgpack.gz").to_owned())
        .collect();
    files.retain(|f| {
        !f.name.ends_with(".msgpack") || !gz_stems.contains(f.name.trim_end_matches(".msgpack"))
    });

    files
}

// ── Historical file reader ────────────────────────────────────────────────────

/// Read one bounded page from a historical segment.
///
/// Indexed files seek directly to the relevant plain byte ranges or independent
/// gzip members.  Legacy files remain readable through a sequential fallback
/// that uses `MultiGzDecoder` to handle both single-member and multi-member gz.
pub fn read_history_page(path: &Path, query: &HistoryQuery) -> anyhow::Result<HistoryPage> {
    if let Ok(index) = load_index(path) {
        read_indexed_history_page(path, query, &index)
    } else {
        read_legacy_history_page(path, query)
    }
}

fn read_indexed_history_page(
    path: &Path,
    query: &HistoryQuery,
    index: &HistoryIndex,
) -> anyhow::Result<HistoryPage> {
    let limit = query.limit.clamp(1, HISTORY_PAGE_MAX);

    // The first block whose end_micros >= from_micros determines the starting
    // ordinal for time-range queries.  A cursor that points further ahead wins.
    let first_candidate = index
        .blocks
        .iter()
        .find(|block| {
            query
                .from_micros
                .is_none_or(|from| block.end_micros >= from)
        })
        .map_or(index.total_entries, |block| block.first_entry);
    // If a cursor was supplied it must be >= first_candidate so we never move
    // backwards relative to the time filter.
    let cursor = query.cursor.unwrap_or(first_candidate).max(first_candidate);

    let mut file = std::fs::File::open(path)?;
    let mut events = Vec::with_capacity(limit);
    let mut next_cursor = cursor;
    let mut has_more = false;

    'blocks: for block in &index.blocks {
        let block_end_entry = block.first_entry + u64::from(block.entries);
        // Skip blocks entirely before the cursor position.
        if block_end_entry <= cursor {
            continue;
        }
        // Skip blocks outside the requested time window.
        if query
            .from_micros
            .is_some_and(|from| block.end_micros < from)
        {
            continue;
        }
        if query.to_micros.is_some_and(|to| block.start_micros > to) {
            break;
        }

        file.seek(SeekFrom::Start(block.offset))?;
        let decoded = if index.compressed_blocks {
            let gz = flate2::read::GzDecoder::new((&mut file).take(block.len));
            decode_msgpack_block(gz)
        } else {
            decode_msgpack_block((&mut file).take(block.len))
        };

        for (position, event) in decoded.into_iter().enumerate() {
            let ordinal = block.first_entry + position as u64;
            if ordinal < cursor {
                continue;
            }
            if event_matches(&event, query) {
                if events.len() < limit {
                    events.push(event);
                    next_cursor = ordinal + 1;
                } else {
                    has_more = true;
                    next_cursor = ordinal;
                    break 'blocks;
                }
            }
        }
    }

    Ok(HistoryPage {
        events,
        total_entries: Some(index.total_entries),
        start_micros: index.start_micros,
        end_micros: index.end_micros,
        next_cursor: has_more.then_some(next_cursor),
        has_more,
        indexed: true,
    })
}

fn read_legacy_history_page(path: &Path, query: &HistoryQuery) -> anyhow::Result<HistoryPage> {
    use std::io::BufReader;

    let file = std::fs::File::open(path)?;
    // MultiGzDecoder handles both single-member (old) and multi-member (new)
    // gzip files transparently.
    let reader: Box<dyn Read> = if path.to_str().is_some_and(|s| s.ends_with(".gz")) {
        Box::new(flate2::read::MultiGzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut de = rmp_serde::Deserializer::new(BufReader::new(reader));
    let limit = query.limit.clamp(1, HISTORY_PAGE_MAX);
    let cursor = query.cursor.unwrap_or(0);
    let mut ordinal = 0u64;
    let mut events = Vec::with_capacity(limit);
    let mut has_more = false;

    // Cap total records scanned so a rare filter on a large legacy file does
    // not stall the blocking thread pool indefinitely.
    let max_scan: u64 = if query.qname.as_deref().is_some_and(|q| !q.is_empty())
        || query.rcode.is_some()
        || query.source.as_deref().is_some_and(|s| !s.is_empty())
        || query.from_micros.is_some()
        || query.to_micros.is_some()
    {
        (limit as u64).saturating_mul(100).max(10_000)
    } else {
        u64::MAX
    };

    loop {
        if ordinal.saturating_sub(cursor) >= max_scan {
            break;
        }
        let result: Result<DecodedEvent, _> = serde::de::Deserialize::deserialize(&mut de);
        match result {
            Ok(event) => {
                let current = ordinal;
                ordinal += 1;
                if current < cursor || !event_matches(&event, query) {
                    continue;
                }
                if events.len() < limit {
                    events.push(event);
                } else {
                    has_more = true;
                    // current is the ordinal of the overflow event; next call
                    // resumes from it.
                    ordinal = current;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    Ok(HistoryPage {
        events,
        total_entries: None,
        start_micros: None,
        end_micros: None,
        next_cursor: has_more.then_some(ordinal),
        has_more,
        indexed: false,
    })
}

fn event_matches(event: &DecodedEvent, query: &HistoryQuery) -> bool {
    query
        .from_micros
        .is_none_or(|from| event.unix_micros >= from)
        && query.to_micros.is_none_or(|to| event.unix_micros <= to)
        && query
            .qname
            .as_deref()
            .is_none_or(|q| q.is_empty() || event.qname.contains(q))
        && query.rcode.is_none_or(|rcode| event.rcode == rcode)
        && query
            .source
            .as_deref()
            .is_none_or(|source| source.is_empty() || event.source == source)
}

/// Decode all msgpack events from `reader` into a `Vec`.
/// Used for indexed reads where the block size is already bounded.
fn decode_msgpack_block<R: Read>(reader: R) -> Vec<DecodedEvent> {
    let mut de = rmp_serde::Deserializer::new(reader);
    let mut events = Vec::new();
    loop {
        let result: Result<DecodedEvent, _> = serde::de::Deserialize::deserialize(&mut de);
        match result {
            Ok(ev) => events.push(ev),
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/worker.rs"]
mod tests;
