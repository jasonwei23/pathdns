//! Hand-rolled HTTP API for the query log dashboard.
//!
//! Routes:
//!   GET  /                        → dashboard HTML (embedded)
//!   GET  /api/stats               → current counters + avg RTT + QPS
//!   GET  /api/stats/history       → last 3600 per-second QPS counts
//!   GET  /api/stats/buckets       → StatsRing data divided into equal time buckets (?seconds=&buckets=)
//!   GET  /api/querylog            → paginated events from ring (?limit=&before_seq=&q=)
//!   DELETE /api/querylog          → clear ring buffer
//!   GET  /api/querylog/files      → list historical segments and metadata
//!   GET  /api/querylog/history    → paginated historical query
//!   GET  /api/upstreams           → per-node stats snapshot

use super::{QpsRing, QueryLogHandle};
use crate::querylog::ring::{EventRing, StatsRing};
use crate::querylog::worker::micros_to_rfc3339;
use crate::server::AppState;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{interval, MissedTickBehavior};

static DASHBOARD_HTML: &str = include_str!("page.html");
/// At most two concurrent history queries — keeps memory and CPU predictable
/// on router-class hardware while allowing a second reader during pagination.
static HISTORY_QUERY_GATE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

/// Cap on concurrently open dashboard connections (including long-lived
/// `/api/querylog/stream` SSE subscribers), so an unauthenticated or
/// misconfigured-exposure deployment can't be driven into fd/memory
/// exhaustion by opening unbounded connections; excess connections are
/// dropped immediately rather than queued.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;
static CONNECTION_GATE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

pub async fn serve(
    listener: TcpListener,
    token: Option<String>,
    ring: Arc<EventRing>,
    qps_ring: Arc<QpsRing>,
    stats_ring: Arc<StatsRing>,
    handle: QueryLogHandle,
    state: Arc<AppState>,
) {
    let token = Arc::new(token);
    let gate = CONNECTION_GATE.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let Ok((mut conn, _peer)) = listener.accept().await else {
            continue;
        };
        // Reject immediately (no queueing) once at the concurrent-connection cap,
        // so a flood of connections can't pile up waiting for a permit either.
        let Ok(permit) = gate.try_acquire() else {
            continue;
        };
        let ring = ring.clone();
        let qps_ring = qps_ring.clone();
        let stats_ring = stats_ring.clone();
        let handle = handle.clone();
        let state = state.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(req)) =
                tokio::time::timeout(Duration::from_secs(5), read_request(&mut conn)).await
            else {
                return;
            };

            // SSE endpoint: stream events instead of returning a buffered response.
            if req.method == "GET" && req.path == "/api/querylog/stream" {
                handle_sse(req, conn, ring, (*token).as_deref()).await;
                return;
            }

            let (status, body, content_type) = dispatch(
                req,
                &ring,
                &qps_ring,
                &stats_ring,
                &handle,
                &state,
                token.as_deref(),
            )
            .await;

            let header = format!(
                "HTTP/1.1 {status}\r\n\
                 Content-Type: {content_type}\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-store\r\n\
                 Connection: close\r\n\
                 \r\n",
                body.len()
            );
            let _ = conn.write_all(header.as_bytes()).await;
            let _ = conn.write_all(&body).await;
        });
    }
}

// ── Request parsing ───────────────────────────────────────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    query: String,
    auth: Option<String>,
    /// Value of the `Last-Event-Id` header, used by browser EventSource on reconnect.
    last_event_id: Option<String>,
}

async fn read_request(conn: &mut tokio::net::TcpStream) -> std::io::Result<HttpRequest> {
    let mut buf = vec![0u8; 4096];
    let mut total = 0;
    loop {
        let n = conn.read(&mut buf[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total >= buf.len() {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf[..total]);
    parse_http_request(&text)
}

fn parse_http_request(text: &str) -> std::io::Result<HttpRequest> {
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    let method = parts.first().copied().unwrap_or("GET").to_string();
    let full_path = parts.get(1).copied().unwrap_or("/");
    let (path, query) = if let Some(pos) = full_path.find('?') {
        (&full_path[..pos], &full_path[pos + 1..])
    } else {
        (full_path, "")
    };

    // Case-insensitive header-name match done directly on `line` (not a separately
    // lowercased copy) so the byte offset used to slice off the header name always
    // stays valid — `to_lowercase()`/`to_uppercase()` can change a string's byte
    // length for some Unicode case folds, which would otherwise risk slicing off a
    // UTF-8 char boundary and panicking (fatal to the whole process: release builds
    // set `panic = "abort"`).
    let mut auth = None;
    let mut last_event_id = None;
    for line in lines {
        if let Some(value) = strip_header_prefix(line, "authorization:") {
            if let Some(tok) = value.trim().strip_prefix("Bearer ") {
                auth = Some(tok.trim().to_string());
            }
        } else if let Some(value) = strip_header_prefix(line, "last-event-id:") {
            last_event_id = Some(value.trim().to_string());
        }
    }

    Ok(HttpRequest {
        method: method.to_uppercase(),
        path: path.to_string(),
        query: query.to_string(),
        auth,
        last_event_id,
    })
}

/// If `line` starts with `prefix` (ASCII case-insensitive), return the rest of the
/// line. `prefix` must be ASCII; the comparison and slice both operate on `line`'s
/// own bytes, so there is no risk of slicing at a non-char-boundary offset.
fn strip_header_prefix<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    if bytes.len() < prefix.len() || !bytes[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        return None;
    }
    Some(&line[prefix.len()..])
}

fn parse_query_param(query: &str, key: &str) -> Option<String> {
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return percent_decode(v);
            }
        }
    }
    None
}

/// Parse query param `key` as `T`, falling back to `default` if absent or unparsable.
fn query_param<T: std::str::FromStr>(query: &str, key: &str, default: T) -> T {
    parse_query_param(query, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse query param `key` as `T`, returning `None` if absent or unparsable.
fn query_param_opt<T: std::str::FromStr>(query: &str, key: &str) -> Option<T> {
    parse_query_param(query, key).and_then(|v| v.parse().ok())
}

/// Cache hit rate as a percentage, or 0.0 when there have been no queries yet.
fn hit_rate_pct(hits: u64, total: u64) -> f64 {
    if total > 0 {
        hits as f64 / total as f64 * 100.0
    } else {
        0.0
    }
}

/// The configured historical query-log directory, if file logging is enabled.
fn querylog_dir(state: &AppState) -> Option<std::path::PathBuf> {
    state
        .hot
        .load()
        .cfg
        .dashboard
        .file
        .as_ref()
        .map(|f| f.dir.clone())
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex(bytes[i + 1])?;
                let lo = hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

async fn dispatch(
    req: HttpRequest,
    ring: &Arc<EventRing>,
    qps_ring: &QpsRing,
    stats_ring: &StatsRing,
    handle: &QueryLogHandle,
    state: &AppState,
    token: Option<&str>,
) -> (&'static str, Vec<u8>, &'static str) {
    if matches!(
        (req.method.as_str(), req.path.as_str()),
        ("GET", "/") | ("GET", "/index.html")
    ) {
        return (
            "200 OK",
            DASHBOARD_HTML.as_bytes().to_vec(),
            "text/html; charset=utf-8",
        );
    }

    if let Some(expected) = token {
        let provided = req.auth.as_deref().unwrap_or("");
        if !ct_str_eq(provided, expected) {
            return (
                "401 Unauthorized",
                br#"{"error":"unauthorized"}"#.to_vec(),
                "application/json",
            );
        }
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/stats") => {
            let body = render_stats(handle, qps_ring, ring, state);
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/stats/history") => {
            let n = query_param(&req.query, "n", 3600usize).min(3600);
            let data = qps_ring.snapshot(n);
            let body = serde_json::to_vec(&data).unwrap_or_default();
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/querylog") => {
            let limit = query_param(&req.query, "limit", 100usize);
            let before_seq = query_param_opt::<u64>(&req.query, "before_seq");
            let after_seq = query_param_opt::<u64>(&req.query, "after_seq");
            let filter = parse_query_param(&req.query, "q");
            // A rare/non-matching substring filter forces `query()` to linearly
            // scan the whole ring (bounded by `limit` only applies to matches, not
            // to items examined) while holding a blocking `std::sync::Mutex` — run
            // it on the blocking pool so it can't stall this async worker thread
            // (and, with it, every other request scheduled on the same thread).
            let ring = ring.clone();
            let events = tokio::task::spawn_blocking(move || {
                ring.query(before_seq, after_seq, limit, filter.as_deref())
            })
            .await
            .unwrap_or_default();
            let body = render_ring_events(&events);
            ("200 OK", body, "application/json")
        }

        ("DELETE", "/api/querylog") => {
            ring.clear();
            ("204 No Content", vec![], "application/json")
        }

        // List available historical segments and their index metadata.
        ("GET", "/api/querylog/files") => {
            let dir = querylog_dir(state);
            match dir {
                None => {
                    let body = b"[]".to_vec();
                    ("200 OK", body, "application/json")
                }
                Some(dir) => {
                    let result = tokio::task::spawn_blocking(move || {
                        crate::querylog::worker::list_history_files(&dir)
                    })
                    .await
                    .unwrap_or_default();

                    let body = serde_json::to_vec(&result).unwrap_or_default();
                    ("200 OK", body, "application/json")
                }
            }
        }

        // Paginated historical segment reader.
        ("GET", "/api/querylog/history") => {
            let file_name = parse_query_param(&req.query, "file").unwrap_or_default();
            let limit = query_param(&req.query, "limit", 100usize).clamp(1, 200);
            let cursor = query_param_opt::<u64>(&req.query, "cursor");
            let from_micros = query_param_opt::<u64>(&req.query, "from");
            let to_micros = query_param_opt::<u64>(&req.query, "to");
            let qname = parse_query_param(&req.query, "q");
            let rcode = query_param_opt::<u8>(&req.query, "rcode");
            let source = parse_query_param(&req.query, "source");
            let upstream = parse_query_param(&req.query, "upstream");
            let client = parse_query_param(&req.query, "client");
            let qtype = query_param_opt::<u16>(&req.query, "type");

            let Some(dir) = querylog_dir(state) else {
                return (
                    "404 Not Found",
                    br#"{"error":"file logging disabled"}"#.to_vec(),
                    "application/json",
                );
            };

            if !safe_history_filename(&file_name) {
                return (
                    "400 Bad Request",
                    br#"{"error":"invalid file name"}"#.to_vec(),
                    "application/json",
                );
            }

            let gate = HISTORY_QUERY_GATE.get_or_init(|| tokio::sync::Semaphore::new(2));
            let Ok(Ok(_permit)) =
                tokio::time::timeout(Duration::from_secs(2), gate.acquire()).await
            else {
                return (
                    "503 Service Unavailable",
                    br#"{"error":"history query busy"}"#.to_vec(),
                    "application/json",
                );
            };

            let path = dir.join(&file_name);
            let query = crate::querylog::worker::HistoryQuery {
                limit,
                cursor,
                from_micros,
                to_micros,
                qname,
                rcode,
                source,
                upstream,
                client,
                qtype,
            };
            let result = tokio::task::spawn_blocking(move || {
                crate::querylog::worker::read_history_page(&path, &query)
            })
            .await;

            match result {
                Ok(Ok(page)) => {
                    let body = render_history_page(&page);
                    ("200 OK", body, "application/json")
                }
                _ => (
                    "500 Internal Server Error",
                    br#"{"error":"read failed"}"#.to_vec(),
                    "application/json",
                ),
            }
        }

        ("GET", "/api/stats/buckets") => {
            let seconds = query_param(&req.query, "seconds", 3600usize).clamp(1, 86400);
            let buckets = query_param(&req.query, "buckets", 12usize).clamp(1, 1440);
            let snaps = stats_ring.bucket_aggregate(seconds, buckets);
            let json_buckets: Vec<serde_json::Value> = snaps
                .iter()
                .map(|s| {
                    let rate = hit_rate_pct(s.cache_hits, s.queries);
                    serde_json::json!({
                        "queries":        s.queries,
                        "cache_hits":     s.cache_hits,
                        "cache_hit_rate_pct": rate,
                        "upstream_ok":    s.upstream_ok,
                        "upstream_err":   s.upstream_err,
                        "filtered":       s.filtered,
                    })
                })
                .collect();
            let body = serde_json::to_vec(&json_buckets).unwrap_or_default();
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/stats/aggregate") => {
            let seconds = query_param(&req.query, "seconds", 3600usize).clamp(1, 86400);
            let (agg, from_secs) = stats_ring.aggregate(seconds);
            let to_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let cache_rate = hit_rate_pct(agg.cache_hits, agg.queries);
            let body = serde_json::to_vec(&serde_json::json!({
                "seconds": seconds,
                "from_unix": from_secs,
                "to_unix": to_secs,
                "queries": agg.queries,
                "cache_hits": agg.cache_hits,
                "cache_hit_rate_pct": cache_rate,
                "upstream_ok": agg.upstream_ok,
                "upstream_err": agg.upstream_err,
                "filtered": agg.filtered,
            }))
            .unwrap_or_default();
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/rules") => {
            let body = render_rules(state);
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/upstreams") => {
            let body = render_upstreams(state);
            ("200 OK", body, "application/json")
        }

        _ => (
            "404 Not Found",
            br#"{"error":"not found"}"#.to_vec(),
            "application/json",
        ),
    }
}

// ── Security helpers ──────────────────────────────────────────────────────────

/// Accept only safe, unambiguous historical segment file names.
/// Must start with "querylog-" and end with ".msgpack" or ".msgpack.gz"; no path separators.
fn safe_history_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name.starts_with("querylog-")
        && (name.ends_with(".msgpack.gz") || name.ends_with(".msgpack"))
}

// ── SSE handler ──────────────────────────────────────────────────────────────

/// Serve an SSE stream of live query events.
///
/// Auth: checks `Authorization: Bearer` header first, then `?token=` query
/// parameter (needed because `EventSource` in browsers cannot set headers).
///
/// On reconnect, the browser sends `Last-Event-Id: <seq>` automatically;
/// the server backfills all ring events with seq > that value so the client
/// picks up from where it left off.
async fn handle_sse(
    req: HttpRequest,
    mut conn: tokio::net::TcpStream,
    ring: Arc<EventRing>,
    token: Option<&str>,
) {
    if let Some(expected) = token {
        let header_tok = req.auth.as_deref().unwrap_or("");
        let param_tok = parse_query_param(&req.query, "token").unwrap_or_default();
        if !ct_str_eq(header_tok, expected) && !ct_str_eq(&param_tok, expected) {
            let _ = conn
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 24\r\nConnection: close\r\n\r\n\
                      {\"error\":\"unauthorized\"}",
                )
                .await;
            return;
        }
    }

    // Subscribe before backfill to avoid missing events in the window between
    // ring query and subscription.
    let mut rx = ring.subscribe();

    // Backfill: prefer Last-Event-Id header (auto-sent by browser on reconnect),
    // fall back to ?last_seq= query parameter for initial page load.
    let last_seq = req
        .last_event_id
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| parse_query_param(&req.query, "last_seq").and_then(|v| v.parse::<u64>().ok()));

    let sse_headers = "HTTP/1.1 200 OK\r\n\
                       Content-Type: text/event-stream\r\n\
                       Cache-Control: no-cache\r\n\
                       Connection: keep-alive\r\n\
                       X-Accel-Buffering: no\r\n\
                       \r\n";
    if conn.write_all(sse_headers.as_bytes()).await.is_err() {
        return;
    }

    if let Some(after) = last_seq {
        // Send backfill oldest-first (ring.query returns newest-first, so reverse).
        let events = ring.query(None, Some(after), 1000, None);
        for ev in events.iter().rev() {
            let line = format!("id:{}\ndata:{}\n\n", ev.seq, event_to_json(ev));
            if conn.write_all(line.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    // Real-time loop: forward new events and send periodic heartbeats.
    let mut hb = interval(Duration::from_secs(15));
    hb.set_missed_tick_behavior(MissedTickBehavior::Skip);
    hb.tick().await; // discard immediate first tick

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(ev) => {
                        let line = format!("id:{}\ndata:{}\n\n", ev.seq, event_to_json(&ev));
                        if conn.write_all(line.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Receiver fell behind; tell the client to reconnect from the ring.
                        let _ = conn.write_all(format!(": lagged {n}\n\n").as_bytes()).await;
                        return;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
            _ = hb.tick() => {
                if conn.write_all(b": ping\n\n").await.is_err() {
                    return;
                }
            }
        }
    }
}

// ── JSON renderers ────────────────────────────────────────────────────────────

fn render_stats(
    handle: &QueryLogHandle,
    qps_ring: &QpsRing,
    ring: &EventRing,
    state: &AppState,
) -> Vec<u8> {
    let c = &handle.counters;
    let total = c.queries_total();
    let cache = c.cache_hits.load(Ordering::Relaxed);
    let up_ok = c.upstream_ok.load(Ordering::Relaxed);
    let up_err = c.upstream_err.load(Ordering::Relaxed);
    let drops = c.inflight_drops.load(Ordering::Relaxed);
    let upstream_inflight_drops = c.upstream_inflight_drops.load(Ordering::Relaxed);
    let udp_truncated = c.udp_truncated.load(Ordering::Relaxed);
    let udp_send_drops = c.udp_send_drops.load(Ordering::Relaxed);
    let udp_send_errors = c.udp_send_errors.load(Ordering::Relaxed);
    let udp_rx_overflow = c.udp_rx_overflow.load(Ordering::Relaxed);
    let udp_rmem_pct = c.udp_rmem_pct.load(Ordering::Relaxed);
    let udp_recv_lat_us = c.udp_recv_lat_us.load(Ordering::Relaxed);
    let queued = c.inflight_queued.load(Ordering::Relaxed);
    let rtt_sum = c.rtt_sum_us.load(Ordering::Relaxed);
    let rtt_n = c.rtt_count.load(Ordering::Relaxed);
    let avg_resolution_us = rtt_sum.checked_div(rtt_n).unwrap_or(0);
    let cache_rate = hit_rate_pct(cache, total);
    let qps_now = qps_ring.snapshot(1).first().copied().unwrap_or(0);
    let ring_len = ring.len();
    let sf_hits = c.singleflight_hits.load(Ordering::Relaxed);
    let hedged = c.hedged_queries.load(Ordering::Relaxed);
    let filtered = c.filtered.load(Ordering::Relaxed);
    let events_enqueued = c.events_enqueued.load(Ordering::Relaxed);
    let events_processed = c.events_processed.load(Ordering::Relaxed);
    let events_dropped_full = c.events_dropped_full.load(Ordering::Relaxed);
    let events_dropped_closed = c.events_dropped_closed.load(Ordering::Relaxed);
    let queue_high_watermark = c.queue_high_watermark.load(Ordering::Relaxed);
    let ring_evictions = c.ring_evictions.load(Ordering::Relaxed);
    let file_write_errors = c.file_write_errors.load(Ordering::Relaxed);

    let add_ip_dropped = state.ipset.as_ref().map_or(0, |m| m.dropped_ips());

    let reload = &state.reload;
    let reload_last_error = reload.last_error();

    serde_json::to_vec(&serde_json::json!({
        "queries_total": total,
        "queries_udp": c.queries_udp.load(Ordering::Relaxed),
        "queries_tcp": c.queries_tcp.load(Ordering::Relaxed),
        "cache_hits": cache,
        "cache_hit_rate_pct": cache_rate,
        "upstream_ok": up_ok,
        "upstream_err": up_err,
        "inflight_drops": drops,
        "upstream_inflight_drops": upstream_inflight_drops,
        "udp_truncated": udp_truncated,
        "udp_send_drops": udp_send_drops,
        "udp_send_errors": udp_send_errors,
        "udp_rx_overflow": udp_rx_overflow,
        "udp_rmem_pct": udp_rmem_pct,
        "udp_recv_lat_us": udp_recv_lat_us,
        "inflight_queued": queued,
        "avg_resolution_us": avg_resolution_us,
        "qps_now": qps_now,
        "ring_len": ring_len,
        "singleflight_hits": sf_hits,
        "hedged_queries": hedged,
        "filtered": filtered,
        "events_enqueued": events_enqueued,
        "events_processed": events_processed,
        "events_dropped_full": events_dropped_full,
        "events_dropped_closed": events_dropped_closed,
        "queue_depth": handle.queue_depth(),
        "queue_high_watermark": queue_high_watermark,
        "ring_evictions": ring_evictions,
        "file_write_errors": file_write_errors,
        "cache_entries": state.cache.entry_count(),
        "cache_capacity": state.cache.capacity(),
        "add_ip_dropped": add_ip_dropped,
        // Hot-reload visibility: the reload paths' own logging is compiled
        // out, so this is where a failing or restart-requiring reload shows up.
        "reload_generation": state.hot_generation(),
        "reload_applied": reload.applied.load(Ordering::Relaxed),
        "reload_failed_attempts": reload.failed_attempts.load(Ordering::Relaxed),
        "reload_restart_required": reload.restart_required.load(Ordering::Relaxed),
        "reload_last_applied_unix": reload.last_applied_unix.load(Ordering::Relaxed),
        "reload_last_error": reload_last_error,
    }))
    .unwrap_or_default()
}

fn event_to_json(ev: &super::QueryLogEvent) -> String {
    serde_json::to_string(&serde_json::json!({
        "seq": ev.seq,
        "time": micros_to_rfc3339(ev.unix_micros),
        "client": ev.client.to_string(),
        "client_port": ev.client_port,
        "qname": ev.qname.as_ref(),
        "qtype": ev.qtype,
        "rcode": ev.rcode,
        "elapsed_us": ev.elapsed_us,
        "response_bytes": ev.response_bytes,
        "source": ev.source,
        "upstream": ev.upstream.as_deref(),
    }))
    .unwrap_or_default()
}

fn render_ring_events(events: &[std::sync::Arc<super::QueryLogEvent>]) -> Vec<u8> {
    let body = format!(
        "[{}]",
        events
            .iter()
            .map(|ev| event_to_json(ev))
            .collect::<Vec<_>>()
            .join(",")
    );
    body.into_bytes()
}

/// Render a history page using the same event JSON shape as the live ring
/// (notably `time` as RFC3339 rather than raw `unix_micros`) so the dashboard
/// can render live and archive events through one code path.
fn render_history_page(page: &crate::querylog::worker::HistoryPage) -> Vec<u8> {
    let values: Vec<_> = page
        .events
        .iter()
        .map(|ev| {
            serde_json::json!({
                "seq": ev.seq,
                "time": micros_to_rfc3339(ev.unix_micros),
                "client": ev.client,
                "client_port": ev.client_port,
                "qname": ev.qname,
                "qtype": ev.qtype,
                "rcode": ev.rcode,
                "elapsed_us": ev.elapsed_us,
                "response_bytes": ev.response_bytes,
                "source": ev.source,
                "upstream": ev.upstream,
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "items": values,
        "total_entries": page.total_entries,
        "start_time": page.start_micros.map(micros_to_rfc3339),
        "end_time": page.end_micros.map(micros_to_rfc3339),
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "indexed": page.indexed,
    }))
    .unwrap_or_default()
}

fn render_upstreams(state: &AppState) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024);
    out.push(b'[');
    let mut first = true;
    let hot = state.hot.load();
    for server in &hot.servers {
        // Fixed-answer servers (A://, AAAA://, RCODE://) never query a real
        // upstream, so there are no connection nodes to report here.
        let crate::server::ServerKind::Upstream(pool) = &server.kind else {
            continue;
        };
        if !first {
            out.push(b',');
        }
        first = false;
        let snaps = pool.node_snapshots(&server.name);
        let nodes_json = render_node_snapshots(&snaps);
        let entry = serde_json::json!({
            "server": server.name.as_str(),
            "nodes": nodes_json,
        });
        out.extend_from_slice(serde_json::to_string(&entry).unwrap_or_default().as_bytes());
    }
    out.push(b']');
    out
}

fn render_rules(state: &AppState) -> Vec<u8> {
    let hot = state.hot.load();
    let tag_counts: std::collections::HashMap<&str, usize> = hot
        .ruleset
        .as_deref()
        .map(|db| db.tag_counts().collect())
        .unwrap_or_default();

    let rules: Vec<_> = hot
        .rules
        .iter()
        .map(|g| {
            let matcher: Vec<_> = g
                .matcher
                .iter()
                .map(|m| match m {
                    crate::config::RuleMatcher::Domain(pattern) => serde_json::json!({
                        "kind": "domain",
                        "pattern": pattern,
                    }),
                    crate::config::RuleMatcher::Tag { include, exclude } => {
                        let tag_json = |t: &String| {
                            serde_json::json!({
                                "tag": t,
                                "count": tag_counts.get(t.as_str()).copied().unwrap_or(0),
                            })
                        };
                        serde_json::json!({
                            "kind": "tag",
                            "include": include.iter().map(tag_json).collect::<Vec<_>>(),
                            "exclude": exclude.iter().map(tag_json).collect::<Vec<_>>(),
                        })
                    }
                })
                .collect();

            let filters: Vec<_> = g
                .filters
                .iter()
                .map(|f| {
                    let action = match f.action {
                        crate::response_filter::FilterAction::Accept => "accept".to_string(),
                        crate::response_filter::FilterAction::Drop => "drop".to_string(),
                        crate::response_filter::FilterAction::Forward(idx) => format!(
                            "forward:{}",
                            hot.servers.get(idx).map(|s| s.name.as_str()).unwrap_or("?")
                        ),
                    };
                    let mut response_type: Vec<u16> = f.response_type.iter().copied().collect();
                    response_type.sort_unstable();
                    let mut response_rcode: Vec<u8> = f.response_rcode.iter().copied().collect();
                    response_rcode.sort_unstable();
                    let mut response_qclass: Vec<u16> = f.response_qclass.iter().copied().collect();
                    response_qclass.sort_unstable();
                    serde_json::json!({
                        "action": action,
                        "answer_ip": f.answer_ip.include,
                        "answer_ip_exclude": f.answer_ip.exclude,
                        "response_type": response_type,
                        "response_rcode": response_rcode,
                        "response_qclass": response_qclass,
                    })
                })
                .collect();

            serde_json::json!({
                "matcher": matcher,
                "filters": filters,
                "server": g.server,
            })
        })
        .collect();

    serde_json::to_vec(&rules).unwrap_or_default()
}

fn render_node_snapshots(snaps: &[crate::stats::NodeStatsSnapshot]) -> Vec<serde_json::Value> {
    snaps
        .iter()
        .map(|s| {
            let avg_rtt_us = if s.rtt_count() > 0 {
                s.rtt_sum_us / s.rtt_count()
            } else {
                0
            };
            serde_json::json!({
                "name": s.name.as_str(),
                "addr": s.addr.as_str(),
                "queries_ok": s.queries_ok,
                "queries_err": s.queries_err,
                "queries_timeout": s.queries_timeout,
                "queries_cancelled": s.queries_cancelled,
                "active_inflight": s.active_inflight,
                "avg_rtt_us": avg_rtt_us,
            })
        })
        .collect()
}

/// Cap for `ct_str_eq`'s fixed-width comparison loop, generously above any
/// realistic bearer token. Timing must not depend on the true length of either
/// input, so the loop always runs this many iterations rather than stopping
/// early on a length mismatch (which would leak the configured token's length).
const MAX_TOKEN_CMP_LEN: usize = 4096;

/// Constant-time string comparison. Deliberately does not short-circuit on a
/// length mismatch: an early `a.len() != b.len()` return would make the
/// comparison faster for a wrong-length guess than for a same-length wrong
/// guess, leaking the true token length via response timing before the
/// constant-time fold even runs.
fn ct_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff: u8 = (a.len() != b.len()) as u8;
    for i in 0..MAX_TOKEN_CMP_LEN {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}
