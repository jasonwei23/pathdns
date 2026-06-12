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

static DASHBOARD_HTML: &str = include_str!("page.html");
/// One concurrent history query at a time — keeps memory and CPU predictable
/// on router-class hardware.
static HISTORY_QUERY_GATE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

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
    loop {
        let Ok((mut conn, _peer)) = listener.accept().await else {
            continue;
        };
        let ring = ring.clone();
        let qps_ring = qps_ring.clone();
        let stats_ring = stats_ring.clone();
        let handle = handle.clone();
        let state = state.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let Ok(Ok(req)) =
                tokio::time::timeout(Duration::from_secs(5), read_request(&mut conn)).await
            else {
                return;
            };

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

    let mut auth = None;
    for line in lines {
        if line.to_lowercase().starts_with("authorization:") {
            let value = line[14..].trim();
            if let Some(tok) = value.strip_prefix("Bearer ") {
                auth = Some(tok.trim().to_string());
            }
        }
    }

    Ok(HttpRequest {
        method: method.to_uppercase(),
        path: path.to_string(),
        query: query.to_string(),
        auth,
    })
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
    ring: &EventRing,
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
            let n = parse_query_param(&req.query, "n")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(3600)
                .min(3600);
            let data = qps_ring.snapshot(n);
            let body = serde_json::to_vec(&data).unwrap_or_default();
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/querylog") => {
            let limit = parse_query_param(&req.query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100);
            let before_seq =
                parse_query_param(&req.query, "before_seq").and_then(|v| v.parse::<u64>().ok());
            let filter = parse_query_param(&req.query, "q");
            let events = ring.query(before_seq, limit, filter.as_deref());
            let body = render_ring_events(&events);
            ("200 OK", body, "application/json")
        }

        ("DELETE", "/api/querylog") => {
            ring.clear();
            ("204 No Content", vec![], "application/json")
        }

        // List available historical segments and their index metadata.
        ("GET", "/api/querylog/files") => {
            let dir = state.hot.load().cfg.querylog.file.as_ref().map(|f| f.dir.clone());
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
            let limit = parse_query_param(&req.query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 200);
            let cursor =
                parse_query_param(&req.query, "cursor").and_then(|v| v.parse::<u64>().ok());
            let from_micros =
                parse_query_param(&req.query, "from").and_then(|v| v.parse::<u64>().ok());
            let to_micros =
                parse_query_param(&req.query, "to").and_then(|v| v.parse::<u64>().ok());
            let qname = parse_query_param(&req.query, "q");
            let rcode =
                parse_query_param(&req.query, "rcode").and_then(|v| v.parse::<u8>().ok());
            let source = parse_query_param(&req.query, "source");

            let Some(dir) = state.hot.load().cfg.querylog.file.as_ref().map(|f| f.dir.clone()) else {
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

            let gate = HISTORY_QUERY_GATE.get_or_init(|| tokio::sync::Semaphore::new(1));
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
            let seconds = parse_query_param(&req.query, "seconds")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(3600)
                .clamp(1, 86400);
            let buckets = parse_query_param(&req.query, "buckets")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(12)
                .clamp(1, 1440);
            let snaps = stats_ring.bucket_aggregate(seconds, buckets);
            let json_buckets: Vec<serde_json::Value> = snaps
                .iter()
                .map(|s| {
                    let rate = if s.queries > 0 {
                        s.cache_hits as f64 / s.queries as f64 * 100.0
                    } else {
                        0.0
                    };
                    serde_json::json!({
                        "queries":        s.queries,
                        "cache_hits":     s.cache_hits,
                        "cache_hit_rate_pct": rate,
                        "upstream_ok":    s.upstream_ok,
                        "upstream_err":   s.upstream_err,
                        "null_responses": s.null_responses,
                        "stale_served":   s.stale_served,
                        "filtered":       s.filtered,
                    })
                })
                .collect();
            let body = serde_json::to_vec(&json_buckets).unwrap_or_default();
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/stats/aggregate") => {
            let seconds = parse_query_param(&req.query, "seconds")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(3600)
                .clamp(1, 86400);
            let (agg, from_secs) = stats_ring.aggregate(seconds);
            let to_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let cache_rate = if agg.queries > 0 {
                agg.cache_hits as f64 / agg.queries as f64 * 100.0
            } else {
                0.0
            };
            let body = serde_json::to_vec(&serde_json::json!({
                "seconds": seconds,
                "from_unix": from_secs,
                "to_unix": to_secs,
                "queries": agg.queries,
                "cache_hits": agg.cache_hits,
                "cache_hit_rate_pct": cache_rate,
                "upstream_ok": agg.upstream_ok,
                "upstream_err": agg.upstream_err,
                "null_responses": agg.null_responses,
                "stale_served": agg.stale_served,
                "filtered": agg.filtered,
            }))
            .unwrap_or_default();
            ("200 OK", body, "application/json")
        }

        ("GET", "/api/groups") => {
            let body = render_groups(state);
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

// ── JSON renderers ────────────────────────────────────────────────────────────

fn render_stats(
    handle: &QueryLogHandle,
    qps_ring: &QpsRing,
    ring: &EventRing,
    state: &AppState,
) -> Vec<u8> {
    let c = &handle.counters;
    let total = c.queries_total.load(Ordering::Relaxed);
    let cache = c.cache_hits.load(Ordering::Relaxed);
    let up_ok = c.upstream_ok.load(Ordering::Relaxed);
    let up_err = c.upstream_err.load(Ordering::Relaxed);
    let drops = c.inflight_drops.load(Ordering::Relaxed);
    let queued = c.inflight_queued.load(Ordering::Relaxed);
    let rtt_sum = c.rtt_sum_us.load(Ordering::Relaxed);
    let rtt_n = c.rtt_count.load(Ordering::Relaxed);
    let avg_resolution_us = rtt_sum.checked_div(rtt_n).unwrap_or(0);
    let cache_rate = if total > 0 {
        cache as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    let qps_now = qps_ring.snapshot(1).first().copied().unwrap_or(0);
    let ring_len = ring.len();
    let sf_hits = c.singleflight_hits.load(Ordering::Relaxed);
    let stale_served = c.stale_served.load(Ordering::Relaxed);
    let refresh_started = c.cache_refresh_started.load(Ordering::Relaxed);
    let refresh_failed = c.cache_refresh_failed.load(Ordering::Relaxed);
    let hedged = c.hedged_queries.load(Ordering::Relaxed);
    let filtered = c.filtered.load(Ordering::Relaxed);
    let null_responses = c.null_responses.load(Ordering::Relaxed);
    let events_enqueued = c.events_enqueued.load(Ordering::Relaxed);
    let events_processed = c.events_processed.load(Ordering::Relaxed);
    let events_dropped_full = c.events_dropped_full.load(Ordering::Relaxed);
    let events_dropped_closed = c.events_dropped_closed.load(Ordering::Relaxed);
    let queue_high_watermark = c.queue_high_watermark.load(Ordering::Relaxed);
    let ring_evictions = c.ring_evictions.load(Ordering::Relaxed);
    let file_write_errors = c.file_write_errors.load(Ordering::Relaxed);

    serde_json::to_vec(&serde_json::json!({
        "queries_total": total,
        "queries_udp": c.queries_udp.load(Ordering::Relaxed),
        "queries_tcp": c.queries_tcp.load(Ordering::Relaxed),
        "cache_hits": cache,
        "cache_hit_rate_pct": cache_rate,
        "upstream_ok": up_ok,
        "upstream_err": up_err,
        "inflight_drops": drops,
        "inflight_queued": queued,
        "avg_resolution_us": avg_resolution_us,
        "qps_now": qps_now,
        "ring_len": ring_len,
        "singleflight_hits": sf_hits,
        "stale_served": stale_served,
        "cache_refresh_started": refresh_started,
        "cache_refresh_failed": refresh_failed,
        "hedged_queries": hedged,
        "filtered": filtered,
        "null_responses": null_responses,
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
    }))
    .unwrap_or_default()
}

fn render_ring_events(events: &[std::sync::Arc<super::QueryLogEvent>]) -> Vec<u8> {
    let values: Vec<_> = events
        .iter()
        .map(|ev| {
            let answer_ips: Vec<String> = ev.answer_ips.iter().map(ToString::to_string).collect();
            serde_json::json!({
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
                "group": ev.group.as_deref(),
                "answer_ips": answer_ips,
            })
        })
        .collect();
    serde_json::to_vec(&values).unwrap_or_default()
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
                "group": ev.group,
                "answer_ips": ev.answer_ips,
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
    let mut first_group = true;
    let hot = state.hot.load();
    for group in &hot.groups {
        let Some(pool) = &group.upstream else {
            continue;
        };
        if !first_group {
            out.push(b',');
        }
        first_group = false;
        let prefix = format!("group-{}", group.name);
        let snaps = pool.node_snapshots(&prefix);
        let nodes_json = render_node_snapshots(&snaps);
        let entry = serde_json::json!({
            "group": group.name.as_str(),
            "nodes": nodes_json,
        });
        out.extend_from_slice(serde_json::to_string(&entry).unwrap_or_default().as_bytes());
    }
    out.push(b']');
    out
}

fn render_groups(state: &AppState) -> Vec<u8> {
    let geosite = state.geosite.load_full();
    let tag_counts: std::collections::HashMap<&str, usize> = geosite
        .as_deref()
        .map(|db| db.tag_counts().collect())
        .unwrap_or_default();

    let hot = state.hot.load();
    let groups: Vec<_> = hot
        .groups
        .iter()
        .map(|g| {
            let tags: Vec<_> = g
                .geosite_include
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "tag": t,
                        "include": true,
                        "count": tag_counts.get(t.as_str()).copied().unwrap_or(0),
                    })
                })
                .chain(g.geosite_exclude.iter().map(|t| {
                    serde_json::json!({
                        "tag": t,
                        "include": false,
                        "count": tag_counts.get(t.as_str()).copied().unwrap_or(0),
                    })
                }))
                .collect();

            let mut filter_qtypes: Vec<u16> = g.filter_qtype.iter().copied().collect();
            filter_qtypes.sort_unstable();

            serde_json::json!({
                "name": g.name,
                "tags": tags,
                "filter_qtype": filter_qtypes,
                "has_upstream": g.upstream.is_some(),
                "fixed_rcode": g.fixed_rcode,
            })
        })
        .collect();

    serde_json::to_vec(&groups).unwrap_or_default()
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

fn ct_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_params_are_percent_decoded() {
        assert_eq!(
            parse_query_param("q=hello%20world", "q").as_deref(),
            Some("hello world")
        );
        assert_eq!(
            parse_query_param("q=%E4%BE%8B%E5%AD%90", "q").as_deref(),
            Some("例子")
        );
    }

    #[test]
    fn invalid_percent_encoding_is_rejected() {
        assert!(parse_query_param("q=%zz", "q").is_none());
    }

    #[test]
    fn dashboard_defers_archive_queries_until_range_commit() {
        assert!(DASHBOARD_HTML.contains("oninput=\"previewArchiveRange('start')\""));
        assert!(DASHBOARD_HTML.contains("onchange=\"commitArchiveRange()\""));
        assert!(DASHBOARD_HTML.contains("function selectArchiveFile(name)"));
        assert!(DASHBOARD_HTML.contains("setArchiveRange("));
        assert!(DASHBOARD_HTML.contains("function resetArchiveRange()"));
    }

    #[test]
    fn safe_filename_rejects_path_traversal() {
        assert!(!safe_history_filename("../etc/passwd"));
        assert!(!safe_history_filename("other-1234.msgpack.gz")); // wrong prefix
        assert!(!safe_history_filename("querylog-1234/x.msgpack.gz")); // slash
        assert!(safe_history_filename(
            "querylog-00001749000000000000.msgpack.gz"
        ));
        assert!(safe_history_filename(
            "querylog-00001749000000000000.msgpack"
        ));
    }
}
