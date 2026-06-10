//! Prometheus metrics HTTP endpoint.
//!
//! Serves a minimal HTTP/1.1 response with Prometheus text format (version 0.0.4) on
//! `--metrics-addr`. No external HTTP framework; only tokio TCP.
//!
//! Scrape path: any GET request to any URL returns the metrics page.  The server
//! reads and discards the HTTP request headers, then writes the response.

use crate::server::AppState;
use crate::stats::{
    self, NodeStatsSnapshot, QueryLatencySnapshot, RTT_BUCKETS, RTT_BUCKET_BOUNDS_US,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn serve_metrics(addr: SocketAddr, state: Arc<AppState>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            crate::warn!("metrics event=bind_failed addr={addr} error={e}");
            return;
        }
    };
    crate::startup!("metrics addr=http://{addr}");
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            // Drain HTTP request headers (we only need to avoid sending a response
            // before the client finishes its request line).
            let _ = tokio::time::timeout(Duration::from_secs(5), drain_request(&mut conn)).await;
            let body = render(&state);
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n",
                body.len()
            );
            let _ = conn.write_all(header.as_bytes()).await;
            let _ = conn.write_all(body.as_bytes()).await;
        });
    }
}

/// Read from `conn` until we see `\r\n\r\n` (end of HTTP headers) or the buffer fills.
async fn drain_request(conn: &mut tokio::net::TcpStream) {
    let mut buf = [0u8; 2048];
    let mut total = 0usize;
    loop {
        match conn.read(&mut buf[total..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if total >= buf.len() {
                    break;
                }
            }
        }
    }
}

// Prometheus text format renderer.

fn render(state: &AppState) -> String {
    let mut out = String::with_capacity(8192);
    let g = stats::global_snapshot();

    // Global counters.

    write_counter(
        &mut out,
        "dns_queries_total",
        "Total DNS queries received",
        &[
            (&[("proto", "udp")], g.queries_udp),
            (&[("proto", "tcp")], g.queries_tcp),
        ],
    );

    write_gauge(
        &mut out,
        "dns_cache_size",
        "Current number of entries in the DNS response cache",
        state.cache.len() as u64,
    );

    write_counter(
        &mut out,
        "dns_cache_lookups_total",
        "DNS cache lookup outcomes",
        &[
            (&[("result", "hit")], g.cache_hits),
            (&[("result", "miss")], g.cache_misses),
            (&[("result", "stale_refresh")], g.cache_stale_refresh),
            (&[("result", "stale_error")], g.cache_stale_error),
            (
                &[("result", "stale_client_timeout")],
                g.cache_stale_client_timeout,
            ),
        ],
    );

    write_counter(
        &mut out,
        "dns_cache_refresh_total",
        "Background cache refresh task outcomes",
        &[
            (&[("result", "started")], g.cache_refresh_started),
            (&[("result", "skipped")], g.cache_refresh_skipped),
            (&[("result", "failed")], g.cache_refresh_failed),
        ],
    );

    write_counter(
        &mut out,
        "dns_singleflight_hits_total",
        "Queries deduplicated by singleflight (follower path)",
        &[(&[], g.singleflight_hits)],
    );

    write_counter(
        &mut out,
        "dns_inflight_total",
        "Queries that hit the max-inflight limit (queued = waited; dropped = timed out or hard-dropped)",
        &[
            (&[("result", "queued")], g.inflight_queued),
            (&[("result", "dropped")], g.inflight_drops),
        ],
    );

    if g.hedged_queries > 0 || g.hedge_wins > 0 {
        write_counter(
            &mut out,
            "dns_hedged_queries_total",
            "Upstream queries where the hedge timer fired (a second upstream was started)",
            &[(&[], g.hedged_queries)],
        );
        write_counter(
            &mut out,
            "dns_hedge_wins_total",
            "Queries where the hedged (secondary) upstream provided the winning response",
            &[(&[], g.hedge_wins)],
        );
    }

    write_counter(
        &mut out,
        "dns_queries_routed_total",
        "DNS queries by routing decision",
        &[
            (&[("target", "none_race")], g.routed_none_race),
            (&[("target", "null")], g.routed_null),
            (&[("target", "group")], g.routed_group),
            (&[("target", "aaaa_filtered")], g.routed_aaaa_filtered),
        ],
    );

    // Routing hot-path effectiveness: route-cache hit ratio and the cost of misses.
    // route_compute_seconds_sum / dns_route_lookups_total{result="computed"} gives the
    // average matcher-walk cost; a low cache-hit ratio plus a high average identifies
    // GeoSite matching as the bottleneck.
    write_counter(
        &mut out,
        "dns_route_lookups_total",
        "Routing decisions by source (L1 route cache vs full index walk)",
        &[
            (&[("result", "cache_hit")], g.route_cache_hits),
            (&[("result", "computed")], g.route_computed),
        ],
    );
    write_counter(
        &mut out,
        "dns_route_compute_microseconds_total",
        "Cumulative time spent computing routes on route-cache misses (microseconds)",
        &[(&[], g.route_compute_sum_us)],
    );

    write_counter(
        &mut out,
        "dns_geosite_lookups_total",
        "GeoSite tag verdicts by source (L2 result cache vs full matcher walk)",
        &[
            (&[("result", "cache_hit")], g.geosite_cache_hits),
            (&[("result", "walk")], g.geosite_walks),
        ],
    );

    // Upstream transport health: TC fallbacks double per-query latency; recv-loop
    // restarts indicate socket-level churn that surfaces as timeouts.
    write_counter(
        &mut out,
        "dns_tc_fallback_total",
        "UDP responses truncated (TC=1) and retried over TCP",
        &[(&[], g.tc_fallbacks)],
    );
    write_counter(
        &mut out,
        "dns_udp_recv_restarts_total",
        "UDP upstream receive loops restarted after socket errors",
        &[(&[], g.udp_recv_restarts)],
    );

    // Concurrency watermark: how close the server runs to its global inflight cap.
    let max_inflight = state.cfg.max_inflight;
    let in_use = max_inflight.saturating_sub(state.limit.available_permits());
    write_gauge(
        &mut out,
        "dns_inflight_current",
        "Queries currently being processed (global semaphore permits in use)",
        in_use as u64,
    );
    write_gauge(
        &mut out,
        "dns_inflight_limit",
        "Configured max-inflight limit",
        max_inflight as u64,
    );

    let ql = stats::query_latency_snapshot();
    write_query_latency_histogram(&mut out, &ql);

    // Per-upstream node stats.

    let mut all_nodes: Vec<NodeStatsSnapshot> = Vec::new();
    for g in &state.groups {
        if let Some(pool) = &g.upstream {
            collect_pool_nodes(&mut all_nodes, pool, &format!("group-{}", g.name));
        }
    }

    if !all_nodes.is_empty() {
        write_upstream_counters(&mut out, &all_nodes);
        write_upstream_rtt_histogram(&mut out, &all_nodes);
        write_upstream_inflight(&mut out, &all_nodes);
    }

    out
}

fn collect_pool_nodes(
    out: &mut Vec<NodeStatsSnapshot>,
    pool: &crate::upstream::UpstreamPool,
    prefix: &str,
) {
    for snap in pool.node_snapshots(prefix) {
        out.push(snap);
    }
}

// Low-level Prometheus text format helpers.

fn write_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    out.push_str(&format!("{name} {value}\n"));
}

fn write_counter(out: &mut String, name: &str, help: &str, rows: &[(&[(&str, &str)], u64)]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for (labels, value) in rows {
        out.push_str(name);
        if !labels.is_empty() {
            out.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!("{k}=\"{v}\""));
            }
            out.push('}');
        }
        out.push_str(&format!(" {value}\n"));
    }
}

fn write_upstream_counters(out: &mut String, nodes: &[NodeStatsSnapshot]) {
    let name = "dns_upstream_queries_total";
    out.push_str(&format!("# HELP {name} Upstream DNS query outcomes\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for n in nodes {
        out.push_str(&format!(
            "{name}{{upstream=\"{}\",result=\"ok\"}} {}\n",
            n.name, n.queries_ok
        ));
        out.push_str(&format!(
            "{name}{{upstream=\"{}\",result=\"err\"}} {}\n",
            n.name, n.queries_err
        ));
    }

    // Timeout is a subset of err; expose separately so callers can compute
    // non-timeout error rates.  Only render when hedging has been active
    // (i.e. at least one node has recorded a timeout or cancellation).
    let any_detail = nodes
        .iter()
        .any(|n| n.queries_timeout > 0 || n.queries_cancelled > 0);
    if any_detail {
        let tname = "dns_upstream_timeouts_total";
        out.push_str(&format!(
            "# HELP {tname} Upstream queries that ended in a timeout (subset of err)\n"
        ));
        out.push_str(&format!("# TYPE {tname} counter\n"));
        for n in nodes {
            out.push_str(&format!(
                "{tname}{{upstream=\"{}\"}} {}\n",
                n.name, n.queries_timeout
            ));
        }

        let cname = "dns_upstream_cancelled_total";
        out.push_str(&format!(
            "# HELP {cname} In-flight upstream queries cancelled because a hedge partner responded first\n"
        ));
        out.push_str(&format!("# TYPE {cname} counter\n"));
        for n in nodes {
            out.push_str(&format!(
                "{cname}{{upstream=\"{}\"}} {}\n",
                n.name, n.queries_cancelled
            ));
        }
    }
}

fn write_upstream_inflight(out: &mut String, nodes: &[NodeStatsSnapshot]) {
    let name = "dns_upstream_active_inflight";
    out.push_str(&format!(
        "# HELP {name} Currently in-flight queries per upstream node\n"
    ));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    for n in nodes {
        out.push_str(&format!(
            "{name}{{upstream=\"{}\"}} {}\n",
            n.name, n.active_inflight
        ));
    }
}

fn write_query_latency_histogram(out: &mut String, ql: &QueryLatencySnapshot) {
    let name = "dns_query_latency_seconds";
    out.push_str(&format!(
        "# HELP {name} End-to-end latency for slow-path (cache-miss) DNS queries\n"
    ));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    write_histogram_series(out, name, None, &ql.hist, ql.count, ql.sum_us);
}

fn write_upstream_rtt_histogram(out: &mut String, nodes: &[NodeStatsSnapshot]) {
    let name = "dns_upstream_rtt_seconds";
    out.push_str(&format!("# HELP {name} Upstream DNS query RTT histogram\n"));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for n in nodes {
        write_histogram_series(out, name, Some(&n.name), &n.rtt_hist, n.rtt_count(), n.rtt_sum_us);
    }
}

/// Render one Prometheus histogram series (buckets + _count + _sum).
/// `upstream` adds an `upstream="<name>"` label to every line when Some.
fn write_histogram_series(
    out: &mut String,
    name: &str,
    upstream: Option<&str>,
    hist: &[u64; RTT_BUCKETS],
    count: u64,
    sum_us: u64,
) {
    // Prepended inside bucket label set before "le=...": "" or "upstream=\"foo\","
    let bucket_prefix = upstream.map_or_else(String::new, |u| format!("upstream=\"{u}\","));
    // Appended after metric name for _count/_sum: "" or "{upstream=\"foo\"}"
    let outer_labels = upstream.map_or_else(String::new, |u| format!("{{upstream=\"{u}\"}}"));

    let mut cumulative = 0u64;
    for (i, &bound_us) in RTT_BUCKET_BOUNDS_US.iter().enumerate() {
        cumulative += hist[i];
        let bound_s = bound_us as f64 / 1_000_000.0;
        out.push_str(&format!(
            "{name}_bucket{{{bucket_prefix}le=\"{bound_s:.6}\"}} {cumulative}\n"
        ));
    }
    cumulative += hist[RTT_BUCKETS - 1];
    out.push_str(&format!(
        "{name}_bucket{{{bucket_prefix}le=\"+Inf\"}} {cumulative}\n"
    ));
    out.push_str(&format!("{name}_count{outer_labels} {count}\n"));
    let sum_s = sum_us as f64 / 1_000_000.0;
    out.push_str(&format!("{name}_sum{outer_labels} {sum_s:.6}\n"));
}
