# PathDNS

A policy-based DNS forwarder for split-horizon deployments. Routes queries to different upstream resolvers based on GeoSite domain classification and custom group rules, with optional ipset/nftset integration for IP-based routing decisions.

Runs on Linux. UDP and TCP listeners with automatic `SO_REUSEPORT` sharding.

---

## Features

- UDP and TCP DNS listeners with automatic `SO_REUSEPORT` sharding.
- Named routing groups, each with their own GeoSite matchers and upstream resolvers.
- Configurable fallback for unmatched queries: route to a group, race two groups, or return empty.
- IP-based primary/secondary selection: race two upstreams and test response IPs against an ipset/nftset to pick the winner.
- GeoSite domain classification using V2Ray/Xray `.dat` or `.json` files (full, suffix, keyword, regexp matchers). Only referenced tags are loaded.
- Encrypted transports: `tls://` (DoT), `https://` (DoH/HTTP1.1), `quic://` (DoQ, RFC 9250), `h3://` (DoH/HTTP3).
- Persistent mux connections for TCP/TLS upstreams with automatic reconnect.
- DNS cache with TTL patching, stale-while-revalidate, optional background refresh, and optional disk persistence across restarts.
- Singleflight deduplication: concurrent identical cache-miss queries share one upstream request.
- Graceful rate limiting: configurable per-query queue timeout before shedding with SERVFAIL when `max-inflight` is full.
- Per-domain verdict cache for `fallback.default-group: none` routing decisions.
- Query type filtering with optional group and GeoSite tag conditions.
- Native Linux netlink backend for ipset/nftset test and add operations (no shell-out).
- Per-upstream hedged requests: fire a second upstream after a configurable delay.
- Prometheus metrics endpoint.
- Silent in normal operation; `-v` enables full diagnostic logging.

---

## Build

```sh
# Standard build
cargo build --release

# With DNS-over-QUIC support (quic:// upstreams)
cargo build --release --features doq

# With DNS-over-HTTP/3 support (h3:// upstreams; also enables doq)
cargo build --release --features h3

# Static musl binary (OpenWrt / minimal environments)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Cross-compile from Windows

Requires LLVM-MinGW (`ld.lld.exe` in PATH) and the `x86_64-unknown-linux-musl` Rust target:

```sh
cargo +stable-x86_64-pc-windows-gnu build --release --target x86_64-unknown-linux-musl
```

Produces a static ELF binary (~1.5 MB).

---

## CLI

```
pathdns -c <config.json> [-v] [-h]
```

| Flag | Description |
|------|-------------|
| `-c <FILE>` | Path to JSON config file (required) |
| `-v` | Enable verbose/diagnostic logging |
| `-h` | Print help and exit |

All configuration is done via the JSON file. There are no other CLI flags.

---

## Configuration

PathDNS reads a JSON file passed with `-c`. Unknown top-level keys cause a startup error.

### Minimal example

```json
{
  "bind": "0.0.0.0:53",
  "group": [
    { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
    { "name": "overseas", "tag": ["!cn"], "upstream": ["tcp://1.1.1.1"] }
  ],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "fallback": { "default-group": "domestic" },
  "cache": { "size": 10000 }
}
```

### Example with ipset-based primary/secondary routing

```json
{
  "bind": "0.0.0.0:53",
  "group": [
    {
      "name": "domestic",
      "tag": ["cn"],
      "upstream": ["119.29.29.29"],
      "add-ip": "mainroute,mainroute6"
    },
    {
      "name": "overseas",
      "tag": ["!cn"],
      "upstream": ["tcp://1.1.1.1"]
    }
  ],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "fallback": {
    "default-group": "none",
    "primary":       "domestic",
    "secondary":     "overseas",
    "ipset-name4":   "mainroute",
    "ipset-name6":   "mainroute6"
  },
  "cache": { "size": 10000 },
  "verdict-cache": { "size": 4096 }
}
```

---

## All Config Keys

### Top-level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind` | string | `"127.0.0.1:65353"` | Listen address. Append `@udp` or `@tcp` to restrict protocol. |
| `worker-threads` | int | CPU count | Tokio worker thread count and number of `SO_REUSEPORT` sockets. |
| `max-inflight` | int | `worker-threads × 1024` | Max concurrent in-flight client queries. |
| `inflight-queue-ms` | int (ms) | `0` | When > 0, queries that exceed `max-inflight` wait up to N ms for a slot before being shed with SERVFAIL. `0` = hard-drop immediately. |
| `upstream-max-inflight` | int | `256` | Per-upstream in-flight query limit. |
| `timeout-ms` | int (ms) | `5000` | Upstream query timeout. |
| `udp-buf-size` | int | `4096` | UDP receive buffer size per socket (bytes). |
| `upstream-udp-sockets` | int | CPU count | UDP socket pool size per upstream node. |
| `hedge-delay-ms` | int (ms) | `0` (disabled) | Fire a second upstream after N ms with no reply. |
| `verbose` | bool | `false` | Enable diagnostic logging (same as `-v`). |
| `metrics-addr` | string | — | Prometheus scrape address (e.g. `"0.0.0.0:9153"`). |
| `geosite-file` | string array | — | GeoSite `.dat` or `.json` files. Required when any group uses `tag`. |
| `no-ipset-blacklist` | bool | `false` | Allow loopback/unspecified IPs in ipset add operations. |
| `group` | array | — | Routing groups (see [Groups](#groups)). |
| `fallback` | object | — | Fallback for unmatched queries (see [Fallback](#fallback)). Required. |
| `cache` | object | — | DNS cache settings (see [Cache](#cache)). |
| `verdict-cache` | object | — | Per-domain verdict cache for `none` fallback (see [Verdict Cache](#verdict-cache)). |

### Groups

Groups are matched top-to-bottom. The first group whose GeoSite tags match the query name wins.

```json
"group": [
  {
    "name":     "domestic",
    "tag":      ["cn"],
    "upstream": ["119.29.29.29", "223.5.5.5"],
    "add-ip":   "chnroute,chnroute6"
  },
  {
    "name":        "overseas",
    "tag":         ["!cn"],
    "upstream":    ["tls://1.1.1.1"],
    "cache":       { "size": 0 },
    "filter-qtype": 65
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique group name. Use `"null"` to return empty responses (no `upstream` needed). |
| `tag` | string array | GeoSite tag expressions. `"TAG"` includes, `"!TAG"` excludes. |
| `upstream` | string array | Upstream resolvers for this group (see [Upstream URLs](#upstream-urls)). |
| `add-ip` | string | `"v4set,v6set"` — add resolved IPs to these ipset/nftset sets. |
| `cache` | object | Per-group cache overrides (see [Group-level cache overrides](#group-level-cache-overrides)). |
| `filter-qtype` | int or int array | Drop queries of the given QTYPE(s) for this group (values 0–65535; e.g. `28` drops AAAA, `65` drops HTTPS). |

**Tag matching rules:**
- A domain matches a group if it appears in any included tag.
- `!TAG` excludes: a domain in the excluded tag is never routed to this group regardless of other rules.
- A group with no positive tags matches all domains not excluded — useful for catch-all groups.

### Fallback

Applied when no group matches a query.

```json
"fallback": { "default-group": "domestic" }
```

| `default-group` value | Behavior |
|-----------------------|----------|
| `"<group-name>"` | Route to the named group. |
| `"none"` | Race `primary` and `secondary`; use ipset to pick the winner if configured, otherwise return the first response. |
| `"null"` | Return an empty response. |

**Fields for `"none"` fallback:**

| Field | Type | Description |
|-------|------|-------------|
| `primary` | string | Primary group name (required when `default-group` is `"none"`). |
| `secondary` | string | Secondary group name (required when `default-group` is `"none"`). |
| `ipset-name4` | string | IPv4 ipset/nftset for testing primary response IPs. |
| `ipset-name6` | string | IPv6 ipset/nftset for testing primary response IPs. |
| `noip-as-primary-ip` | bool | Treat NODATA primary replies as primary IPs (default: `false`). |

Without `ipset-name4`/`ipset-name6`, the `"none"` fallback races both upstreams and returns the first non-SERVFAIL response.

### Cache

```json
"cache": {
  "size":                    10000,
  "stale-expire-ttl":        86400,
  "stale-ttl":               30,
  "stale-ttl-reset":         true,
  "stale-client-timeout-ms": 0,
  "nodata-ttl":              60,
  "min-ttl":                 0,
  "max-ttl":                 0,
  "refresh":                 20,
  "refresh-min-ttl":         0,
  "persist": {
    "path":     "/etc/pathdns/cache.db",
    "interval": 300
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | `10000` | Cache capacity in entries (`0` disables). |
| `stale-expire-ttl` | int (seconds) | `0` | Serve stale entries for up to N seconds after TTL expiry (RFC 8767). `0` disables stale serving. |
| `stale-ttl` | int (seconds) | `30` | TTL advertised in stale replies. |
| `stale-ttl-reset` | bool | `true` | When `true`, stale replies always use `stale-ttl`. When `false`, advertise the actual remaining stale window. |
| `stale-client-timeout-ms` | int (ms) | `0` | When > 0 and a stale entry exists, wait up to N ms for a fresh upstream answer before falling back to the stale reply. `0` disables (serve stale immediately). |
| `nodata-ttl` | int (seconds) | `60` | TTL for NODATA/NXDOMAIN responses with no SOA record. |
| `min-ttl` | int (seconds) | `0` | Minimum TTL applied at write time (cache insertion). |
| `max-ttl` | int (seconds) | `0` | Maximum TTL applied at write time (`0` = no cap). |
| `refresh` | int (percent) | — | Trigger background refresh when remaining TTL ≤ N% of original TTL. |
| `refresh-min-ttl` | int (seconds) | `0` | Trigger background refresh when remaining TTL ≤ N seconds. Complements `refresh`. |
| `persist.path` | string | — | File path for cache persistence. |
| `persist.interval` | int (seconds) | `0` | Save cache to disk every N seconds. `0` saves only on shutdown. |

Concurrent cache-miss queries for the same question share one upstream request (singleflight). With `persist` configured, the cache is saved to disk on shutdown (and periodically if `interval > 0`) and restored on startup, surviving restarts with warm entries. On load, a config fingerprint is compared against the stored value; if the routing-relevant configuration has changed (groups, tags, filter-qtype, cache policies, GeoSite file paths), the persisted cache is discarded rather than served with stale routing assumptions.

### Group-level cache overrides

A group's `cache` key overrides per-entry behaviour for responses routed to that group. Only the 7 fields below may be set; instance-wide settings (`persist`, `stale-client-timeout-ms`, `refresh-min-ttl`, `stale-ttl-reset`) are not accepted.

| Field | Type | Description |
|-------|------|-------------|
| `size` | int | Only `0` is accepted — disables caching for this group. Cannot be combined with other fields. |
| `stale-expire-ttl` | int (seconds) | Override stale serving window. |
| `stale-ttl` | int (seconds) | Override stale reply TTL. |
| `nodata-ttl` | int (seconds) | Override NODATA/NXDOMAIN TTL. |
| `min-ttl` | int (seconds) | Override minimum TTL at write time. Must not exceed `max-ttl`. |
| `max-ttl` | int (seconds) | Override maximum TTL at write time. |
| `refresh` | int (0–100) | Override background refresh threshold (percent). |

Example: disable caching for the overseas group:
```json
{ "name": "overseas", "upstream": ["tls://1.1.1.1"], "cache": { "size": 0 } }
```

### Verdict Cache

Caches primary/secondary routing decisions for the `"none"` fallback to avoid repeated ipset lookups.

```json
"verdict-cache": { "size": 4096, "ttl": 3600 }
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | — | Capacity in entries (`0` disables). |
| `ttl` | int (seconds) | `0` (no expiry) | Per-entry TTL. |

---

## Upstream URLs

| URL form | Protocol |
|----------|----------|
| `1.1.1.1` | UDP + TCP (both created) |
| `udp://1.1.1.1` | UDP only |
| `udp://1.1.1.1:5353` | UDP on custom port |
| `tcp://1.1.1.1` | TCP (persistent mux connection) |
| `tls://1.1.1.1` | DNS-over-TLS (RFC 7858) |
| `tls://1.1.1.1?sni=dns.example` | DoT with explicit SNI |
| `https://8.8.8.8/dns-query` | DNS-over-HTTPS (HTTP/1.1) |
| `quic://dns.adguard.com` | DNS-over-QUIC (requires `--features doq`) |
| `h3://dns.cloudflare.com/dns-query` | DoH over HTTP/3 (requires `--features h3`) |

**ECS mode** (per-upstream, via query parameter):

| Parameter | Effect |
|-----------|--------|
| `?ecs=strip` | Remove EDNS Client Subnet before forwarding (default) |
| `?ecs=forward` | Forward ECS unchanged |
| `?ecs=1.2.3.0/24` | Replace ECS with a fixed subnet |

---

## Filtering

Drop queries by type for a specific group using the per-group `filter-qtype` field. Accepts a single QTYPE integer or an array of integers (values 0–65535).

```json
{ "name": "overseas", "upstream": ["tls://1.1.1.1"], "filter-qtype": [28, 65] }
```

Common type numbers: `1` = A, `28` = AAAA, `65` = HTTPS.

---

## ipset / nftset

Uses native Linux netlink — no shell-out to `ipset` or `nft`.

**Test sets** (for `"none"` fallback routing) are configured in `fallback.ipset-name4` / `fallback.ipset-name6`.

**Add sets** (populate with resolved IPs) are configured per-group with `add-ip: "v4set,v6set"`.

nftset names use `family@table@set` syntax (e.g. `inet@fw4@chnroute`). IP additions are queued and batched asynchronously in a background thread.

Loopback and unspecified IPs are excluded from add operations by default. Use `"no-ipset-blacklist": true` to allow them.

---

## GeoSite Files

Pass `.dat` (V2Ray/Xray binary protobuf) or `.json` files. Multiple files are merged; duplicate tags accumulate domains.

Only tags referenced in `group[].tag` are parsed — the full database is never loaded.

GeoSite files are watched for changes and hot-reloaded automatically.

**Note on `!` in tag names:** Tags like `geolocation-!cn` contain `!` which bash treats as a history expansion trigger in interactive shells. In a JSON config file no quoting is needed. On the command line (if passing tags as arguments), use single quotes.

**Supported matcher types:**

| `.dat` type | `.json` prefix | Behavior |
|-------------|----------------|----------|
| `RootDomain` | `domain:` or bare | Suffix match: domain and all subdomains |
| `Full` | `full:` | Exact match only |
| `Plain` | `keyword:` | Substring match |
| `Regex` | `regexp:` | Regular expression match |

---

## Example Configurations

### GeoSite split — two groups, fallback to domestic

```json
{
  "bind": "0.0.0.0:53",
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "group": [
    { "name": "domestic", "tag": ["cn"],           "upstream": ["223.5.5.5"] },
    { "name": "overseas", "tag": ["geolocation-!cn"], "upstream": ["tls://1.1.1.1"] }
  ],
  "fallback": { "default-group": "domestic" },
  "cache": { "size": 10000, "stale-expire-ttl": 86400, "refresh": 20 }
}
```

### ipset-based primary/secondary for unmatched domains

```json
{
  "bind": "0.0.0.0:53",
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "group": [
    {
      "name": "domestic",
      "tag":  ["cn"],
      "upstream": ["223.5.5.5"],
      "add-ip": "chnroute,chnroute6"
    },
    {
      "name": "overseas",
      "tag":  ["geolocation-!cn"],
      "upstream": ["tls://1.1.1.1"]
    }
  ],
  "fallback": {
    "default-group": "none",
    "primary":       "domestic",
    "secondary":     "overseas",
    "ipset-name4":   "chnroute",
    "ipset-name6":   "chnroute6"
  },
  "cache": { "size": 10000, "stale-expire-ttl": 86400, "refresh": 20 },
  "verdict-cache": { "size": 4096 }
}
```

### Block a domain category (null group)

```json
{
  "bind": "0.0.0.0:53",
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "group": [
    { "name": "null",     "tag": ["category-ads-all"] },
    { "name": "domestic", "tag": ["cn"],               "upstream": ["223.5.5.5"] },
    { "name": "overseas", "tag": ["geolocation-!cn"],  "upstream": ["tls://1.1.1.1"] }
  ],
  "fallback": { "default-group": "domestic" },
  "cache": { "size": 10000 }
}
```

### Block AAAA queries

Use `filter-qtype` inside the group definition:

```json
{
  "bind": "127.0.0.1:53",
  "group": [
    { "name": "default", "upstream": ["223.5.5.5"], "filter-qtype": 28 }
  ],
  "fallback": { "default-group": "default" },
  "cache": { "size": 10000 }
}
```

### Multiple GeoSite files

Tags from multiple files are merged:

```json
{
  "geosite-file": ["/etc/pathdns/geosite.dat", "/etc/pathdns/custom.json"],
  "group": [
    { "name": "domestic", "tag": ["cn", "private"], "upstream": ["223.5.5.5"] }
  ],
  "fallback": { "default-group": "domestic" }
}
```

### DoH upstream with ECS stripping

```json
{
  "group": [
    { "name": "default", "upstream": ["https://8.8.8.8/dns-query?ecs=strip"] }
  ],
  "fallback": { "default-group": "default" }
}
```

---

## Prometheus Metrics

Enable with `"metrics-addr": "0.0.0.0:9153"`.

| Metric | Type | Description |
|--------|------|-------------|
| `dns_queries_total{proto}` | counter | Queries received (udp/tcp) |
| `dns_cache_lookups_total{result}` | counter | Cache hits / misses / stale |
| `dns_cache_refresh_total{result}` | counter | Background refresh outcomes |
| `dns_singleflight_hits_total` | counter | Deduplicated in-flight queries |
| `dns_inflight_total{result}` | counter | Queries that hit `max-inflight`: `result="queued"` waited in queue; `result="dropped"` were shed with SERVFAIL |
| `dns_queries_routed_total{target}` | counter | Routing decisions (none_race / null / group / aaaa_filtered) |
| `dns_query_latency_seconds` | histogram | End-to-end slow-path latency |
| `dns_upstream_queries_total{upstream,result}` | counter | Per-upstream ok/err counts |
| `dns_upstream_rtt_seconds{upstream}` | histogram | Per-upstream RTT |
| `dns_upstream_active_inflight{upstream}` | gauge | In-flight queries per upstream |
| `dns_geosite_reloads_total{result}` | counter | GeoSite hot-reload outcomes |

---

## Performance Design

**UDP fast path:** Cache hits and filter hits are processed inline without spawning a Tokio task. Only cache misses spawn a task. The receive buffer is handed off to the task via a single `BytesMut → Bytes` freeze (no copy); the loop immediately reuses a fresh buffer.

**SO_REUSEPORT sharding:** `worker-threads` sockets are bound at startup. The kernel distributes packets and connections across them with no central lock.

**Upstream node selection:** `UpstreamPool::exchange` scores nodes by `EWMA_RTT × (1 + active_inflight)` and selects the lowest-score node. A periodic probe forces the least-recently-used healthy node to be tried so slow-but-healthy nodes are re-measured. Penalised nodes (≥ 3 consecutive failures) are skipped on the first pass and used as fallback only.

**Singleflight:** Concurrent cache-miss queries for the same question share one upstream request via a `tokio::sync::watch` channel. Followers receive the leader's response with no additional upstream traffic.

**Single-pass TTL scanner:** `effective_ttl_and_offsets` walks all DNS resource records once, collecting TTL patch offsets and extracting `min(SOA_TTL, SOA_MINIMUM)` for NODATA/NXDOMAIN caching in the same pass.

---

## License

MIT
