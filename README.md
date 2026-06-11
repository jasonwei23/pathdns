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
- Encrypted transports: `tls://` (DoT), `https://` (DoH, HTTP/2 via ALPN), `quic://` (DoQ, RFC 9250), `h3://` (DoH/HTTP3).
- Persistent mux connections for TCP/TLS upstreams with automatic reconnect.
- DNS cache with per-RR independent TTL countdown, negative TTL capping (RFC 2308 §5), stale-while-revalidate, optional background refresh, and optional disk persistence across restarts.
- EDNS-aware cache isolation: responses are keyed by EDNS variant (DO bit, EDNS version, ECS subnet) so DO=0 and DO=1 clients never share cache entries. When an upstream uses `ecs=strip`, all clients share one cache entry regardless of their ECS subnet (ECS-normalized cache key).
- DNS 0x20 QNAME case randomization: outgoing queries apply random per-letter capitalisation to the QNAME and verify the server echoes the same case back, adding ~16 bits of entropy against cache-poisoning attacks.
- Upstream response size cap: configurable per-byte limit rejects oversized TCP/TLS frames before they reach the cache.
- TCP connection limit and per-frame read timeouts guard against slowloris-style attacks.
- Singleflight deduplication: concurrent identical cache-miss queries share one upstream request.
- Graceful rate limiting: configurable per-query queue timeout before shedding with SERVFAIL when `max-inflight` is full.
- Per-domain verdict cache for racing-fallback routing decisions.
- Query type filtering with optional group and GeoSite tag conditions.
- Native Linux netlink backend for ipset/nftset test and add operations (no shell-out).
- Per-upstream hedged requests: fire a second upstream after a configurable delay.
- Native query log subsystem: per-query structured events through a bounded non-blocking channel, in-memory ring buffer, optional rotating MessagePack files with gzip compression and age-based retention, and an authenticated HTTP API with a built-in dashboard.
- Always-on lock-free counters with negligible hot-path overhead; detailed event collection is opt-in.
- Operational statistics are exposed only through the built-in dashboard/API; there is no verbose per-query stderr mode or separate metrics endpoint.

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
pathdns -c <config.json> [-h]
```

| Flag | Description |
|------|-------------|
| `-c <FILE>` | Path to JSON config file (required) |
| `-h` | Print help and exit |

All configuration is done via the JSON file. There are no other CLI flags.

---

## Configuration

PathDNS reads a JSON file passed with `-c`. Unknown top-level keys cause a startup error.

### Minimal example

```json
{
  "bind": ["0.0.0.0:53", "[::]:53"],
  "group": [
    { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
    { "name": "overseas", "tag": ["!cn"], "upstream": ["tcp://1.1.1.1"] }
  ],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "fallback": "domestic",
  "cache": { "size": 10000 }
}
```

### Example with ipset-based primary/secondary routing

```json
{
  "bind": ["0.0.0.0:53", "[::]:53"],
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
| `bind` | string or array | `"127.0.0.1:65353"` | Listen address(es). Append `@udp` or `@tcp` to restrict protocol per address. **IPv6 sockets are v6-only**: `"0.0.0.0:53"` does not accept IPv6 and `"[::]:53"` does not accept IPv4 — for dual-stack use `["0.0.0.0:53", "[::]:53"]`. |
| `worker-threads` | int | CPU count | Tokio worker thread count and number of `SO_REUSEPORT` sockets. |
| `max-inflight` | int | `worker-threads × 1024` | Max concurrent in-flight client queries. |
| `inflight-queue-ms` | int (ms) | `0` | When > 0, queries that exceed `max-inflight` wait up to N ms for a slot before being shed with SERVFAIL. `0` = hard-drop immediately. |
| `upstream-max-inflight` | int | `256` | Per-upstream in-flight query limit. |
| `timeout-ms` | int (ms) | `3000` | Upstream query timeout. |
| `udp-buf-size` | int | `4096` | UDP receive buffer size per socket (bytes). |
| `upstream-udp-sockets` | int | `max(worker-threads, 32)` | UDP socket pool size per upstream node. Higher values improve source-port randomness (RFC 5452). |
| `upstream-max-response-bytes` | int | `0` | Reject TCP/TLS upstream responses larger than this (bytes). `0` = no limit. |
| `hedge-delay-ms` | int (ms) | `0` (disabled) | Fire a second upstream after N ms with no reply. |
| `tcp-max-connections` | int | `1024` | Maximum concurrent inbound TCP client connections. `0` = unlimited. |
| `tcp-read-timeout-ms` | int (ms) | `5000` | Timeout for reading the DNS message body after the 2-byte length prefix. `0` = disabled. |
| `tcp-idle-timeout-ms` | int (ms) | `30000` | Timeout for waiting for the next request on an idle TCP connection. `0` = disabled. |
| `querylog` | object | — | Query log / dashboard settings (see [Query Log](#query-log--dashboard)). |
| `geosite-file` | string array | — | GeoSite `.dat` or `.json` files. Required when any group uses `tag`. |
| `no-ipset-blacklist` | bool | `false` | Allow loopback/unspecified IPs in ipset add operations. |
| `group` | array | — | Routing groups (see [Groups](#groups)). |
| `fallback` | string or object | — | Fallback for unmatched queries (see [Fallback](#fallback)). Required. |
| `cache` | object | — | DNS cache settings (see [Cache](#cache)). |
| `verdict-cache` | object | — | Per-domain verdict cache for racing fallback (see [Verdict Cache](#verdict-cache)). |

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

Applied when no group matches a query. Three forms:

```json
"fallback": "domestic"
```
Route unmatched queries to the named group. `"fallback": "null"` returns empty responses instead.

```json
"fallback": {
  "primary":     "domestic",
  "secondary":   "overseas",
  "ipset-name4": "chnroute",
  "ipset-name6": "chnroute6"
}
```
Racing mode: query `primary` and `secondary` concurrently. With `ipset-name4`/`ipset-name6` configured, the primary response's IPs are tested against the ipset to pick the winner; without them, the first non-SERVFAIL response wins.

**Racing mode fields:**

| Field | Type | Description |
|-------|------|-------------|
| `primary` | string | Primary group name (required). |
| `secondary` | string | Secondary group name (required). |
| `ipset-name4` | string | IPv4 ipset/nftset for testing primary response IPs. |
| `ipset-name6` | string | IPv6 ipset/nftset for testing primary response IPs. |
| `noip-as-primary-ip` | bool | Treat NODATA primary replies as primary IPs (default: `false`). |

**Legacy form** (still accepted): `{"default-group": "<name>"}`, `{"default-group": "null"}`, and `{"default-group": "none", "primary": ..., "secondary": ...}` map to the forms above.

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

Caches primary/secondary routing decisions for the racing fallback to avoid repeated ipset lookups.

```json
"verdict-cache": { "size": 4096, "ttl": 3600 }
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | — | Capacity in entries (`0` disables). |
| `ttl` | int (seconds) | `0` (no expiry) | Per-entry TTL. |

### Query Log

Configures per-query event collection and the dashboard HTTP API. The section is optional; omit it entirely to keep only the always-on lock-free counters.

```json
"querylog": {
  "bind":    "0.0.0.0:8080",
  "token":   "your-secret-token",
  "memory":  1000,
  "channel": 4096,
  "answer-ips": false,
  "file": {
    "dir":              "/var/lib/pathdns/querylog",
    "max-mb":           8,
    "max-segments":     3,
    "batch-size":       256,
    "flush-interval-ms": 500,
    "retention-days":   30,
    "compress":         true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind` | string or array | — | Listen address(es) for the dashboard + HTTP API. Like the DNS `bind`, IPv6 sockets are v6-only — for dual-stack use `["0.0.0.0:8080", "[::]:8080"]`. Omit to disable the API. |
| `token` | string | — | Bearer token required on every API request (`Authorization: Bearer <token>`). When omitted, the API is unauthenticated — only safe on a trusted network. |
| `memory` | int | `1000` | In-memory ring buffer capacity. `0` disables the ring; file collection can still remain active. |
| `channel` | int | `4096` | Bounded mpsc channel depth between the DNS hot path and the log worker. When full, new events are dropped (non-blocking) rather than stalling queries. |
| `answer-ips` | bool | `false` | Extract A/AAAA answer IPs into detailed events. Disabled by default because it requires scanning each response. |
| `file.dir` | string | `"./querylog"` | Directory for rotating MessagePack segments. Created if missing. |
| `file.max-mb` | int (MB) | `8` | Rotate to a new segment when the current one reaches this size. |
| `file.max-segments` | int | `3` | Keep at most this many compressed segments; oldest are pruned. |
| `file.batch-size` | int | `256` | Maximum events to accumulate before one write call. Reduces syscall overhead at high query rates. |
| `file.flush-interval-ms` | int (ms) | `500` | How often the background worker flushes its write buffer to the OS. |
| `file.retention-days` | int | — | Delete compressed segments whose embedded timestamp is older than this many days. Applied in addition to `max-segments`. |
| `file.compress` | bool | `true` | Gzip-compress segments after rotation. Disabling saves CPU at the cost of larger on-disk files. |

Omitting the entire `querylog` section fully disables detailed event collection. When the section is present, event collection is enabled when `memory > 0` or a `file` section is present. The hot path reserves capacity in a bounded channel before constructing an event; if the channel is full, the event is dropped and the DNS response is unaffected. Serialisation and batched file writes are handled by the background worker — the DNS hot path never performs I/O.

**File format:** active segments are named `querylog-{timestamp}.msgpack` (a sequence of concatenated MessagePack maps, one per event). On rotation the segment is gzip-compressed to `querylog-{timestamp}.msgpack.gz` in a background thread-pool task so the worker never stalls.

Dashboard counters count each successfully parsed client query once at ingress. Internal cache refreshes are tracked separately and do not affect client QPS, query totals, average resolution time, or detailed client events.

Each event is a JSON object:

```json
{
  "seq": 12345,
  "time": "2026-06-10T08:21:33.123456Z",
  "client": "192.168.1.50",
  "client_port": 51234,
  "qname": "example.com",
  "qtype": 1,
  "rcode": 0,
  "elapsed_us": 1820,
  "response_bytes": 76,
  "source": "upstream",
  "group": "overseas",
  "answer_ips": ["93.184.216.34"]
}
```

`source` is one of `cache`, `stale`, `upstream`, `singleflight`, `filtered`, `overload`, or `null`.

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
| `https://8.8.8.8/dns-query` | DNS-over-HTTPS (HTTP/2 via ALPN, fallback to HTTP/1.1) |
| `quic://dns.adguard.com` | DNS-over-QUIC (requires `--features doq`) |
| `h3://dns.cloudflare.com/dns-query` | DoH over HTTP/3 (requires `--features h3`) |

**ECS mode** (per-upstream, via query parameter):

| Parameter | Effect |
|-----------|--------|
| `?ecs=strip` | Remove EDNS Client Subnet before forwarding (default). All clients share one cache entry regardless of their ECS subnet. |
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

**Test sets** (for racing fallback routing) are configured in `fallback.ipset-name4` / `fallback.ipset-name6`.

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
  "bind": ["0.0.0.0:53", "[::]:53"],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "group": [
    { "name": "domestic", "tag": ["cn"],           "upstream": ["223.5.5.5"] },
    { "name": "overseas", "tag": ["geolocation-!cn"], "upstream": ["tls://1.1.1.1"] }
  ],
  "fallback": "domestic",
  "cache": { "size": 10000, "stale-expire-ttl": 86400, "refresh": 20 }
}
```

### ipset-based primary/secondary for unmatched domains

```json
{
  "bind": ["0.0.0.0:53", "[::]:53"],
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
  "bind": ["0.0.0.0:53", "[::]:53"],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "group": [
    { "name": "null",     "tag": ["category-ads-all"] },
    { "name": "domestic", "tag": ["cn"],               "upstream": ["223.5.5.5"] },
    { "name": "overseas", "tag": ["geolocation-!cn"],  "upstream": ["tls://1.1.1.1"] }
  ],
  "fallback": "domestic",
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
  "fallback": "default",
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
  "fallback": "domestic"
}
```

### DoH upstream with ECS stripping

```json
{
  "group": [
    { "name": "default", "upstream": ["https://8.8.8.8/dns-query?ecs=strip"] }
  ],
  "fallback": "default"
}
```

---

## Query Log & Dashboard

Enable by adding a `querylog` section with a `bind` address (see [Query Log config](#query-log)). Browse to `http://<bind>/` for the built-in web dashboard, or query the JSON API directly.

When a token is configured, the dashboard HTML remains publicly loadable so its sign-in form can be displayed. All `/api/*` requests require `Authorization: Bearer <token>`.

| Method & path | Description |
|---------------|-------------|
| `GET /` | Single-page web dashboard: lifetime stat cards, a time-range selector (1 m / 5 m / 15 m / 1 h / 6 h / 24 h) showing windowed counters, a QPS chart, a routing groups table, a query log, and an upstream table. |
| `GET /api/stats` | Snapshot of counters: total queries, cache-hit rate, current QPS, average RTT, upstream ok/err, inflight drops, ring length. |
| `GET /api/stats/history?n=<N>` | Last `N` seconds of per-second QPS samples (max 3600). |
| `GET /api/stats/aggregate?seconds=<N>` | Aggregated counters over the last N seconds (1–86400). Returns total queries, cache hits/rate, upstream ok/err, null responses, stale served, filtered. Used by the dashboard time-range selector. |
| `GET /api/groups` | Routing groups in match order with their GeoSite tags (include/exclude), per-tag rule count, `filter-qtype`, and whether they have an upstream or are null groups. |
| `GET /api/querylog?limit=<L>&before_seq=<S>&q=<filter>` | Recent events from the in-memory ring, newest first. `before_seq` paginates older entries; `q` filters by qname substring. |
| `DELETE /api/querylog` | Clear the in-memory event ring. |
| `GET /api/querylog/files` | JSON array of available compressed historical segments with their names and sizes (`[{"name":"querylog-…msgpack.gz","size_bytes":…}]`). Returns `[]` when file logging is disabled. |
| `GET /api/querylog/history?file=<name>&limit=<L>&q=<filter>` | Decode a historical `.msgpack.gz` segment and return its events as JSON. `file` must be a name returned by `/api/querylog/files`; `limit` caps results (max 10 000); `q` filters by qname substring. Decoding runs in a background thread and does not block the DNS path. |
| `GET /api/upstreams` | Per-upstream-node stats: ok/err/timeout counts, active inflight, RTT. |

Example:

```sh
curl -H "Authorization: Bearer your-secret-token" http://127.0.0.1:8080/api/stats
```

---

## Performance Design

**UDP fast path:** Cache hits and filter hits are processed inline without spawning a Tokio task. Only cache misses spawn a task. The receive buffer is handed off to the task via a single `BytesMut → Bytes` freeze (no copy); the loop immediately reuses a fresh buffer.

**SO_REUSEPORT sharding:** `worker-threads` sockets are bound at startup. The kernel distributes packets and connections across them with no central lock.

**Upstream node selection:** `UpstreamPool::exchange` scores nodes by `EWMA_RTT × (1 + active_inflight)` and selects the lowest-score node. A periodic probe forces the least-recently-used healthy node to be tried so slow-but-healthy nodes are re-measured. Penalised nodes (≥ 3 consecutive failures) are skipped on the first pass and used as fallback only.

**Singleflight:** Concurrent cache-miss queries for the same question share one upstream request via a `tokio::sync::watch` channel. Followers receive the leader's response with no additional upstream traffic.

**Single-pass TTL scanner:** `effective_ttl_and_offsets` walks all DNS resource records once, collecting `(offset, clamped_rr_ttl)` pairs and extracting `min(SOA_TTL, SOA_MINIMUM)` for NODATA/NXDOMAIN (capped at 10 800 s per RFC 2308 §5) in the same pass. At serve time each RR is patched to its own `original_ttl − elapsed` countdown rather than a shared minimum.

---

## License

MIT
