# PathDNS

A policy-based DNS forwarder for split-horizon deployments. Routes queries to different upstream resolvers based on GeoSite domain classification and custom group rules, with optional ipset/nftset integration for IP-based routing decisions.

Runs on Linux.

---

## What makes it different

- **GeoSite routing** — named groups each with their own GeoSite tag matchers and upstream resolvers; top-to-bottom match order.
- **ipset-test fallback** — for unmatched domains, races two upstreams and decides which answer to use by testing response IPs against an ipset/nftset. The decision is policy-based (IP membership), not speed-based.
- **EDNS-aware cache isolation** — DO bit and ECS subnet are part of the cache key. When an upstream uses `ecs=strip`, all clients share one entry regardless of subnet.
- **DNS 0x20 randomization** — outgoing queries apply random per-letter capitalisation to the QNAME and reject responses that don't echo it back (~16 bits of anti-poisoning entropy).
- **Verdict cache** — caches per-domain routing decisions for the racing fallback to avoid repeated ipset lookups.
- **Encrypted upstreams** — DoT (`tls://`), DoH (`https://`), DoQ (`quic://`, `--features doq`), DoH3 (`h3://`, `--features h3`).
- **Stale-while-revalidate** — configurable serve-stale window (RFC 8767) with optional background refresh, per-RR independent TTL countdown.
- **Hot-reload** — GeoSite files and routing config are watched and reloaded without restart.
- **Batch UDP I/O** (Linux) — `recvmmsg`/`sendmmsg` process up to 32 packets per syscall pair.
- **Built-in dashboard** — authenticated HTTP API and single-page web UI with live QPS chart, counter cards, query log, and upstream stats.

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

---

## CLI

```
pathdns -c <config.json>
```

All configuration is done via the JSON file.

---

## Configuration

### Minimal example

```json
{
  "bind": ["0.0.0.0:53", "[::]:53"],
  "group": [
    { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
    { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://1.1.1.1"] }
  ],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "fallback": "domestic",
  "cache": { "size": 10000 }
}
```

### ipset-based primary/secondary routing

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
    { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://1.1.1.1"] }
  ],
  "geosite-file": ["/etc/pathdns/geosite.dat"],
  "fallback": {
    "primary":     "domestic",
    "secondary":   "overseas",
    "ipset-name4": "mainroute",
    "ipset-name6": "mainroute6"
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
| `bind` | string or array | `"127.0.0.1:65353"` | Listen address(es). Append `@udp` or `@tcp` to restrict protocol per address. IPv6 sockets are v6-only; for dual-stack use `["0.0.0.0:53", "[::]:53"]`. |
| `worker-threads` | int | CPU count | Tokio worker thread count and number of `SO_REUSEPORT` sockets. |
| `max-inflight` | int | `worker-threads × 1024` | Max concurrent in-flight client queries. |
| `inflight-queue-ms` | int (ms) | `0` | When > 0, queries that exceed `max-inflight` wait up to N ms for a slot before being shed with SERVFAIL. `0` = hard-drop immediately. |
| `upstream-max-inflight` | int | `256` | Per-upstream in-flight query limit. |
| `timeout-ms` | int (ms) | `3000` | Upstream query timeout. |
| `udp-buf-size` | int | `4194304` | SO_RCVBUF/SO_SNDBUF size per UDP socket (bytes). |
| `udp-batch-size` | int | `32` | Packets per `recvmmsg`/`sendmmsg` call (Linux only; max 64). Hot-reloadable. |
| `upstream-udp-sockets` | int | `max(worker-threads, 32)` | UDP socket pool size per upstream node. |
| `upstream-max-response-bytes` | int | `0` | Reject TCP/TLS upstream responses larger than this. `0` = no limit. |
| `hedge-delay-ms` | int (ms) | `0` | Fire a second upstream after N ms with no reply. `0` = disabled. |
| `tcp-max-connections` | int | `1024` | Maximum concurrent inbound TCP connections. `0` = unlimited. |
| `tcp-read-timeout-ms` | int (ms) | `5000` | Timeout for reading the DNS message body. `0` = disabled. |
| `tcp-idle-timeout-ms` | int (ms) | `30000` | Idle TCP connection timeout. `0` = disabled. |
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
    "name":         "overseas",
    "tag":          ["!cn"],
    "upstream":     ["tls://1.1.1.1"],
    "cache":        { "size": 0 },
    "filter-qtype": 65
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique group name. |
| `tag` | string array | GeoSite tag expressions. `"TAG"` includes, `"!TAG"` excludes. |
| `upstream` | string array | Upstream resolvers (see [Upstream URLs](#upstream-urls)). Omit to return a fixed response without querying any upstream. |
| `add-ip` | string | `"v4set,v6set"` — add resolved IPs to these ipset/nftset sets. |
| `cache` | object | Per-group cache overrides (see [Group-level cache overrides](#group-level-cache-overrides)). |
| `filter-qtype` | int or int array | Drop queries of the given QTYPE(s) for this group (e.g. `28` = AAAA, `65` = HTTPS). |

**Tag matching:** a domain matches a group if it appears in any included tag and none of the excluded tags. A group with no positive tags matches everything not otherwise excluded — use this for catch-all groups.

### Fallback

Applied when no group matches. Three forms:

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
**Ipset-test mode** — the winner is decided by ipset membership, not speed:

1. Both groups are queried concurrently.
2. The primary's answer IPs are tested against the configured ipset/nftset.
3. IPs in the set → return primary's answer. IPs not in the set → return secondary's answer.
4. The verdict is cached per domain (see [Verdict Cache](#verdict-cache)); subsequent queries go straight to the winning group.

Non-A/AAAA queries fall back to the first non-SERVFAIL answer.

| Field | Type | Description |
|-------|------|-------------|
| `primary` | string | Group preferred when its answer IPs are in the ipset (required). |
| `secondary` | string | Group used when the primary's IPs are not in the ipset (required). |
| `ipset-name4` | string | IPv4 ipset/nftset to test primary's IPs against. At least one of the two is required. |
| `ipset-name6` | string | IPv6 ipset/nftset to test primary's IPs against. |
| `noip-as-primary-ip` | bool | Treat NODATA primary replies as if their IPs were in the set (default: `false`). |

### Cache

```json
"cache": {
  "size":                    10000,
  "stale-expire-ttl":        86400,
  "stale-ttl":               30,
  "stale-ttl-reset":         true,
  "stale-client-timeout-ms": 1800,
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
| `stale-expire-ttl` | int (s) | `0` | Serve stale entries for up to N seconds after TTL expiry (RFC 8767). `0` disables stale serving. |
| `stale-ttl` | int (s) | `30` | TTL advertised in stale replies. |
| `stale-ttl-reset` | bool | `true` | When `true`, stale replies always advertise `stale-ttl`. When `false`, advertise the actual remaining window. |
| `stale-client-timeout-ms` | int (ms) | `1800` | When > 0 and a stale entry exists, wait up to N ms for a fresh upstream answer before serving stale. |
| `nodata-ttl` | int (s) | `60` | TTL for NODATA/NXDOMAIN responses with no SOA record. |
| `min-ttl` | int (s) | `0` | Minimum TTL applied at cache insertion. |
| `max-ttl` | int (s) | `0` | Maximum TTL applied at cache insertion. `0` = no cap. |
| `refresh` | int (%) | — | Background refresh when remaining TTL ≤ N% of original TTL. |
| `refresh-min-ttl` | int (s) | `0` | Background refresh when remaining TTL ≤ N seconds. Complements `refresh`. |
| `persist.path` | string | — | File path for cache persistence. |
| `persist.interval` | int (s) | `0` | Save to disk every N seconds. `0` = save on shutdown only. |

With `persist` configured, the cache survives restarts. On load, a config fingerprint is compared; if routing-relevant config has changed (groups, tags, cache policies, GeoSite files), the persisted cache is discarded.

### Group-level cache overrides

A group's `cache` key overrides per-entry behaviour for responses routed to that group. Only these fields are accepted:

| Field | Type | Description |
|-------|------|-------------|
| `size` | int | Only `0` is valid — disables caching for this group. |
| `stale-expire-ttl` | int (s) | Override stale serving window. |
| `stale-ttl` | int (s) | Override stale reply TTL. |
| `nodata-ttl` | int (s) | Override NODATA/NXDOMAIN TTL. |
| `min-ttl` | int (s) | Override minimum TTL at write time. |
| `max-ttl` | int (s) | Override maximum TTL at write time. |
| `refresh` | int (0–100) | Override background refresh threshold (percent). |

### Verdict Cache

Caches primary/secondary routing decisions for the racing fallback.

```json
"verdict-cache": { "size": 4096, "ttl": 3600 }
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | — | Capacity in entries. |
| `ttl` | int (s) | `0` | Per-entry TTL. `0` = no expiry. |

### Query Log

```json
"querylog": {
  "bind":    "0.0.0.0:8080",
  "token":   "your-secret-token",
  "memory":  1000,
  "channel": 4096,
  "answer-ips": false,
  "file": {
    "dir":               "/var/lib/pathdns/querylog",
    "max-mb":            8,
    "max-segments":      3,
    "batch-size":        256,
    "flush-interval-ms": 500,
    "retention-days":    30,
    "compress":          true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind` | string or array | — | Dashboard + API listen address(es). Omit to disable. |
| `token` | string | — | Bearer token required on all `/api/*` requests. Omit only on trusted networks. |
| `memory` | int | `1000` | In-memory ring buffer capacity. `0` disables the ring. |
| `channel` | int | `4096` | Bounded channel between the DNS hot path and log worker. Full = events dropped (DNS unaffected). |
| `answer-ips` | bool | `false` | Extract A/AAAA answer IPs into events. |
| `file.dir` | string | `"./querylog"` | Directory for rotating MessagePack segments. |
| `file.max-mb` | int (MB) | `8` | Rotate when the current segment reaches this size. |
| `file.max-segments` | int | `3` | Keep at most this many compressed segments. |
| `file.batch-size` | int | `256` | Max events per write call. |
| `file.flush-interval-ms` | int (ms) | `500` | How often the worker flushes to disk. |
| `file.retention-days` | int | — | Delete segments older than N days. |
| `file.compress` | bool | `true` | Gzip-compress segments after rotation. |

---

## Upstream URLs

| URL form | Protocol |
|----------|----------|
| `1.1.1.1` | UDP (equivalent to `udp://1.1.1.1`) |
| `udp://1.1.1.1:5353` | UDP on custom port |
| `tcp://1.1.1.1` | TCP (persistent mux connection) |
| `tls://1.1.1.1` | DNS-over-TLS |
| `tls://1.1.1.1?sni=dns.example` | DoT with explicit SNI |
| `https://8.8.8.8/dns-query` | DNS-over-HTTPS (HTTP/2) |
| `quic://dns.adguard.com` | DNS-over-QUIC (`--features doq`) |
| `h3://dns.cloudflare.com/dns-query` | DoH over HTTP/3 (`--features h3`) |
| `RCODE://NOERROR` | Fixed empty response |
| `RCODE://NXDOMAIN` | Fixed NXDOMAIN |
| `RCODE://SERVFAIL` | Fixed SERVFAIL |
| `RCODE://REFUSED` | Fixed REFUSED |

**ECS mode** (per-upstream query parameter):

| Parameter | Effect |
|-----------|--------|
| `?ecs=strip` | Remove ECS before forwarding (default) |
| `?ecs=forward` | Forward ECS unchanged |
| `?ecs=1.2.3.0/24` | Replace ECS with a fixed subnet |

---

## GeoSite Files

Pass `.dat` (V2Ray/Xray binary protobuf) or `.json` files. Multiple files are merged. Only tags referenced in `group[].tag` are parsed.

Files are watched and hot-reloaded automatically.

| `.dat` type | `.json` prefix | Behaviour |
|-------------|----------------|-----------|
| `RootDomain` | `domain:` or bare | Suffix match (domain and all subdomains) |
| `Full` | `full:` | Exact match only |
| `Plain` | `keyword:` | Substring match |
| `Regex` | `regexp:` | Regular expression match |

---

## ipset / nftset

Uses native Linux netlink — no `ipset` or `nft` shell-out.

- **Test sets** (racing fallback): `fallback.ipset-name4` / `fallback.ipset-name6`.
- **Add sets** (populate with resolved IPs): per-group `add-ip: "v4set,v6set"`.

nftset names use `family@table@set` syntax (e.g. `inet@fw4@chnroute`). IP additions are batched asynchronously. Loopback and unspecified IPs are excluded by default; use `"no-ipset-blacklist": true` to allow them.

---

## Query Log & Dashboard

Enable by adding a `querylog` section with a `bind` address. Browse to `http://<bind>/` for the web dashboard, or query the JSON API directly.

| Method & path | Description |
|---------------|-------------|
| `GET /` | Web dashboard: stat cards, time-range selector, QPS chart, query log, upstream table. |
| `GET /api/stats` | Counter snapshot: total queries, cache-hit rate, QPS, average RTT, upstream ok/err. |
| `GET /api/stats/history?n=<N>` | Last N seconds of per-second QPS samples (max 3600). |
| `GET /api/stats/aggregate?seconds=<N>` | Aggregated counters over the last N seconds. |
| `GET /api/groups` | Routing groups in match order with tags and rule counts. |
| `GET /api/querylog?limit=<L>&before_seq=<S>&q=<filter>` | Recent events from the in-memory ring. |
| `DELETE /api/querylog` | Clear the in-memory ring. |
| `GET /api/querylog/files` | List compressed historical segments. |
| `GET /api/querylog/history?file=<name>&limit=<L>&q=<filter>` | Decode a historical segment. |
| `GET /api/upstreams` | Per-upstream-node stats: ok/err/timeout, inflight, RTT. |

```sh
curl -H "Authorization: Bearer your-secret-token" http://127.0.0.1:8080/api/stats
```

Each query event:

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

`source`: `cache`, `stale`, `upstream`, `singleflight`, `filtered`, `overload`, `rcode`, or `null`.

---

## License

MIT
