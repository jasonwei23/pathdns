# PathDNS

A policy-based DNS forwarder for split-horizon deployments. Routes queries to different upstream resolvers based on GeoSite domain classification and custom routing rules, with optional ipset/nftset integration for IP-based routing decisions.

**Linux only.** The project uses Linux-specific APIs throughout (io_uring, `sendmmsg`, `SO_REUSEPORT`, netlink for ipset/nftset, `SO_BINDTODEVICE`) and is not designed to run on other platforms.

> **Requires Linux kernel 6.0 or newer.** The UDP receive path is built exclusively on **io_uring multishot `recvmsg`** with provided buffer rings — there is **no `recvmmsg` fallback**. pathdns probes for support at startup and **refuses to start** with a clear error if the kernel is too old. See [Requirements](#requirements).

---

## Requirements

| Requirement | Why |
|---|---|
| **Linux ≥ 6.0** | UDP datagrams are received with a single io_uring **multishot `recvmsg`** fed by a kernel-managed **provided buffer ring** (the ring registration needs 5.19, multishot recvmsg needs 6.0). One submission then delivers packets continuously — one completion per packet, no per-packet recv syscall. |
| io_uring not seccomp-blocked | Some container runtimes disable the `io_uring_setup`/`io_uring_enter` syscalls. pathdns needs them for the receive path. |

There is **no compatibility/fallback layer**: this branch deliberately drops the
older `recvmmsg` receive loop. The startup probe arms a multishot `recvmsg` on a
throwaway loopback socket and confirms a round trip; if that fails, pathdns exits
with:

```
io_uring multishot recvmsg is unavailable — pathdns requires Linux 6.0+ ...
```

Check your kernel with `uname -r`. Most current distributions (and OpenWrt ≥ 23.05
on supported targets) ship ≥ 6.0; older long-term router kernels (5.4 / 5.10 / 5.15)
do **not** work with this build.

Sends still use `sendmmsg`, and the dashboard's drop diagnostics — `SO_RXQ_OVFL`
(kernel receive-overflow drops) and `SO_MEMINFO` (receive-buffer occupancy) — are
carried on the io_uring receive path.

---

## What makes it different

- **GeoSite routing** — named rules each with their own GeoSite tag matchers and upstream resolvers; top-to-bottom match order.
- **Answer map** — `route.answer` maps domain patterns (exact/subdomain/keyword/regex or `tag:` GeoSite expressions) straight to synthesised responses (`A://`, `AAAA://`, `CNAME://` with server-side chasing, `RCODE://`), consulted before the forwarding rules.
- **ipset-test fallback** — for unmatched domains, races two upstreams and decides which answer to use by testing response IPs against an ipset/nftset. The decision is policy-based (IP membership), not speed-based.
- **EDNS-aware cache isolation** — DO bit and ECS subnet are part of the cache key. When an upstream uses `ecs=strip`, all clients share one entry regardless of subnet.
- **DNS 0x20 randomization** — plaintext UDP queries apply random per-letter capitalisation to the QNAME and reject responses that don't echo it back (~16 bits of anti-poisoning entropy). Encrypted transports (DoT/DoH/DoQ/DoH3) are already authenticated by TLS/QUIC, so they skip it.
- **Verdict cache** — caches per-domain routing decisions for the racing fallback to avoid repeated ipset lookups.
- **Encrypted upstreams** — DoT (`tls://`), DoH (`https://`), DoQ (`quic://`, `--features doq`), DoH3 (`h3://`, `--features h3`).
- **Hot-reload** — GeoSite files and routing config are watched and reloaded without restart.
- **io_uring UDP receive** (Linux 6.0+) — a single multishot `recvmsg` over a provided buffer ring delivers datagrams with no per-packet recv syscall; responses are batched with `sendmmsg`. No `recvmmsg` fallback.
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

### Testing

Behaviour is verified by black-box integration scripts that drive a running
binary over real DNS — see [`testing/`](testing/README.md) (e.g.
`testing/test_match.py`, a 30-case domain-matching matrix).

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
  "bind": { "addr": "0.0.0.0", "port": 53 },
  "route": {
    "geosite": ["/etc/pathdns/geosite.dat"],
    "rules": [
      { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
      { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://dns.google?bootstrap=119.29.29.29"] }
    ],
    "final": "domestic"
  },
  "cache": { "size": 10000 }
}
```

### Dual-stack, specific interface

```json
{
  "bind": {
    "addr":      ["0.0.0.0", "::"],
    "port":      53,
    "interface": ["br-lan"]
  },
  "route": {
    "geosite": ["/etc/pathdns/geosite.dat"],
    "rules": [
      { "name": "domestic", "tag": ["cn"],  "upstream": ["119.29.29.29"] },
      { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://dns.google?bootstrap=119.29.29.29"] }
    ],
    "final": "domestic"
  },
  "cache": { "size": 10000 }
}
```

### ipset-based primary/secondary routing

```json
{
  "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
  "route": {
    "geosite": ["/etc/pathdns/geosite.dat"],
    "rules": [
      {
        "name":   "domestic",
        "tag":    ["cn"],
        "upstream": ["119.29.29.29"],
        "add-ip": "mainroute,mainroute6"
      },
      { "name": "overseas", "tag": ["!cn"], "upstream": ["tls://dns.google?bootstrap=119.29.29.29"] }
    ],
    "final": {
      "primary":       "domestic",
      "secondary":     "overseas",
      "ipset4":        "mainroute",
      "ipset6":        "mainroute6",
      "verdict-cache": { "size": 4096, "ttl": 3600 }
    }
  },
  "cache": { "size": 10000 }
}
```

---

## All Config Keys

### Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind` | object | — | Listen address configuration (see [`bind`](#bind)). Defaults to `127.0.0.1:65353` UDP+TCP when omitted. |
| `route` | object | — | Routing configuration: GeoSite files, rules, and final target (see [`route`](#route)). |
| `cache` | object | — | DNS cache settings (see [Cache](#cache)). |
| `dashboard` | object | — | Optional query log and web dashboard (see [Dashboard](#dashboard)). Omit to disable. |
| `runtime` | object | — | Runtime / protocol knobs (see [`runtime`](#runtime)). All fields have auto-derived defaults; omit the section entirely if the defaults are acceptable. |

### `bind`

Controls where PathDNS listens for DNS queries.

```json
"bind": {
  "addr":      ["0.0.0.0", "::"],
  "port":      53,
  "proto":     "both",
  "interface": ["br-lan"]
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | string or string array | `"127.0.0.1"` | IP address(es) to bind. Plain IPs without port: `"0.0.0.0"`, `"::1"`, `["0.0.0.0", "::"]`. |
| `port` | int | `65353` | UDP and TCP listen port. |
| `proto` | string | `"both"` | Protocol to listen on. `"udp"`, `"tcp"`, or `"both"`. |
| `interface` | string array | — | Network interface filter via `SO_BINDTODEVICE`. `["eth0", "br-lan"]` accepts traffic arriving on those interfaces only; `["!wan"]` accepts all except those listed. Mixing allow and deny entries is an error. |

IPv6 sockets are v6-only; for dual-stack bind both `"0.0.0.0"` and `"::"`.

### `route`

Groups all routing configuration: the GeoSite data sources, the matching rules, and the target for unmatched queries.

```json
"route": {
  "geosite": ["/etc/pathdns/geosite.dat"],
  "rules":   [...],
  "final":   "domestic"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `geosite` | string array | GeoSite `.dat` (V2Ray/Xray protobuf) or `.json` files. Required when any rule uses `tag`. Files are hot-reloaded on change. |
| `rules` | array | Routing rules matched top-to-bottom (see [Rules](#rules)). |
| `final` | string or object | Target for unmatched queries (see [Final](#final)). When omitted, the last entry in `rules` is used. |

#### Rules

Rules are matched top-to-bottom. The first rule whose GeoSite tags match the query name wins.

```json
"rules": [
  {
    "name":     "domestic",
    "tag":      ["cn"],
    "upstream": ["119.29.29.29", "223.5.5.5"],
    "add-ip":   "chnroute,chnroute6"
  },
  {
    "name":         "overseas",
    "tag":          ["!cn"],
    "upstream":     ["tls://dns.google?bootstrap=119.29.29.29"],
    "cache":        { "size": 0 },
    "filter-qtype": 65
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique rule name. |
| `tag` | string array | GeoSite tag expressions. `"TAG"` includes, `"!TAG"` excludes. |
| `upstream` | string array | Real upstream resolvers (see [Upstream URLs](#upstream-urls)). Fixed/synthesised responses (`A://`, `AAAA://`, `CNAME://`, `RCODE://`) are **not** allowed here — configure them in [`route.answer`](#answer-map) instead. |
| `add-ip` | string | `"v4set,v6set"` — add resolved IPs to these ipset/nftset sets. Append `/N` (ipset) or `@N` (nftset) for a CIDR mask: `"chnroute/24,chnroute6@48"` writes each IP as its enclosing prefix. |
| `cache` | object | Per-rule cache overrides (see [Rule-level cache overrides](#rule-level-cache-overrides)). |
| `filter-qtype` | int or int array | Suppress the given QTYPE(s) for this rule by returning an empty `NOERROR`/NODATA response, with no upstream query (e.g. `28` = AAAA, `65` = HTTPS). Returning NODATA — rather than dropping — lets clients fail over immediately instead of waiting for a timeout. |
| `collapse` | bool | Collapse CNAME chains in A/AAAA answers to a single record at the query name (default `false`). A chain `www.paypal.com → … → CNAME e5308.x.akamaiedge.net → A 95.100.196.60` is rewritten to `www.paypal.com. A 95.100.196.60` (the address record's TTL is kept). Only applies to A/AAAA; other qtypes and non-CNAME answers pass through unchanged. The EDNS OPT record is preserved; the authority section is dropped (incompatible with DNSSEC validation). |

**Tag matching:** a domain matches a rule if it appears in any included tag and none of the excluded tags. A rule with no positive tags matches everything not otherwise excluded — use this for catch-all rules.

#### Answer map

`route.answer` is the single place for **synthesised responses** — it maps domain patterns directly to a fixed answer, **consulted before `rules`**. `rules` only forward to real upstreams; anything answered locally (`A://`, `AAAA://`, `CNAME://`, `RCODE://`) goes here.

```json
"route": {
  "answer": {
    "tag:ads":            "RCODE://NXDOMAIN",
    "tag:cn,!gfw":        "CNAME://proxy.example.com",
    "a.example.com":      "CNAME://target-a.com",
    "b.example.com":      ["A://1.2.3.4", "AAAA://::1"],
    "full:c.example.com": "AAAA://::1",
    "keyword:tracker":    "RCODE://NXDOMAIN"
  },
  "rules": [ ... ],
  "final": "domestic"
}
```

| Part | Description |
|------|-------------|
| key | A match pattern. Inline domain forms use the GeoSite `.json` conventions: `full:` (exact), `domain:` or bare (subdomain rule — matches the domain itself and dot-delimited subdomains), `keyword:` (substring), `regexp:` (regex). `tag:EXPR` references the GeoSite database, where `EXPR` is a comma-separated tag expression with the same include/`!`exclude semantics as a rule's `tag` (e.g. `tag:cn,!gfw`); it requires at least one include tag and a configured `geosite` file. |
| value | A single `A://` / `AAAA://` / `CNAME://` / `RCODE://` URL, or an array of them. One `A://` and one `AAAA://` may coexist; `CNAME://` and `RCODE://` are each exclusive. Real upstreams are not allowed here. Append `?ttl=N` to set the record TTL (seconds, default `60`), e.g. `"A://1.2.3.4?ttl=300"`. |

**Matching:** lookup priority is full → subdomain/root-domain (most specific wins) → tag → keyword → regex. A hit short-circuits the routing rules. A `CNAME://` value is server-side chased (see [CNAME chasing](#cname-chasing)) through the rule table.

**TTL:** each record's TTL is the entry's `?ttl=` value (default `60s`). For `A`/`AAAA`/`CNAME` it is the record TTL the client sees; for `RCODE`/NODATA (which carries no record) it is how long PathdNS caches the negative response. CNAME-chased A/AAAA records keep their upstream TTL — only the synthesised CNAME uses `?ttl=`.

**Caching:** answer-map responses are cached like any other answer, so repeat queries are served from the fast path. Entries are ECS-independent and shared across all clients; cache hits report no rule.

A single entry whose key matches several domains (e.g. `keyword:` or a broad subdomain rule) lets one line cover many names; conversely, ten domains needing ten different targets become ten lines here instead of ten rules.

#### Final

Applied when no rule matches. **Omit `route.final` to fall back to the last rule.** Two explicit forms:

```json
"final": "domestic"
```
Route unmatched queries to the named rule. (There is no empty-response fallback — to return NXDOMAIN/empty for specific names, give them an `RCODE://` entry in [`route.answer`](#answer-map).)

```json
"final": {
  "primary":       "domestic",
  "secondary":     "overseas",
  "ipset4":        "chnroute",
  "ipset6":        "chnroute6",
  "verdict-cache": { "size": 4096, "ttl": 3600 }
}
```
**Ipset-test mode** — the winner is decided by ipset membership, not speed:

1. Both rules are queried concurrently.
2. The primary's answer IPs are tested against the configured ipset/nftset.
3. IPs in the set → return primary's answer. IPs not in the set → return secondary's answer.
4. The verdict is cached per domain (`verdict-cache`); subsequent queries skip the race.

Non-A/AAAA queries fall back to the first non-SERVFAIL answer.

| Field | Type | Description |
|-------|------|-------------|
| `primary` | string | Rule preferred when its answer IPs are in the ipset (required). |
| `secondary` | string | Rule used when the primary's IPs are not in the ipset (required). |
| `ipset4` | string | IPv4 ipset/nftset to test primary's IPs against. At least one of the two is required. |
| `ipset6` | string | IPv6 ipset/nftset to test primary's IPs against. |
| `noip-as-primary-ip` | bool | Treat NODATA primary replies as if their IPs were in the set (default: `false`). |
| `verdict-cache` | object | Cache per-domain routing decisions to skip repeated ipset lookups (see below). |

**`verdict-cache`** inside `route.final`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | — | Capacity in entries. |
| `ttl` | int (s) | `0` | Per-entry TTL. `0` = no expiry. |

### `runtime`

Optional sub-object for runtime and protocol knobs. **The concurrency defaults
are derived from the host's CPU count**, so changing them is rarely necessary.
Tune these only for special network environments, debugging, or measured bottlenecks.

```json
"runtime": {
  "worker-threads": 4
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `worker-threads` | int | **auto** (CPU count, min 2) | Tokio worker thread count and number of `SO_REUSEPORT` sockets. |
| `max-inflight` | int | **auto** (`worker-threads × 1024`) | Max concurrent in-flight client queries. |
| `inflight-queue-ms` | int (ms) | `0` | When > 0, queries that exceed `max-inflight` wait up to N ms for a slot before being shed with SERVFAIL. `0` = hard-drop immediately. |
| `upstream-max-inflight` | int | `256` | Per-upstream in-flight query limit. |
| `timeout-ms` | int (ms) | `3000` | Upstream query timeout. |
| `hedge-delay-ms` | int (ms) | `0` | Fire a second upstream after N ms with no reply. `0` = disabled. |
| `upstream-max-response-bytes` | int | `0` | Reject TCP/TLS upstream responses larger than this. `0` = no limit. |
| `tcp-max-connections` | int | `1024` | Maximum concurrent inbound TCP connections. `0` = unlimited. |
| `tcp-read-timeout-ms` | int (ms) | `5000` | Timeout for reading the DNS message body. `0` = disabled. |
| `tcp-idle-timeout-ms` | int (ms) | `30000` | Idle TCP connection timeout. `0` = disabled. |
| `udp-buf-size` | int | `4194304` | `SO_RCVBUF`/`SO_SNDBUF` size per UDP socket (bytes). |
| `upstream-udp-sockets` | int | **auto** (`max(worker-threads, 32)`) | UDP socket pool size per upstream node. |

### Cache

```json
"cache": {
  "size":                    10000,
  "min-ttl":                 0,
  "max-ttl":                 0,
  "persist": {
    "path":     "/etc/pathdns/cache.db",
    "interval": 300
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | `10000` | Cache capacity in entries (`0` disables). |
| `min-ttl` | int (s) | `0` | Minimum TTL applied at cache insertion. Also the floor for NODATA/NXDOMAIN responses that carry no SOA. |
| `max-ttl` | int (s) | `0` | Maximum TTL applied at cache insertion. `0` = no cap. |
| `persist.path` | string | — | File path for cache persistence. |
| `persist.interval` | int (s) | `0` | Save to disk every N seconds. `0` = save on shutdown only. |

Negative responses (NODATA/NXDOMAIN) are cached for their SOA TTL (capped at 10800 s per RFC 2308), clamped by `min-ttl`/`max-ttl`; with no SOA they fall to `min-ttl`. Synthesised `route.answer` `RCODE://` responses use their own `?ttl=` instead.

With `persist` configured, the cache survives restarts. On load, a config fingerprint is compared; if routing-relevant config has changed (rules, tags, cache policies, GeoSite files), the persisted cache is discarded.

### Rule-level cache overrides

A rule's `cache` key overrides per-entry behaviour for responses routed to that rule. Only these fields are accepted:

| Field | Type | Description |
|-------|------|-------------|
| `size` | int | Only `0` is valid — disables caching for this rule. |
| `min-ttl` | int (s) | Override minimum TTL at write time. |
| `max-ttl` | int (s) | Override maximum TTL at write time. |

### Dashboard

```json
"dashboard": {
  "port":    8080,
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

The dashboard listens on the same IP addresses as `bind` (port substituted), and respects `bind.interface` via `SO_BINDTODEVICE`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | int | — | Dashboard + API listen port. Omit to disable. |
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
| `tls://dns.google?bootstrap=223.5.5.5` | DoT with hostname — resolved via 223.5.5.5 at startup |
| `tls://1.1.1.1?sni=dns.example` | DoT with explicit SNI |
| `https://8.8.8.8/dns-query` | DNS-over-HTTPS (HTTP/2) |
| `quic://dns.adguard.com?bootstrap=223.5.5.5` | DNS-over-QUIC (`--features doq`) |
| `h3://dns.cloudflare.com/dns-query?bootstrap=223.5.5.5` | DoH over HTTP/3 (`--features h3`) |

Synthesised responses — `A://`, `AAAA://`, `CNAME://`, and `RCODE://NOERROR|NXDOMAIN|SERVFAIL|REFUSED` — are configured in [`route.answer`](#answer-map), not in `rules.upstream`.

**Per-upstream query parameters:**

| Parameter | Effect |
|-----------|--------|
| `?bootstrap=IP[:port]` | IP-literal resolver used to look up the upstream **hostname** at startup. Required when the upstream is specified by hostname (e.g. `tls://dns.google`). Port defaults to 53. `/etc/resolv.conf` is never consulted. |
| `?ecs=strip` | Remove ECS before forwarding (default) |
| `?ecs=forward` | Forward ECS unchanged |
| `?ecs=1.2.3.0/24` | Replace ECS with a fixed subnet |
| `?sni=name` | Override the TLS SNI name (TLS-based upstreams only) |
| `?no-sni` | Disable TLS SNI extension (`tls://` only) |
| `?mark=0x1` | Apply a Linux `SO_MARK` (fwmark) to this upstream's egress socket(s) for policy routing. Hex (`0x1`) or decimal (`1`). Works on every transport (UDP/TCP/DoT/DoH/DoQ/DoH3). **Requires `CAP_NET_ADMIN`** — startup/connect fails with a clear error otherwise. |

**fwmark policy routing example** — send one upstream's traffic out a specific table/VPN:

```sh
# pathdns: "upstream": ["udp://10.0.0.1?mark=0x1"]
ip rule add fwmark 0x1 table 100
ip route add default via 192.168.50.1 table 100   # e.g. a VPN/WAN gateway
```

Queries to that upstream are stamped with fwmark `0x1`, so the kernel routes them
via table 100 while everything else uses the main table.

### CNAME chasing

When a [`route.answer`](#answer-map) entry uses `CNAME://target`, PathdNS goes beyond simply returning the CNAME record: it also **resolves the target server-side** and includes the result in the same response.

**How it works:**

1. A query for `D` (e.g. `baidu.com A`) matches an answer entry with value `CNAME://proxy.example.com`.
2. PathdNS returns `D CNAME target` and simultaneously resolves `target` through the routing `rules`.
3. The A/AAAA records for `target` are appended to the same response, so the client receives the complete answer chain in one packet.

**Loop prevention** — the target is routed through `rules` only; `route.answer` is not re-consulted, so a CNAME target cannot loop back into the answer map.

If no rule matches the target, or the upstream query fails, PathdNS falls back to returning the bare CNAME record and lets the client follow it.

Non-A/AAAA query types (MX, TXT, …) skip chasing and receive only the CNAME record.

**Example — block `cn` domains by redirecting to a proxy hostname:**

```json
"route": {
  "answer": {
    "tag:cn": "CNAME://proxy.example.com"
  },
  "rules": [
    { "name": "overseas", "upstream": ["tls://dns.google?bootstrap=8.8.8.8"] }
  ],
  "final": "overseas"
}
```

A query for `baidu.com A` matches the `tag:cn` answer entry and returns:
```
baidu.com.        CNAME  proxy.example.com.
proxy.example.com A      203.0.113.1
```

The client resolves `baidu.com` directly to `203.0.113.1` without a second round-trip.

---

## GeoSite Files

Pass `.dat` (V2Ray/Xray binary protobuf) or `.json` files via `route.geosite`. Multiple files are merged. Only tags referenced in `route.rules[].tag` or `route.answer` (`tag:` keys) are parsed.

Files are watched and hot-reloaded automatically.

| `.dat` type | `.json` prefix | Behaviour |
|-------------|----------------|-----------|
| `RootDomain` | `domain:` or bare | Subdomain/root-domain match (domain itself and dot-delimited subdomains) |
| `Full` | `full:` | Exact match only |
| `Plain` | `keyword:` | Substring match |
| `Regex` | `regexp:` | Regular expression match |

---

## ipset / nftset

Uses native Linux netlink — no `ipset` or `nft` shell-out.

- **Test sets** (racing final): `route.final.ipset4` / `route.final.ipset6`.
- **Add sets** (populate with resolved IPs): per-rule `add-ip: "v4set,v6set"`.

**Set name syntax**

| Kind | Format | Mask (optional) | Example |
|------|--------|-----------------|---------|
| ipset | `setname` | `/N` suffix | `chnroute` · `chnroute/24` |
| nftset | `family@table@set` | `@N` 4th segment | `inet@fw4@chnroute` · `inet@fw4@chnroute@24` |

The optional mask writes each resolved IP as its enclosing CIDR prefix instead of a host address — useful for `hash:net` ipsets or nftset interval sets. For nftset interval sets PathDNS automatically detects the `NFT_SET_INTERVAL` flag at startup and writes range elements accordingly.

IP additions are batched and deduplicated by a background worker, which writes them to the configured sets without blocking the DNS reply. Special-use addresses are always silently skipped: loopback (127/8, ::1), unspecified (0/8, ::), RFC 1918 private (10/8, 172.16/12, 192.168/16), link-local (169.254/16, fe80::/10), multicast (224/4, ff00::/8), broadcast, CGNAT (100.64/10, RFC 6598), and documentation ranges (RFC 5737 / RFC 3849).

> The kernel commits an nftables/ipset add within the `send()` syscall, so a resolved IP is typically in the set within tens of microseconds of the reply being sent — well before the client opens a connection.

---

## Dashboard & Query Log

Enable by adding a `dashboard` section with a `port`. Browse to `http://<bind-addr>:<port>/` for the web UI, or query the JSON API directly.

| Method & path | Description |
|---------------|-------------|
| `GET /` | Web dashboard: stat cards, time-range selector, QPS chart, query log, upstream table. |
| `GET /api/stats` | Counter snapshot: total queries, cache-hit rate, QPS, average RTT, upstream ok/err. |
| `GET /api/stats/history?n=<N>` | Last N seconds of per-second QPS samples (max 3600). |
| `GET /api/stats/aggregate?seconds=<N>` | Aggregated counters over the last N seconds. |
| `GET /api/rules` | Routing rules in match order with tags and rule counts. |
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
  "rule": "overseas",
  "answer_ips": ["93.184.216.34"]
}
```

`source`: `cache`, `upstream`, `singleflight`, `filtered`, `overload`, `rcode`, or `answer`.

- `answer` — response synthesised from a `route.answer` entry (`A://`, `AAAA://`, or `CNAME://`).
- `rcode` — fixed `RCODE://` response from a `route.answer` entry.

---

## License

MIT
