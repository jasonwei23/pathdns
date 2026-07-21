# PathDNS

A policy-based DNS forwarder for split-horizon deployments. Routes queries to different upstream resolvers based on ruleset domain classification and custom routing rules, with optional ipset/nftset integration for IP-based routing decisions.

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

- **Ruleset routing** — rules matched by domain pattern and/or ruleset tag, each pointing at a named `route.servers` entry; top-to-bottom match order. Multiple rules sharing a server share one connection pool.
- **Encrypted upstreams** — DoT (`tls://`, `dot` feature, on by default), DoH (`https://`, `doh` feature, on by default), DoQ (`quic://`, `--features doq`), DoH3 (`h3://`, `--features h3`). Build `--no-default-features` for a UDP/TCP-only resolver that drops the entire TLS/HTTP stack (~22 fewer crates).
- **EDNS-aware cache isolation** — DO bit and ECS subnet are part of the cache key. When an upstream uses `ecs=strip`, all clients share one entry regardless of subnet.
- **io_uring UDP receive** (Linux 6.0+) — a single multishot `recvmsg` over a provided buffer ring delivers datagrams with no per-packet recv syscall; responses are batched with `sendmmsg`.
- **Hot-reload** — ruleset files and routing config are watched and reloaded without restart.
- **Built-in dashboard** — authenticated HTTP API and single-page web UI with live QPS chart, counter cards, query log, and upstream stats.

---

## Build

```sh
# Standard build — DoT (tls://) and DoH (https://) are enabled by default
cargo build --release

# Minimal build — UDP/TCP DNS only, drops the rustls/tokio-rustls/h2/webpki-roots
# stack (~22 fewer crates). tls:// and https:// upstreams are rejected at startup.
cargo build --release --no-default-features

# Only one encrypted transport (e.g. DoT but not DoH)
cargo build --release --no-default-features --features dot

# With DNS-over-QUIC support (quic:// upstreams)
cargo build --release --features doq

# With DNS-over-HTTP/3 support (h3:// upstreams; also enables doq)
cargo build --release --features h3

# Static musl binary (OpenWrt / minimal environments)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

**Cargo features:** `dot` (DoT), `doh` (DoH, implies `dot`), `doq` (DoQ), `h3` (DoH3, implies `doq`), `jemalloc`. `default = ["dot", "doh"]`.

### Testing

Behaviour is verified by black-box integration scripts that drive a running
binary over real DNS — see [`testing/`](testing/README.md) (e.g.
`testing/test_match.py`, a 23-case domain-matching matrix).

### Fuzzing

The wire-format parsers that touch untrusted bytes directly — DNS query/response
parsing (`src/dns/`) and the mihomo `.mrs` ruleset decoder (`src/mrs.rs`) — are
covered by `cargo-fuzz` targets under [`fuzz/`](fuzz). These complement the
black-box tests above: they don't check behaviour, only that malformed input
(a hostile packet, a corrupted or hand-crafted `.mrs` file) can't panic or
consume unbounded memory/CPU. CI runs a short timed smoke pass on every push;
run it for longer locally with:

```sh
cargo install cargo-fuzz
rustup toolchain install nightly   # required by libFuzzer's instrumentation
cargo +nightly fuzz run fuzz_dns_wire      # or fuzz_mrs_domain / fuzz_mrs_ipcidr
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
  "bind": { "addr": "0.0.0.0", "port": 53 },
  "route": {
    "servers": {
      "domestic-dns": "119.29.29.29",
      "overseas-dns": "tls://dns.google?bootstrap=domestic-dns"
    },
    "ruleset": [{ "tag": "cn", "format": "mrs", "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" }],
    "rules": [
      { "matcher": ["tag:cn"],  "upstream": "domestic-dns" },
      { "matcher": ["tag:!cn"], "upstream": "overseas-dns" }
    ],
    "final": "overseas-dns"
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
    "servers": {
      "domestic-dns": "119.29.29.29",
      "overseas-dns": "tls://dns.google?bootstrap=domestic-dns"
    },
    "ruleset": [{ "tag": "cn", "format": "mrs", "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" }],
    "rules": [
      { "matcher": ["tag:cn"],  "upstream": "domestic-dns" },
      { "matcher": ["tag:!cn"], "upstream": "overseas-dns" }
    ],
    "final": "overseas-dns"
  },
  "cache": { "size": 10000 }
}
```

### answer-ip-based primary/secondary routing

```json
{
  "bind": { "addr": ["0.0.0.0", "::"], "port": 53 },
  "route": {
    "servers": {
      "domestic-dns": "119.29.29.29",
      "overseas-dns": "tls://dns.google?bootstrap=domestic-dns"
    },
    "ruleset": [
      { "tag": "cn",    "format": "mrs",  "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" },
      { "tag": "cn-ip", "format": "text", "behavior": "ipcidr", "path": "/etc/pathdns/cn-ip.list" }
    ],
    "rules": [
      {
        "matcher":  ["tag:cn"],
        "upstream": "domestic-dns",
        "filter": [
          { "response-type": "A",    "action": "accept", "add-ip": "mainroute" },
          { "response-type": "AAAA", "action": "accept", "add-ip": "mainroute6" }
        ]
      },
      { "matcher": ["tag:!cn"], "upstream": "overseas-dns" }
    ],
    "final": {
      "primary":       "domestic-dns",
      "secondary":     "overseas-dns",
      "answer-ip":     "cn-ip",
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
| `route` | object | — | Routing configuration: ruleset files, rules, and final target (see [`route`](#route)). |
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

Groups all routing configuration: the ruleset data sources, the matching rules, and the target for unmatched queries.

```json
"route": {
  "servers": { "domestic-dns": "119.29.29.29" },
  "ruleset": [{ "tag": "cn", "format": "mrs", "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" }],
  "rules":   [...],
  "final":   "domestic-dns"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `servers` | object | Named upstreams (or fixed-answer pseudo-upstreams), referenced by name from `rules[].upstream` (see [Servers](#servers)). |
| `ruleset` | array | mihomo-compatible rule-set entries used by `matcher`'s `tag:` expressions (see [Ruleset Files](#ruleset-files)). Required when any rule uses `tag:`. Files are hot-reloaded on change. |
| `rules` | array | Routing rules matched top-to-bottom (see [Rules](#rules)). |
| `final` | string or object | Target for unmatched queries (see [Final](#final)). When omitted, the last entry in `rules` is used. |

#### Servers

`route.servers` is a name → value map. Each entry is either:

- a real upstream: a single [upstream URL](#upstream-urls) string, or an array of them (multiple nodes in one pool, hedged/raced together — see [Encrypted upstreams / hedging](#runtime)), or
- a fixed answer: a single `A://`/`AAAA://`/`RCODE://` URL, or an array of them (see [Fixed-answer servers](#fixed-answer-servers) below).

A single entry can't mix the two — every URL in one entry's array must be all-real or all-fixed. Rules reference a server by name instead of embedding upstream URLs directly, so multiple rules sharing the same resolver share one connection pool (sockets, TLS session cache, RTT stats) instead of opening independent ones.

```json
"servers": {
  "domestic-dns": "119.29.29.29",
  "domestic-dns-multi": ["119.29.29.29", "223.5.5.5"],
  "overseas-dns": "tls://dns.google?bootstrap=domestic-dns",
  "blocked": "RCODE://NXDOMAIN",
  "fixed-a": ["A://1.2.3.4", "AAAA://::1"]
}
```

##### Fixed-answer servers

A `route.servers` entry can be a locally synthesised answer instead of a real upstream — no network I/O at all. Route to one with an ordinary rule (or `route.final`/`rule.filter`'s `forward`), exactly like a real upstream:

```json
"servers": {
  "ads-blocked":     "RCODE://NXDOMAIN",
  "internal-target": ["A://10.0.0.1?ttl=300", "AAAA://fd00::1?ttl=300"]
},
"rules": [
  { "matcher": ["tag:ads"],         "upstream": "ads-blocked" },
  { "matcher": ["+.internal.test"], "upstream": "internal-target" }
]
```

| URL form | Effect |
|----------|--------|
| `A://1.2.3.4` | Answer A queries with this address. |
| `AAAA://::1` | Answer AAAA queries with this address. |
| `RCODE://NOERROR\|NXDOMAIN\|SERVFAIL\|REFUSED` | Answer with a fixed RCODE and no records. |

One `A://` and one `AAAA://` may coexist in the same entry's array (covering both query types); a query type with no matching record in the set gets an empty `NOERROR`/NODATA reply. `RCODE://` is exclusive — it can't be combined with `A://`/`AAAA://` in the same entry. Append `?ttl=N` to set the record TTL (seconds, default `60`), e.g. `"A://1.2.3.4?ttl=300"`; for `RCODE://` (which carries no record) the TTL instead governs how long PathdNS caches the negative response.

Responses are cached like any other rule's, following that rule's own cache policy. Since no network I/O is involved, `strip_ecs` behaves as if the entry always strips ECS, so all clients share one cache entry.

#### Rules

Rules are matched top-to-bottom. The first rule whose `matcher` matches the query name wins.

```json
"rules": [
  {
    "matcher":  ["tag:cn"],
    "upstream": "domestic-dns-multi",
    "filter": [
      { "response-type": "A",    "action": "accept", "add-ip": "chnroute" },
      { "response-type": "AAAA", "action": "accept", "add-ip": "chnroute6" }
    ]
  },
  {
    "matcher":  ["tag:!cn"],
    "upstream": "overseas-dns",
    "filter":   [ { "response-rcode": "NXDOMAIN", "action": "drop" } ]
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `matcher` | string array | Each entry is either a domain pattern or a `tag:` ruleset expression (see below). The rule matches if ANY entry matches. Omit (or leave empty) for a catch-all rule. |
| `upstream` | string | Name of a [`route.servers`](#servers) entry this rule resolves through. |
| `filter` | array | Ordered match-criteria + action entries (see [Rule filters](#rule-filters)). |

**`matcher` entries:**

| Entry | Behaviour |
|-------|-----------|
| `example.com` (bare) | Exact match only |
| `+.example.com` | The domain itself and all dot-delimited subdomains |
| `*.example.com` | Single-label wildcard — matches `a.example.com` but not `example.com` or `a.b.example.com` |
| `.example.com` | Subdomains only, without the apex (rare; treated the same as `+.example.com`) |
| `tag:cn,!gfw` | Ruleset tag expression: matches if tagged `cn` and not tagged `gfw`. `tag:!gfw` alone (no include) is a valid "everything except `gfw`" catch-all. |

Multiple `matcher` entries are ORed together — a rule with `["example.com", "tag:cn"]` matches a query that is *either* exactly `example.com` *or* tagged `cn`. Declaration order between rules always decides ties: a later rule's more-specific pattern does not "win" over an earlier rule's broader one — see [Rule matching order](#rule-matching-order) below if that matters for your config.

Rules have no name of their own — reporting (querylog, dashboard) and cache overrides identify a rule by the `route.servers` entry it resolves through instead. Per-rule cache overrides live in the global [`cache`](#per-server-cache-overrides) section, keyed by server name, not on the rule itself.

##### Rule matching order

Rules are tried strictly top-to-bottom; the first one whose `matcher` matches wins, regardless of how specific that match was. If rule 1 has `matcher: ["*.example.com"]` (wildcard) and rule 2 has `matcher: ["a.example.com"]` (exact), a query for `a.example.com` is answered by rule 1 — it comes first — even though rule 2's pattern is more specific. Put more specific rules earlier if they need to take precedence.

#### Rule filters

`rule.filter` is an ordered list of match-criteria + action entries, inspired by [RouteDNS](https://github.com/folbricht/routedns)'s router/response-blocklist groups: the first entry whose criteria all match wins (same first-match convention as the `rules` table). Criteria within one entry are ANDed; an entry with no criteria at all is a config error. Every dimension is evaluated against the *resolved response*, so a rule with any `filter` entries always queries its upstream first — there is no query-side (QTYPE) filtering.

```json
"filter": [
  { "answer-ip": "cgnat-ip", "action": "drop" },
  { "response-rcode": "NXDOMAIN", "action": "forward", "forward": "overseas-dns" },
  { "response-type": "A",    "action": "accept", "add-ip": "chnroute" },
  { "response-type": "AAAA", "action": "accept", "add-ip": "chnroute6" }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `answer-ip` | string or string array | `route.ruleset` tag(s) (`behavior: ipcidr`), each optionally prefixed with `!` to exclude. Matches if any resolved answer IP falls in an include tag's range (or there are no include tags) **and** none falls in an exclude tag's range — `!cnip` alone means "none of the answer IPs are in this range". Same tag-reference convention as [`route.final`'s `answer-ip` field](#final), so ipcidr data is introduced the same way everywhere it's used. |
| `response-type` | string/int or array | RR type name(s) (`A`/`AAAA`/`CNAME`/`MX`/`TXT`/`NS`/`SOA`/`PTR`/`SRV`/`HTTPS`/`SVCB`/`CAA`/…) or number(s). Matches if any record in the answer section has one of these types. |
| `response-rcode` | string/int or array | RCODE name(s) (`NOERROR`/`FORMERR`/`SERVFAIL`/`NXDOMAIN`/`NOTIMP`/`REFUSED`) or number(s). |
| `response-qclass` | string/int or array | QCLASS name(s) (`IN`/`CH`/`HS`/`NONE`/`ANY`) or number(s). |
| `action` | string | `accept` / `drop` / `forward` (see below). |
| `forward` | string | Target [`route.servers`](#servers) name. Required (and only valid) when `action` is `"forward"`. |
| `add-ip` | string | nftset/ipset target to populate with this entry's resolved IPs (see [ipset / nftset](#ipset--nftset)). Only valid with `action: "accept"`, and only when `response-type` is pinned to exactly one of `"A"`/`"AAAA"` — a query only ever gets one record type back, so that's what makes a single set name unambiguous. |

**Actions:**

- `accept` — return the response as-is. The only action `add-ip` can be used with.
- `drop` — send no reply at all.
- `forward` — answer using a named server's upstream directly, bypassing that server's own routing/filters. The response is still cached and logged under the *matched* rule's own identity and cache policy (not the forward target's). There is no dedicated "empty reply" action — `forward` to an `RCODE://NOERROR` [fixed-answer server](#fixed-answer-servers) produces byte-identical output, and gets that server's own `?ttl=` for free.

#### Final

Applied when no rule matches. **Omit `route.final` to fall back to the last rule.** Two explicit forms:

```json
"final": "overseas-dns"
```
Route unmatched queries straight to the named `route.servers` entry — this bypasses rule-level cache overrides/filters/add-ip entirely (global cache policy applies), since it isn't routed through any rule. (There is no empty-response fallback — to return NXDOMAIN/empty for specific names, route them to an `RCODE://` [fixed-answer server](#fixed-answer-servers) with an ordinary rule.) Omitting `route.final` altogether instead falls back to the *last configured rule*, which does keep that rule's own cache policy/filters/add-ip.

```json
"final": {
  "primary":       "domestic-dns",
  "secondary":     "overseas-dns",
  "answer-ip":     "cn-ip",
  "verdict-cache": { "size": 4096, "ttl": 3600 }
}
```
**Answer-ip test mode** — the winner is decided by IP-CIDR membership, not speed:

1. Both servers are queried concurrently.
2. The primary's answer IPs are tested against the `route.ruleset` tag(s) named by `answer-ip` (each must have `behavior: "ipcidr"`) — the same criterion [`rule.filter`'s `answer-ip`](#rule-filters) uses.
3. IPs in range → return primary's answer. IPs not in range → return secondary's answer.
4. The verdict is cached per domain (`verdict-cache`); subsequent queries skip the race.

Non-A/AAAA queries fall back to the first non-SERVFAIL answer.

| Field | Type | Description |
|-------|------|-------------|
| `primary` | string | `route.servers` name preferred when its answer IPs are in `answer-ip`'s range (required). |
| `secondary` | string | `route.servers` name used when the primary's IPs are not in `answer-ip`'s range (required). |
| `answer-ip` | string or string array | `route.ruleset` tag(s) (`behavior: "ipcidr"`) the primary's answer IPs are tested against (required), each optionally prefixed with `!` to exclude — same convention as [`rule.filter`'s `answer-ip`](#rule-filters), including the "primary wins" polarity: primary wins when it *matches* (which for an exclude-only `!tag` means none of its answer IPs are in `tag`'s range), secondary wins otherwise. |
| `noip-as-primary-ip` | bool | Treat NODATA primary replies as if their IPs were in range (default: `false`). |
| `verdict-cache` | object | Cache per-domain routing decisions to skip repeated answer-ip lookups (see below). |

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
| `upstream-max-inflight` | int | **auto** (`max(worker-threads × 256, 1024)`) | Per-upstream concurrent in-flight query limit (also the ceiling of the per-upstream AIMD window). Queries that exceed it SERVFAIL immediately and are counted in the `upstream_inflight_drops` stat. By Little's law this caps a single upstream at ~`limit ÷ RTT` queries/s; raise it for very high QPS forwarded to few upstreams. |
| `timeout-ms` | int (ms) | `3000` | Upstream query timeout. |
| `hedge-delay-ms` | int (ms) | `0` | Fire a second upstream if the primary hasn't replied after `3 × its own EWMA RTT` (adapts per node — a fast upstream hedges sooner, a naturally slower-but-healthy one isn't hedged against prematurely). This value is only the fallback used until a node has an RTT sample, or right after it fails. `0` = disabled. |
| `upstream-max-response-bytes` | int | `0` | Reject TCP/TLS upstream responses larger than this. `0` = no limit. |
| `tcp-max-connections` | int | `1024` | Maximum concurrent inbound TCP connections. `0` = unlimited. |
| `tcp-read-timeout-ms` | int (ms) | `5000` | Timeout for reading the DNS message body. `0` = disabled. |
| `tcp-idle-timeout-ms` | int (ms) | `30000` | Idle TCP connection timeout. `0` = disabled. |
| `udp-buf-size` | int | `4194304` | `SO_RCVBUF`/`SO_SNDBUF` size per UDP socket (bytes). |
| `upstream-udp-sockets` | int | **auto** (`max(worker-threads, 32)`) | UDP socket pool size per upstream node. |

### Cache

```json
"cache": {
  "size":    10000,
  "min-ttl": 0,
  "max-ttl": 0,
  "overrides": {
    "domestic-dns": { "min-ttl": 30 },
    "overseas-dns": { "no-cache": true }
  },
  "persist": {
    "path":     "/etc/pathdns/cache.db",
    "interval": 300
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `size` | int | `10000` | Cache capacity in entries (`0` disables). Global — the cache is one shared resource, not a per-rule one. |
| `min-ttl` | int (s) | `0` | Minimum TTL applied at cache insertion. Also the floor for NODATA/NXDOMAIN responses that carry no SOA. |
| `max-ttl` | int (s) | `0` | Maximum TTL applied at cache insertion. `0` = no cap. |
| `overrides` | object | — | Per-server cache policy, keyed by `route.servers` name (see [Per-server cache overrides](#per-server-cache-overrides)). |
| `persist.path` | string | — | File path for cache persistence. |
| `persist.interval` | int (s) | `0` | Save to disk every N seconds. `0` = save on shutdown only. |

Negative responses (NODATA/NXDOMAIN) are cached for their SOA TTL (capped at 10800 s per RFC 2308), clamped by `min-ttl`/`max-ttl`; with no SOA they fall to `min-ttl`. A fixed-answer `RCODE://` server's responses use their own `?ttl=` instead.

With `persist` configured, the cache survives restarts. On load, a config fingerprint is compared; if routing-relevant config has changed (rules, tags, cache policies, ruleset files), the persisted cache is discarded.

### Per-server cache overrides

`cache.overrides` is a map keyed by `route.servers` name; each entry tweaks the cache policy for every rule resolving through that server. Fields (all optional): `min-ttl` / `max-ttl` clamp that server's TTLs, and `no-cache: true` disables caching for it entirely.

| Example | Meaning |
|---------|---------|
| `"overrides": { "overseas-dns": { "no-cache": true } }` | Responses from any rule using the `overseas-dns` server are never cached. |
| `"overrides": { "domestic-dns": { "min-ttl": 30 } }` | Global floor stays 0; responses from `domestic-dns` get at least a 30s TTL. |
| `"overrides": { "domestic-dns": { "max-ttl": 3600 } }` | Global cap stays unset; responses from `domestic-dns` are capped at 3600s. |

An entry may set any subset of the three fields — a `min-ttl` override doesn't require a matching `max-ttl`. `no-cache: true` can't be combined with a `min-ttl`/`max-ttl` override for the same server (caching is off entirely, so a TTL bound would be meaningless). Referencing a server that no rule's `upstream` uses, or setting `min-ttl` above `max-ttl`, is a config error. These overrides don't apply when a query is answered by an explicit single-target `route.final` — that bypasses rule matching entirely and uses the global cache policy. A `rule.filter`'s `forward` action still uses the *matched* rule's own override (if any), not the forward target's, since the response is credited to that rule (see [Rule filters](#rule-filters)).

### Dashboard

```json
"dashboard": {
  "port":    8080,
  "token":   "your-secret-token",
  "memory":  1000,
  "channel": 4096,
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
| `tls://dns.google?bootstrap=domestic-dns` | DoT with hostname — resolved via the `domestic-dns` server at startup |
| `tls://1.1.1.1?sni=dns.example` | DoT with explicit SNI |
| `https://8.8.8.8/dns-query` | DNS-over-HTTPS (HTTP/2) |
| `quic://dns.adguard.com?bootstrap=domestic-dns` | DNS-over-QUIC (`--features doq`) |
| `h3://dns.cloudflare.com/dns-query?bootstrap=domestic-dns` | DoH over HTTP/3 (`--features h3`) |

Synthesised responses — `A://`, `AAAA://`, and `RCODE://NOERROR|NXDOMAIN|SERVFAIL|REFUSED` — are configured as [fixed-answer `route.servers` entries](#fixed-answer-servers), not as `rules.upstream` URLs directly.

**Per-upstream query parameters:**

| Parameter | Effect |
|-----------|--------|
| `?bootstrap=<server>` | Name of another `route.servers` entry used to look up this upstream's **hostname** at startup. The bootstrap query is sent to that server's address(es) and carries its `?mark=` fwmark, so a policy-routed resolver is defined once and reused by name. Required when the upstream is specified by hostname (e.g. `tls://dns.google`). The referenced server must be a real upstream (not a fixed answer) that resolves to IP-literal address(es); `/etc/resolv.conf` is never consulted. |
| `?ecs=strip` | Remove ECS before forwarding (default) |
| `?ecs=forward` | Forward ECS unchanged |
| `?ecs=1.2.3.0/24` | Replace ECS with a fixed subnet |
| `?sni=name` | Override the TLS SNI name (TLS-based upstreams only) |
| `?no-sni` | Disable TLS SNI extension (`tls://` only) |
| `?mark=0x1` | Apply a Linux `SO_MARK` (fwmark) to this upstream's egress socket(s) for policy routing. Hex (`0x1`) or decimal (`1`). Works on every transport (UDP/TCP/DoT/DoH/DoQ/DoH3). **Requires `CAP_NET_ADMIN`** — startup/connect fails with a clear error otherwise. |

**fwmark policy routing example** — send one upstream's traffic out a specific table/VPN:

```sh
# pathdns: "servers": { "vpn-dns": "udp://10.0.0.1?mark=0x1" }
ip rule add fwmark 0x1 table 100
ip route add default via 192.168.50.1 table 100   # e.g. a VPN/WAN gateway
```

Queries to that upstream are stamped with fwmark `0x1`, so the kernel routes them
via table 100 while everything else uses the main table.

A `udp://` upstream's sockets are `connect()`ed once and reused; if the underlying
policy-routed path later changes (VPN reconnect, new gateway), a long-lived socket
can end up routing packets nowhere with no error at all — UDP has no handshake to
fail. After 6 consecutive query timeouts on one upstream, PathdNS automatically
recreates its sockets (fresh bind + `SO_MARK` + connect) to pick up the current
route, rate-limited to once per 30s so a genuinely dead upstream doesn't churn
sockets pointlessly.

---

## Ruleset Files

`route.ruleset` is a list of mihomo-compatible rule-set entries, each with an
explicit tag:

```json
"ruleset": [
  { "tag": "cn",  "format": "mrs",  "behavior": "domain", "path": "/etc/pathdns/geosite-cn.mrs" },
  { "tag": "ads", "format": "text", "behavior": "domain", "path": "/etc/pathdns/ads.list" }
]
```

| Field | Values | Meaning |
|-------|--------|---------|
| `tag` | any string | Referenced by `rule.matcher`'s `tag:` expressions. Must be unique across `route.ruleset`. |
| `format` | `"mrs"` / `"text"` | `mrs`: mihomo's zstd-compressed rule-set binary (e.g. the files served by [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)). `text`: one pattern per line, blank lines and `#`/`//` full-line comments skipped (e.g. meta-rules-dat's `*.list` files). |
| `behavior` | `"domain"` / `"ipcidr"` | `domain`: matched against the query name; usable from `rule.matcher`'s `tag:`. `ipcidr`: matched against a resolved IP address; usable from both `route.final`'s `answer-ip` field (see [Final](#final)) and `rule.filter`'s `answer-ip` (see [Rule filters](#rule-filters)) — the same `answer-ip` tag reference either way. Using a tag from the wrong context (e.g. an `ipcidr` tag in `rule.matcher`, or a `domain` tag in `answer-ip`) is a config error. |
| `path` | file path | The rule-set file. Hot-reloaded on change. |

A rule-set file carries no tag of its own — the tag comes entirely from the
`tag` field. This also makes selective loading exact: an entry's file is
never opened unless its tag is referenced by a rule's `matcher`/`answer-ip` expression.

Domain-pattern conventions (shared by `mrs` and `text`, mihomo's own syntax):

| Pattern | Behaviour |
|---------|-----------|
| `example.com` (bare) | Exact match only |
| `+.example.com` | The domain itself and all dot-delimited subdomains |
| `*.example.com` | Single-label wildcard — matches `a.example.com` but not `example.com` or `a.b.example.com` |
| `.example.com` | Subdomains only, without the apex (rare; treated the same as `+.example.com`) |

There is no keyword/regex concept for rule-sets — that matches mihomo's own
`domain`-behavior format, which doesn't support it either.

`ipcidr`-behavior `text` files are one CIDR (`10.0.0.0/8`, `2001:db8::/32`) or
bare IP (treated as a full-length host route) per line, blank lines and
`#`/`//` full-line comments skipped. `mrs` files carry the same ranges in
mihomo's binary form.

---

## ipset / nftset

Uses native Linux netlink — no `ipset` or `nft` shell-out. This populates
sets with resolved IPs for external use (e.g. iptables/nftables policy
routing); it is unrelated to `route.final`'s `answer-ip` test fallback, which
matches against an in-memory `route.ruleset` entry instead (see
[Ruleset Files](#ruleset-files) and [Final](#final)).

- **Add sets** (populate with resolved IPs): a [`rule.filter`](#rule-filters) `accept` entry's `add-ip: "setname"`, gated on a `response-type` pinned to exactly one of `A`/`AAAA` so each entry targets one address family.

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
  "upstream": "overseas-dns"
}
```

`source`: `cache`, `upstream`, `singleflight`, `filtered`, `forwarded`, or `overload`.

- `filtered` — a `rule.filter`'s `drop` action fired; no reply was sent to the client.
- `forwarded` — a `rule.filter`'s `forward` action answered from a named server's upstream directly (see [Rule filters](#rule-filters)).

`upstream` identifies the `route.servers` entry that answered the query — a rule match reports the server its `upstream` field names. A [fixed-answer `route.servers` entry](#fixed-answer-servers) (`A://`/`AAAA://`/`RCODE://`) reports `upstream` too, no differently from a real upstream — the response is still attributed to the named server that produced it. For queries resolved through `route.final` (either the single-target form, or the primary/secondary object form, [see Final](#final)), `upstream` is `final-><name>` once the winning server is known — e.g. `final->domestic-dns` — or the generic `final` when it isn't (e.g. both sides failed).

---

## License

MIT
