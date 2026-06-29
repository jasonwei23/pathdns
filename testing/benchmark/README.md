# Pure-forwarding benchmark

Compares **pathdns** against **unbound**, **smartdns**, and **mosdns** in the one
job a forwarder does on the hot path: receive a query, forward it to one upstream,
return the answer. Caching is disabled in every resolver and the load is a stream
of **unique** qnames, so every query is a real forward (no cache hits, no
single-flight collapsing).

## How it works

```
dnsperf  ──queries──▶  resolver  ──forward──▶  mock upstream (rustmock, :5300)
   ▲                   (:5301..5304)                │
   └──────────────────── answers ◀──────────────────┘
```

- **Mock upstream** (`rustmock.rs`, std-only): answers every query `NOERROR A
  9.9.9.9`, echoing the question (so 0x20 case checks pass). It sustains
  ~300–500k q/s so it never becomes the bottleneck. `benchmock.py` is a slower
  Python fallback (`MOCK=py`).
- **Load generator**: `dnsperf` with a file of unique names and N outstanding
  queries.
- **orchestrator.py** runs everything inside one process tree (so backgrounded
  servers aren't reaped), measures the mock ceiling, then for each resolver:
  starts it, waits for readiness, runs dnsperf `REPEATS` times, records the
  median q/s, average latency, and **NOERROR%**, and prints a comparison table.

`NOERROR%` is the correctness guard: it must be ~100, meaning every query was
genuinely forwarded and answered. A resolver that returns SERVFAIL/NXDOMAIN
without forwarding would otherwise post a misleadingly high q/s (this is exactly
how the harness caught two setup bugs — see "Gotchas").

## Prerequisites

```sh
# pathdns (release build)
cargo build --release

# comparison resolvers + load generator
sudo apt-get install -y dnsperf unbound smartdns
# mosdns: download a release binary and point MOSDNS_BIN at it, or put it on PATH
#   https://github.com/IrineSistiana/mosdns/releases
```

Any resolver whose binary is missing is skipped automatically. `rustmock` is
compiled on first run if `rustc` is present; `queries.txt` is generated on first
run.

## Run

```sh
cd testing/benchmark

# simple: all four on all cores
python3 orchestrator.py

# pinned (recommended on a small box): mock->core0, resolver->cores1-2,
# dnsperf->core3, so the load generator and upstream never starve the resolver.
PIN=1 MOCK_CPU=0 RESOLVER_CPU=1,2 DNSPERF_CPU=3 \
  DURATION=15 REPEATS=3 CLIENTS=8 OUTSTANDING=500 python3 orchestrator.py

# cache-hit mode: a small repeating working set served from each resolver's
# own cache (measures the cache hot path, not forwarding). Uses the *_cache
# configs and a 2000-name query file.
MODE=cache NCACHE=2000 PIN=1 MOCK_CPU=0 RESOLVER_CPU=1,2 DNSPERF_CPU=3 \
  DURATION=15 REPEATS=3 python3 orchestrator.py
```

Key env knobs: `MODE` (`forward`/`cache`), `DURATION`, `REPEATS`, `CLIENTS`
(`-c`), `OUTSTANDING` (`-q`), `PIN`, `*_CPU`, `MOCK` (`rust`/`py`),
`PATHDNS_BIN`, `MOSDNS_BIN`, `NQUERIES`, `NCACHE`.

## Configs

Forward mode (`*.json`/`.conf`/`.yaml`) — pure-forward, cache disabled.
Cache mode (`*_cache.*`) — caching enabled, same single upstream.

| File | Resolver | Notes |
|------|----------|-------|
| `pathdns.json` / `pathdns_cache.json` | pathdns :5301 | catch-all rule → upstream; `cache.size` 0 vs 1M; `runtime.upstream-max-inflight` raised (see below) |
| `unbound.conf` / `unbound_cache.conf` | unbound :5302 | `forward-zone "."`; `local-zone "test." nodefault`; cache off (`*-ttl 0`) vs big msg/rrset cache |
| `smartdns.conf` / `smartdns_cache.conf` | smartdns :5303 | single `server`; `speed-check-mode none`; `cache-size` 0 vs 1M |
| `mosdns.yaml` / `mosdns_cache.yaml` | mosdns :5304 | v5 `forward` + `udp_server`; cache variant adds a `cache` plugin + `has_resp`→`accept` short-circuit |

## Results

> Single 4-core box (Xeon @ 2.1 GHz), Linux 6.18, pinned, Rust mock, 15s ×3
> median, `-c8 -q500`, kernel `net.core.rmem_default=16M`. Absolute q/s is
> depressed because the resolver, load generator, and mock all share 4 cores —
> **the relative ordering and the NOERROR% are the signal, not the absolute q/s.**

| resolver | q/s (median) | avg latency | NOERROR% | notes |
|----------|-------------:|------------:|---------:|-------|
| smartdns | 68,966 | 7.21 ms | 100.0% | fastest here |
| mosdns   | 63,793 | 2.49 ms | 100.0% | lowest latency, but dropped ~1k queries/run |
| **pathdns** | **61,426** | **8.01 ms** | **99.9%** | 0 dropped, with `upstream-max-inflight: 4096` |
| unbound  | 56,771 | 8.77 ms | 100.0% | |

All four land within ~20% of each other — on this workload pure-forwarding
throughput is dominated by the kernel UDP path and CPU contention, not by the
resolver. pathdns sits mid-pack (slightly behind smartdns/mosdns, ahead of
unbound) and was the only one besides smartdns with zero dropped queries.

Caveat: with pathdns left at its **default `upstream-max-inflight: 256`**, the
same run produced ~61k q/s but only **~77–86% NOERROR** (the rest SERVFAIL) — see
below. The number above uses the raised cap.

### Cache-hit mode (`MODE=cache`, 2000-name working set)

Same box/setup; every query (after a tiny warmup) is served from the resolver's
own in-memory cache, so the upstream is idle — this measures the cache hot path.

| resolver | q/s (median) | avg latency | NOERROR% | vs forward |
|----------|-------------:|------------:|---------:|-----------:|
| unbound  | 274,931 | 0.64 ms | 100.0% | 4.8× |
| **pathdns** | **184,556** | **0.80 ms** | **100.0%** | **3.0×** |
| smartdns | 158,097 | 3.13 ms | 100.0% | 2.3× |
| mosdns   | 150,788 | 0.88 ms | 100.0% | 2.4× (dropped ~1.1k/run) |

Cache serving spreads the field much more than forwarding does. **unbound is the
clear leader** (~275k q/s) — cache lookup is the core of a recursive resolver and
it is heavily optimised for it. **pathdns is a solid second** at ~185k q/s and
3× its own forwarding rate, ahead of smartdns and mosdns. smartdns posts notably
higher cache latency here (~3 ms); mosdns again dropped ~1k queries/run.

Every resolver was verified to *actually* cache before timing (100 repeated
queries → exactly 1 upstream forward); mosdns needed an explicit
`has_resp`→`accept` short-circuit, otherwise its sequence re-forwarded on every
hit.

## Important: `upstream-max-inflight`

pathdns defaults to **256** concurrent in-flight queries per upstream
(`runtime.upstream-max-inflight`). Beyond that it fast-fails excess queries with
SERVFAIL rather than queueing them. Under a load test with `-q500` outstanding,
that surfaces as ~15–25% SERVFAIL and caps throughput — **not** an upstream or
mock problem.

By Little's law the per-upstream ceiling is `inflight / RTT`: at the default 256
and a 20 ms upstream RTT that is only ~12.8k q/s **per upstream**. High-QPS
deployments forwarding to a small number of upstreams should raise this (the
benchmark uses `4096`). This is the single most important pathdns tuning knob for
pure-forwarding throughput.

## Gotchas this harness exposed

- **`.test` is RFC 6761 special-use.** unbound ships a default
  `local-zone: "test." static` that returns NXDOMAIN *before* the forward-zone,
  so it never forwarded (and posted an impossible q/s above the mock ceiling).
  Fixed with `local-zone: "test." nodefault`.
- **A slow (Python) mock starves under CPU contention** and drops datagrams;
  pathdns surfaces a lost upstream reply as SERVFAIL (it does not retransmit to
  the upstream, unlike unbound/smartdns/mosdns), so a slow mock unfairly
  penalises it. Use the Rust mock and watch NOERROR%.
