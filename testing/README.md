# pathdns integration testing

Black-box test scripts for a **running** pathdns binary. These replace the old
in-tree `#[cfg(test)]` unit tests: instead of exercising functions in isolation,
they drive a live server over real UDP/TCP DNS and assert on the answers and on
the `/api/*` dashboard endpoints.

Everything here is plain Python 3 (standard library only) plus small DNS mock
upstreams. Run the scripts **from this directory** — they import the shared
`dnslib` helper via `os.path.dirname(__file__)` and resolve config/record paths
relative to the current working directory.

## Layout

| File | What it is |
|------|------------|
| `dnslib.py` | Shared DNS wire helpers: `build_query`, `parse_response`, `udp_query`, `tcp_query`, name (de)coding. Imported by every other script. |
| **Mock upstreams** | |
| `fastmock.py` | Tight single-thread `recvfrom`/`sendto` loop; answers every query `A 9.9.9.9`. For throughput/QPS tests. |
| `slowmock.py` | Fixed delay + fixed A IP. Args: `port tag ip delay_ms`. |
| `richmock.py` | Feature mock keyed by qname prefix; logs received ECS + 0x20 QNAME to `recv_<tag>.log`. Args: `port tag [delay_ms] [dead]`. |
| `mock_upstream.py` | UDP+TCP mock answering by convention (`*.cn → 1.1.1.1`, else `9.9.9.9`; `slow.test`, `nx.test`, …). Args: `port [tag]`. |
| `mock2.py` | Enhanced mock: CNAME chains, large (truncating) responses, configurable IPs. Args: `port [tag] [fixed_a]`. |
| **Tools** | |
| `loadgen.py` | UDP load generator: keeps N queries in flight, unique qnames (cache-miss). Args: `port conc duration`. |
| `sniff.py` | Raw-socket loopback capture; decodes DNS response shape to JSON lines. Args: `seconds port [out.jsonl]`. (Needs `CAP_NET_RAW`/root.) |
| **Test suites** | |
| `test_match.py` | 23-case domain-matching matrix (full / `+.` suffix / `*.` wildcard / ruleset tag include+exclude / precedence / rule routing / normalisation). Self-contained with `cfg_match.json`. |
| `test_client.py` | Core client behaviour over UDP + TCP against a running server. |
| `test_edge.py` | Edge cases + dashboard counter assertions (`/api/stats`). |
| `test_inflight_cap.py` | Verifies the per-upstream inflight cap admits exactly `upstream-max-inflight` concurrent queries and that the `upstream_inflight_drops` stat counts the rest. Args: `[pathdns-binary]`. |
| **Benchmark** | |
| [`benchmark/`](benchmark/README.md) | Pure-forwarding throughput comparison vs unbound / smartdns / mosdns (dnsperf + fast mock upstream). |
| `cfg_match.json` | pathdns config used by `test_match.py` (fixed-answer `route.servers` entries + rules + `route.ruleset`). |
| `ruleset_cn.list` / `ruleset_gfw.list` / `ruleset_ads.list` | Plain-text (`format: text`) rule-sets consumed by `cfg_match.json`. |
| `ruleset_apple.mrs` | mihomo binary (`format: mrs`) rule-set consumed by `cfg_match.json`, exercising the `.mrs` decode path. |

## Quick start: the domain-matching matrix

`test_match.py` is the most self-contained suite. It needs one upstream mock
(routed-rule answers come from upstream) and a pathdns instance loaded with
`cfg_match.json` (dashboard on `:8080`, token `secret`).

```sh
cd testing

# 1. upstream mock that every rule points at (udp://127.0.0.1:5300)
python3 fastmock.py 5300 &

# 2. pathdns listening on 127.0.0.1:5353, dashboard on :8080
#    (run from this dir so the relative ruleset paths resolve)
../target/debug/pathdns -c cfg_match.json &

# 3. run the matrix
python3 test_match.py
```

Expected tail: `=== 23 passed, 0 failed ===`.

`test_match.py` reads each query's matched rule/source back from the query log
(`GET /api/querylog`), so the pathdns config must keep the dashboard enabled
(as `cfg_match.json` does).

## Notes

- Build the binary first: `cargo build` (debug at `target/debug/pathdns`) or
  `cargo build --release`.
- The mocks and `sniff.py` write `recv_*.log` / `cap.jsonl` into the working
  directory; these are git-ignored.
- `sniff.py` opens an `AF_PACKET` raw socket and must run as root.
- All scripts bind loopback only.
