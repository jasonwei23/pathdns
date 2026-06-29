#!/usr/bin/env python3
"""Pure-forwarding benchmark: pathdns vs unbound vs smartdns vs mosdns.

All resolvers forward every query to a shared mock upstream (127.0.0.1:5300),
caching disabled, so each query is a real forward. dnsperf drives load with a
file of unique qnames (no cache / single-flight hits). Everything runs inside
this one process tree so backgrounded servers are not reaped between steps.
"""
import subprocess, socket, struct, time, os, signal, sys, re

BENCH = os.path.dirname(os.path.abspath(__file__))
os.chdir(BENCH)
# Paths (override via env). PATHDNS_BIN / MOSDNS_BIN let you point at any build.
PR = os.environ.get("PATHDNS_BIN",
                    os.path.join(BENCH, "..", "..", "target", "release", "pathdns"))
MOSDNS = os.environ.get("MOSDNS_BIN", "mosdns")  # on PATH, or absolute path
MOCK_PORT = 5300
MOCK_INSTANCES = int(os.environ.get("MOCKS", "2"))
DURATION = int(os.environ.get("DURATION", "15"))
CLIENTS = int(os.environ.get("CLIENTS", "8"))
OUTSTANDING = int(os.environ.get("OUTSTANDING", "500"))
DNSPERF_THREADS = int(os.environ.get("DT", "4"))
NQUERIES = int(os.environ.get("NQUERIES", "500000"))

# MODE selects the workload:
#   forward (default): every query is a unique name -> a real upstream forward
#   cache: a small repeating working set -> after warmup ~all served from the
#          resolver's own cache (measures the cache hot path, not forwarding)
MODE = os.environ.get("MODE", "forward")
NCACHE = int(os.environ.get("NCACHE", "2000"))
SUFFIX = "_cache" if MODE == "cache" else ""
QFILE = "queries_cache.txt" if MODE == "cache" else "queries.txt"

def have(cmd):
    from shutil import which
    return which(cmd) or (os.path.isabs(cmd) and os.path.exists(cmd))

def bootstrap():
    """Generate the query file for the active MODE and compile the Rust mock."""
    if MODE == "cache":
        if not os.path.exists(QFILE):
            print(f"generating {QFILE} ({NCACHE} repeating names)...")
            with open(QFILE, "w") as f:
                f.write("\n".join(f"h{i}.bench.test A" for i in range(NCACHE)))
    elif not os.path.exists(QFILE):
        print(f"generating {QFILE} ({NQUERIES} unique names)...")
        with open(QFILE, "w") as f:
            f.write("\n".join(f"h{i}.bench.test A" for i in range(NQUERIES)))
    if not os.path.exists("./rustmock"):
        if have("rustc"):
            print("compiling rustmock...")
            subprocess.run(["rustc", "-O", "rustmock.rs", "-o", "rustmock"], cwd=BENCH, check=True)
        else:
            print("rustc not found; falling back to benchmock.py (set MOCK=py)")

PIN = os.environ.get("PIN", "0") == "1"
MOCK_CPU = os.environ.get("MOCK_CPU", "0")      # core(s) for mock pool
RESOLVER_CPU = os.environ.get("RESOLVER_CPU", "1,2")  # cores for the resolver
DNSPERF_CPU = os.environ.get("DNSPERF_CPU", "3")      # core for load generator

def pin(cmd, cpus):
    return (["taskset", "-c", cpus] + cmd) if PIN else cmd

procs = []
def spawn(cmd, **kw):
    p = subprocess.Popen(cmd, stdout=kw.get("out", subprocess.DEVNULL),
                         stderr=subprocess.STDOUT, cwd=BENCH)
    procs.append(p)
    return p

def mkq(name, qid=0x1234):
    n = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + n + struct.pack(">HH", 1, 1)

def wait_ready(port, timeout=8.0):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(0.3)
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            c.sendto(mkq("ready.bench.test"), ("127.0.0.1", port))
            c.recvfrom(2048); c.close(); return True
        except Exception:
            time.sleep(0.1)
    c.close(); return False

def kill(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try: p.wait(timeout=3)
        except Exception: p.kill()
    if p in procs: procs.remove(p)

REPEATS = int(os.environ.get("REPEATS", "3"))

def run_dnsperf(port):
    cmd = pin(["dnsperf", "-s", "127.0.0.1", "-p", str(port), "-d", QFILE,
               "-c", str(CLIENTS), "-T", str(DNSPERF_THREADS), "-q", str(OUTSTANDING),
               "-l", str(DURATION)], DNSPERF_CPU)
    out = subprocess.run(cmd, capture_output=True, text=True, cwd=BENCH).stdout
    qps = lat = lost = comp = None
    noerror = 0
    for line in out.splitlines():
        m = re.search(r"Queries per second:\s+([\d.]+)", line);      qps = float(m.group(1)) if m else qps
        m = re.search(r"Average Latency \(s\):\s+([\d.]+)", line);    lat = float(m.group(1)) if m else lat
        m = re.search(r"Queries lost:\s+(\d+)", line);                lost = int(m.group(1)) if m else lost
        m = re.search(r"Queries completed:\s+(\d+)", line);           comp = int(m.group(1)) if m else comp
        m = re.search(r"NOERROR\s+(\d+)", line);                      noerror = int(m.group(1)) if m else noerror
    noerr_pct = (100.0 * noerror / comp) if comp else 0.0
    return qps, lat, lost, noerr_pct, out

def median(xs):
    xs = sorted(x for x in xs if x is not None)
    return xs[len(xs) // 2] if xs else None

bootstrap()

# ── start the shared mock upstream pool ──────────────────────────────────────
MOCK_KIND = os.environ.get("MOCK", "rust")  # "rust" (fast) or "py"
if not os.path.exists("./rustmock"):
    MOCK_KIND = "py"
MOCK_THREADS = os.environ.get("MOCK_THREADS", "4")
if MOCK_KIND == "rust":
    spawn(pin(["./rustmock", str(MOCK_PORT), MOCK_THREADS], MOCK_CPU))
    label = f"1x rustmock ({MOCK_THREADS} threads)"
else:
    for _ in range(MOCK_INSTANCES):
        spawn(pin([sys.executable, "benchmock.py", str(MOCK_PORT)], MOCK_CPU))
    label = f"{MOCK_INSTANCES}x benchmock.py"
time.sleep(0.5)
if not wait_ready(MOCK_PORT):
    print("mock upstream not ready"); sys.exit(1)
print(f"mock upstream: {label} on :{MOCK_PORT}")

RESOLVER_CORES = len(RESOLVER_CPU.split(",")) if PIN else os.cpu_count()
ALL_RESOLVERS = [
    ("pathdns",  [PR, "-c", f"pathdns{SUFFIX}.json"],                5301),
    ("unbound",  ["unbound", "-d", "-c", f"unbound{SUFFIX}.conf"],   5302),
    ("smartdns", ["smartdns", "-f", "-c", f"smartdns{SUFFIX}.conf"], 5303),
    ("mosdns",   [MOSDNS, "start", "-c", f"mosdns{SUFFIX}.yaml", "-d", BENCH,
                  "--cpu", str(RESOLVER_CORES)],                     5304),
]
# Skip any resolver whose binary is not installed.
RESOLVERS = []
for name, cmd, port in ALL_RESOLVERS:
    if name == "pathdns" and not os.path.exists(PR):
        print(f"skip pathdns: binary not found at {PR} (build with cargo build --release)")
    elif name != "pathdns" and not have(cmd[0]):
        print(f"skip {name}: '{cmd[0]}' not found on PATH")
    else:
        RESOLVERS.append((name, cmd, port))

# ── upstream ceiling: point dnsperf straight at the mock ─────────────────────
print("\nmeasuring mock-upstream ceiling (dnsperf -> mock directly)...")
cq, cl, clost, cne, _ = run_dnsperf(MOCK_PORT)
print(f"  mock ceiling: {cq:,.0f} q/s, avg latency {cl*1000:.3f} ms")

results = []
for name, cmd, port in RESOLVERS:
    print(f"\n=== {name} (:{port}) ===")
    log = open(f"{name}.run.log", "w")
    p = spawn(pin(cmd, RESOLVER_CPU), out=log)
    if not wait_ready(port):
        print(f"  {name} FAILED to become ready; see {name}.run.log")
        kill(p); log.close(); results.append((name, None, None, None, None)); continue
    time.sleep(0.5)  # settle
    qpss, lats, losts, nes = [], [], [], []
    for r in range(REPEATS):
        qps, lat, lost, noerr, out = run_dnsperf(port)
        open(f"{name}.dnsperf.{r}.out", "w").write(out)
        if qps is not None:
            qpss.append(qps); lats.append(lat); losts.append(lost); nes.append(noerr)
            print(f"  run {r+1}: {qps:,.0f} q/s | {lat*1000:.3f} ms | NOERROR {noerr:.1f}% | lost {lost}")
    kill(p); log.close()
    results.append((name, median(qpss), median(lats), max(losts) if losts else None,
                    min(nes) if nes else None))
    time.sleep(0.5)

for p in list(procs): kill(p)

title = "CACHE-HIT" if MODE == "cache" else "PURE-FORWARDING"
print("\n" + "=" * 72)
print(f"{title} BENCHMARK  ({os.cpu_count()} cores, {DURATION}s x{REPEATS} median, "
      f"-c{CLIENTS} -q{OUTSTANDING})")
if MODE == "cache":
    print(f"working set: {NCACHE} names (repeating) -> served from each resolver's cache")
print(f"mock upstream ceiling (dnsperf->mock direct): {cq:,.0f} q/s")
print("=" * 72)
print(f"{'resolver':<10} {'q/s (median)':>14} {'avg lat (ms)':>14} {'NOERROR%':>10} {'lost':>8}")
print("-" * 72)
base = next((q for n, q, l, ls, ne in results if n == "pathdns" and q), None)
for name, qps, lat, lost, noerr in results:
    if qps is None:
        print(f"{name:<10} {'FAILED':>14}")
    else:
        rel = f"  {qps/base*100:.0f}% of pathdns" if base else ""
        print(f"{name:<10} {qps:>14,.0f} {lat*1000:>14.3f} {noerr:>9.1f}% {lost:>8}{rel}")
print("=" * 72)
print("Note: single 4-core box — resolver, dnsperf load generator, and the mock")
print("upstream all contend for the same CPUs, so absolute q/s is depressed and")
print("relative ordering is the meaningful signal. NOERROR% must be ~100 (all")
print("queries genuinely forwarded to the mock and answered).")
