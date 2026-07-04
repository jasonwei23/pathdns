#!/usr/bin/env python3
"""Regression test for the per-upstream inflight cap + upstream_inflight_drops stat.

Starts a deliberately SLOW upstream mock (so queries stay in flight), runs pathdns
with a small `upstream-max-inflight`, fires a concurrent burst larger than the cap,
and asserts that:
  * exactly `cap` queries succeed (NOERROR) and the rest SERVFAIL, and
  * the dashboard `upstream_inflight_drops` counter equals the SERVFAIL count
    (and the global `inflight_drops` stays 0 — they are distinct mechanisms).

Run from this directory:  python3 test_inflight_cap.py /path/to/pathdns
"""
import subprocess, socket, struct, time, signal, os, sys, json, threading, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PATHDNS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "target", "release", "pathdns")
CAP = 64
BURST = 200
PORT, MOCK_PORT, DASH = 5301, 5300, 8080

CFG = {
    "bind": {"addr": "127.0.0.1", "port": PORT, "proto": "udp"},
    "route": {"rules": [{"name": "all", "upstream": [f"udp://127.0.0.1:{MOCK_PORT}"]}], "final": "all"},
    "cache": {"size": 0},
    "runtime": {"worker-threads": 2, "upstream-max-inflight": CAP},
    "dashboard": {"port": DASH, "token": "secret"},
}

def slow_mock(port, stop, delay=0.25):
    """Reply to every query after `delay` seconds (keeps queries in flight)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.settimeout(0.2)
    A = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("9.9.9.9")
    def reply(d, a):
        time.sleep(delay)
        off = 12
        while off < len(d) and d[off] != 0:
            off += 1 + d[off]
        qe = off + 1 + 4
        m = bytearray(d[:qe]); m[2] = 0x84; m[3] = 0; m[6] = 0; m[7] = 1; m[8] = m[9] = m[10] = m[11] = 0
        try: s.sendto(bytes(m) + A, a)
        except OSError: pass
    while not stop.is_set():
        try: d, a = s.recvfrom(2048)
        except socket.timeout: continue
        threading.Thread(target=reply, args=(d, a), daemon=True).start()
    s.close()

def mkq(name, qid):
    n = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + n + struct.pack(">HH", 1, 1)

def stats():
    req = urllib.request.Request(f"http://127.0.0.1:{DASH}/api/stats", headers={"Authorization": "Bearer secret"})
    return json.load(urllib.request.urlopen(req))

def main():
    json.dump(CFG, open("inflight_cap.json", "w"))
    stop = threading.Event()
    t = threading.Thread(target=slow_mock, args=(MOCK_PORT, stop)); t.start()
    time.sleep(0.3)
    pd = subprocess.Popen([PATHDNS, "-c", "inflight_cap.json"],
                          stdout=open("inflight_cap.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(1.0)
    try:
        # Blocking sends (with a generous socket buffer) so every query reaches
        # the server; the slow mock (250 ms) keeps the permitted ones in flight
        # long enough that the rest hit the cap.
        socks = []
        for i in range(BURST):
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.settimeout(3.0)
            c.sendto(mkq(f"q{i}.cap.test", i & 0xffff), ("127.0.0.1", PORT))
            socks.append(c)
        noerr = servfail = lost = 0
        for c in socks:
            try:
                r, _ = c.recvfrom(2048); rc = r[3] & 0x0f
                noerr += rc == 0; servfail += rc == 2
            except socket.timeout:
                lost += 1
            c.close()
        st = stats()
        drops = st.get("upstream_inflight_drops", -1)
        gdrops = st.get("inflight_drops", -1)
        print(f"cap={CAP} burst={BURST}: NOERROR={noerr} SERVFAIL={servfail} lost={lost} | "
              f"upstream_inflight_drops={drops} global_inflight_drops={gdrops}")
        # Robust invariants: the cap admits exactly `cap` concurrent queries, the
        # rest SERVFAIL, the counter accounts for every cap rejection, and the
        # global slow-path counter (a different mechanism) is untouched.
        ok = (noerr == CAP and servfail == BURST - CAP
              and drops == servfail and gdrops == 0 and lost == 0)
        print("PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
    finally:
        pd.send_signal(signal.SIGTERM); time.sleep(0.3)
        if pd.poll() is None: pd.kill()
        stop.set(); t.join()

if __name__ == "__main__":
    main()
