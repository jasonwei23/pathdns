"""Compare eager, lazy, and adaptive UDP batches on a Linux runner."""
import json
import os
import pathlib
import re
import socket
import statistics
import struct
import subprocess
import time
import urllib.request

work = pathlib.Path(os.environ["RUNNER_TEMP"])
alpha = list(sorted(os.sched_getaffinity(0)))
assert len(alpha) >= 4, alpha
dns_cpus = ",".join(map(str, alpha[:2]))
test_cpus = ",".join(map(str, alpha[2:4]))
dns_port = 15300
admin_port = 15301
nodes = 12
sockets_per_node = 4
upstream_ports = range(15400, 15400 + nodes)
endpoint = "127.0.0.1"
target = f"{endpoint}:{dns_port}"
config = work / "reuse-ab.json"
config.write_text(json.dumps({
    "bind": {"addr": endpoint, "port": dns_port, "proto": "udp"},
    "runtime": {"worker-threads": 2, "upstream-udp-sockets": sockets_per_node,
                "udp-diagnostics": "basic"},
    "cache": {"size": 0},
    "dashboard": {"port": admin_port, "memory": 0},
    "route": {
        "servers": {f"s{i}": f"udp://{endpoint}:{port}"
                    for i, port in enumerate(upstream_ports)},
        "rules": [{"matcher": [f"+.node{i}.test"], "upstream": f"s{i}"}
                  for i in range(nodes)],
        "final": "s0",
    },
}))


def launch(argv, cpus, **kwargs):
    return subprocess.Popen(["taskset", "-c", cpus, *map(str, argv)], **kwargs)


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def memory(pid):
    def field(name, key):
        for line in pathlib.Path(f"/proc/{pid}/{name}").read_text().splitlines():
            if line.startswith(key + ":"):
                return int(line.split()[1])
        raise KeyError(key)
    return {"vms_kib": field("status", "VmSize"),
            "pss_kib": field("smaps_rollup", "Pss"),
            "pss_anon_kib": field("smaps_rollup", "Pss_Anon")}


def prime():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)
        for node in range(nodes):
            name = f"node{node}".encode("ascii")
            qname = bytes([len(name)]) + name + b"\x04test\0"
            for query_id in range(sockets_per_node * 4):
                query = struct.pack(">6H", query_id, 0x100, 1, 0, 0, 0) + qname + b"\0\x01\0\x01"
                client.sendto(query, (endpoint, dns_port))
                reply = client.recv(512)
                assert reply[:2] == query[:2] and reply[3] & 15 == 0 and reply[6:8] == b"\0\x01"


def stats():
    with urllib.request.urlopen(f"http://{endpoint}:{admin_port}/api/stats", timeout=3) as reply:
        return json.load(reply)


mocks = []
runs = {"base": [], "lazy": [], "adaptive": []}
try:
    for port in upstream_ports:
        mocks.append(launch([work / "reuse-mock", port, 1, 0], test_cpus,
                            stderr=subprocess.DEVNULL))
    time.sleep(0.3)
    for variant in (
        "base", "lazy", "adaptive", "adaptive", "lazy", "base",
        "lazy", "base", "adaptive", "adaptive", "base", "lazy",
    ):
        server = launch([work / f"pathdns-{variant}", "-c", config], dns_cpus)
        try:
            for _ in range(60):
                assert server.poll() is None
                try:
                    stats()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("PathDNS never became ready")
            idle = memory(server.pid)
            prime()
            primed = memory(server.pid)
            before = stats()
            load = launch([work / "reuse-load", "udp", target, 2, 128, 5, "unique"],
                          test_cpus, stdout=subprocess.PIPE, text=True)
            try:
                samples = []
                for _ in range(3):
                    time.sleep(1.2)
                    samples.append(memory(server.pid))
                loaded = {key: statistics.median(s[key] for s in samples) for key in samples[0]}
                stdout, _ = load.communicate(timeout=15)
            finally:
                stop(load)
            assert load.returncode == 0
            row = re.search(r"= (\d+) qps .*p99~(\d+)us", stdout.split("  attempt")[0])
            assert row, stdout
            after = stats()
            data = {"idle": idle, "primed": primed, "loaded": loaded,
                    "qps": int(row[1]), "p99_us": int(row[2]),
                    "upstream_err": after["upstream_err"] - before["upstream_err"],
                    "rx_overflow": after["udp_rx_overflow"] - before["udp_rx_overflow"]}
            runs[variant].append(data)
            print(f"RESULT {variant} {json.dumps(data)} {stdout.strip()}", flush=True)
        finally:
            stop(server)
finally:
    for mock in mocks:
        stop(mock)

for variant, results in runs.items():
    medians = {k: statistics.median(result[k] for result in results)
               for k in ("qps", "p99_us", "upstream_err", "rx_overflow")}
    for stage in ("idle", "primed", "loaded"):
        medians[stage] = {field: statistics.median(result[stage][field] for result in results)
                          for field in results[0][stage]}
    print(f"MEDIAN {variant} {json.dumps(medians)}")
