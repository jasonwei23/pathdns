"""UDP DNS load generator: keep CONC queries in flight for DURATION seconds,
count completed responses. Each query has a unique qname (forces cache miss)."""
import socket, struct, sys, time, select

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5353
CONC = int(sys.argv[2]) if len(sys.argv) > 2 else 512
DURATION = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0

def mkquery(seq):
    qid = seq & 0xFFFF
    name = b""
    for label in (f"h{seq}", "bench", "test"):
        b = label.encode(); name += bytes([len(b)]) + b
    name += b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)

socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(min(CONC, 64))]
for s in socks:
    s.setblocking(False)
    s.connect(("127.0.0.1", PORT))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)

seq = 0
completed = 0
errors = 0
inflight_per = [0] * len(socks)
TARGET = CONC // len(socks) + 1
poller = select.poll()
for s in socks:
    poller.register(s, select.POLLIN)
fdmap = {s.fileno(): s for s in socks}

end = time.time() + DURATION
# prime
for idx, s in enumerate(socks):
    for _ in range(TARGET):
        try:
            s.send(mkquery(seq)); seq += 1; inflight_per[idx] += 1
        except BlockingIOError:
            break

while time.time() < end:
    for fd, ev in poller.poll(100):
        s = fdmap[fd]; idx = socks.index(s)
        # drain all available responses
        while True:
            try:
                d = s.recv(2048)
            except BlockingIOError:
                break
            except Exception:
                errors += 1; break
            completed += 1
            inflight_per[idx] -= 1
            # refill
            try:
                s.send(mkquery(seq)); seq += 1; inflight_per[idx] += 1
            except BlockingIOError:
                pass

elapsed = DURATION
print(f"CONC={CONC} duration={DURATION}s completed={completed} errors={errors} "
      f"QPS={completed/elapsed:,.0f}")
