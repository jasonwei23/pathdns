"""Enhanced mock upstream: CNAME chains, large responses, configurable IPs."""
import socket, struct, sys, threading, time, os, json
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import decode_name, encode_name

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5300
TAG = sys.argv[2] if len(sys.argv) > 2 else "up"
# Optional fixed A IP for ALL names (used to make primary/secondary differ)
FIXED_A = sys.argv[3] if len(sys.argv) > 3 else None
RECORD = f"recv2_{TAG}.log"

def a_rr(name, ip, ttl=60):
    rd = socket.inet_aton(ip)
    return encode_name(name) + struct.pack(">HHIH", 1, 1, ttl, len(rd)) + rd

def aaaa_rr(name, ip, ttl=60):
    rd = socket.inet_pton(socket.AF_INET6, ip)
    return encode_name(name) + struct.pack(">HHIH", 28, 1, ttl, len(rd)) + rd

def cname_rr(name, target, ttl=60):
    rd = encode_name(target)
    return encode_name(name) + struct.pack(">HHIH", 5, 1, ttl, len(rd)) + rd

def build_response(query):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
    off = 12
    qname, off = decode_name(query, off)
    qtype, qclass = struct.unpack(">HH", query[off:off+4])
    qend = off + 4
    has_opt = False
    o = qend
    try:
        for _ in range(ar):
            n2, o = decode_name(query, o)
            rtype = struct.unpack(">H", query[o:o+2])[0]
            rdlen = struct.unpack(">H", query[o+8:o+10])[0]
            if rtype == 41:
                has_opt = True
            o += 10 + rdlen
    except Exception:
        pass
    try:
        with open(RECORD, "a") as f:
            f.write(json.dumps({"qname": qname, "qtype": qtype, "t": time.time()}) + "\n")
    except Exception:
        pass

    lname = qname.lower()
    answers = b""
    ancount = 0
    nscount = 0
    authority = b""
    rcode = 0

    if lname == "nx.test":
        rcode = 3
    elif lname.startswith("chain") and qtype == 1:
        # CNAME chain: chainN.test -> c1.cdn.test -> c2.cdn.test -> A 9.9.9.9
        answers = cname_rr(qname, "c1.cdn.test")
        answers += cname_rr("c1.cdn.test", "c2.cdn.test")
        answers += a_rr("c2.cdn.test", FIXED_A or "9.9.9.9")
        ancount = 3
    elif lname == "big.test" and qtype == 1:
        # Many A records to force a response > 512 bytes (no EDNS) -> truncation
        for i in range(40):
            answers += a_rr(qname, f"10.0.{i//256}.{i%256}")
        ancount = 40
    elif qtype == 1:
        ip = FIXED_A or ("1.1.1.1" if lname.endswith(".cn") else "9.9.9.9")
        answers = a_rr(qname, ip)
        ancount = 1
    elif qtype == 28:
        ip = "2606:4700:4700::1111" if lname.endswith(".cn") else "2001:4860:4860::8888"
        answers = aaaa_rr(qname, ip)
        ancount = 1

    question = query[12:qend]
    arcount = 0
    additional = b""
    if has_opt:
        additional = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
        arcount = 1
    resp_flags = 0x8180 | rcode
    header = struct.pack(">HHHHHH", qid, resp_flags, 1, ancount, nscount, arcount)
    return header + question + answers + authority + additional

def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        try:
            s.sendto(build_response(data), addr)
        except Exception as e:
            sys.stderr.write(f"mock err: {e}\n")

def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT)); s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()

def handle_tcp(conn):
    try:
        while True:
            hdr = conn.recv(2)
            if len(hdr) < 2: break
            ln = struct.unpack(">H", hdr)[0]
            buf = b""
            while len(buf) < ln:
                c = conn.recv(ln - len(buf))
                if not c: return
                buf += c
            resp = build_response(buf)
            conn.sendall(struct.pack(">H", len(resp)) + resp)
    except Exception:
        pass
    finally:
        conn.close()

if __name__ == "__main__":
    try: open(RECORD, "w").close()
    except Exception: pass
    threading.Thread(target=tcp_server, daemon=True).start()
    print(f"mock2 {TAG} on 127.0.0.1:{PORT} fixedA={FIXED_A}", flush=True)
    udp_server()
