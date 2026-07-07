"""Mock upstream DNS resolver over UDP + TCP. Answers deterministically by name.

Conventions:
  *.cn  -> A 1.1.1.1  (pretend "domestic")
  *     -> A 9.9.9.9  (pretend "overseas")
  name 'slow.test' -> delayed 1.5s
  name 'nx.test'   -> NXDOMAIN
  name 'echo.test' -> echoes the QNAME case in a TXT-ish way (just A 9.9.9.9)
  AAAA -> ::1 style addresses
It also records the last received QNAME (with 0x20 case) and ECS option to a file.
"""
import socket, struct, sys, threading, time, os, json
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import decode_name, encode_name

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5300
TAG = sys.argv[2] if len(sys.argv) > 2 else "up"
RECORD = f"recv_{TAG}.log"

def build_response(query, override_ip=None):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", query[:12])
    off = 12
    qname, off = decode_name(query, off)
    qtype, qclass = struct.unpack(">HH", query[off:off+4])
    qend = off + 4
    # record what we saw (preserve 0x20 case) + any ECS
    has_opt = False
    ecs_raw = None
    o = qend
    # crude scan for OPT in additional
    try:
        for _ in range(ar):
            n2, o = decode_name(query, o)
            rtype = struct.unpack(">H", query[o:o+2])[0]
            if rtype == 41:
                has_opt = True
                rdlen = struct.unpack(">H", query[o+8:o+10])[0]
                rdata = query[o+10:o+10+rdlen]
                if rdata:
                    ecs_raw = rdata.hex()
                o += 10 + rdlen
            else:
                rdlen = struct.unpack(">H", query[o+8:o+10])[0]
                o += 10 + rdlen
    except Exception:
        pass
    try:
        with open(RECORD, "a") as f:
            f.write(json.dumps({"qname_wire": qname, "qtype": qtype, "ecs": ecs_raw,
                                "has_opt": has_opt, "t": time.time()}) + "\n")
    except Exception:
        pass

    lname = qname.lower()
    if lname == "slow.test":
        time.sleep(1.5)
    rcode = 0
    answers = b""
    ancount = 0
    nscount = 0
    authority = b""
    if lname == "nx.test":
        rcode = 3
        # SOA in authority for negative caching
        soa = encode_name("nx.test") + struct.pack(">HHI", 6, 1, 60)
        rd = encode_name("ns.nx.test") + encode_name("root.nx.test") + struct.pack(">IIIII", 1, 3600, 600, 86400, 30)
        soa += struct.pack(">H", len(rd)) + rd
        authority = soa
        nscount = 1
    elif qtype == 1:  # A
        ip = override_ip or ("1.1.1.1" if lname.endswith(".cn") or lname == "cn" else "9.9.9.9")
        rd = socket.inet_aton(ip)
        answers = encode_name(qname) + struct.pack(">HHIH", 1, 1, 60, len(rd)) + rd
        ancount = 1
    elif qtype == 28:  # AAAA
        ip = "2606:4700:4700::1111" if lname.endswith(".cn") else "2001:4860:4860::8888"
        rd = socket.inet_pton(socket.AF_INET6, ip)
        answers = encode_name(qname) + struct.pack(">HHIH", 28, 1, 60, len(rd)) + rd
        ancount = 1
    else:
        # NODATA
        pass

    # echo QNAME exactly as received (0x20 preserved) -> reuse original question bytes
    question = query[12:qend]
    arcount = 0
    additional = b""
    if has_opt:
        additional = b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)
        arcount = 1
    resp_flags = 0x8180 | rcode  # QR + RD + RA + rcode
    header = struct.pack(">HHHHHH", qid, resp_flags, 1, ancount, nscount, arcount)
    return header + question + answers + authority + additional

def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        try:
            resp = build_response(data)
            s.sendto(resp, addr)
        except Exception as e:
            sys.stderr.write(f"mock err: {e}\n")

def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(16)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()

def handle_tcp(conn):
    try:
        while True:
            hdr = conn.recv(2)
            if len(hdr) < 2:
                break
            ln = struct.unpack(">H", hdr)[0]
            buf = b""
            while len(buf) < ln:
                c = conn.recv(ln - len(buf))
                if not c:
                    return
                buf += c
            resp = build_response(buf)
            conn.sendall(struct.pack(">H", len(resp)) + resp)
    except Exception:
        pass
    finally:
        conn.close()

if __name__ == "__main__":
    try:
        open(RECORD, "w").close()
    except Exception:
        pass
    threading.Thread(target=tcp_server, daemon=True).start()
    print(f"mock upstream {TAG} on 127.0.0.1:{PORT} (udp+tcp)", flush=True)
    udp_server()
