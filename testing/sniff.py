"""Capture UDP DNS packets on loopback for port 5353 and decode response shape.
Usage: sniff.py <seconds> <port>
Writes JSON lines: dir, sport, dport, udp_len, dns parsed summary."""
import socket, struct, sys, time, json, os
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import decode_name

DUR = float(sys.argv[1]) if len(sys.argv) > 1 else 5
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5353
OUT = sys.argv[3] if len(sys.argv) > 3 else "cap.jsonl"

def parse_dns(buf):
    if len(buf) < 12:
        return {"err": "short", "size": len(buf)}
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    info = {"size": len(buf), "id": qid, "qr": (flags >> 15) & 1, "tc": (flags >> 9) & 1,
            "rcode": flags & 0xF, "qd": qd, "an": an, "ns": ns, "ar": ar, "opt": False,
            "opt_udpsize": None, "rtypes": []}
    off = 12
    try:
        for _ in range(qd):
            _, off = decode_name(buf, off); off += 4
        for _ in range(an):
            _, off = decode_name(buf, off)
            rt, rc, ttl, rdl = struct.unpack(">HHIH", buf[off:off+10]); off += 10 + rdl
            info["rtypes"].append(rt)
        for _ in range(ns):
            _, off = decode_name(buf, off)
            rt, rc, ttl, rdl = struct.unpack(">HHIH", buf[off:off+10]); off += 10 + rdl
        for _ in range(ar):
            no = off
            name, off = decode_name(buf, off)
            rt = struct.unpack(">H", buf[off:off+2])[0]
            cls = struct.unpack(">H", buf[off+2:off+4])[0]
            rdl = struct.unpack(">H", buf[off+8:off+10])[0]
            if rt == 41:
                info["opt"] = True
                info["opt_udpsize"] = cls
            off += 10 + rdl
    except Exception as e:
        info["parse_err"] = str(e)
    return info

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind(("lo", 0))
    s.settimeout(0.5)
    end = time.time() + DUR
    out = open(OUT, "w")
    n = 0
    while time.time() < end:
        try:
            frame = s.recv(65535)
        except socket.timeout:
            continue
        # loopback: 16-byte sll? On AF_PACKET raw with lo we get the ethernet-ish hdr.
        # Find IPv4 header: try offsets 0,2,14,16
        for base in (14, 16, 0, 2):
            if base + 20 > len(frame):
                continue
            vihl = frame[base]
            if (vihl >> 4) != 4:
                continue
            ihl = (vihl & 0xF) * 4
            proto = frame[base + 9]
            if proto != 17:  # UDP
                break
            ipend = base + ihl
            if ipend + 8 > len(frame):
                break
            sport, dport, ulen, _ = struct.unpack(">HHHH", frame[ipend:ipend+8])
            if PORT not in (sport, dport):
                break
            payload = frame[ipend+8: ipend+ulen]
            rec = {"dir": "resp" if sport == PORT else "query",
                   "sport": sport, "dport": dport, "udp_len": ulen,
                   "dns": parse_dns(payload)}
            out.write(json.dumps(rec) + "\n"); out.flush()
            n += 1
            break
    out.close()
    print(f"captured {n} packets -> {OUT}", flush=True)

if __name__ == "__main__":
    main()
