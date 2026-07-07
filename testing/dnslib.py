"""Minimal DNS message encode/decode + a mock UDP/TCP upstream. No deps."""
import struct, socket

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label == "":
            continue
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"

def decode_name(buf, off):
    labels = []
    jumped = False
    start_off = off
    while True:
        length = buf[off]
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                start_off = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        if length == 0:
            break
        labels.append(buf[off:off + length].decode("latin1"))
        off += length
    if not jumped:
        start_off = off
    return ".".join(labels), start_off

def build_query(name, qtype=1, qid=0x1234, rd=True, do=False, ecs=None, txid=None):
    if txid is not None:
        qid = txid
    flags = 0x0100 if rd else 0x0000
    arcount = 1 if (do or ecs is not None) else 0
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, arcount)
    q = encode_name(name) + struct.pack(">HH", qtype, 1)
    msg = header + q
    if arcount:
        # OPT record
        rdata = b""
        if ecs is not None:
            # ecs = (family, srcprefix, addrbytes)
            fam, srcp, addr = ecs
            opt_data = struct.pack(">HBB", fam, srcp, 0) + addr
            rdata = struct.pack(">HH", 8, len(opt_data)) + opt_data
        ttl = 0x00008000 if do else 0  # DO bit
        opt = b"\x00" + struct.pack(">HHIH", 41, 4096, ttl, len(rdata)) + rdata
        msg += opt
    return msg

def parse_response(buf):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0x0F
    off = 12
    questions = []
    for _ in range(qd):
        name, off = decode_name(buf, off)
        qtype, qclass = struct.unpack(">HH", buf[off:off+4])
        off += 4
        questions.append((name, qtype))
    answers = []
    for _ in range(an):
        name, off = decode_name(buf, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off+10])
        off += 10
        rdata = buf[off:off+rdlen]
        val = None
        if rtype == 1 and rdlen == 4:
            val = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and rdlen == 16:
            val = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            val, _ = decode_name(buf, off)
        answers.append((name, rtype, ttl, val))
        off += rdlen
    return {"qid": qid, "flags": flags, "rcode": rcode, "questions": questions,
            "answers": answers, "ancount": an, "raw": buf}

def udp_query(server, port, name, qtype=1, timeout=3, **kw):
    msg = build_query(name, qtype, **kw)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, (server, port))
    data, _ = s.recvfrom(65535)
    s.close()
    return parse_response(data), msg

def tcp_query(server, port, name, qtype=1, timeout=3, **kw):
    msg = build_query(name, qtype, **kw)
    s = socket.create_connection((server, port), timeout)
    s.settimeout(timeout)
    s.sendall(struct.pack(">H", len(msg)) + msg)
    ln = struct.unpack(">H", _recvn(s, 2))[0]
    data = _recvn(s, ln)
    s.close()
    return parse_response(data), msg

def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("short read")
        buf += chunk
    return buf
