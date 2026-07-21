"""Minimal high-throughput UDP DNS mock for benchmarking upstreams.
Answers every query NOERROR with one A record (9.9.9.9), echoing the question.
SO_REUSEPORT so several instances can share one port (kernel load-balances).
Args: port"""
import socket, struct, sys
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5300
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 << 20)
s.bind(("127.0.0.1", PORT))
A_RR = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("9.9.9.9")
buf = bytearray(2048)
recvinto = s.recvfrom_into
sendto = s.sendto
while True:
    try:
        n, addr = recvinto(buf)
        if n < 12:
            continue
        # response: copy query, set QR+AA, ancount=1, append one A RR
        m = bytearray(buf[:n])
        m[2] = 0x84            # QR=1, AA=1, opcode 0
        m[3] = 0x00
        m[6] = 0; m[7] = 1     # ANCOUNT=1
        m[8] = 0; m[9] = 0     # NSCOUNT=0
        m[10] = 0; m[11] = 0   # ARCOUNT=0 (drop any OPT for simplicity)
        # truncate any additional/authority by only keeping header+question
        # find question end
        off = 12
        while off < n and buf[off] != 0:
            off += 1 + buf[off]
        qend = off + 1 + 4     # null label + qtype + qclass
        sendto(bytes(m[:12]) + bytes(buf[12:qend]) + A_RR, addr)
    except Exception:
        pass
