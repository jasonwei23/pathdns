"""High-throughput UDP DNS mock: tight single-thread recvfrom/sendto loop.
Echoes the query as a NOERROR response with one A record (9.9.9.9)."""
import socket, struct, sys
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5300
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
s.bind(("127.0.0.1", PORT))
A_RR = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("9.9.9.9")
print(f"fastmock :{PORT}", flush=True)
recvinto = s.recvfrom_into
buf = bytearray(2048)
while True:
    try:
        n, addr = s.recvfrom_into(buf)
    except Exception:
        continue
    if n < 12:
        continue
    # Build response: copy header+question, set QR/RA, ANCOUNT=1, append A RR.
    # question ends at first 0x00 label terminator after offset 12, +4 (qtype+qclass)
    i = 12
    while i < n and buf[i] != 0:
        i += 1 + buf[i]
    qend = i + 1 + 4
    if qend > n:
        continue
    resp = bytearray(buf[:qend])
    resp[2] = 0x81; resp[3] = 0x80  # QR=1 RD=1 RA=1 rcode=0
    resp[6] = 0; resp[7] = 1        # ANCOUNT=1
    resp[8] = 0; resp[9] = 0        # NSCOUNT=0
    resp[10] = 0; resp[11] = 0      # ARCOUNT=0
    resp += A_RR
    try:
        s.sendto(resp, addr)
    except Exception:
        pass
