import sys, os, socket, struct, time, json, urllib.request
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import udp_query, tcp_query, build_query, parse_response

S, P = "127.0.0.1", 5353

def stats():
    req = urllib.request.Request("http://127.0.0.1:8080/api/stats",
                                 headers={"Authorization": "Bearer secret"})
    return json.load(urllib.request.urlopen(req))

# Baseline
b = stats()
print("baseline tcp=%d udp=%d total=%d" % (b["queries_tcp"], b["queries_udp"], b["queries_total"]))

# Send 5 distinct TCP queries (cache misses)
for i in range(5):
    tcp_query(S, P, f"tcponly{i}.example", 1)
a = stats()
print("after 5 TCP miss: tcp=%d udp=%d total=%d  (delta tcp=%d udp=%d)"
      % (a["queries_tcp"], a["queries_udp"], a["queries_total"],
         a["queries_tcp"]-b["queries_tcp"], a["queries_udp"]-b["queries_udp"]))

# Malformed: truncated packet (just 3 bytes)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(b"\x12\x34\x01", (S, P))
try:
    d,_ = s.recvfrom(4096); print("malformed 3-byte -> got %d bytes resp" % len(d))
except socket.timeout:
    print("malformed 3-byte -> dropped (no response) [OK]")
s.close()

# Header only, 0 questions
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
hdr = struct.pack(">HHHHHH", 0x1111, 0x0100, 0, 0, 0, 0)
s.sendto(hdr, (S, P))
try:
    d,_ = s.recvfrom(4096); r=parse_response(d)
    print("qdcount=0 -> resp rcode=%d (FORMERR=1 expected)" % r["rcode"])
except socket.timeout:
    print("qdcount=0 -> dropped (no response)")
s.close()

# Non-QUERY opcode (opcode=2 STATUS) -> NOTIMP(4) expected
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
flags = (2<<11)  # opcode=2
msg = struct.pack(">HHHHHH", 0x2222, flags, 1, 0, 0, 0) + b"\x03foo\x00" + struct.pack(">HH",1,1)
s.sendto(msg, (S, P))
try:
    d,_ = s.recvfrom(4096); r=parse_response(d)
    print("opcode=2 STATUS -> rcode=%d (NOTIMP=4 expected)" % r["rcode"])
except socket.timeout:
    print("opcode=2 -> dropped")
s.close()

# CHAOS class -> NOTIMP(4)
r,_ = udp_query(S, P, "version.bind", 16)  # TXT but class IN; test class via raw
# raw CHAOS
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
msg = struct.pack(">HHHHHH", 0x3333, 0x0100, 1, 0, 0, 0) + b"\x07version\x04bind\x00" + struct.pack(">HH",16,3)
s.sendto(msg,(S,P))
try:
    d,_=s.recvfrom(4096); r=parse_response(d); print("CHAOS class -> rcode=%d (NOTIMP=4 expected)"%r["rcode"])
except socket.timeout:
    print("CHAOS -> dropped")
s.close()

print("\nfinal stats:", json.dumps({k:stats()[k] for k in ["queries_total","queries_udp","queries_tcp","filtered","upstream_ok","upstream_err"]}))
