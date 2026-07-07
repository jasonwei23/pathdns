"""Upstream mock with a fixed delay and fixed A IP. Args: port tag ip delay_ms"""
import socket, struct, sys, threading, time, os
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import decode_name, encode_name

PORT=int(sys.argv[1]); TAG=sys.argv[2]; IP=sys.argv[3]; DELAY=float(sys.argv[4])/1000.0

def build(query):
    qid,flags,qd,an,ns,ar=struct.unpack(">HHHHHH",query[:12])
    off=12; qname,off=decode_name(query,off)
    qtype,qclass=struct.unpack(">HH",query[off:off+4]); qend=off+4
    has_opt=False; o=qend
    try:
        for _ in range(ar):
            n2,o=decode_name(query,o); rt=struct.unpack(">H",query[o:o+2])[0]
            rdlen=struct.unpack(">H",query[o+8:o+10])[0]
            if rt==41: has_opt=True
            o+=10+rdlen
    except Exception: pass
    if DELAY>0: time.sleep(DELAY)
    ans=b""; anc=0
    if qtype==1:
        rd=socket.inet_aton(IP); ans=encode_name(qname)+struct.pack(">HHIH",1,1,60,len(rd))+rd; anc=1
    q=query[12:qend]; arc=0; add=b""
    if has_opt: add=b"\x00"+struct.pack(">HHIH",41,4096,0,0); arc=1
    return struct.pack(">HHHHHH",qid,0x8180,1,anc,0,arc)+q+ans+add

def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",PORT))
    while True:
        d,a=s.recvfrom(65535)
        threading.Thread(target=lambda d=d,a=a: s.sendto(build(d),a),daemon=True).start()

print(f"slowmock {TAG} :{PORT} ip={IP} delay={DELAY*1000:.0f}ms",flush=True)
udp()
