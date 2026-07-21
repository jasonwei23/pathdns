"""Rich upstream mock for feature testing. Behavior keyed by qname prefix.
Logs received ECS + qname to recv_<tag>.log. Args: port tag [delay_ms]"""
import socket, struct, sys, threading, time, os, json
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import decode_name, encode_name

PORT=int(sys.argv[1]); TAG=sys.argv[2]
DELAY=float(sys.argv[3])/1000.0 if len(sys.argv)>3 else 0.0
DEAD = (len(sys.argv)>4 and sys.argv[4]=="dead")
REC=f"recv_{TAG}.log"
HITS={"n":0}

def soa(name, minttl):
    rd=encode_name("ns."+name)+encode_name("root."+name)+struct.pack(">IIIII",1,3600,600,86400,minttl)
    return encode_name(name)+struct.pack(">HHIH",6,1,minttl,len(rd))+rd

def build(query):
    qid,flags,qd,an,ns,ar=struct.unpack(">HHHHHH",query[:12])
    off=12; qname,off=decode_name(query,off)
    qtype,qclass=struct.unpack(">HH",query[off:off+4]); qend=off+4
    has_opt=False; ecs=None; o=qend
    try:
        for _ in range(ar):
            n2,o=decode_name(query,o); rt=struct.unpack(">H",query[o:o+2])[0]
            rdlen=struct.unpack(">H",query[o+8:o+10])[0]; rdata=query[o+10:o+10+rdlen]
            if rt==41:
                has_opt=True
                p=0
                while p+4<=len(rdata):
                    oc=struct.unpack(">H",rdata[p:p+2])[0]; ol=struct.unpack(">H",rdata[p+2:p+4])[0]
                    if oc==8: ecs=rdata[p+4:p+4+ol].hex()
                    p+=4+ol
            o+=10+rdlen
    except Exception: pass
    HITS["n"]+=1
    try:
        with open(REC,"a") as f: f.write(json.dumps({"qname":qname,"qtype":qtype,"ecs":ecs,"t":time.time()})+"\n")
    except Exception: pass

    ln=qname.lower()
    if DELAY>0: time.sleep(DELAY)
    rcode=0; ans=b""; anc=0; auth=b""; nsc=0
    # ttlNNN.* -> A with ttl NNN
    ttl=60
    if ln.startswith("ttl"):
        try: ttl=int(ln.split(".")[0][3:])
        except: ttl=60
    if ln.startswith("nxdomain"):
        rcode=3; auth=soa("nxdomain.test",90); nsc=1
    elif ln.startswith("nodata"):
        auth=soa("nodata.test",70); nsc=1   # NOERROR, no answer, SOA min 70
    elif ln.startswith("big") and qtype==1:
        for i in range(40): rd=socket.inet_aton(f"10.0.{i//256}.{i%256}"); ans+=encode_name(qname)+struct.pack(">HHIH",1,1,60,len(rd))+rd
        anc=40
    elif qtype==1:
        rd=socket.inet_aton("9.9.9.9"); ans=encode_name(qname)+struct.pack(">HHIH",1,1,ttl,len(rd))+rd; anc=1
    elif qtype==28:
        rd=socket.inet_pton(socket.AF_INET6,"2001:4860:4860::8888"); ans=encode_name(qname)+struct.pack(">HHIH",28,1,ttl,len(rd))+rd; anc=1
    q=query[12:qend]; arc=0; add=b""
    if has_opt: add=b"\x00"+struct.pack(">HHIH",41,4096,0,0); arc=1
    return struct.pack(">HHHHHH",qid,0x8180|rcode,1,anc,nsc,arc)+q+ans+auth+add

def handle(d,a,s):
    if DEAD: return
    try: s.sendto(build(d),a)
    except Exception as e: sys.stderr.write(f"err {e}\n")

def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",PORT))
    while True:
        d,a=s.recvfrom(65535)
        threading.Thread(target=handle,args=(d,a,s),daemon=True).start()

def tcp():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",PORT)); s.listen(16)
    while True:
        c,_=s.accept(); threading.Thread(target=htcp,args=(c,),daemon=True).start()
def htcp(c):
    try:
        while True:
            h=c.recv(2)
            if len(h)<2: break
            ln=struct.unpack(">H",h)[0]; b=b""
            while len(b)<ln:
                x=c.recv(ln-len(b))
                if not x: return
                b+=x
            if DEAD: return
            r=build(b); c.sendall(struct.pack(">H",len(r))+r)
    except Exception: pass
    finally: c.close()

if __name__=="__main__":
    open(REC,"w").close()
    threading.Thread(target=tcp,daemon=True).start()
    print(f"richmock {TAG} :{PORT} delay={DELAY*1000:.0f}ms dead={DEAD}",flush=True)
    udp()
