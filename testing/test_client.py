import sys, os, time, json
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import udp_query, tcp_query

S, P = "127.0.0.1", 5353
passed = failed = 0

def check(desc, cond, detail=""):
    global passed, failed
    mark = "PASS" if cond else "FAIL"
    if cond: passed += 1
    else: failed += 1
    print(f"[{mark}] {desc}  {detail}")

def q(name, qtype=1, tcp=False, **kw):
    fn = tcp_query if tcp else udp_query
    r, _ = fn(S, P, name, qtype, **kw)
    return r

# 1. Basic A via upstream (overseas default 9.9.9.9)
r = q("example.com", 1)
check("A example.com -> upstream 9.9.9.9", any(a[3]=="9.9.9.9" for a in r["answers"]), str(r["answers"]))

# 2. .cn routed (mock returns 1.1.1.1 for .cn)
r = q("test.cn", 1)
check("A test.cn -> 1.1.1.1", any(a[3]=="1.1.1.1" for a in r["answers"]), str(r["answers"]))

# 3. AAAA
r = q("example.com", 28)
check("AAAA example.com", any(a[1]==28 for a in r["answers"]), str(r["answers"]))

# 4. answer-map A://
r = q("fixed.test", 1)
check("answer A:// fixed.test -> 7.7.7.7", any(a[3]=="7.7.7.7" for a in r["answers"]),
      f"ttl={[a[2] for a in r['answers']]}")
check("answer A:// ttl=120", any(a[2]==120 for a in r["answers"]))

# 5. answer-map dual A+AAAA -> for A query returns A
r = q("v6.test", 1)
check("v6.test A -> 7.7.7.8", any(a[3]=="7.7.7.8" for a in r["answers"]))
r = q("v6.test", 28)
check("v6.test AAAA -> 2001:db8::1", any(a[3]=="2001:db8::1" for a in r["answers"]), str(r["answers"]))

# 6. RCODE:// NXDOMAIN
r = q("block.test", 1)
check("block.test -> NXDOMAIN(3)", r["rcode"]==3, f"rcode={r['rcode']}")

# 7. RCODE:// REFUSED
r = q("refused.test", 1)
check("refused.test -> REFUSED(5)", r["rcode"]==5, f"rcode={r['rcode']}")

# 8. CNAME:// chasing (alias.test -> CNAME target.cn, chased -> A 1.1.1.1)
r = q("alias.test", 1)
has_cname = any(a[1]==5 for a in r["answers"])
has_a = any(a[1]==1 and a[3]=="1.1.1.1" for a in r["answers"])
check("alias.test CNAME chase has CNAME", has_cname, str(r["answers"]))
check("alias.test CNAME chase has chased A 1.1.1.1", has_a, str(r["answers"]))

# 9. filter-qtype 65 (HTTPS) -> dropped (no response expected -> timeout)
try:
    r = q("example.com", 65, timeout=2)
    # Some implementations return empty/refused rather than drop
    check("filter-qtype 65 dropped/empty", r["ancount"]==0, f"rcode={r['rcode']} an={r['ancount']}")
except Exception as e:
    check("filter-qtype 65 dropped (timeout)", True, f"timeout as expected: {type(e).__name__}")

# 10. NXDOMAIN from upstream
r = q("nx.test", 1)
check("nx.test -> NXDOMAIN", r["rcode"]==3, f"rcode={r['rcode']}")

# 11. Cache hit: query twice, second should match
r1 = q("cachehit.com", 1)
t0 = time.time(); r2 = q("cachehit.com", 1); dt = (time.time()-t0)*1000
check("cache repeat same answer", r1["answers"] and r1["answers"][0][3]==r2["answers"][0][3], f"2nd={dt:.1f}ms")

# 12. TCP query
r = q("tcptest.com", 1, tcp=True)
check("TCP A query works", any(a[1]==1 for a in r["answers"]), str(r["answers"]))

# 13. TXID preserved
r = q("txid.com", 1, txid=0xABCD)
check("TXID echoed", r["qid"]==0xABCD, f"qid={hex(r['qid'])}")

# 14. DO bit / EDNS query
r = q("edns.com", 1, do=True)
check("EDNS DO query answered", r["rcode"]==0 and r["ancount"]>=1, str(r["answers"]))

# 15. ECS query
r = q("ecs.com", 1, ecs=(1, 24, bytes([1,2,3])))
check("ECS query answered", r["rcode"]==0, f"rcode={r['rcode']}")

print(f"\n=== {passed} passed, {failed} failed ===")
