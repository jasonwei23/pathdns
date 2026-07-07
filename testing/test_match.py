import sys, os, time, json, socket, struct, urllib.request
sys.path.insert(0, os.path.dirname(__file__))
from dnslib import udp_query

S, P = "127.0.0.1", 5353
passed = failed = 0

def querylog(qname):
    req = urllib.request.Request(
        "http://127.0.0.1:8080/api/querylog?limit=200",
        headers={"Authorization": "Bearer secret"})
    data = json.load(urllib.request.urlopen(req))
    evs = data if isinstance(data, list) else data.get("events", data.get("items", []))
    for e in evs:
        if e.get("qname", "").lower() == qname.lower():
            return e
    return None

def probe(qname, qtype=1):
    r, _ = udp_query(S, P, qname, qtype, timeout=3)
    time.sleep(0.05)
    e = querylog(qname)
    ips = [a[3] for a in r["answers"]]
    rule = e.get("rule") if e else "?"
    src = e.get("source") if e else "?"
    return {"rcode": r["rcode"], "ips": ips, "rule": rule, "source": src}

def chk(desc, got, want):
    global passed, failed
    ok = want(got)
    print("[%s] %-45s -> ips=%s rule=%s src=%s rcode=%d"
          % ("PASS" if ok else "FAIL", desc, got["ips"], got["rule"], got["source"], got["rcode"]))
    if ok: passed += 1
    else: failed += 1

print("=== ANSWER-MAP inline patterns ===")
chk("bare exact.test exact", probe("exact.test"), lambda g: "1.1.1.1" in g["ips"] and g["source"]=="answer")
chk("bare NOT subdomain (sub.exact.test)", probe("sub.exact.test"), lambda g: "1.1.1.1" not in g["ips"])
chk("+.zone.test apex", probe("zone.test"), lambda g: "2.2.2.2" in g["ips"])
chk("+.zone.test subdomain a.b.zone.test", probe("a.b.zone.test"), lambda g: "2.2.2.2" in g["ips"])
chk("+. boundary notzone.test (no match)", probe("notzone.test"), lambda g: "2.2.2.2" not in g["ips"])
chk("+. boundary zone.test.evil.com (no match)", probe("zone.test.evil.com"), lambda g: "2.2.2.2" not in g["ips"])
chk("*.wild.test single-label a.wild.test", probe("a.wild.test"), lambda g: "3.3.3.3" in g["ips"])
chk("*.wild.test NOT apex wild.test", probe("wild.test"), lambda g: "3.3.3.3" not in g["ips"])
chk("*.wild.test NOT two-label a.b.wild.test", probe("a.b.wild.test"), lambda g: "3.3.3.3" not in g["ips"])

print("=== Ruleset tag: expressions in answer-map ===")
chk("tag:cn,!gfw  bilibili.com (cn, not gfw)", probe("bilibili.com"), lambda g: "5.5.5.5" in g["ips"])
chk("tag:cn (suffix) sub.bilibili.com", probe("sub.bilibili.com"), lambda g: "5.5.5.5" in g["ips"])
chk("tag:cn (full) exactcn.test", probe("exactcn.test"), lambda g: "5.5.5.5" in g["ips"])
chk("tag:cn (wildcard) x.starcn.test", probe("x.starcn.test"), lambda g: "5.5.5.5" in g["ips"])
chk("tag:cn (wildcard boundary) a.b.starcn.test", probe("a.b.starcn.test"), lambda g: "5.5.5.5" not in g["ips"])
chk("tag:cn,!gfw EXCLUDES gfw: both-cn-gfw.test", probe("both-cn-gfw.test"), lambda g: "5.5.5.5" not in g["ips"])
chk("tag:ads -> NXDOMAIN  ads.doubleclick.net", probe("ads.doubleclick.net"), lambda g: g["rcode"]==3 and g["source"]=="answer")

print("=== PRECEDENCE ===")
chk("exact > tag: both.test (exact 6.6.6.6, not tag 5.5.5.5)", probe("both.test"), lambda g: "6.6.6.6" in g["ips"])

print("=== RULE routing (answer-map miss -> rules) ===")
# both-cn-gfw.test: answer tag:cn,!gfw excluded -> falls to rules -> domestic(cn)
chk("rule domestic: both-cn-gfw.test (cn, gfw)", probe("both-cn-gfw.test"), lambda g: g["rule"]=="domestic")
chk("rule overseas: blocked.com (gfw, not cn)", probe("blocked.com"), lambda g: g["rule"]=="overseas")
chk("rule apple-rule: store.apple.com", probe("store.apple.com"), lambda g: g["rule"]=="apple-rule")
chk("rule noncn(!cn): random-uncat.example", probe("random-uncat.example"), lambda g: g["rule"]=="noncn")

print("=== NORMALIZATION ===")
chk("case-insensitive EXACT.TEST", probe("EXACT.TEST"), lambda g: "1.1.1.1" in g["ips"])
chk("case-insensitive BiLiBiLi.CoM (tag cn)", probe("BiLiBiLi.CoM"), lambda g: "5.5.5.5" in g["ips"])

print("\n=== %d passed, %d failed ===" % (passed, failed))
