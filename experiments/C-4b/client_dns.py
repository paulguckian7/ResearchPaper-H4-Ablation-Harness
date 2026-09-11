"""DNS-flavoured client for C-4, mirroring C-1..C3's client exactly:
resolve via a named resolver, then reach the target through the
resolved address. Evidence roles match C-1..C3: I and A are verified
by DIRECT bypass calls to the target (independent of which resolver, if
any, is reachable); X is the per-resolver pinned probe (resolution +
delivery); O is the real operation's outcome."""
import json, sys, urllib.request, urllib.error

def resolve(resolver, zone):
    try:
        with urllib.request.urlopen(f"http://{resolver}:8080/resolve?name={zone}", timeout=5) as r:
            return json.loads(r.read())["address"]
    except Exception as e:
        return None

def call_target(address, marker=False):
    if address is None:
        return 0, {"error": "resolution failed"}
    req = urllib.request.Request(
        address + "/fwd",
        data=json.dumps({"test_value": 42, "marker": marker}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Route": "dns"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except Exception as e:
        return 0, {"error": repr(e)}

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "probe":
        # Pinned single-route probe: resolve via exactly this resolver, marker.
        resolver, zone = sys.argv[2], sys.argv[3]
        addr = resolve(resolver, zone)
        status, body = call_target(addr, marker=True)
        print(json.dumps({"resolved": addr, "status": status, "body": body}))
    elif mode == "op":
        # Real operation: try each resolver in order (disjunction).
        resolvers = sys.argv[2].split(",")
        zone = sys.argv[3]
        for r in resolvers:
            addr = resolve(r, zone)
            if addr is None:
                continue
            status, body = call_target(addr)
            if status == 200 and body.get("written") == 42:
                print(json.dumps({"resolver": r, "resolved": addr, "status": status, "body": body}))
                sys.exit(0)
        print(json.dumps({"resolver": None, "status": 0, "body": {"error": "no resolution/route succeeded"}}))
    else:
        raise SystemExit("usage: client_dns.py probe <resolver> <zone> | op <r1,r2,...> <zone>")
