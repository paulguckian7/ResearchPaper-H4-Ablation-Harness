"""Client K for Cut configurations. Addresses each router directly by its
container name -- routes are pinned by which router the request is sent
to, not by a header a shared ingress interprets (protocol rule A8)."""
import json, sys, urllib.request

def call(router, marker=False):
    req = urllib.request.Request(
        f"http://{router}:8080/fwd",
        data=json.dumps({"test_value": 42, "marker": marker}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Route": router},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except Exception as e:
        return 0, {"error": repr(e)}

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "probe":
        # Pinned single-route probe: hits exactly one named router, marker=True.
        status, body = call(sys.argv[2], marker=True)
        print(json.dumps({"status": status, "body": body}))
    elif mode == "op":
        # Real operation: tries each configured router in order (disjunction
        # over available routes), stopping at the first that reports routed.
        # This is O's own logic, separate from the per-route Cut probes.
        routers = sys.argv[2].split(",")
        for r in routers:
            status, body = call(r)
            if status == 200 and body.get("routed"):
                print(json.dumps({"router": r, "status": status, "body": body}))
                sys.exit(0)
        print(json.dumps({"router": None, "status": 0, "body": {"error": "no route succeeded"}}))
    else:
        raise SystemExit("usage: send.py probe <router> | op <router1,router2,...>")
