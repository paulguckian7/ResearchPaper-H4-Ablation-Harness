import json, sys, urllib.request, urllib.error
mode = sys.argv[1] if len(sys.argv) > 1 else "op"
marker = mode == "probe"
req = urllib.request.Request(
    "http://proxy:8080/fwd",
    data=json.dumps({"test_value": 42, "marker": marker}).encode("utf-8"),
    headers={"Content-Type": "application/json", "X-Route": "default"}, method="POST"
)
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read())}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "body": {"raw": e.read().decode(errors='replace')[:200]}}))
except Exception as e:
    print(json.dumps({"status": 0, "body": {"error": repr(e)}}))
