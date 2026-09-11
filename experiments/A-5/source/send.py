import json, os, sys, urllib.error, urllib.request
target = os.environ.get("TARGET", "agent")
source_name = os.environ.get("SOURCE_NAME", "T")
req = urllib.request.Request(
    f"http://{target}:8080/content",
    data=json.dumps({"test_value": 42}).encode("utf-8"),
    headers={"Content-Type": "application/json", "X-Source": source_name},
    method="POST"
)
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read())}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "body": json.loads(e.read())}))
except Exception as e:
    print(json.dumps({"status": 0, "body": {"error": repr(e)}}))
