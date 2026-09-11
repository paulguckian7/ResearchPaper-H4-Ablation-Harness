import json
import sys
import urllib.error
import urllib.request

req = urllib.request.Request(
    "http://receiver:8080/push",
    data=json.dumps({"test_value": 42}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=5) as r:
        body = json.loads(r.read().decode("utf-8"))
        print(json.dumps({"status": r.status, "body": body}))
except urllib.error.HTTPError as e:
    body = json.loads(e.read().decode("utf-8"))
    print(json.dumps({"status": e.code, "body": body}))
    sys.exit(0)
