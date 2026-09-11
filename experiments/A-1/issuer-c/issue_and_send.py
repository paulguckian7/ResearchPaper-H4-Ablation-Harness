import json, os, time, urllib.request
import jwt

PRIVATE_KEY = open("/app/private.pem", "rb").read()
ISS = os.environ.get("ISS_NAME", "issuer-c")
RP_URL = os.environ.get("RP_URL", "http://rp:8080")

token = jwt.encode(
    {"iss": ISS, "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 300},
    PRIVATE_KEY, algorithm="RS256"
)
req = urllib.request.Request(
    RP_URL + "/admin-write",
    headers={"Authorization": f"Bearer {token}"}, method="POST"
)
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read())}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "body": json.loads(e.read())}))
