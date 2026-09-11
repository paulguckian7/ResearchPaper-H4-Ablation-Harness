import json, ssl, os, urllib.request, urllib.error

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # this test exercises client-cert auth, not server identity
ctx.load_cert_chain("/app/client.cert.pem", "/app/client.key.pem")

url = os.environ.get("RP_URL", "https://rp:8443/admin-write")
req = urllib.request.Request(url, method="POST")
try:
    with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
        print(json.dumps({"status": r.status, "body": json.loads(r.read())}))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "body": json.loads(e.read())}))
