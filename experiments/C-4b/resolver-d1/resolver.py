"""Resolver used across C-4's sub-configurations. If UPSTREAM is set,
forwards /resolve to it (models D1/D2 both fronting a shared H). If not,
answers directly with TARGET_ADDRESS (models a direct authoritative
answer). Every call is fresh -- no caching, matching the protocol's
'disable caching, fresh names' rule for the ecological DNS validation."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json, os, urllib.request

TARGET_ADDRESS = os.environ.get("TARGET_ADDRESS", "")
UPSTREAM = os.environ.get("UPSTREAM", "")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            body = json.dumps({"ok": True}).encode()
        elif u.path == "/resolve":
            if UPSTREAM:
                try:
                    with urllib.request.urlopen(f"{UPSTREAM}/resolve{('?'+u.query) if u.query else ''}", timeout=5) as r:
                        body = r.read()
                except Exception as e:
                    self.send_response(502); self.end_headers()
                    self.wfile.write(json.dumps({"error": repr(e)}).encode())
                    return
            else:
                body = json.dumps({"address": TARGET_ADDRESS}).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
