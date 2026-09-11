"""Minimal HTTP-based 'resolver'. Answers GET /resolve?name=<zone> with the
configured address for that zone. Deliberately not real DNS wire protocol --
this tests the structural relation (admission of an externally supplied
answer, and whether the connecting mechanism gives it effect), not DNS
implementation detail."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json, os

TARGET_ADDRESS = os.environ.get("TARGET_ADDRESS", "http://target:8080")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            body = json.dumps({"ok": True}).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        if u.path == "/resolve":
            body = json.dumps({"address": TARGET_ADDRESS}).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        self.send_response(404); self.end_headers()

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
