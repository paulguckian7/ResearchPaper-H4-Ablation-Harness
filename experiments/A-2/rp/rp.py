"""Relying party for A-2 (conferring Authority via mutual TLS client certs).

The TLS handshake itself (Interface: does the client present a cert
signed by a trusted CA) is separated from role_policy (Authority: is
that CA's identity permitted the requested role). Ablation edits
role_policy only; the CA stays in the trust bundle, so the handshake
still succeeds for a descoped client.
"""
import http.server, ssl, ssl as ssl_mod
import json, os, socket, threading, time

DATA = "/data"
STATE = os.path.join(DATA, "state.json")
RUNTIME_DIR = "/run/h4"
EVENTS = os.path.join(RUNTIME_DIR, "events.jsonl")
SOCK = os.path.join(RUNTIME_DIR, "internal.sock")
os.makedirs(DATA, exist_ok=True)
os.makedirs(RUNTIME_DIR, exist_ok=True)

io_lock = threading.Lock()
# Maps client certificate CN -> the CA that is expected to have issued it,
# purely for the role_policy keying below (not part of TLS validation,
# which trusts anything chaining to ca-bundle.pem regardless of CN).
role_policy = {"T": ["admin"], "C": ["admin"]}

def save_json(path, obj):
    tmp = path + ".tmp"
    with io_lock:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        os.replace(tmp, path)

def load_json(path, default):
    with io_lock:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default

def log(event, **kw):
    rec = {"ts": time.time(), "event": event, **kw}
    with io_lock:
        with open(EVENTS, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

def reset():
    global role_policy
    save_json(STATE, {"test_value": 0})
    role_policy = {"T": ["admin"], "C": ["admin"]}
    with io_lock:
        try:
            os.remove(EVENTS)
        except FileNotFoundError:
            pass
    log("reset")

def cert_cn(cert_dict):
    for rdn in cert_dict.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return None

def internal_server():
    try:
        os.remove(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK); os.chmod(SOCK, 0o600); srv.listen(5)
    while True:
        conn, _ = srv.accept()
        with conn:
            raw = b""
            while True:
                part = conn.recv(4096)
                if not part: break
                raw += part
                if b"\n" in raw: break
            cmd = raw.decode("utf-8").strip()
            parts = cmd.split()
            try:
                if parts[0] == "RESET":
                    reset(); result = {"ok": True}
                elif parts[0] == "SCOPE_REMOVE":
                    cn, role = parts[1], parts[2]
                    role_policy[cn] = [r for r in role_policy.get(cn, []) if r != role]
                    log("scope_changed", cn=cn, removed=role)
                    result = {"ok": True, "role_policy": {k: list(v) for k, v in role_policy.items()}}
                elif parts[0] == "ACCESS_STATE":
                    result = {"role_policy": {k: list(v) for k, v in role_policy.items()}}
                else:
                    result = {"error": "unknown command"}
            except Exception as e:
                result = {"error": repr(e)}
            conn.sendall((json.dumps(result) + "\n").encode("utf-8"))

if not os.path.exists(STATE):
    reset()
threading.Thread(target=internal_server, daemon=True).start()

class HealthHandler(http.server.BaseHTTPRequestHandler):
    """Plain HTTP, no client cert required -- health/state checks. Real
    deployments commonly split health endpoints from mTLS-protected ones
    for exactly this reason: monitoring shouldn't need a client cert."""
    def log_message(self, fmt, *args): return
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"ok": True}).encode()
        elif self.path == "/state":
            body = json.dumps({"state": load_json(STATE, {})}).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class Handler(http.server.BaseHTTPRequestHandler):
    """mTLS-protected -- client certificate required by the TLS layer
    before any request here is even parsed."""
    def log_message(self, fmt, *args): return
    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/admin-write":
            self._json(404, {"error": "not found"}); return

        # By the time we get here, the TLS layer has ALREADY required and
        # verified a client certificate chaining to a trusted CA (Interface).
        # This handler only runs Authority: the role check.
        peer = self.connection.getpeercert()
        cn = cert_cn(peer) if peer else None
        log("interface_admit", cn=cn)
        log("handler_reached", cn=cn)

        allowed = role_policy.get(cn, [])
        if "admin" not in allowed:
            log("authority_denied", cn=cn, allowed=list(allowed))
            self._json(200, {"I": 1, "X": 1, "A": 0, "O": 0}); return

        st = load_json(STATE, {})
        st["test_value"] = 42
        save_json(STATE, st)
        log("state_write", cn=cn)
        self._json(200, {"I": 1, "X": 1, "A": 1, "O": 1})

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/app/server.cert.pem", "/app/server.key.pem")
ctx.load_verify_locations("/app/ca-bundle.pem")
ctx.verify_mode = ssl.CERT_REQUIRED

health_srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), HealthHandler)
threading.Thread(target=health_srv.serve_forever, daemon=True).start()

srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
