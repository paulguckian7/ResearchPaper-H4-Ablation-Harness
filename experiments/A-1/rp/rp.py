"""Relying party for A-1 (conferring Authority via RS256 JWT).

Trust store: public keys for issuer-t and issuer-c, baked in at build
time. Authority is the role_policy mapping issuer -> allowed roles.

Ablation: SCOPE_REMOVE <iss> <role> edits role_policy only. The issuer's
public key stays in the trust store throughout, so signature
verification (Interface) is unaffected by the ablation -- this is what
makes it a source-specific Authority ablation rather than an Interface
one (protocol A5/A6).
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, os, socket, threading, time
import jwt

DATA = "/data"
STATE = os.path.join(DATA, "state.json")
RUNTIME_DIR = "/run/h4"
EVENTS = os.path.join(RUNTIME_DIR, "events.jsonl")
SOCK = os.path.join(RUNTIME_DIR, "internal.sock")
os.makedirs(DATA, exist_ok=True)
os.makedirs(RUNTIME_DIR, exist_ok=True)

io_lock = threading.Lock()

TRUST_STORE = {
    "issuer-t": open("/app/issuer-t.pub.pem", "rb").read(),
    "issuer-c": open("/app/issuer-c.pub.pem", "rb").read(),
}
role_policy = {"issuer-t": ["admin"], "issuer-c": ["admin"]}

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
    role_policy = {"issuer-t": ["admin"], "issuer-c": ["admin"]}
    with io_lock:
        try:
            os.remove(EVENTS)
        except FileNotFoundError:
            pass
    log("reset")

def handle_token(token):
    # Two-step verification, as real JWT-consuming code does: read the
    # unverified claims to find which issuer to trust, THEN verify the
    # signature against that specific issuer's key. A token claiming an
    # unrecognised issuer is rejected before any signature check.
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        log("interface_reject", reason=f"malformed token: {e!r}")
        return {"I": 0, "X": 0, "A": 0, "O": 0, "error": "malformed token"}

    iss = unverified.get("iss")
    if iss not in TRUST_STORE:
        log("interface_reject", iss=iss, reason="untrusted issuer")
        return {"I": 0, "X": 0, "A": 0, "O": 0, "error": "untrusted issuer"}

    try:
        claims = jwt.decode(token, TRUST_STORE[iss], algorithms=["RS256"], issuer=iss)
    except Exception as e:
        log("interface_reject", iss=iss, reason=f"signature/claims invalid: {e!r}")
        return {"I": 0, "X": 0, "A": 0, "O": 0, "error": "signature invalid"}

    # I: admitted -- signature verified against the trusted issuer key.
    log("interface_admit", iss=iss)
    # X: reaches the handler.
    log("handler_reached", iss=iss, role=claims.get("role"))

    allowed = role_policy.get(iss, [])
    if claims.get("role") not in allowed:
        log("authority_denied", iss=iss, role=claims.get("role"), allowed=list(allowed))
        return {"I": 1, "X": 1, "A": 0, "O": 0}

    st = load_json(STATE, {})
    st["test_value"] = 42
    save_json(STATE, st)
    log("state_write", iss=iss)
    return {"I": 1, "X": 1, "A": 1, "O": 1}

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
                    iss, role = parts[1], parts[2]
                    role_policy[iss] = [r for r in role_policy.get(iss, []) if r != role]
                    log("scope_changed", iss=iss, removed=role, current=list(role_policy[iss]))
                    result = {"ok": True, "role_policy": {k: list(v) for k, v in role_policy.items()}}
                elif parts[0] == "SCOPE_RESTORE":
                    iss, role = parts[1], parts[2]
                    if role not in role_policy.get(iss, []):
                        role_policy.setdefault(iss, []).append(role)
                    result = {"ok": True, "role_policy": {k: list(v) for k, v in role_policy.items()}}
                elif parts[0] == "ACCESS_STATE":
                    result = {"role_policy": {k: list(v) for k, v in role_policy.items()},
                              "trusted_issuers": list(TRUST_STORE.keys())}
                else:
                    result = {"error": "unknown command"}
            except Exception as e:
                result = {"error": repr(e)}
            conn.sendall((json.dumps(result) + "\n").encode("utf-8"))

if not os.path.exists(STATE):
    reset()
threading.Thread(target=internal_server, daemon=True).start()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return
    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True}); return
        if self.path == "/state":
            self._json(200, {"state": load_json(STATE, {})}); return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/admin-write":
            self._json(404, {"error": "not found"}); return
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self._json(401, {"error": "missing bearer token"}); return
        token = auth[len("Bearer "):]
        result = handle_token(token)
        self._json(200, result)

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
