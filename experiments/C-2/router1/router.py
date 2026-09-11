"""Generic router used by X-1 (single hop, app-level routing table that can
be cleared -- the Channel ablation) and by C-1..C-4 (pure forwarder; the
Cut ablation is stopping the container, not clearing its table).

ROUTE_TABLE_CLEARABLE=1 enables SET_BINDING/REMOVE_BINDING (X-1 only).
NEXT_HOP env var gives the fixed forward target for router-only use (C-*).
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, os, socket, threading, time, urllib.request, urllib.error

DATA = "/data"
EVENTS = os.path.join(DATA, "events.jsonl")
SOCK = "/run/h4/internal.sock"
CLEARABLE = os.environ.get("ROUTE_TABLE_CLEARABLE") == "1"
DEFAULT_NEXT_HOP = os.environ.get("NEXT_HOP", "")

os.makedirs(DATA, exist_ok=True)
os.makedirs(os.path.dirname(SOCK), exist_ok=True)
io_lock = threading.Lock()
routing = {"default": DEFAULT_NEXT_HOP} if DEFAULT_NEXT_HOP else {}

def log(event, **kw):
    rec = {"ts": time.time(), "event": event, **kw}
    with io_lock:
        with open(EVENTS, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

def internal_server():
    global routing
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
            # RESET is a lifecycle command available on every router
            # regardless of ROUTE_TABLE_CLEARABLE, which governs only
            # whether the routing table itself can be manipulated
            # (SET_BINDING / REMOVE_BINDING). An earlier version gated
            # RESET behind CLEARABLE too, which meant a router with
            # ROUTE_TABLE_CLEARABLE unset -- as used by C-1..C-4, which
            # never need to clear a binding -- also silently refused RESET.
            if cmd == "RESET":
                try:
                    os.remove(EVENTS)
                except FileNotFoundError:
                    pass
                conn.sendall(b'{"ok":true}\n')
            elif not CLEARABLE:
                conn.sendall(b'{"error":"routing manipulation not enabled on this router"}\n')
            elif cmd == "REMOVE_BINDING":
                routing.pop("default", None)
                log("binding_removed")
                conn.sendall(b'{"ok":true}\n')
            elif cmd.startswith("SET_BINDING "):
                routing["default"] = cmd.split(" ", 1)[1].strip()
                log("binding_set", target=routing["default"])
                conn.sendall(b'{"ok":true}\n')
            else:
                conn.sendall(b'{"error":"unknown command"}\n')

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
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/fwd":
            self._json(404, {"error": "not found"}); return
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        route = self.headers.get("X-Route", "default")
        log("interface_admit", route=route)
        target = routing.get("default", "")
        if not target:
            log("route_absent", route=route)
            self._json(200, {"admitted": True, "routed": False}); return
        try:
            req = urllib.request.Request(
                target + "/fwd", data=raw,
                headers={"Content-Type": "application/json", "X-Route": route},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                body = json.loads(r.read().decode("utf-8"))
            log("forwarded", route=route, target=target)
            self._json(200, {"admitted": True, "routed": True, "downstream": body})
        except Exception as e:
            log("forward_failed", route=route, target=target, error=repr(e))
            self._json(200, {"admitted": True, "routed": False, "error": repr(e)})

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
