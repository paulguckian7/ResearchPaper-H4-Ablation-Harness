"""Generic sink used by X-1 (Channel/Dependency) and C-1..C-4 (Cut).

Exposes:
  POST /fwd   -- the pathway's terminus. Writes protected state unless
                 the request is tagged as a marker or route-probe.
  GET  /state, /events
  Unix socket: RESET, AUTHORITY_PROBE, ACCESS_STATE

AUTHORITY_PROBE/ACCESS_STATE let the runner verify Authority directly at
the sink, independent of whichever route (if any) delivered a request --
this is how "A unchanged" is established when a route is cut.
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, os, socket, threading, time

DATA = "/data"
STATE = os.path.join(DATA, "state.json")
EVENTS = os.path.join(DATA, "events.jsonl")
SOCK = "/run/h4/internal.sock"

os.makedirs(DATA, exist_ok=True)
os.makedirs(os.path.dirname(SOCK), exist_ok=True)
io_lock = threading.Lock()

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
    save_json(STATE, {"test_value": 0, "marker_seen": False, "authority_probe": None})
    with io_lock:
        try:
            os.remove(EVENTS)
        except FileNotFoundError:
            pass
    log("reset")

def access_state():
    stt = os.stat(STATE)
    return {
        "process_uid": os.getuid(), "process_gid": os.getgid(),
        "state_owner_uid": stt.st_uid, "state_mode": oct(stt.st_mode & 0o777),
        "state_writable_by_process": os.access(STATE, os.W_OK),
        "data_dir_writable_by_process": os.access(DATA, os.W_OK)
    }

def authority_probe():
    st = load_json(STATE, {})
    st["authority_probe"] = "ok"
    save_json(STATE, st)
    log("authority_probe_write")
    return {"authority_probe": "ok"}

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
            try:
                if cmd == "RESET":
                    reset(); result = {"ok": True}
                elif cmd == "AUTHORITY_PROBE":
                    result = authority_probe()
                elif cmd == "ACCESS_STATE":
                    result = access_state()
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
        if self.path == "/state":
            self._json(200, {"state": load_json(STATE, {})}); return
        if self.path == "/events":
            with io_lock:
                try:
                    rows = [json.loads(x) for x in open(EVENTS, encoding="utf-8") if x.strip()]
                except FileNotFoundError:
                    rows = []
            self._json(200, rows); return
        if self.path == "/health":
            self._json(200, {"ok": True}); return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/fwd":
            self._json(404, {"error": "not found"}); return
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        route = self.headers.get("X-Route", "default")
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._json(400, {"error": "bad payload"}); return
        marker = bool(payload.get("marker"))
        log("interface_admit", route=route)
        log("handler_reached", route=route, marker=marker)
        if marker:
            st = load_json(STATE, {}); st["marker_seen"] = True; save_json(STATE, st)
            log("route_probe_reached", route=route)
            self._json(200, {"admitted": True, "marker_seen": True, "route": route}); return
        st = load_json(STATE, {})
        st["test_value"] = int(payload.get("test_value", 42))
        save_json(STATE, st)
        log("state_write", route=route, value=st["test_value"])
        self._json(200, {"admitted": True, "written": st["test_value"], "route": route})

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
