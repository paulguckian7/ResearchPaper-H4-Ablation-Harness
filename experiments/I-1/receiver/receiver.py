from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
import os
import queue
import socket
import threading
import time

DATA = "/data"
STATE = os.path.join(DATA, "state.json")
POLICY = os.path.join(DATA, "policy.json")
EVENTS = os.path.join(DATA, "events.jsonl")
SOCK = "/run/h4/internal.sock"

os.makedirs(DATA, exist_ok=True)
os.makedirs(os.path.dirname(SOCK), exist_ok=True)

workq = queue.Queue()
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
    save_json(STATE, {
        "test_value": 0,
        "marker_seen": False,
        "authority_probe": None
    })
    save_json(POLICY, {"deny_ip": None})
    with io_lock:
        try:
            os.remove(EVENTS)
        except FileNotFoundError:
            pass
    log("reset")

def worker():
    while True:
        item = workq.get()
        try:
            kind = item["kind"]
            if kind == "operation":
                log("handler_reached",
                    client_ip=item["client_ip"],
                    value=item["value"])
                st = load_json(STATE, {})
                st["test_value"] = item["value"]
                save_json(STATE, st)
                log("state_write",
                    client_ip=item["client_ip"],
                    value=item["value"])
                item["result"]["written"] = item["value"]

            elif kind == "x_marker":
                # This enters the exact same internal queue used by admitted work,
                # immediately downstream of the nominated HTTP admission decision.
                log("x_marker_reached_handler")
                st = load_json(STATE, {})
                st["marker_seen"] = True
                save_json(STATE, st)
                item["result"]["marker_seen"] = True

            elif kind == "authority_probe":
                # Same receiver process and execution identity writes the same
                # protected state used by the operation.
                st = load_json(STATE, {})
                st["authority_probe"] = "ok"
                save_json(STATE, st)
                log("authority_probe_write")
                item["result"]["authority_probe"] = "ok"
        except Exception as e:
            item["result"]["error"] = repr(e)
        finally:
            item["done"].set()
            workq.task_done()

def submit(item, timeout=5):
    item["done"] = threading.Event()
    item["result"] = {}
    workq.put(item)
    if not item["done"].wait(timeout):
        raise TimeoutError("worker did not complete item")
    return item["result"]

def internal_server():
    try:
        os.remove(SOCK)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o600)
    srv.listen(5)

    while True:
        conn, _ = srv.accept()
        with conn:
            raw = b""
            while True:
                part = conn.recv(4096)
                if not part:
                    break
                raw += part
                if b"\n" in raw:
                    break
            cmd = raw.decode("utf-8").strip()

            try:
                if cmd == "X_MARKER":
                    result = submit({"kind": "x_marker"})
                elif cmd == "AUTHORITY_PROBE":
                    result = submit({"kind": "authority_probe"})
                elif cmd.startswith("SET_DENY_IP "):
                    ip = cmd.split(" ", 1)[1].strip()
                    save_json(POLICY, {"deny_ip": ip})
                    log("policy_changed", deny_ip=ip)
                    result = {"deny_ip": ip}
                elif cmd == "RESET":
                    reset()
                    result = {"ok": True}
                else:
                    result = {"error": "unknown command"}
            except Exception as e:
                result = {"error": repr(e)}

            conn.sendall((json.dumps(result) + "\n").encode("utf-8"))

if not os.path.exists(STATE):
    reset()

threading.Thread(target=worker, daemon=True).start()
threading.Thread(target=internal_server, daemon=True).start()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/state":
            self._json(200, {
                "state": load_json(STATE, {}),
                "policy": load_json(POLICY, {})
            })
            return

        if self.path == "/events":
            with io_lock:
                try:
                    with open(EVENTS, "r", encoding="utf-8") as f:
                        rows = [json.loads(x) for x in f if x.strip()]
                except FileNotFoundError:
                    rows = []
            self._json(200, rows)
            return

        if self.path == "/health":
            self._json(200, {"ok": True})
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/push":
            self._json(404, {"error": "not found"})
            return

        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        client_ip = self.client_address[0]

        policy = load_json(POLICY, {"deny_ip": None})
        if policy.get("deny_ip") == client_ip:
            log("interface_reject", client_ip=client_ip)
            self._json(403, {
                "admitted": False,
                "client_ip": client_ip
            })
            return

        log("interface_admit", client_ip=client_ip)

        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
            value = int(payload["test_value"])
        except Exception:
            self._json(400, {"error": "bad payload"})
            return

        result = submit({
            "kind": "operation",
            "client_ip": client_ip,
            "value": value
        })

        if "error" in result:
            self._json(500, result)
            return

        self._json(200, {
            "admitted": True,
            "written": result.get("written"),
            "client_ip": client_ip
        })

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
