from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, os, queue, socket, threading, time

DATA = "/data"
STATE = os.path.join(DATA, "state.json")
# Events and the X-marker's own bookkeeping live under /run/h4, NOT under
# /data. The Authority ablation for this configuration removes write access
# to /data (the protected state) specifically. If event logging or marker
# bookkeeping lived under /data too, ablating Authority would also break the
# ability to log/observe events -- silently corrupting X evidence at exactly
# the point it needs to stay measurable. Keeping them on a separate,
# unablated path is what makes A4's independence requirement ("X and A
# measured independently") actually hold under this ablation.
RUNTIME_DIR = "/run/h4"
EVENTS = os.path.join(RUNTIME_DIR, "events.jsonl")
SOCK = os.path.join(RUNTIME_DIR, "internal.sock")

os.makedirs(DATA, exist_ok=True)
os.makedirs(RUNTIME_DIR, exist_ok=True)

workq = queue.Queue()
io_lock = threading.Lock()
_runtime = {"marker_seen": False}  # never written to /data; see note above

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
    save_json(STATE, {"test_value": 0, "authority_probe": None})
    _runtime["marker_seen"] = False
    with io_lock:
        try:
            os.remove(EVENTS)
        except FileNotFoundError:
            pass
    log("reset")

def process_admitted(raw, source, marker=False):
    """Post-admission path: parsing, submission, queue, worker handling.
    Used identically for real content and for the X marker."""
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
        value = int(payload.get("test_value", 42))
    except Exception:
        return 400, {"error": "bad payload"}

    result = submit({"kind": "operation", "source": source, "value": value, "marker": marker})
    if "error" in result:
        return 500, result
    return 200, result

def worker():
    # A single try/finally handles both branches uniformly. An earlier
    # version called item["done"].set() and workq.task_done() explicitly in
    # the marker branch and then "continue" -- but "continue" still runs the
    # enclosing "finally", so task_done() fired twice per marker item and
    # crashed this thread (queue.ValueError: task_done() called too many
    # times) after the first marker probe. Caught by running the agent
    # standalone and sending a marker probe followed by a real request:
    # the second request hung until timeout because no worker remained to
    # service the queue. Using if/else instead of if+continue removes the
    # double call.
    while True:
        item = workq.get()
        try:
            log("handler_reached", source=item["source"], value=item["value"], marker=item.get("marker", False))
            if item.get("marker"):
                # Branches off before the state write, so it cannot change
                # O, and records to runtime memory rather than /data, so it
                # cannot be blocked by the Authority ablation this
                # configuration applies to /data.
                _runtime["marker_seen"] = True
                item["result"]["marker_seen"] = True
            else:
                try:
                    st = load_json(STATE, {})
                    st["test_value"] = item["value"]
                    save_json(STATE, st)
                    log("state_write", source=item["source"], value=item["value"])
                    item["result"]["written"] = item["value"]
                except PermissionError as e:
                    log("authority_denied", source=item["source"], reason=repr(e))
                    item["result"]["authority_denied"] = True
                    item["result"]["error_detail"] = repr(e)
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

def access_state():
    """Access-control state for the acting mechanism, read inside the
    agent process under its own execution identity."""
    stt = os.stat(STATE)
    return {
        "process_uid": os.getuid(),
        "process_gid": os.getgid(),
        "state_path": STATE,
        "state_owner_uid": stt.st_uid,
        "state_owner_gid": stt.st_gid,
        "state_mode": oct(stt.st_mode & 0o777),
        "data_dir_mode": oct(os.stat(DATA).st_mode & 0o777),
        "state_writable_by_process": os.access(STATE, os.W_OK),
        "data_dir_writable_by_process": os.access(DATA, os.W_OK)
    }

def authority_probe():
    """Same-identity attempt to write the protected state. Distinct from
    a real operation so it can be invoked as an independent Authority
    check before and after ablation."""
    try:
        st = load_json(STATE, {})
        st["authority_probe"] = "ok"
        save_json(STATE, st)
        log("authority_probe_write")
        return {"authority_probe": "ok"}
    except PermissionError as e:
        log("authority_probe_denied", reason=repr(e))
        return {"authority_probe": "denied", "error_detail": repr(e)}

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
                    code, body = process_admitted(
                        json.dumps({"test_value": 0}).encode("utf-8"),
                        source="internal-x-marker", marker=True
                    )
                    result = {"status": code, **body}
                elif cmd == "ACCESS_STATE":
                    result = access_state()
                elif cmd == "AUTHORITY_PROBE":
                    result = authority_probe()
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
            st = load_json(STATE, {})
            st["marker_seen"] = _runtime["marker_seen"]
            self._json(200, {"state": st})
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
        # Admission is unconditional in A-3: this configuration tests the
        # Authority row, not Interface. There is no source-specific denial
        # policy here.
        if self.path != "/content":
            self._json(404, {"error": "not found"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n) if n else b""
        source = self.headers.get("X-Source", "unknown")
        log("interface_admit", source=source)
        code, result = process_admitted(raw, source)
        self._json(code, result)

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
