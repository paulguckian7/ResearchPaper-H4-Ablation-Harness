"""The connecting mechanism (the 'stub' + host-local egress enforcement).

CONNECT <resolver> <name> does, in one call, exactly what the manifest and
paper section describe:
  1. Admit the resolver's answer (I) -- an HTTP call to the resolver.
  2. Pass the resolved address to the connecting logic (X) -- logged as
     handler_reached regardless of what happens next.
  3. Check host-local egress policy keyed on resolver provenance (A) --
     the designated set, held in this process, not the resolver's.
  4. If designated, attempt the connection and report whether the
     operation's transition occurred (O).

WITHDRAW/RESTORE change the designated set. This is the enforcement being
ablated -- it is a control the client already holds over itself, not a
new mechanism introduced at ablation time (protocol rule A10: an
enforcement mechanism present in the baseline, on the same node).
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, os, socket, threading, time, urllib.request, urllib.error

RUNTIME_DIR = "/run/h4"
EVENTS = os.path.join(RUNTIME_DIR, "events.jsonl")
SOCK = os.path.join(RUNTIME_DIR, "internal.sock")
os.makedirs(RUNTIME_DIR, exist_ok=True)

io_lock = threading.Lock()
designated = {"resolver-t": True, "resolver-c": True}

def log(event, **kw):
    rec = {"ts": time.time(), "event": event, **kw}
    with io_lock:
        with open(EVENTS, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")

def reset():
    global designated
    designated = {"resolver-t": True, "resolver-c": True}
    with io_lock:
        try:
            os.remove(EVENTS)
        except FileNotFoundError:
            pass
    log("reset")

def connect(resolver_host, zone):
    # I: admission of the resolver's answer.
    try:
        with urllib.request.urlopen(f"http://{resolver_host}:8080/resolve?name={zone}", timeout=5) as r:
            addr = json.loads(r.read())["address"]
    except Exception as e:
        log("interface_reject", resolver=resolver_host, reason=repr(e))
        return {"I": 0, "X": 0, "A": 0, "O": 0, "error": repr(e)}
    log("interface_admit", resolver=resolver_host, address=addr)

    # X: the resolved address reaches the connecting mechanism's logic.
    log("handler_reached", resolver=resolver_host, address=addr)

    # A: host-local egress policy, keyed on which resolver supplied the
    # answer -- NOT on the address itself, so this is source-specific to
    # the resolver, not a general destination restriction.
    if not designated.get(resolver_host, False):
        log("authority_denied", resolver=resolver_host, address=addr)
        return {"I": 1, "X": 1, "A": 0, "O": 0, "resolved_address": addr}

    try:
        req = urllib.request.Request(
            addr + "/fwd",
            data=json.dumps({"test_value": 42}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Route": resolver_host},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            body = json.loads(r.read())
        log("state_write_attempted", resolver=resolver_host, written=body.get("written"))
        O = int(body.get("written") == 42)
    except Exception as e:
        log("connect_failed", resolver=resolver_host, error=repr(e))
        O = 0
    return {"I": 1, "X": 1, "A": 1, "O": O, "resolved_address": addr}

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
                elif parts[0] == "WITHDRAW":
                    designated[parts[1]] = False
                    log("egress_policy_changed", resolver=parts[1], designated=False)
                    result = {"ok": True, "designated": dict(designated)}
                elif parts[0] == "RESTORE":
                    designated[parts[1]] = True
                    log("egress_policy_changed", resolver=parts[1], designated=True)
                    result = {"ok": True, "designated": dict(designated)}
                elif parts[0] == "ACCESS_STATE":
                    result = {"designated": dict(designated)}
                elif parts[0] == "CONNECT":
                    result = connect(parts[1], parts[2])
                else:
                    result = {"error": "unknown command"}
            except Exception as e:
                result = {"error": repr(e)}
            conn.sendall((json.dumps(result) + "\n").encode("utf-8"))

threading.Thread(target=internal_server, daemon=True).start()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"ok": True}).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        if self.path == "/events":
            with io_lock:
                try:
                    rows = [json.loads(x) for x in open(EVENTS, encoding="utf-8") if x.strip()]
                except FileNotFoundError:
                    rows = []
            body = json.dumps(rows).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        self.send_response(404); self.end_headers()

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
