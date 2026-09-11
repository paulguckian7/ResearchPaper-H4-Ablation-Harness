import socket, sys, json
SOCK = "/run/h4/internal.sock"
if len(sys.argv) != 2:
    raise SystemExit("usage: internal_probe.py CMD")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
s.sendall((sys.argv[1] + "\n").encode("utf-8"))
s.shutdown(socket.SHUT_WR)
raw = b""
while True:
    part = s.recv(4096)
    if not part: break
    raw += part
print(raw.decode("utf-8").strip())
