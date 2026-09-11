import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

def sh(*args, check=True):
    p = subprocess.run(args, cwd=ROOT, encoding="utf-8", errors="replace", capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{p.stdout}\n{p.stderr}")
    return p

def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())

def sink_probe(cmd):
    p = sh("docker", "compose", "exec", "-T", "sink", "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def source(mode):
    p = sh("docker", "compose", "exec", "-T", "source", "python", "/app/send.py", mode)
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "X-2.yaml", ROOT / "docker-compose.yml",
    ROOT / "proxy" / "nginx.baseline.conf", ROOT / "proxy" / "nginx.ablated.conf",
    ROOT / "sink" / "sink.py", ROOT / "source" / "send.py",
]

def proxy_is_up():
    """nginx has no JSON /health endpoint like the Python components do.
    Any HTTP response at all -- even a 404 -- proves it's listening and
    accepting connections; only a connection-level failure (refused,
    reset, no response) means it isn't up yet."""
    try:
        req = urllib.request.Request("http://127.0.0.1:18410/", method="GET")
        urllib.request.urlopen(req, timeout=2)
        return True
    except urllib.error.HTTPError:
        return True  # got a real HTTP response (e.g. 404) -- nginx is up
    except Exception:
        return False

def wait_up():
    # Bug fixed here: this previously checked only the sink's readiness,
    # never nginx's. Confirmed by a real run where baseline failed with
    # ConnectionRefusedError (nginx not listening yet) while post-ablation
    # -- which runs after several more seconds of setup -- correctly
    # returned a 404 with nginx's own server header. The ablation
    # mechanism itself was working the whole time; only the race in this
    # function was wrong.
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            sink_ok = get("http://127.0.0.1:18411/health").get("ok")
        except Exception:
            sink_ok = False
        if sink_ok and proxy_is_up():
            return
        time.sleep(0.5)
    raise RuntimeError("sink and/or proxy did not become ready")

def one_run(n, level):
    run_dir = RESULTS / level / f"run-{n:02d}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)
    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_up()
    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    sink_probe("RESET")
    probe = source("probe")
    auth = sink_probe("AUTHORITY_PROBE")
    sink_probe("RESET")
    op = source("op")

    I_base = int(probe.get("status") == 200)  # nginx accepted and routed the probe
    X_base = int(probe.get("status") == 200 and probe.get("body", {}).get("marker_seen") is True)
    A_base = int(auth.get("authority_probe") == "ok")
    state = get("http://127.0.0.1:18411/state")
    O_base = int(state["state"].get("test_value") == 42)
    baseline = [I_base, X_base, A_base, O_base]

    sink_probe("RESET")
    sh("docker", "compose", "cp", "proxy/nginx.ablated.conf", "proxy:/etc/nginx/nginx.conf")
    sh("docker", "compose", "exec", "-T", "proxy", "nginx", "-s", "reload")
    time.sleep(1)

    probe2 = source("probe")
    auth2 = sink_probe("AUTHORITY_PROBE")
    sink_probe("RESET")
    op2 = source("op")

    # I: nginx still admits the CONNECTION (returns an HTTP response at
    # all, specifically 404 -- not a refused/reset connection), so admission
    # at the transport level is unchanged even though routing is gone.
    I_post = int(probe2.get("status") in (200, 404))
    X_post = int(probe2.get("status") == 200 and probe2.get("body", {}).get("marker_seen") is True)
    A_post = int(auth2.get("authority_probe") == "ok")
    state2 = get("http://127.0.0.1:18411/state")
    O_post = int(state2["state"].get("test_value") == 42)
    post = [I_post, X_post, A_post, O_post]

    (run_dir / "baseline.probe.json").write_text(json.dumps(probe, indent=2))
    (run_dir / "post.probe.json").write_text(json.dumps(probe2, indent=2))

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,0,1,0]) else "FAIL_OR_NEEDS_REVIEW"
    record = {
        "test": "X-2", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,0,1,0], "post_observed": post,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"X-2 {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    print(f"  (UNTESTED harness -- review baseline.probe.json / post.probe.json before trusting this verdict)")
    return record

def dry_run():
    print("Dry run only: X-2 WILL NOT BE EXECUTED.\n")
    print("THIS HARNESS HAS NOT BEEN FUNCTIONALLY TESTED (no local nginx available during development).")
    for cmd in [("docker","--version"),("docker","compose","version"),(sys.executable,"--version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True); print((p.stdout or p.stderr).strip())
    sh("docker","compose","config")
    print("\nDocker Compose configuration validates successfully.")
    print("Harness is ready, but see manifest 'known_risks' before treating results as confirmatory.")

def main():
    if "--dry-run" in sys.argv: dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes UNTESTED H4 configuration X-2.")
    print(f"Level: {level}"); print(f"Runs: {runs}")
    if input("Type EXECUTE to continue: ") != "EXECUTE": print("Cancelled."); return
    try:
        start = 1; d = RESULTS / level
        if d.exists():
            existing = [int(p.name.split("-")[1]) for p in d.glob("run-*")]
            if existing: start = max(existing) + 1
        recs = [one_run(n, level) for n in range(start, start + runs)]
    finally:
        sh("docker", "compose", "down", "-v", check=False)
    outcomes = {}
    for r in recs: outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    print("Summary:", outcomes)

if __name__ == "__main__":
    main()
