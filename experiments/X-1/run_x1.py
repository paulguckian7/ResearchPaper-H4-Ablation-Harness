import json, subprocess, sys, time, urllib.request
from pathlib import Path
from datetime import datetime, timezone
import hashlib

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

def sh(*args, check=True):
    p = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{p.stdout}\n{p.stderr}")
    return p

def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())

def post(url, payload, headers=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json", **(headers or {})},
                                  method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def probe(container, cmd):
    p = sh("docker", "compose", "exec", "-T", container, "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "X-1.yaml",
    ROOT / "docker-compose.yml", ROOT / "router" / "router.py", ROOT / "sink" / "sink.py",
    ROOT / "source" / "send.py", ROOT / "internal_probe.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18110/health").get("ok"): return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("router did not become ready")

def one_run(n, level):
    level_dir = RESULTS / level
    run_dir = level_dir / f"run-{n:02d}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_up()

    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    (run_dir / "docker.images.txt").write_text(
        sh("docker", "images", "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}").stdout, encoding="utf-8")

    src_hashes = {}
    for f in SOURCE_FILES:
        try:
            src_hashes[str(f.name)] = sha256_file(f)
        except FileNotFoundError:
            src_hashes[str(f.name)] = "MISSING"

    probe("router", "RESET")
    probe("sink", "RESET")

    # Baseline: ensure the router's binding is present (it is, by default,
    # from the NEXT_HOP env var, but this makes the baseline explicit).
    probe("router", "SET_BINDING http://sink:8080")
    probe("router", "RESET"); probe("sink", "RESET")
    status_body = json.loads(sh("docker", "compose", "exec", "-T", "source", "python", "/app/send.py").stdout.strip().splitlines()[-1])
    sink_state = get("http://127.0.0.1:18111/state")
    sink_events = get("http://127.0.0.1:18111/events")
    router_events_present = status_body.get("status") == 200 and status_body["body"].get("routed") is True

    auth_probe = probe("sink", "AUTHORITY_PROBE")

    I_base = router_events_present  # request was admitted+routed
    X_base = any(e["event"] == "state_write" for e in sink_events)
    A_base = auth_probe.get("authority_probe") == "ok"
    O_base = sink_state["state"].get("test_value") == 42
    baseline = [int(I_base), int(X_base), int(A_base), int(O_base)]
    (run_dir / "baseline.events.json").write_text(json.dumps(sink_events, indent=2))
    (run_dir / "baseline.state.json").write_text(json.dumps(sink_state, indent=2))

    # Ablation: remove routing binding
    probe("router", "RESET"); probe("sink", "RESET")
    removed = probe("router", "REMOVE_BINDING")

    op_result = json.loads(sh("docker", "compose", "exec", "-T", "source", "python", "/app/send.py").stdout.strip().splitlines()[-1])
    marker_result = post("http://127.0.0.1:18110/fwd", {"marker": True}, headers={"X-Route": "x-marker"})

    sink_state2 = get("http://127.0.0.1:18111/state")
    sink_events2 = get("http://127.0.0.1:18111/events")
    auth_probe2 = probe("sink", "AUTHORITY_PROBE")
    access2 = probe("sink", "ACCESS_STATE")

    I_post = op_result.get("status") == 200 and op_result["body"].get("admitted") is True  # router still admits
    X_post = any(e["event"] in ("state_write", "route_probe_reached") for e in sink_events2)
    A_post = auth_probe2.get("authority_probe") == "ok" and access2.get("state_writable_by_process") is True
    O_post = sink_state2["state"].get("test_value") == 42
    post = [int(I_post), int(X_post), int(A_post), int(O_post)]

    (run_dir / "post.events.json").write_text(json.dumps(sink_events2, indent=2))
    (run_dir / "post.state.json").write_text(json.dumps(sink_state2, indent=2))
    (run_dir / "post.access_state.json").write_text(json.dumps(access2, indent=2))

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,0,1,0]) else "FAIL"

    record = {
        "test": "X-1", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,0,1,0], "post_observed": post,
        "outcome": outcome, "source_sha256": src_hashes,
        "op_result": op_result, "marker_result": marker_result,
        "removed_binding_result": removed,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"X-1 {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: X-1 WILL NOT BE EXECUTED.\n")
    for cmd in [("docker", "--version"), ("docker", "compose", "version"), (sys.executable, "--version")]:
        p = subprocess.run(cmd, text=True, capture_output=True)
        print((p.stdout or p.stderr).strip())
    p = sh("docker", "compose", "config")
    print("\nDocker Compose configuration validates successfully.")
    for f in SOURCE_FILES:
        try:
            print(f"SHA256 {f.name}: {sha256_file(f)}")
        except FileNotFoundError:
            print(f"MISSING: {f}")
    print("\nHarness is ready.")
    print("Use --execute only after any intended preregistration is frozen/deposited.")

def main():
    if "--dry-run" in sys.argv:
        dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print(f"WARNING: this executes preregistered H4 configuration X-1.")
    print(f"Level: {level}")
    print(f"Runs: {runs}")
    answer = input("Type EXECUTE to continue: ")
    if answer != "EXECUTE":
        print("Cancelled."); return
    try:
        start = 1
        d = RESULTS / level
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
