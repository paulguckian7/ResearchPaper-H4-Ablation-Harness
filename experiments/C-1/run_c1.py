import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request

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

def sink_direct_admit_check():
    """Verify I directly against the sink's own /fwd endpoint, bypassing
    every router -- this is what makes 'I unchanged' a checked claim rather
    than an assumption when the routes to it are cut."""
    req = urllib.request.Request(
        "http://127.0.0.1:18141/fwd",
        data=json.dumps({"marker": True}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Route": "direct-bypass-check"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status == 200 and json.loads(r.read()).get("marker_seen") is True

def client(mode, arg):
    p = sh("docker", "compose", "exec", "-T", "client", "python", "/app/send.py", mode, arg)
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "C-1.yaml", ROOT / "docker-compose.yml",
    ROOT / "router1" / "router.py", ROOT / "sink" / "sink.py", ROOT / "client" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18140/health").get("ok") and get("http://127.0.0.1:18141/health").get("ok"):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("services did not become ready")

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

    # Baseline: pinned probe via router1, then real op via router1, then A
    # verified independently at the sink.
    probe_result = client("probe", "router1")
    op_result = client("op", "router1")
    auth = sink_probe("AUTHORITY_PROBE")
    state = get("http://127.0.0.1:18141/state")
    events = get("http://127.0.0.1:18141/events")

    I_base = int(sink_direct_admit_check())
    X_base = int(probe_result["body"].get("marker_seen") is True)
    A_base = int(auth.get("authority_probe") == "ok")
    O_base = int(state["state"].get("test_value") == 42)
    baseline = [I_base, X_base, A_base, O_base]
    (run_dir / "baseline.events.json").write_text(json.dumps(events, indent=2))
    (run_dir / "baseline.state.json").write_text(json.dumps(state, indent=2))

    # Ablation: assessed Cut -- router1 is the only route. Stop it.
    sink_probe("RESET")
    sh("docker", "compose", "stop", "router1")

    probe_result2 = client("probe", "router1")
    op_result2 = client("op", "router1")
    auth2 = sink_probe("AUTHORITY_PROBE")  # direct to sink, bypasses router1 entirely
    access2 = sink_probe("ACCESS_STATE")
    state2 = get("http://127.0.0.1:18141/state")
    events2 = get("http://127.0.0.1:18141/events")

    I_post = int(sink_direct_admit_check())
    X_post = int(probe_result2["status"] != 0 and probe_result2["body"].get("marker_seen") is True)
    A_post = int(auth2.get("authority_probe") == "ok")
    O_post = int(state2["state"].get("test_value") == 42)
    post = [I_post, X_post, A_post, O_post]

    (run_dir / "post.events.json").write_text(json.dumps(events2, indent=2))
    (run_dir / "post.state.json").write_text(json.dumps(state2, indent=2))
    (run_dir / "post.access_state.json").write_text(json.dumps(access2, indent=2))

    sh("docker", "compose", "start", "router1")  # restore for teardown cleanliness

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,0,1,0]) else "FAIL"
    record = {
        "test": "C-1", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,0,1,0], "post_observed": post,
        "outcome": outcome, "source_sha256": src_hashes,
        "probe_baseline": probe_result, "probe_post": probe_result2,
        "op_baseline": op_result, "op_post": op_result2,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"C-1 {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: C-1 WILL NOT BE EXECUTED.\n")
    for cmd in [("docker", "--version"), ("docker", "compose", "version"), (sys.executable, "--version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True)
        print((p.stdout or p.stderr).strip())
    sh("docker", "compose", "config")
    print("\nDocker Compose configuration validates successfully.")
    for f in SOURCE_FILES:
        try: print(f"SHA256 {f.name}: {sha256_file(f)}")
        except FileNotFoundError: print(f"MISSING: {f}")
    print("\nHarness is ready.")

def main():
    if "--dry-run" in sys.argv:
        dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes preregistered H4 configuration C-1.")
    print(f"Level: {level}"); print(f"Runs: {runs}")
    if input("Type EXECUTE to continue: ") != "EXECUTE":
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
