import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SINK_PORT = 18162

def sh(*args, check=True):
    p = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
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
    req = urllib.request.Request(
        f"http://127.0.0.1:{SINK_PORT}/fwd",
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
    ROOT.parent.parent / "manifests" / "C-3.yaml", ROOT / "docker-compose.yml",
    ROOT / "router1" / "router.py", ROOT / "router2" / "router.py",
    ROOT / "gateway" / "router.py", ROOT / "sink" / "sink.py", ROOT / "client" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18160/health").get("ok") and \
               get("http://127.0.0.1:18161/health").get("ok") and \
               get(f"http://127.0.0.1:{SINK_PORT}/health").get("ok"):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("services did not become ready")

def sub_ablation(n, level, sub_id, stop_service, prediction):
    """Each of C-3a and C-3b is run from a FRESH build (protocol requirement:
    'separately, from a fresh build')."""
    run_dir = RESULTS / level / f"run-{n:02d}-{sub_id}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_up()
    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    sink_probe("RESET")
    probe_r1 = client("probe", "router1")
    op_result = client("op", "router1,router2")
    auth = sink_probe("AUTHORITY_PROBE")
    state = get(f"http://127.0.0.1:{SINK_PORT}/state")
    events = get(f"http://127.0.0.1:{SINK_PORT}/events")
    I_base = int(sink_direct_admit_check())
    X_base = int(probe_r1["body"].get("marker_seen") is True)
    A_base = int(auth.get("authority_probe") == "ok")
    O_base = int(state["state"].get("test_value") == 42)
    baseline = [I_base, X_base, A_base, O_base]
    (run_dir / "baseline.events.json").write_text(json.dumps(events, indent=2))

    sink_probe("RESET")
    sh("docker", "compose", "stop", stop_service)

    probe_r1_post = client("probe", "router1")
    probe_r2_post = client("probe", "router2")
    op_result2 = client("op", "router1,router2")
    auth2 = sink_probe("AUTHORITY_PROBE")
    state2 = get(f"http://127.0.0.1:{SINK_PORT}/state")
    events2 = get(f"http://127.0.0.1:{SINK_PORT}/events")

    I_post = int(sink_direct_admit_check())
    r1_ok = probe_r1_post["status"] == 200 and probe_r1_post["body"].get("marker_seen") is True
    r2_ok = probe_r2_post["status"] == 200 and probe_r2_post["body"].get("marker_seen") is True
    X_post = int(r1_ok or r2_ok)
    A_post = int(auth2.get("authority_probe") == "ok")
    O_post = int(state2["state"].get("test_value") == 42)
    post = [I_post, X_post, A_post, O_post]

    (run_dir / "post.events.json").write_text(json.dumps(events2, indent=2))
    (run_dir / "post.state.json").write_text(json.dumps(state2, indent=2))

    outcome = "PASS" if (baseline == [1,1,1,1] and post == prediction) else "FAIL"
    record = {
        "test": "C-3", "sub": sub_id, "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(), "stopped_service": stop_service,
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": prediction, "post_observed": post,
        "router1_probe_ok": r1_ok, "router2_probe_ok": r2_ok,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    sh("docker", "compose", "down", "-v", check=False)
    print(f"C-3{sub_id} {level} run {n} (stopped {stop_service}): "
          f"baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: C-3 WILL NOT BE EXECUTED.\n")
    for cmd in [("docker", "--version"), ("docker", "compose", "version"), (sys.executable, "--version")]:
        p = subprocess.run(cmd, text=True, capture_output=True)
        print((p.stdout or p.stderr).strip())
    sh("docker", "compose", "config")
    print("\nDocker Compose configuration validates successfully.")
    print("\nHarness is ready. Runs C-3a (stop gateway) and C-3b (stop router1) from separate fresh builds.")

def main():
    if "--dry-run" in sys.argv:
        dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes preregistered H4 configuration C-3 (two sub-ablations, each from a fresh build).")
    print(f"Level: {level}"); print(f"Runs (each): {runs}")
    if input("Type EXECUTE to continue: ") != "EXECUTE":
        print("Cancelled."); return
    d = RESULTS / level
    existing_a = [int(p.name.split("-")[1]) for p in d.glob("run-*-a")] if d.exists() else []
    start = max(existing_a) + 1 if existing_a else 1
    recs = []
    for n in range(start, start + runs):
        recs.append(sub_ablation(n, level, "a", "gateway", [1, 0, 1, 0]))
        recs.append(sub_ablation(n, level, "b", "router1", [1, 1, 1, 1]))
    outcomes = {}
    for r in recs: outcomes[f"{r['sub']}:{r['outcome']}"] = outcomes.get(f"{r['sub']}:{r['outcome']}", 0) + 1
    print("Summary:", outcomes)

if __name__ == "__main__":
    main()
