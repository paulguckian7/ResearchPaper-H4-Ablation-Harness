import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request, urllib.error

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

def probe(container, cmd):
    p = sh("docker", "compose", "exec", "-T", container, "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def send(source_service):
    p = sh("docker", "compose", "exec", "-T", source_service, "python", "/app/send.py")
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "A-3.yaml", ROOT / "docker-compose.yml",
    ROOT / "agent" / "agent.py", ROOT / "agent" / "internal_probe.py",
    ROOT / "source" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18120/health").get("ok") and get("http://127.0.0.1:18121/health").get("ok"):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("agents did not become ready")

def evaluate(port, container, events, access, real_result, marker_result, auth_probe):
    I = any(e["event"] == "interface_admit" for e in events)
    X = any(e["event"] == "handler_reached" and e.get("marker") is True for e in events) and \
        marker_result.get("status") == 200 and marker_result.get("marker_seen") is True
    A = access.get("state_writable_by_process") is True and \
        access.get("data_dir_writable_by_process") is True and \
        auth_probe.get("authority_probe") == "ok"
    O = real_result["body"].get("written") == 42
    return [int(I), int(X), int(A), int(O)]

def one_run(n, level):
    run_dir = RESULTS / level / f"run-{n:02d}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_up()

    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    (run_dir / "docker.images.txt").write_text(
        sh("docker", "images", "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}").stdout, encoding="utf-8")
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    for c in ("agent-t", "agent-c"):
        probe(c, "RESET")

    # ---- Baseline: both T and C succeed ----
    result_t = send("source-t")
    marker_t = probe("agent-t", "X_MARKER")
    access_t = probe("agent-t", "ACCESS_STATE")
    auth_t = probe("agent-t", "AUTHORITY_PROBE")
    events_t = get("http://127.0.0.1:18120/events")
    baseline_t = evaluate(18120, "agent-t", events_t, access_t, result_t, marker_t, auth_t)

    result_c = send("source-c")
    marker_c = probe("agent-c", "X_MARKER")
    access_c = probe("agent-c", "ACCESS_STATE")
    auth_c = probe("agent-c", "AUTHORITY_PROBE")
    events_c = get("http://127.0.0.1:18121/events")
    baseline_c = evaluate(18121, "agent-c", events_c, access_c, result_c, marker_c, auth_c)

    (run_dir / "baseline.agent-t.events.json").write_text(json.dumps(events_t, indent=2))
    (run_dir / "baseline.agent-c.events.json").write_text(json.dumps(events_c, indent=2))

    # ---- Ablation: remove agent-t's write permission only ----
    for c in ("agent-t", "agent-c"):
        probe(c, "RESET")
    sh("docker", "compose", "exec", "-T", "-u", "root", "agent-t", "chmod", "555", "/data")
    sh("docker", "compose", "exec", "-T", "-u", "root", "agent-t", "chmod", "444", "/data/state.json")

    result_t2 = send("source-t")
    marker_t2 = probe("agent-t", "X_MARKER")
    access_t2 = probe("agent-t", "ACCESS_STATE")
    auth_t2 = probe("agent-t", "AUTHORITY_PROBE")
    events_t2 = get("http://127.0.0.1:18120/events")

    I2 = any(e["event"] == "interface_admit" for e in events_t2)
    X2 = any(e["event"] == "handler_reached" and e.get("marker") is True for e in events_t2)
    # Absence evidence (protocol A5): access-control state withholds the
    # control, and the enforcing mechanism (AUTHORITY_PROBE) records a
    # denial. A_absent_confirmed is True exactly when both legs of that
    # evidence line up -- i.e. when Authority is correctly shown ABSENT.
    # Bug fixed here: an earlier version used this boolean directly as the
    # reported "A" value (int(A_absent_confirmed)), which reports A=1
    # ("present") on a correctly confirmed denial -- backwards. A must be
    # the negation: 0 when absence is confirmed, 1 otherwise.
    A_absent_confirmed = access_t2.get("state_writable_by_process") is False and auth_t2.get("authority_probe") == "denied"
    A2 = not A_absent_confirmed
    # O absent: the operation's specified transition (test_value -> 42) did
    # not occur.
    O2_occurred = result_t2["body"].get("written") == 42
    post_t_protocol = [int(I2), int(X2), int(A2), int(O2_occurred)]

    (run_dir / "post.agent-t.events.json").write_text(json.dumps(events_t2, indent=2))
    (run_dir / "post.agent-t.access_state.json").write_text(json.dumps(access_t2, indent=2))

    # Control C unaffected: send again, expect still (1,1,1,1)
    result_c2 = send("source-c")
    marker_c2 = probe("agent-c", "X_MARKER")
    access_c2 = probe("agent-c", "ACCESS_STATE")
    auth_c2 = probe("agent-c", "AUTHORITY_PROBE")
    events_c2 = get("http://127.0.0.1:18121/events")
    control_result = evaluate(18121, "agent-c", events_c2, access_c2, result_c2, marker_c2, auth_c2)

    outcome = "PASS" if (baseline_t == [1,1,1,1] and post_t_protocol == [1,1,0,0] and control_result == [1,1,1,1]) else "FAIL"

    record = {
        "test": "A-3", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed_T": baseline_t, "baseline_observed_C": baseline_c,
        "post_prediction_T": [1,1,0,0], "post_observed_T": post_t_protocol,
        "control_prediction_C": [1,1,1,1], "control_observed_C": control_result,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"A-3 {level} run {n}: T baseline={tuple(baseline_t)} T post={tuple(post_t_protocol)} C control={tuple(control_result)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: A-3 WILL NOT BE EXECUTED.\n")
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
    print(f"WARNING: this executes preregistered H4 configuration A-3.")
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
