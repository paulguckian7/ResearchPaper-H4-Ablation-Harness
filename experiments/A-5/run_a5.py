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

def probe(cmd):
    p = sh("docker", "compose", "exec", "-T", "agent", "python", "/app/internal_probe.py", cmd)
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
    ROOT.parent.parent / "manifests" / "A-5.yaml", ROOT / "docker-compose.yml",
    ROOT / "agent" / "agent.py", ROOT / "agent" / "internal_probe.py",
    ROOT / "source" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18130/health").get("ok"): return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("agent did not become ready")

def check(source_name, events, access, result, marker, auth, expect_written):
    I = any(e["event"] == "interface_admit" and e.get("source") == source_name for e in events)
    X = any(e["event"] == "handler_reached" and e.get("source") == source_name for e in events)
    A = (access.get("state_writable_by_process") is True and auth.get("authority_probe") == "ok") \
        if expect_written else \
        (access.get("state_writable_by_process") is False and auth.get("authority_probe") == "denied")
    O = result["body"].get("written") == 42
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
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    # ---- Baseline: T succeeds ----
    probe("RESET")
    result_t = send("source-t")
    marker_t = probe("X_MARKER")
    access_t = probe("ACCESS_STATE")
    auth_t = probe("AUTHORITY_PROBE")
    events_t = get("http://127.0.0.1:18130/events")
    baseline_t = check("T", events_t, access_t, result_t, marker_t, auth_t, expect_written=True)

    # ---- Baseline: C succeeds (separate check, same shared state) ----
    probe("RESET")
    result_c = send("source-c")
    marker_c = probe("X_MARKER")
    access_c = probe("ACCESS_STATE")
    auth_c = probe("AUTHORITY_PROBE")
    events_c = get("http://127.0.0.1:18130/events")
    baseline_c = check("C", events_c, access_c, result_c, marker_c, auth_c, expect_written=True)

    (run_dir / "baseline.T.events.json").write_text(json.dumps(events_t, indent=2))
    (run_dir / "baseline.C.events.json").write_text(json.dumps(events_c, indent=2))

    # ---- Only admissible ablation: remove the SHARED agent's write control ----
    probe("RESET")
    sh("docker", "compose", "exec", "-T", "-u", "root", "agent", "chmod", "555", "/data")
    sh("docker", "compose", "exec", "-T", "-u", "root", "agent", "chmod", "444", "/data/state.json")

    result_t2 = send("source-t")
    marker_t2 = probe("X_MARKER")
    access_t2 = probe("ACCESS_STATE")
    auth_t2 = probe("AUTHORITY_PROBE")
    events_t2 = get("http://127.0.0.1:18130/events")
    post_t = check("T", events_t2, access_t2, result_t2, marker_t2, auth_t2, expect_written=False)

    result_c2 = send("source-c")
    marker_c2 = probe("X_MARKER")
    access_c2 = probe("ACCESS_STATE")
    auth_c2 = probe("AUTHORITY_PROBE")
    events_c2 = get("http://127.0.0.1:18130/events")
    post_c = check("C", events_c2, access_c2, result_c2, marker_c2, auth_c2, expect_written=False)

    (run_dir / "post.T.events.json").write_text(json.dumps(events_t2, indent=2))
    (run_dir / "post.C.events.json").write_text(json.dumps(events_c2, indent=2))
    (run_dir / "post.access_state.json").write_text(json.dumps(access_t2, indent=2))

    # Prediction: post is [1,1,0,0] for BOTH T and C -- the denial is NOT
    # source-specific. This CONFIRMS the negative-case prediction.
    expected = [1, 1, 0, 0]
    not_source_specific = (post_t == expected and post_c == expected)
    outcome = "PASS (confirms non-source-specific: reclassify as Concentration)" if (
        baseline_t == [1,1,1,1] and baseline_c == [1,1,1,1] and not_source_specific
    ) else "FAIL (source-specific denial found or evidence contradicts baseline -- see protocol criterion 4)"

    record = {
        "test": "A-5", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_T": baseline_t, "baseline_C": baseline_c,
        "post_T": post_t, "post_C": post_c,
        "not_source_specific": not_source_specific,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"A-5 {level} run {n}: baseline T={tuple(baseline_t)} C={tuple(baseline_c)} | "
          f"post T={tuple(post_t)} C={tuple(post_c)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: A-5 WILL NOT BE EXECUTED.\n")
    for cmd in [("docker", "--version"), ("docker", "compose", "version"), (sys.executable, "--version")]:
        p = subprocess.run(cmd, text=True, capture_output=True)
        print((p.stdout or p.stderr).strip())
    sh("docker", "compose", "config")
    print("\nDocker Compose configuration validates successfully.")
    for f in SOURCE_FILES:
        try:
            print(f"SHA256 {f.name}: {sha256_file(f)}")
        except FileNotFoundError:
            print(f"MISSING: {f}")
    print("\nHarness is ready. Note: this experiment's PASS outcome means the")
    print("negative-case prediction was CONFIRMED (no source-specific ablation")
    print("exists), not that anything 'worked' in the usual sense.")

def main():
    if "--dry-run" in sys.argv:
        dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes preregistered H4 configuration A-5 (negative case).")
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
    print(f"Ran {len(recs)} runs; see individual outcomes above.")

if __name__ == "__main__":
    main()
