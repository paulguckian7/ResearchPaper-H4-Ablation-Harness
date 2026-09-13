import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

# Bug fixed here: "docker compose up --build" failed intermittently
# with "Error response from daemon: i/o timeout" under sustained batch
# use -- confirmed multiple times on real runs, always transient (the
# same command succeeds seconds later with no code change). This is a
# Docker Desktop daemon/proxy issue, not a defect in the command being
# run, so the correct fix is to retry automatically rather than fail
# the whole run. Retries apply ONLY to docker/docker-compose
# invocations, never to anything else "sh" runs -- a genuine test
# failure (an assertion on the observed I/X/A/O tuple, for instance)
# never goes through this function at all, so retrying here cannot
# mask a real result.
import time as _time

def _sh_with_retry(args, check=True, timeout=None, max_attempts=4):
    is_docker = len(args) > 0 and args[0] in ("docker",)
    attempts = max_attempts if is_docker else 1
    delays = [5, 15, 30]
    last = None
    for attempt in range(attempts):
        kwargs = dict(cwd=ROOT, encoding="utf-8", errors="replace", capture_output=True)
        if timeout is not None:
            kwargs["timeout"] = timeout
        p = subprocess.run(args, **kwargs)
        if p.returncode == 0:
            return p
        transient = is_docker and (
            "i/o timeout" in (p.stderr or "") or "i/o timeout" in (p.stdout or "")
        )
        last = p
        if not transient or attempt == attempts - 1:
            break
        wait = delays[min(attempt, len(delays) - 1)]
        print(f"  transient Docker error, retrying in {wait}s (attempt {attempt+1}/{attempts})...")
        _time.sleep(wait)
    if check and last.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{last.stdout}\n{last.stderr}")
    return last

def sh(*args, check=True):
    return _sh_with_retry(args, check=check)

def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())

def rp_cmd(cmd):
    p = sh("docker", "compose", "exec", "-T", "rp", "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def send(service):
    p = sh("docker", "compose", "exec", "-T", service, "python", "/app/send.py")
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "A-2.yaml", ROOT / "docker-compose.yml",
    ROOT / "rp" / "rp.py", ROOT / "source-t" / "send.py", ROOT / "source-c" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18190/health").get("ok"): return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("rp did not become ready")

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

    rp_cmd("RESET")
    baseline_t = send("source-t")["body"]
    rp_cmd("RESET")
    baseline_c = send("source-c")["body"]
    bt = [baseline_t["I"], baseline_t["X"], baseline_t["A"], baseline_t["O"]]
    bc = [baseline_c["I"], baseline_c["X"], baseline_c["A"], baseline_c["O"]]

    rp_cmd("RESET")
    rp_cmd("SCOPE_REMOVE T admin")
    access = rp_cmd("ACCESS_STATE")
    post_t = send("source-t")["body"]
    control_c = send("source-c")["body"]
    pt = [post_t["I"], post_t["X"], post_t["A"], post_t["O"]]
    cc = [control_c["I"], control_c["X"], control_c["A"], control_c["O"]]

    (run_dir / "baseline.T.json").write_text(json.dumps(baseline_t, indent=2))
    (run_dir / "baseline.C.json").write_text(json.dumps(baseline_c, indent=2))
    (run_dir / "post.T.json").write_text(json.dumps(post_t, indent=2))
    (run_dir / "control.C.json").write_text(json.dumps(control_c, indent=2))
    (run_dir / "post.access_state.json").write_text(json.dumps(access, indent=2))

    outcome = "PASS" if (bt == [1,1,1,1] and bc == [1,1,1,1] and pt == [1,1,0,0] and cc == [1,1,1,1]) else "FAIL"
    record = {
        "test": "A-2", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_T": bt, "baseline_C": bc, "post_prediction_T": [1,1,0,0], "post_T": pt,
        "control_prediction_C": [1,1,1,1], "control_C": cc,
        "outcome": outcome, "source_sha256": src_hashes,
        "note": "No-cert sanity check is manual -- see manifest 'sanity_check'.",
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"A-2 {level} run {n}: baseline T={tuple(bt)} C={tuple(bc)} | post T={tuple(pt)} C(control)={tuple(cc)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: A-2 WILL NOT BE EXECUTED.\n")
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
    print("WARNING: this executes preregistered H4 configuration A-2.")
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
