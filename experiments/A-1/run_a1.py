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

def rp_cmd(cmd):
    p = sh("docker", "compose", "exec", "-T", "rp", "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def issue(service):
    p = sh("docker", "compose", "exec", "-T", service, "python", "/app/issue_and_send.py")
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "A-1.yaml", ROOT / "docker-compose.yml",
    ROOT / "rp" / "rp.py", ROOT / "issuer-t" / "issue_and_send.py", ROOT / "issuer-c" / "issue_and_send.py",
]

def wait_up():
    deadline = time.time() + 90  # pip install during build/startup can be slow
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18180/health").get("ok"): return
        except Exception:
            time.sleep(1)
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
    baseline_t = issue("issuer-t")["body"]
    rp_cmd("RESET")
    baseline_c = issue("issuer-c")["body"]
    bt = [baseline_t["I"], baseline_t["X"], baseline_t["A"], baseline_t["O"]]
    bc = [baseline_c["I"], baseline_c["X"], baseline_c["A"], baseline_c["O"]]

    rp_cmd("RESET")
    rp_cmd("SCOPE_REMOVE issuer-t admin")
    access = rp_cmd("ACCESS_STATE")
    post_t = issue("issuer-t")["body"]
    control_c = issue("issuer-c")["body"]
    pt = [post_t["I"], post_t["X"], post_t["A"], post_t["O"]]
    cc = [control_c["I"], control_c["X"], control_c["A"], control_c["O"]]

    (run_dir / "baseline.T.json").write_text(json.dumps(baseline_t, indent=2))
    (run_dir / "baseline.C.json").write_text(json.dumps(baseline_c, indent=2))
    (run_dir / "post.T.json").write_text(json.dumps(post_t, indent=2))
    (run_dir / "control.C.json").write_text(json.dumps(control_c, indent=2))
    (run_dir / "post.access_state.json").write_text(json.dumps(access, indent=2))

    outcome = "PASS" if (bt == [1,1,1,1] and bc == [1,1,1,1] and pt == [1,1,0,0] and cc == [1,1,1,1]) else "FAIL"
    record = {
        "test": "A-1", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_T": bt, "baseline_C": bc, "post_prediction_T": [1,1,0,0], "post_T": pt,
        "control_prediction_C": [1,1,1,1], "control_C": cc,
        "outcome": outcome, "source_sha256": src_hashes,
        "note": "Forged-signature sanity check is run manually, not part of automated PASS/FAIL -- see manifest 'sanity_check'.",
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"A-1 {level} run {n}: baseline T={tuple(bt)} C={tuple(bc)} | post T={tuple(pt)} C(control)={tuple(cc)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: A-1 WILL NOT BE EXECUTED.\n")
    for cmd in [("docker", "--version"), ("docker", "compose", "version"), (sys.executable, "--version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True)
        print((p.stdout or p.stderr).strip())
    sh("docker", "compose", "config")
    print("\nDocker Compose configuration validates successfully.")
    for f in SOURCE_FILES:
        try: print(f"SHA256 {f.name}: {sha256_file(f)}")
        except FileNotFoundError: print(f"MISSING: {f}")
    print("\nNote: the build step pip-installs pyjwt and cryptography and")
    print("needs network access the first time.")
    print("Harness is ready.")

def main():
    if "--dry-run" in sys.argv:
        dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes preregistered H4 configuration A-1.")
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
