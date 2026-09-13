import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
TARGET_PORT = 18341

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

def target_probe(cmd):
    p = sh("docker", "compose", "exec", "-T", "target", "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def target_direct(marker=True):
    req = urllib.request.Request(
        f"http://127.0.0.1:{TARGET_PORT}/fwd",
        data=json.dumps({"marker": marker}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Route": "direct-bypass-check"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status == 200 and json.loads(r.read()).get("marker_seen") is True

def client(mode, *args):
    p = sh("docker", "compose", "exec", "-T", "client", "python", "/app/send.py", mode, *args)
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "C-4a.yaml", ROOT / "docker-compose.yml",
    ROOT / "resolver-d1" / "resolver.py", ROOT / "target" / "target.py", ROOT / "client" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18340/health").get("ok") and get(f"http://127.0.0.1:{TARGET_PORT}/health").get("ok"):
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

    target_probe("RESET")
    probe = client("probe", "resolver-d1", "zone")
    auth = target_probe("AUTHORITY_PROBE")
    I_base = int(target_direct())
    X_base = int(probe.get("body", {}).get("marker_seen") is True)
    A_base = int(auth.get("authority_probe") == "ok")
    target_probe("RESET")
    op = client("op", "resolver-d1", "zone")
    O_base = int(op.get("body", {}).get("written") == 42)
    baseline = [I_base, X_base, A_base, O_base]

    target_probe("RESET")
    sh("docker", "compose", "stop", "resolver-d1")

    probe2 = client("probe", "resolver-d1", "zone")
    auth2 = target_probe("AUTHORITY_PROBE")
    I_post = int(target_direct())
    X_post = int(probe2.get("status") not in (0, None) and probe2.get("body", {}).get("marker_seen") is True)
    A_post = int(auth2.get("authority_probe") == "ok")
    target_probe("RESET")
    op2 = client("op", "resolver-d1", "zone")
    O_post = int(op2.get("body", {}).get("written") == 42)
    post = [I_post, X_post, A_post, O_post]

    sh("docker", "compose", "start", "resolver-d1")

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,0,1,0]) else "FAIL"
    record = {
        "test": "C-4a", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,0,1,0], "post_observed": post,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"C-4a {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    return record

def dry_run():
    print("Dry run only: C-4a WILL NOT BE EXECUTED.\n")
    for cmd in [("docker","--version"),("docker","compose","version"),(sys.executable,"--version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True); print((p.stdout or p.stderr).strip())
    sh("docker","compose","config"); print("\nDocker Compose configuration validates successfully.\nHarness is ready.")

def main():
    if "--dry-run" in sys.argv: dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes preregistered H4 configuration C-4a.")
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
