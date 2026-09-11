import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
TARGET_PORT = 18352

def sh(*args, check=True):
    p = subprocess.run(args, cwd=ROOT, encoding="utf-8", errors="replace", capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{p.stdout}\n{p.stderr}")
    return p

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
    ROOT.parent.parent / "manifests" / "C-4b.yaml", ROOT / "docker-compose.yml",
    ROOT / "resolver-d1" / "resolver.py", ROOT / "resolver-d2" / "resolver.py",
    ROOT / "target" / "target.py", ROOT / "client" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18350/health").get("ok") and get("http://127.0.0.1:18351/health").get("ok") \
               and get(f"http://127.0.0.1:{TARGET_PORT}/health").get("ok"):
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
    probe_d1 = client("probe", "resolver-d1", "zone")
    auth = target_probe("AUTHORITY_PROBE")
    I_base = int(target_direct())
    X_base = int(probe_d1.get("body", {}).get("marker_seen") is True)
    A_base = int(auth.get("authority_probe") == "ok")
    target_probe("RESET")
    op = client("op", "resolver-d1,resolver-d2", "zone")
    O_base = int(op.get("body", {}).get("written") == 42)
    baseline = [I_base, X_base, A_base, O_base]

    target_probe("RESET")
    sh("docker", "compose", "stop", "resolver-d1")

    probe_d1_post = client("probe", "resolver-d1", "zone")
    probe_d2_post = client("probe", "resolver-d2", "zone")
    auth2 = target_probe("AUTHORITY_PROBE")
    I_post = int(target_direct())
    d1_failed = probe_d1_post.get("status") in (0, None) or probe_d1_post.get("resolved") is None
    d2_ok = probe_d2_post.get("status") == 200 and probe_d2_post.get("body", {}).get("marker_seen") is True
    X_post = int(d1_failed and d2_ok)
    A_post = int(auth2.get("authority_probe") == "ok")
    target_probe("RESET")
    op2 = client("op", "resolver-d1,resolver-d2", "zone")
    O_post = int(op2.get("body", {}).get("written") == 42)
    post = [I_post, X_post, A_post, O_post]

    sh("docker", "compose", "start", "resolver-d1")

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,1,1,1]) else "FAIL"
    record = {
        "test": "C-4b", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,1,1,1], "post_observed": post,
        "resolver_d1_failed_alone": d1_failed, "resolver_d2_succeeded_alone": d2_ok,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"C-4b {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} "
          f"(d1 alone failed={d1_failed}, d2 alone worked={d2_ok}) => {outcome}")
    return record

def dry_run():
    print("Dry run only: C-4b WILL NOT BE EXECUTED.\n")
    for cmd in [("docker","--version"),("docker","compose","version"),(sys.executable,"--version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True); print((p.stdout or p.stderr).strip())
    sh("docker","compose","config"); print("\nDocker Compose configuration validates successfully.\nHarness is ready.")

def main():
    if "--dry-run" in sys.argv: dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes preregistered H4 configuration C-4b.")
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
