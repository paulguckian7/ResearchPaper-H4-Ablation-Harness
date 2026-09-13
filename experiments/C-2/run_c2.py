import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone
import urllib.request

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SINK_PORT = 18152

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

def sink_probe(cmd):
    p = sh("docker", "compose", "exec", "-T", "sink", "python", "/app/internal_probe.py", cmd)
    return json.loads(p.stdout.strip().splitlines()[-1])

def marker_seen(body):
    # Walks through as many "downstream" levels as the response
    # actually has, rather than assuming a fixed hop count. A one-level
    # version of this was initially correct for C-1/C-2 (single-hop:
    # router -> sink) but NOT for C-3 (two-hop: router1 -> gateway ->
    # sink, which nests "downstream" twice) -- see C-3's run_c3.py for
    # the real-run evidence that forced this to be generalised. Kept
    # identical across C-1/C-2/C-3 rather than three separate
    # implementations of the same idea.
    node = body
    seen_guard = 0
    while isinstance(node, dict) and seen_guard < 10:
        if node.get("marker_seen") is True:
            return True
        node = node.get("downstream")
        seen_guard += 1
    return False

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
    ROOT.parent.parent / "manifests" / "C-2.yaml", ROOT / "docker-compose.yml",
    ROOT / "router1" / "router.py", ROOT / "router2" / "router.py",
    ROOT / "sink" / "sink.py", ROOT / "client" / "send.py",
]

def wait_up():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if get("http://127.0.0.1:18150/health").get("ok") and \
               get("http://127.0.0.1:18151/health").get("ok") and \
               get(f"http://127.0.0.1:{SINK_PORT}/health").get("ok"):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("services did not become ready")

def one_run(n, level):
    run_dir = RESULTS / level / f"run-{n:02d}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", "--remove-orphans", check=False)  # --remove-orphans added: catches containers left behind by a Ctrl+C mid-command, which a plain "down -v" can miss
    sh("docker", "compose", "up", "-d", "--build")
    wait_up()
    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    sink_probe("RESET")

    # Baseline: both routes individually probed (pinned, per A8), operation
    # tried via router1 first.
    probe_r1 = client("probe", "router1")
    op_result = client("op", "router1,router2")
    auth = sink_probe("AUTHORITY_PROBE")
    state = get(f"http://127.0.0.1:{SINK_PORT}/state")
    events = get(f"http://127.0.0.1:{SINK_PORT}/events")

    I_base = int(sink_direct_admit_check())
    X_base = int(marker_seen(probe_r1["body"]))  # per-route probe via router1 alone
    A_base = int(auth.get("authority_probe") == "ok")
    O_base = int(state["state"].get("test_value") == 42)
    baseline = [I_base, X_base, A_base, O_base]
    (run_dir / "baseline.events.json").write_text(json.dumps(events, indent=2))
    (run_dir / "baseline.state.json").write_text(json.dumps(state, indent=2))

    # Ablation: stop router1 ONLY. router2 must still work.
    sink_probe("RESET")
    sh("docker", "compose", "stop", "router1")

    probe_r1_post = client("probe", "router1")   # must fail
    probe_r2_post = client("probe", "router2")   # must still succeed -- the disjunction
    op_result2 = client("op", "router1,router2")  # falls through to router2
    auth2 = sink_probe("AUTHORITY_PROBE")
    state2 = get(f"http://127.0.0.1:{SINK_PORT}/state")
    events2 = get(f"http://127.0.0.1:{SINK_PORT}/events")

    I_post = int(sink_direct_admit_check())
    r1_failed = probe_r1_post["status"] == 0
    r2_succeeded = probe_r2_post["status"] == 200 and marker_seen(probe_r2_post["body"])
    X_post = int(r1_failed and r2_succeeded)  # disjunction over the assessed route set holds
    A_post = int(auth2.get("authority_probe") == "ok")
    O_post = int(state2["state"].get("test_value") == 42)
    post = [I_post, X_post, A_post, O_post]

    (run_dir / "post.events.json").write_text(json.dumps(events2, indent=2))
    (run_dir / "post.state.json").write_text(json.dumps(state2, indent=2))

    sh("docker", "compose", "start", "router1")

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,1,1,1]) else "FAIL"
    record = {
        "test": "C-2", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,1,1,1], "post_observed": post,
        "router1_failed_alone": r1_failed, "router2_succeeded_alone": r2_succeeded,
        "outcome": outcome, "source_sha256": src_hashes,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"C-2 {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} "
          f"(router1 alone failed={r1_failed}, router2 alone worked={r2_succeeded}) => {outcome}")
    return record

def dry_run():
    print("Dry run only: C-2 WILL NOT BE EXECUTED.\n")
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
    print("WARNING: this executes preregistered H4 configuration C-2.")
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
        sh("docker", "compose", "down", "-v", "--remove-orphans", check=False)  # --remove-orphans added: catches containers left behind by a Ctrl+C mid-command, which a plain "down -v" can miss
    outcomes = {}
    for r in recs: outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    print("Summary:", outcomes)

if __name__ == "__main__":
    main()
