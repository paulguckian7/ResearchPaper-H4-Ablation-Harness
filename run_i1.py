import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
EXP = ROOT / "experiments" / "I-1"
MANIFEST = ROOT / "manifests" / "I-1.yaml"
RESULT_ROOT = EXP / "results"
BASE = "http://127.0.0.1:18080"

def sh(*args, cwd=None, check=True):
    p = subprocess.run(
        args,
        cwd=cwd or EXP,
        text=True,
        capture_output=True
    )
    if check and p.returncode != 0:
        raise RuntimeError(
            "Command failed: " + " ".join(args) +
            "\nSTDOUT:\n" + p.stdout +
            "\nSTDERR:\n" + p.stderr
        )
    return p

def http_get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))

def wait_receiver():
    deadline = time.time() + 60
    last = None
    while time.time() < deadline:
        try:
            d = http_get("/health")
            if d.get("ok"):
                return
        except Exception as e:
            last = e
            time.sleep(0.5)
    raise RuntimeError(f"receiver did not become ready: {last!r}")

def docker_exec(service, *cmd):
    p = sh("docker", "compose", "exec", "-T", service, *cmd)
    return p.stdout.strip()

def internal_probe(command):
    out = docker_exec("receiver", "python", "/app/internal_probe.py", command)
    try:
        return json.loads(out.splitlines()[-1])
    except Exception:
        return {"raw": out}

def source_ip():
    out = docker_exec(
        "source",
        "python",
        "-c",
        "import socket; print(socket.gethostbyname(socket.gethostname()))"
    )
    return out.strip()

def send_source():
    out = docker_exec("source", "python", "/app/send.py")
    return json.loads(out.splitlines()[-1])

def state():
    return http_get("/state")

def events():
    return http_get("/events")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def snapshot_environment(run_dir):
    shutil.copy2(MANIFEST, run_dir / "manifest.snapshot.yaml")

    resolved = sh("docker", "compose", "config").stdout
    (run_dir / "docker-compose.resolved.yaml").write_text(resolved, encoding="utf-8")

    images = sh(
        "docker", "images", "--digests",
        "--format", "{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.ID}}",
        cwd=EXP
    ).stdout
    (run_dir / "docker.images.txt").write_text(images, encoding="utf-8")

    git = sh("git", "rev-parse", "HEAD", cwd=ROOT, check=False)
    (run_dir / "git-head.txt").write_text(
        git.stdout.strip() if git.returncode == 0 else "not available",
        encoding="utf-8"
    )

    versions = []
    for cmd in [
        ("docker", "--version"),
        ("docker", "compose", "version"),
        (sys.executable, "--version"),
    ]:
        p = subprocess.run(cmd, text=True, capture_output=True)
        versions.append((p.stdout or p.stderr).strip())
    (run_dir / "versions.txt").write_text("\n".join(versions), encoding="utf-8")

def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def classify(baseline, post, evidence_ok):
    if not evidence_ok:
        return "AMBIGUOUS"
    if baseline == [1, 1, 1, 1] and post == [0, 1, 1, 0]:
        return "PASS"
    return "FAIL"

def baseline_measure():
    internal_probe("RESET")
    before = state()
    src = send_source()
    after = state()
    ev = events()

    I = int(any(e.get("event") == "interface_admit" for e in ev))
    X = int(any(e.get("event") == "handler_reached" for e in ev))
    A = int(any(e.get("event") == "state_write" for e in ev))
    O = int(
        before["state"].get("test_value") == 0
        and after["state"].get("test_value") == 42
    )

    evidence_ok = (
        src.get("status") == 200
        and I == 1 and X == 1 and A == 1 and O == 1
    )

    return [I, X, A, O], evidence_ok, {
        "source_result": src,
        "state": after,
        "events": ev
    }

def post_measure(ip):
    internal_probe("RESET")
    policy_result = internal_probe(f"SET_DENY_IP {ip}")

    # Attempt the actual operation from S.
    src = send_source()

    # Independent X check: inject immediately downstream of nominated Interface.
    x_result = internal_probe("X_MARKER")

    # Independent A check: same receiver process/identity writes same state.
    a_result = internal_probe("AUTHORITY_PROBE")

    st = state()
    ev = events()

    reject = any(
        e.get("event") == "interface_reject"
        and e.get("client_ip") == ip
        for e in ev
    )
    policy_denies = st["policy"].get("deny_ip") == ip
    I = 0 if (policy_denies and reject and src.get("status") == 403) else 1

    x_seen = (
        st["state"].get("marker_seen") is True
        and any(e.get("event") == "x_marker_reached_handler" for e in ev)
        and x_result.get("marker_seen") is True
    )
    X = int(x_seen)

    a_seen = (
        st["state"].get("authority_probe") == "ok"
        and any(e.get("event") == "authority_probe_write" for e in ev)
        and a_result.get("authority_probe") == "ok"
    )
    A = int(a_seen)

    O = int(st["state"].get("test_value") == 42)

    evidence_ok = (
        policy_denies
        and reject
        and src.get("status") == 403
        and x_seen
        and a_seen
        and O == 0
    )

    return [I, X, A, O], evidence_ok, {
        "policy_result": policy_result,
        "source_result": src,
        "x_probe_result": x_result,
        "authority_probe_result": a_result,
        "state": st,
        "events": ev
    }

def save_checksums(run_dir):
    rows = []
    for p in sorted(run_dir.rglob("*")):
        if p.is_file() and p.name != "checksums.sha256":
            rows.append(f"{sha256_file(p)}  {p.relative_to(run_dir).as_posix()}")
    (run_dir / "checksums.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")

def one_run(run_number, level):
    level_dir = RESULT_ROOT / level
    run_dir = level_dir / f"run-{run_number:02d}"
    if run_dir.exists():
        raise RuntimeError(
            f"{run_dir} already exists. Results are append-only; move/archive it explicitly."
        )
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_receiver()

    snapshot_environment(run_dir)

    ip = source_ip()

    baseline, baseline_evidence_ok, baseline_evidence = baseline_measure()
    write_json(run_dir / "baseline.events.json", baseline_evidence["events"])
    write_json(run_dir / "baseline.state.json", baseline_evidence["state"])

    post, post_evidence_ok, post_evidence = post_measure(ip)
    write_json(run_dir / "post.events.json", post_evidence["events"])
    write_json(run_dir / "post.state.json", post_evidence["state"])

    outcome = classify(
        baseline,
        post,
        baseline_evidence_ok and post_evidence_ok
    )

    governance = {
        "system": {"S": "D1", "R": "D1"},
        "system-of-systems": {"S": "D2", "R": "D1"},
    }[level]

    record = {
        "test": "I-1",
        "harness_version": "0.1.0",
        "run": run_number,
        "level": level,
        "governance_assignment": governance,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "baseline_prediction": [1, 1, 1, 1],
        "baseline_observed": baseline,
        "baseline_evidence_complete": baseline_evidence_ok,
        "post_prediction": [0, 1, 1, 0],
        "post_observed": post,
        "post_evidence_complete": post_evidence_ok,
        "outcome": outcome,
        "baseline_evidence_summary": {
            "source_result": baseline_evidence["source_result"]
        },
        "post_evidence_summary": {
            "policy_result": post_evidence["policy_result"],
            "source_result": post_evidence["source_result"],
            "x_probe_result": post_evidence["x_probe_result"],
            "authority_probe_result": post_evidence["authority_probe_result"]
        }
    }

    write_json(run_dir / "record.json", record)
    save_checksums(run_dir)

    print(
        f"I-1 {level} run {run_number}: "
        f"baseline={tuple(baseline)} post={tuple(post)} => {outcome}"
    )
    return record

def dry_run():
    print("Dry run only: I-1 WILL NOT BE EXECUTED.\n")
    commands = [
        ("docker", "--version"),
        ("docker", "compose", "version"),
        (sys.executable, "--version")
    ]
    for cmd in commands:
        p = subprocess.run(cmd, text=True, capture_output=True)
        print((p.stdout or p.stderr).strip())

    p = sh("docker", "compose", "config")
    print("\nDocker Compose configuration validates successfully.")

    for pth in [
        ROOT / "manifests" / "I-1.yaml",
        EXP / "receiver" / "receiver.py",
        EXP / "receiver" / "internal_probe.py",
        EXP / "source" / "send.py",
    ]:
        print(f"SHA256 {pth.relative_to(ROOT)}: {sha256_file(pth)}")

    print("\nHarness is ready.")
    print("Use --execute only after any intended preregistration is frozen/deposited.")

def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument(
        "--level",
        choices=["system", "system-of-systems"],
        default="system"
    )
    args = ap.parse_args()

    if args.dry_run:
        dry_run()
        return

    print("WARNING: this executes preregistered H4 configuration I-1.")
    print(f"Level: {args.level}")
    print(f"Runs: {args.runs}")
    answer = input("Type EXECUTE to continue: ")
    if answer != "EXECUTE":
        print("Cancelled.")
        return

    records = []
    try:
        start = 1
        level_dir = RESULT_ROOT / args.level
        if level_dir.exists():
            existing = []
            for p in level_dir.glob("run-*"):
                try:
                    existing.append(int(p.name.split("-")[1]))
                except Exception:
                    pass
            if existing:
                start = max(existing) + 1

        for n in range(start, start + args.runs):
            records.append(one_run(n, args.level))
    finally:
        sh("docker", "compose", "down", "-v", check=False)

    counts = {}
    for r in records:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

    print("\nSummary")
    for key in ["PASS", "FAIL", "AMBIGUOUS"]:
        print(f"{key}: {counts.get(key, 0)}")
    print(f"Evidence: {RESULT_ROOT / args.level}")

if __name__ == "__main__":
    main()
