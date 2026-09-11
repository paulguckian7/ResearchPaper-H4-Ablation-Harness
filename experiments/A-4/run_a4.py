import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

def sh(*args, check=True, timeout=600):
    p = subprocess.run(args, cwd=ROOT, encoding="utf-8", errors="replace", capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{p.stdout}\n{p.stderr}")
    return p

def exec_scanner(*args, check=True, timeout=600):
    return sh("docker", "compose", "exec", "-T", "scanner", *args, check=check, timeout=timeout)

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "A-4.yaml", ROOT / "docker-compose.yml",
    ROOT / "scanner" / "Dockerfile",
]

def wait_signatures():
    print("Waiting for freshclam to fetch signatures (up to 5 minutes)...")
    p = exec_scanner("sh", "-c",
        "for i in $(seq 1 60); do "
        "[ -f /var/lib/clamav/daily.cvd -o -f /var/lib/clamav/daily.cld ] && exit 0; "
        "sleep 5; done; exit 1", check=False, timeout=330)
    if p.returncode != 0:
        raise RuntimeError("Signatures did not arrive within 5 minutes -- check network access "
                            "to ClamAV's mirrors and container logs (docker compose logs scanner).")

def one_run(n, level):
    run_dir = RESULTS / level / f"run-{n:02d}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_signatures()
    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    sig_check = exec_scanner("sh", "-c", "ls -la /var/lib/clamav/daily.c*d 2>/dev/null || echo NONE", check=False)
    (run_dir / "signature_state.txt").write_text(sig_check.stdout)
    I_base = int("NONE" not in sig_check.stdout)

    exec_scanner("mkdir", "-p", "/scan")
    exec_scanner("cp", "/scan/eicar-source.txt", "/scan/eicar.txt")
    exec_scanner("chmod", "755", "/quarantine")  # ensure baseline is writable

    scan1 = exec_scanner("clamdscan", "--move=/quarantine", "/scan/eicar.txt", check=False)
    (run_dir / "baseline.scan.txt").write_text(f"exit={scan1.returncode}\n{scan1.stdout}\n{scan1.stderr}")

    q_check1 = exec_scanner("sh", "-c", "ls /quarantine/ 2>/dev/null || echo EMPTY", check=False)
    O_base = int("eicar" in q_check1.stdout)
    X_base = int(scan1.returncode == 1)  # clamdscan: 1 = virus/match found
    A_base = O_base  # move succeeded iff O succeeded, given detection occurred

    baseline = [I_base, X_base, A_base, O_base]

    # Ablation: remove quarantine write permission. Signature fetching and
    # detection logic are completely untouched.
    exec_scanner("sh", "-c", "rm -f /quarantine/*", check=False)  # reset quarantine for post phase
    exec_scanner("cp", "/scan/eicar-source.txt", "/scan/eicar.txt")
    access_before = exec_scanner("stat", "-c", "%U %a", "/quarantine", check=False)
    exec_scanner("chmod", "555", "/quarantine")
    access_after = exec_scanner("stat", "-c", "%U %a", "/quarantine", check=False)
    (run_dir / "post.access_state.txt").write_text(
        f"before: {access_before.stdout.strip()}\nafter: {access_after.stdout.strip()}")

    scan2 = exec_scanner("clamdscan", "--move=/quarantine", "/scan/eicar.txt", check=False)
    (run_dir / "post.scan.txt").write_text(f"exit={scan2.returncode}\n{scan2.stdout}\n{scan2.stderr}")

    sig_check2 = exec_scanner("sh", "-c", "ls -la /var/lib/clamav/daily.c*d 2>/dev/null || echo NONE", check=False)
    q_check2 = exec_scanner("sh", "-c", "ls /quarantine/ 2>/dev/null || echo EMPTY", check=False)

    I_post = int("NONE" not in sig_check2.stdout)  # signature access unaffected by the ablation
    X_post = int(scan2.returncode == 1)  # detection still occurs -- independent of the move
    O_post = int("eicar" in q_check2.stdout)  # move should have FAILED -- file not in quarantine
    A_post = int(not O_post and X_post == 1)  # move denied despite detection succeeding

    post = [I_post, X_post, A_post, O_post]
    exec_scanner("chmod", "755", "/quarantine", check=False)  # restore for teardown cleanliness

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [1,1,0,0]) else "FAIL_OR_NEEDS_REVIEW"
    record = {
        "test": "A-4", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [1,1,0,0], "post_observed": post,
        "outcome": outcome, "source_sha256": src_hashes,
        "scan1_exit": scan1.returncode, "scan2_exit": scan2.returncode,
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"A-4 {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    print(f"  (UNTESTED, HIGHEST-RISK harness -- review baseline.scan.txt / post.scan.txt / post.access_state.txt)")
    return record

def dry_run():
    print("Dry run only: A-4 WILL NOT BE EXECUTED.\n")
    print("THIS IS THE LEAST-VERIFIED HARNESS IN THE SUITE.")
    print("No ClamAV binaries or mirror-network access were available to test this during development.")
    print("Recommend reading manifests/A-4.yaml 'known_risks' in full before running.\n")
    for cmd in [("docker","--version"),("docker","compose","version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True); print((p.stdout or p.stderr).strip())
    sh("docker","compose","config")
    print("\nDocker Compose configuration validates successfully.")
    print("Harness is ready. First run will take several minutes (signature download).")

def main():
    if "--dry-run" in sys.argv: dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes the LEAST-VERIFIED H4 configuration, A-4.")
    print("Strongly recommend --runs 1 first, and reviewing every output file, before a full batch.")
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
