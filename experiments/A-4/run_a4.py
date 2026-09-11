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

def exec_scanner(*args, check=True, timeout=600, user=None):
    # Bug fixed here: every call through this helper previously ran with
    # no explicit user, which for the official clamav/clamav image's
    # default entrypoint means root (the documented non-root mode is an
    # explicit opt-in: --user clamav --entrypoint /init-unprivileged,
    # which this Dockerfile does not use). Root ignores Unix permission
    # bits entirely, so a chmod-based ablation has no effect on anything
    # run as root -- confirmed by a real run where A_post=1 (a write
    # test reported WRITABLE) immediately after chmod 555. clamdscan
    # invocations and the write-test verification now explicitly run as
    # the "clamav" user via user="clamav", so they are actually subject
    # to the directory permission the ablation changes. Administrative
    # commands (chmod itself, mkdir, cp of the source file) stay as the
    # default user, matching the pattern used in A-3/A-5 where root
    # applies the ablation but the tested process is non-root.
    cmd = ["docker", "compose", "exec", "-T"]
    if user:
        cmd += ["-u", user]
    cmd += ["scanner", *args]
    return sh(*cmd, check=check, timeout=timeout)

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

def wait_clamd_ready():
    # Bug fixed here: wait_signatures() only confirmed the signature
    # FILES exist on disk, never that clamd itself had finished starting
    # and created its socket. Confirmed by a real run: signatures were
    # present (daily.cvd on disk) but clamdscan failed with "Could not
    # connect to clamd on LocalSocket /tmp/clamd.sock: No such file or
    # directory" -- clamd was still starting. ClamAV's own docs note
    # that loading signatures into memory (~1.2GB) is a separate,
    # sometimes slow step from downloading them, and the container's
    # own default CLAMD_STARTUP_TIMEOUT is 1800 seconds -- a strong hint
    # this step can genuinely take a while. Poll for the socket file
    # itself, not just the signature files.
    print("Waiting for clamd to finish starting (socket to appear, up to 10 minutes)...")
    p = exec_scanner("sh", "-c",
        "for i in $(seq 1 120); do "
        "[ -S /tmp/clamd.sock ] && exit 0; "
        "sleep 5; done; exit 1", check=False, timeout=630)
    if p.returncode != 0:
        raise RuntimeError("clamd did not create its socket within 10 minutes -- check "
                            "container logs (docker compose logs scanner) for a clamd startup "
                            "error (e.g. insufficient RAM allocated to Docker Desktop).")

def one_run(n, level):
    run_dir = RESULTS / level / f"run-{n:02d}"
    if run_dir.exists():
        raise RuntimeError(f"{run_dir} exists; results are append-only")
    run_dir.mkdir(parents=True)

    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_signatures()
    wait_clamd_ready()
    (run_dir / "docker-compose.resolved.yaml").write_text(sh("docker", "compose", "config").stdout, encoding="utf-8")
    src_hashes = {f.name: (sha256_file(f) if f.exists() else "MISSING") for f in SOURCE_FILES}

    sig_check = exec_scanner("sh", "-c", "ls -la /var/lib/clamav/daily.c*d 2>/dev/null || echo NONE", check=False)
    (run_dir / "signature_state.txt").write_text(sig_check.stdout)
    I_base = int("NONE" not in sig_check.stdout)

    exec_scanner("mkdir", "-p", "/scan")
    exec_scanner("cp", "/scan/eicar-source.txt", "/scan/eicar.txt")
    exec_scanner("chmod", "755", "/quarantine")  # ensure baseline is writable

    # X and A/O are measured with TWO separate clamdscan invocations, not
    # one with --move. Bug fixed here: clamdscan --move performs setup
    # (creating a lock file) in the DESTINATION directory before it scans
    # the source at all -- confirmed by a real run where a permission-
    # denied destination made the whole invocation abort at "action_setup"
    # (exit 2) without ever reporting a detection result. That means
    # --move's exit code cannot be used to measure X independently of A,
    # which was the original (wrong) assumption. A plain scan with no
    # destination dependency measures detection on its own; a separate
    # --move call, on a freshly re-copied file, measures the write.
    scan1_plain = exec_scanner("clamdscan", "/scan/eicar.txt", check=False, user="clamav")
    X_base = int(scan1_plain.returncode == 1)  # clamdscan: 1 = virus/match found

    exec_scanner("cp", "/scan/eicar-source.txt", "/scan/eicar.txt")  # re-copy; plain scan doesn't consume it, but don't assume
    scan1 = exec_scanner("clamdscan", "--move=/quarantine", "/scan/eicar.txt", check=False, user="clamav")
    (run_dir / "baseline.scan.txt").write_text(
        f"plain scan: exit={scan1_plain.returncode}\n{scan1_plain.stdout}\n{scan1_plain.stderr}\n"
        f"---\nmove scan: exit={scan1.returncode}\n{scan1.stdout}\n{scan1.stderr}")

    q_check1 = exec_scanner("sh", "-c", "ls /quarantine/ 2>/dev/null || echo EMPTY", check=False)
    O_base = int("eicar" in q_check1.stdout)

    # A measured independently via a real write test, not inferred from O.
    # An earlier version set A_base = O_base directly -- coupling A to the
    # very outcome it's supposed to explain, the same mistake fixed in
    # A-3/A-5 (see their CHANGELOG entries).
    write_test1 = exec_scanner("sh", "-c",
        "touch /quarantine/.write_test 2>&1 && rm -f /quarantine/.write_test && echo WRITABLE || echo NOT_WRITABLE",
        check=False, user="clamav")
    A_base = int("WRITABLE" in write_test1.stdout and "NOT_WRITABLE" not in write_test1.stdout)

    baseline = [I_base, X_base, A_base, O_base]

    # Ablation: remove quarantine write permission. Signature fetching and
    # detection logic are completely untouched.
    #
    # Bug fixed here: the quarantine reset before ablation used a flat
    # "rm -f /quarantine/*", which does not remove subdirectories or
    # dotfiles. Confirmed by a real run where O_post came back 1 (file
    # still "in quarantine") despite the directory being chmod 555 --
    # which makes it impossible for clamdscan to have written anything
    # NEW there, since directory-level write denial blocks file creation
    # regardless of clamdscan's own behaviour. The only explanation
    # consistent with that is baseline's quarantined file never having
    # been removed. Replaced with a recursive find+delete, and the
    # resulting state is explicitly logged BEFORE ablation, not assumed.
    exec_scanner("sh", "-c", "find /quarantine -mindepth 1 -exec rm -rf {} + 2>/dev/null; true", check=False)
    pre_ablation_check = exec_scanner("sh", "-c", "ls -la /quarantine/ 2>&1", check=False)
    (run_dir / "pre_ablation_quarantine_state.txt").write_text(pre_ablation_check.stdout)
    if "eicar" in pre_ablation_check.stdout.lower():
        raise RuntimeError(
            "Quarantine reset failed -- eicar still present after find+delete. "
            "See pre_ablation_quarantine_state.txt. Do not trust this run's post-ablation O.")

    exec_scanner("cp", "/scan/eicar-source.txt", "/scan/eicar.txt")
    access_before = exec_scanner("stat", "-c", "%U %a", "/quarantine", check=False)
    exec_scanner("chmod", "555", "/quarantine")
    access_after = exec_scanner("stat", "-c", "%U %a", "/quarantine", check=False)
    (run_dir / "post.access_state.txt").write_text(
        f"before: {access_before.stdout.strip()}\nafter: {access_after.stdout.strip()}")

    # Same two-call split as baseline: plain scan for X, separate --move
    # for A/O, so a destination permission failure can't suppress the
    # detection result the way a single --move call did before.
    scan2_plain = exec_scanner("clamdscan", "/scan/eicar.txt", check=False, user="clamav")
    X_post = int(scan2_plain.returncode == 1)

    exec_scanner("cp", "/scan/eicar-source.txt", "/scan/eicar.txt")
    scan2 = exec_scanner("clamdscan", "--move=/quarantine", "/scan/eicar.txt", check=False, user="clamav")
    (run_dir / "post.scan.txt").write_text(
        f"plain scan: exit={scan2_plain.returncode}\n{scan2_plain.stdout}\n{scan2_plain.stderr}\n"
        f"---\nmove scan: exit={scan2.returncode}\n{scan2.stdout}\n{scan2.stderr}")

    sig_check2 = exec_scanner("sh", "-c", "ls -la /var/lib/clamav/daily.c*d 2>/dev/null || echo NONE", check=False)
    q_check2 = exec_scanner("sh", "-c", "ls /quarantine/ 2>/dev/null || echo EMPTY", check=False)

    I_post = int("NONE" not in sig_check2.stdout)  # signature access unaffected by the ablation
    O_post = int("eicar" in q_check2.stdout)  # move should have FAILED -- file not in quarantine

    # A measured independently again -- same fix as baseline, plus the
    # directory permission string as corroborating evidence.
    write_test2 = exec_scanner("sh", "-c",
        "touch /quarantine/.write_test 2>&1 && rm -f /quarantine/.write_test && echo WRITABLE || echo NOT_WRITABLE",
        check=False, user="clamav")
    A_post = int("WRITABLE" in write_test2.stdout and "NOT_WRITABLE" not in write_test2.stdout)

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
