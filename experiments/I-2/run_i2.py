import json, subprocess, sys, time, hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RECEIVERS = ["receiver-1", "receiver-2", "receiver-3"]

def sh(*args, check=True):
    p = subprocess.run(args, cwd=ROOT, encoding="utf-8", errors="replace", capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {args}\n{p.stdout}\n{p.stderr}")
    return p

def publish(mode="publish"):
    p = sh("docker", "compose", "exec", "-T", "source-t", "python", "/app/publish.py", mode)
    return json.loads(p.stdout.strip().splitlines()[-1])

def clear_retained():
    # Publishing an empty retained message clears the broker's retained
    # state for the topic. Necessary between baseline and post-ablation
    # checks in the SAME run: without this, receivers subscribing after
    # the (denied) post-ablation publish would still see baseline's
    # retained message and falsely report O=1.
    publish("clear")

def receive(service):
    p = sh("docker", "compose", "exec", "-T", service, "python", "/app/subscribe_and_record.py")
    return json.loads(p.stdout.strip().splitlines()[-1])

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

SOURCE_FILES = [
    ROOT.parent.parent / "manifests" / "I-2.yaml", ROOT / "docker-compose.yml",
    ROOT / "broker" / "mosquitto.conf", ROOT / "broker" / "acl.baseline.conf", ROOT / "broker" / "acl.ablated.conf",
    ROOT / "source" / "publish.py", ROOT / "receiver" / "subscribe_and_record.py",
]

def wait_up():
    # Mosquitto has no HTTP health endpoint; give it a moment to bind.
    time.sleep(3)

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

    # Baseline: publish RETAINED (so receivers subscribing afterward still
    # get it -- MQTT does not deliver to subscribers who connect after a
    # non-retained publish), then check each receiver.
    pub_result = publish()
    recv_results = {r: receive(r) for r in RECEIVERS}
    (run_dir / "baseline.publish.json").write_text(json.dumps(pub_result, indent=2))
    (run_dir / "baseline.receivers.json").write_text(json.dumps(recv_results, indent=2))

    # MQTTv5 reason codes: the whole 0x00-0x7F range (0-127) is Success,
    # not just literal 0 -- e.g. 16 ("No matching subscribers") is a
    # normal, non-failure code that fires whenever nothing happens to be
    # subscribed at the exact moment of publish, which is expected here
    # since receivers subscribe AFTER the publish and rely on the
    # retained flag to pick the message up regardless of this code.
    # 0x80+ (128+) is the failure range -- e.g. 135 "Not authorized" for
    # an ACL denial. An earlier version checked "== 0" only, which
    # misread a normal 16 as a failure. Confirmed against a real broker
    # run: baseline reason 16 with O=1 (receivers got it via retain) and
    # post-ablation reason 135 with O=0 (correctly denied).
    prv = pub_result.get("puback_reason_value")
    I_base = int(prv is not None and prv < 128)
    O_base = int(all(r.get("got_message") for r in recv_results.values()))
    baseline = [I_base, 1, 1, O_base]  # X, A not meaningfully separable for this row; see manifest

    # Clear the baseline's retained message BEFORE ablation (source-t still
    # has write permission at this point) so post-ablation receivers cannot
    # see a stale retained value and produce a false-positive O.
    clear_retained()

    # Ablation: swap ACL, reload broker.
    sh("docker", "compose", "exec", "-T", "-u", "root", "broker", "cp",
       "/mosquitto/config/acl.ablated.conf", "/mosquitto/config/acl.conf")
    sh("docker", "compose", "kill", "-s", "HUP", "broker")
    time.sleep(1)

    pub_result2 = publish()
    recv_results2 = {r: receive(r) for r in RECEIVERS}
    (run_dir / "post.publish.json").write_text(json.dumps(pub_result2, indent=2))
    (run_dir / "post.receivers.json").write_text(json.dumps(recv_results2, indent=2))

    prv2 = pub_result2.get("puback_reason_value")
    I_post = int(prv2 is not None and prv2 >= 128)  # failure range per MQTTv5, not just nonzero
    O_post = int(not any(r.get("got_message") for r in recv_results2.values()))
    post = [1 - I_post, 1, 1, 1 - O_post]  # encode as protocol convention: I absent -> 0, O absent -> 0
    # (I_post/O_post above are "was it denied" flags; invert for [I,X,A,O] reporting)

    outcome = "PASS" if (baseline == [1,1,1,1] and post == [0,1,1,0]) else "FAIL_OR_NEEDS_REVIEW"
    record = {
        "test": "I-2", "harness_version": "0.2.0", "run": n, "level": level,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_prediction": [1,1,1,1], "baseline_observed": baseline,
        "post_prediction": [0,1,1,0], "post_observed": post,
        "outcome": outcome, "source_sha256": src_hashes,
        "raw_publish_baseline": pub_result, "raw_publish_post": pub_result2,
        "note": "puback_reason_value/str in raw_publish_* are the actual reason code paho-mqtt reported -- check these directly if I still looks wrong; this is the field this harness has never had confirmed against a real broker before now.",
    }
    (run_dir / "record.json").write_text(json.dumps(record, indent=2))
    print(f"I-2 {level} run {n}: baseline={tuple(baseline)} post={tuple(post)} => {outcome}")
    print(f"  (UNTESTED harness -- review raw_publish_baseline/post and receiver JSON before trusting this verdict)")
    return record

def dry_run():
    print("Dry run only: I-2 WILL NOT BE EXECUTED.\n")
    print("THIS HARNESS HAS NOT BEEN FUNCTIONALLY TESTED (no local mosquitto/paho-mqtt available during development).")
    for cmd in [("docker","--version"),("docker","compose","version"),(sys.executable,"--version")]:
        p = subprocess.run(cmd, encoding="utf-8", errors="replace", capture_output=True); print((p.stdout or p.stderr).strip())
    sh("docker","compose","config")
    print("\nDocker Compose configuration validates successfully.")
    print("Harness is ready, but see manifest 'known_risks' before treating results as confirmatory.")

def main():
    if "--dry-run" in sys.argv: dry_run(); return
    runs = int(sys.argv[sys.argv.index("--runs")+1]) if "--runs" in sys.argv else 1
    level = sys.argv[sys.argv.index("--level")+1] if "--level" in sys.argv else "system"
    if "--execute" not in sys.argv:
        print("Pass --dry-run to validate, or --execute --runs N --level system to run."); return
    print("WARNING: this executes UNTESTED H4 configuration I-2. Review the manifest's")
    print("known_risks section first. Recommend running with --runs 1 initially and")
    print("inspecting raw_publish_baseline/post before running a full batch.")
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
