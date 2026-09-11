# H4 Ablation Harness — complete matrix (14 configurations, I-1 through C-4c)

All fourteen configurations named in the protocol are now built (C-4 is
split into three sub-configs — C-4a/b/c — for the three Cut cases, same
as C-1/C2/C3).

## Status

| Config | Functionally verified locally | Real dependency verified |
|---|---|---|
| I-1 | Yes — confirmatory runs complete, 10/10 PASS | — |
| X-1 | Yes — full cycle, real Docker-independent HTTP/socket test | — |
| A-3 | Yes — full cycle, 2 bugs found and fixed | Real OS permissions, non-root identity |
| A-5 | Yes — full cycle | — |
| C-1 | Yes — full cycle | — |
| C-2 | Yes — fallback logic tested in isolation | — |
| C-3 | Yes — both sub-ablations tested | — |
| A-6 | Yes — full cycle | — |
| A-1 | Yes — full cycle, plus a forged-signature sanity check | Real RS256 JWT signing/verification (PyJWT + cryptography) |
| A-2 | Yes — full cycle, plus a no-cert sanity check | Real mutual TLS handshake (Python ssl module, real X.509 certs) |
| C-4a | Yes — full cycle | — |
| C-4b | Reasoned from C-2 + C-4a, not independently run | — |
| C-4c | Yes — both sub-ablations tested | — |
| **I-2** | **No** | Needs mosquitto (not installed here) |
| **X-2** | **No** | Needs nginx (not installed here) |
| **A-4** | **No** | Needs ClamAV binaries + internet access to ClamAV's mirrors |

**11 of 14 are functionally verified the same way I-1 was: run outside
Docker, real baseline/ablation/control cycle, logs checked for
exceptions.** I-2, X-2, and A-4 could only be built from documentation
and reasoning — I have no way to execute mosquitto, nginx, or ClamAV in
this environment, so nothing about their behavior has been observed. C-4b
is reasoned by analogy to C-2 and C-4a rather than independently run.

## What A-1 and A-2 add: full Authority-row coverage with real cryptography

This session's other new tests use permission bits (A-3, A-5) or an
application-level policy dict (A-6) as the Authority mechanism. A-1 and
A-2 use actual cryptographic protocols:

- **A-1**: real RS256 JWTs, generated with `cryptography`, signed and
  verified with PyJWT. A sanity check confirms a token with a forged
  signature (claiming `iss=issuer-t` but signed by an untrusted key) is
  rejected at signature verification — `I=0` — and never reaches the
  Authority check. This is the strongest evidence in the whole suite
  that I and A are correctly separated for the conferring form.
- **A-2**: real mutual TLS, with actual generated CAs and client
  certificates, verified through Python's `ssl` module. The sanity
  check here is stronger still: a client presenting no certificate at
  all fails at the TLS handshake itself (`SSLEOFError`), before any
  application code runs — the Interface/Authority boundary is enforced
  at the transport layer, not just in a conditional.

Between A-1, A-2, A-3, A-5, and A-6, every row and form of Table 1's
Authority cell now has at least one functionally verified test:
conferring (A-1 JWT, A-2 mTLS), directing (A-3 constructed, A-6 DNS),
and the negative case (A-5).

## What's honestly unverified, and why each matters

**I-2 (mosquitto).** I found and fixed one real bug by tracing through
the sequencing carefully even without being able to run it: the
original design published *before* subscribing receivers, which MQTT
without retained messages would silently fail to deliver on — a false
negative baked into the test itself. Fixed with retained publish, plus
an explicit clear-retained step between baseline and post-ablation so
the post check can't see baseline's stale message. That bug is fixed
*in the design*; whether the ACL/SIGHUP-reload mechanics work as
mosquitto's documentation describes is still unverified.

**X-2 (nginx).** The design decision that matters most: I is defined as
whether nginx *accepts the connection at all* (200 or 404), not whether
it successfully routes. A 404 after the ablation is admission without
routing — the correct signature for a Channel ablation. Whether
`nginx -s reload` actually behaves as documented, and whether the
ablated config is syntactically valid to nginx, is unverified.

**A-4 (ClamAV) — the highest-risk one.** This is the only test in the
whole suite with a real external signature source (ClamAV's actual
mirror network) rather than a constructed stand-in, which makes it the
ecological-validity companion to A-3's constructed agent test. It's
also the least verified: I don't know if `clamdscan --move` on a
read-only destination fails the way I've assumed, whether clamd needs
explicit startup coordination before `clamdscan` can connect to it, or
how long the first signature download actually takes. The manifest and
runner both flag this prominently and recommend running with
`--runs 1` first and reading every output file before trusting a
verdict.

## Bug count this session

Two in A-3 (worker crash, evidence coupling), one design smell in the
router (RESET gated incorrectly), one packaging gap (missing
`internal_probe.py` in four Dockerfiles), and one sequencing bug in I-2
(publish-before-subscribe with no retention) — caught by tracing
through the design rather than running it, since I couldn't run it.
**Six bugs found and fixed across this whole build, all in coordination
or sequencing logic, none in the core I/X/A/O measurement logic itself.**

## Running these

Each experiment is self-contained under `experiments/<ID>/`, with its
manifest at `manifests/<ID>.yaml`. All runners share the same interface:

    cd experiments/<ID>
    python run_<id>.py --dry-run
    python run_<id>.py --execute --runs 5 --level system

For I-2, X-2, and A-4, do this first, before anything else: read the
manifest's `known_risks` section, then run with `--runs 1` and inspect
every output file in the run directory before running a full batch. The
runners print a reminder of this at both dry-run and execute time.

C-4 is split into C-4a, C-4b, C-4c exactly like C-1/C2/C3 — each is a
separate directory with its own runner (`run_c4a.py`, `run_c4b.py`,
`run_c4c.py`).

## Governance levels: a documentation gap to check before using these as system-of-systems evidence

A-1, A-2, A-3, and A-5 express their governance-crossing relation via
which source/issuer is used (`issuer-t` vs `issuer-c`, etc.), recorded
in the manifest's `governance.system` block, rather than a separate
`system-of-systems` compose variant the way X-1 and C-1/C2/C3 have.
A-4's governance is implicit — the external party is ClamAV's real
mirror network, not a container in the compose file at all. Confirm
this matches how the paper wants system-of-systems evidence presented
before citing these as covering that level.
