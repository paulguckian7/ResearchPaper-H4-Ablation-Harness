# H4 Ablation Harness

A reproducible Docker/Python test harness for the H4 correspondence and Cut experiments described in:

> *From Node Structure to Systemic Cyber Risk: Extending Interface, Execution Pathway and Authority Across System Relationships and Governance Boundaries*

The harness is intended to test whether relational classes mapped to **Interface (I)**, **Execution Pathway (X)** and **Authority (A)** admit the predicted controlled ablation signatures while the other conditions are independently verified unchanged.

## Status

**Harness version:** 0.1.0  
**Current executable experiment:** I-1 (constructed HTTP Interface ablation)  
**Platform:** Docker Compose + Python 3.10+  
**Licence:** MIT

The repository (doi: 10.5281/zenodo.22711458) deliberately separates:

- `pilot-results/` — calibration runs that are not treated as final H4 evidence;
- `results/` — outputs from the corrected harness;
- `manifests/` — frozen experiment specifications and predictions;
- `docs/` — protocol and evidence guidance.

## Scientific use

If this harness is used with a preregistered protocol, freeze/deposit the protocol and experiment manifest **before** executing any run intended as confirmatory evidence.

The harness never treats failure of the target operation as evidence that a structural condition is absent. I, X and A are measured independently.

## I-1

### Baseline

Source `S` sends:

```json
{"test_value": 42}
```

to the nominated Interface:

```text
Receiver R: HTTP /push
```

The receiver admits the request, places the admitted work item on an **internal queue**, and the same receiver process handles the item and changes protected state:

```text
test_value: 0 -> 42
```

Expected baseline:

```text
(I, X, A, O) = (1, 1, 1, 1)
```

### Ablation

The existing admission policy at the nominated Interface is changed so that Source `S` is denied.

Expected post-ablation signature:

```text
(I, X, A, O) = (0, 1, 1, 0)
```

The conditions are then measured independently:

- **I absent:** the source-specific denial policy is present and the nominated Interface logs rejection of S.
- **X present:** a benign marker is injected through an internal Unix socket **immediately downstream of the nominated Interface**, into the same internal queue and same handler used by admitted work.
- **A present:** the same receiver process performs a benign write to the same protected state under its existing execution identity.
- **O absent:** S does not cause the specified state transition.

The X and A probes are instrumentation channels, not nominated Interfaces for the operation.

## Requirements

- Windows 10/11, macOS, or Linux
- Docker Desktop / Docker Engine
- Docker Compose v2
- Python 3.10+

No third-party Python packages are required by the runner.

## Quick start

### 1. Validate only

This does **not** execute I-1:

```powershell
cd C:\Research\H4_Ablation_Harness
python run_i1.py --dry-run
```

### 2. Run one experiment

Only do this after any intended preregistration is frozen/deposited:

```powershell
python run_i1.py --execute --runs 1 --level system
```

For the system-of-systems coding:

```powershell
python run_i1.py --execute --runs 1 --level system-of-systems
```

The technical configuration is identical; only the governance assignment differs. This is **not** counted as independent technical replication.

### 3. Run the five preregistered repetitions

```powershell
python run_i1.py --execute --runs 5 --level system
python run_i1.py --execute --runs 5 --level system-of-systems
```

Evidence is written to:

```text
experiments/I-1/results/<level>/run-XX/
```

Each run stores:

- `record.json`
- `manifest.snapshot.yaml`
- `docker-compose.resolved.yaml`
- `baseline.events.json`
- `baseline.state.json`
- `post.events.json`
- `post.state.json`
- `docker.images.txt`
- `git-head.txt` where available
- `checksums.sha256`

## Result interpretation

The runner reports one of:

- `PASS` — all baseline and post-ablation measurements match the frozen prediction;
- `FAIL` — at least one measured value conflicts with the prediction;
- `AMBIGUOUS` — the harness cannot establish presence or absence under the evidence rules.

A pass supports H4 only for the tested configuration and mechanism. It does not prove the universal claim.

## Pilot results

Five earlier pilot runs are included where available. They produced the predicted tuple, but the earlier X probe used a separate HTTP control endpoint. They are therefore retained as **calibration evidence only** and are not final H4 evidence under the stricter A4 rule.

## Repository structure

```text
H4_Ablation_Harness/
├── README.md
├── LICENSE
├── CITATION.cff
├── CHANGELOG.md
├── run_i1.py
├── manifests/
│   └── I-1.yaml
├── docs/
│   ├── EVIDENCE_RULES.md
│   └── PUBLICATION_CHECKLIST.md
└── experiments/
    └── I-1/
        ├── docker-compose.yml
        ├── receiver/
        ├── source/
        ├── pilot-results/
        └── results/
```

## Reproducibility principle

The graph/model predicts the structural classification. The running container environment is then changed and observed. The harness does not use the same graph representation to both predict and simulate the result.

## Author

Paul Guckian  
Independent Researcher, London, United Kingdom
