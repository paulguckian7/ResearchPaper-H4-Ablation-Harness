# H4 Ablation Harness

A reproducible Docker/Python test harness for the H4 correspondence and Cut experiments described in:

> *From Node Structure to Systemic Cyber Risk: Extending Interface, Execution Pathway and Authority Across System Relationships and Governance Boundaries*

The harness tests whether relational classes mapped to **Interface (I)**, **Execution Pathway (X)** and **Authority (A)** admit the predicted controlled ablation signatures while the other conditions are independently verified unchanged.

## Status

**Release:** v1.0.0
**Configurations executed:** 14 (I-1, I-2, X-1, X-2, A-1 to A-6, C-1 to C-4c)
**Platform:** Docker Compose + Python 3.10+
**Licence:** MIT
**Archive:** https://doi.org/10.5281/zenodo.22711457 (concept DOI; cite the version DOI for v1.0.0)

This release contains the harness, the manifests holding the fixed predictions, the run records for every configuration, and the five demonstration-case records behind Section 6 of the paper. It is identical to the earlier `v0.3.0` tag apart from the addition of `demonstration-cases/`; manifests, harness code and run records are unchanged between the two.

## Layout

```
H4_Ablation_Harness/
├── README.md
├── LICENSE
├── CITATION.cff
├── CHANGELOG.md
├── REPOSITORY_SHA256SUMS.txt
├── run_i1.py
├── Run-All-H4.ps1
├── manifests/              # fixed specifications and predictions, one per configuration
├── docs/                   # protocol and evidence guidance
├── demonstration-cases/    # per-case assessment records for the paper's Section 6
├── logs/                   # execution logs, including dry runs
└── experiments/            # per-configuration testbeds and run records
    └── <ID>/results/<coding>/run-NN/
```

Each configuration coded at both levels is executed separately under `system/` and `system-of-systems/`. The technical configuration is identical and only the governance assignment differs, so the two are **not** independent technical replications.

## Reported batch

The reported batch is five runs per coding for each configuration, and five per sub-ablation for C-3 and C-4c, which each report two.

`results/` directories contain more run directories than that. The additional executions are calibration runs, or runs in which the execution or evidence-collection scaffolding failed to satisfy the evidence rules. These are retained deliberately rather than deleted, and are excluded from the reported batch: a run is technically invalid where the scaffolding failed to produce evidence meeting the rules, never where a prediction was unmet.

<!-- TODO before release: state here how a reader identifies the five counted runs per configuration, either the field in record.json that marks them or a RESULTS.md mapping each configuration to its counted run directories. -->

## Evidence rules

`docs/EVIDENCE_RULES.md` holds the full rules. Four carry most of the weight:

- every condition is measured independently after every ablation, never inferred from whether the operation succeeded;
- absence requires affirmative warrant: a configured denial with a logged rejection for I, an admitted input with no marker in the specified window for X, withheld access-control state with a same-identity denial record for A;
- every Authority-row test carries a control source that must still take effect after the ablation;
- redesign is not ablation: no mechanism, identity, source, route or enforcement point may be created, split, duplicated or replaced, and an in-processing filter is not an Authority ablation.

For Cut tests each route is probed individually with a pinned marker, and X for the operation is the disjunction of the per-route results, so no result depends on retry, timeout or failover.

## Result interpretation

The runner reports `PASS`, `FAIL` or `AMBIGUOUS`. A pass supports H4 only for the tested configuration and mechanism; it does not prove the universal claim. The graph model predicts the structural classification, the running container environment is then changed and observed, and the harness does not use the same representation both to predict and to simulate the result.

## Scientific use

Freeze the protocol and experiment manifest before executing any run intended as confirmatory evidence. The protocol here was fixed before confirmatory execution but deposited afterwards, so the paper describes it as pre-specified rather than pre-registered.

## Requirements

- Windows 10/11, macOS or Linux
- Docker Desktop or Docker Engine, Compose v2
- Python 3.10+, no third-party packages required by the runner

## Author

Paul Guckian
Independent Researcher, London, United Kingdom
