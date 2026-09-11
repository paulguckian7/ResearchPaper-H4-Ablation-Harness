# Changelog

## 0.1.1 - 2026-09-11

Corrections to I-1 evidence collection so that it conforms to the protocol's presence rules. Confirmatory I-1 runs under 0.1.0 are superseded and retained as calibration.

### Changed
- X marker now enters the post-admission path of the nominated Interface. `/push` and the marker both call `process_admitted()`, so the marker traverses payload parsing, submission, the queue, worker dispatch and handler entry, and is observed as `handler_reached` with `marker: true`. It branches off before the state write, so it cannot change O. Under 0.1.0 the marker was submitted directly to the queue, bypassing payload parsing, and was handled by a separate worker branch.
- The Authority presence check now has both legs: access-control state is read inside the receiver process (`ACCESS_STATE`: process uid/gid, state file owner and mode, write access to the state file and data directory), in addition to the same-identity write. The state is stored as `post.access_state.json` and in `record.json`.
- `record.json` now includes SHA-256 hashes of the manifest, runner, compose file, Dockerfiles and container source files, so each run is tied to the exact code executed even where `git rev-parse` is unavailable.
- `versions.txt` now records host platform and runner interpreter path.

### Unchanged
- `manifests/I-1.yaml` is byte-identical to 0.1.0 (SHA-256 65e2adbc...a8c8). Its `harness_version` field records the version under which the manifest was frozen; the executing harness version is recorded in each `record.json`.
- Operation, nominated Interface, ablation and predictions.

## 0.1.0 - 2026-09-11

Initial publishable harness.

### Added
- Executable I-1 constructed HTTP Interface ablation.
- Clean Docker rebuild for every run.
- Independent evidence collection for I, X, A and O.
- Internal Unix-socket instrumentation.
- X marker injected immediately downstream of the nominated Interface into the same internal queue and handler used by the operation.
- Authority probe executed by the same receiver process.
- System and system-of-systems governance labels.
- Evidence bundles with hashes and resolved Docker configuration.
- Pilot/calibration result separation.
- Publication and evidence documentation.

### Methodological correction from pilot harness
The pilot harness used a separate HTTP endpoint for the X probe. Although the five pilot runs matched the predicted tuple, those runs are retained only as calibration because the stricter protocol requires the X probe to enter at the receiving side of the same nominated Interface. Version 0.1.0 corrects this by using an internal Unix socket and the same queue/handler.
