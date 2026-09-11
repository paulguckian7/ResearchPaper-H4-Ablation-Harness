# Changelog

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
