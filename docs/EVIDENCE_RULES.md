# Evidence Rules

These rules are implemented for I-1 and are intended to mirror the companion preregistration.

## Presence

### Interface present
Evidence that the tested source was admitted at the nominated Interface.

### Execution Pathway present
A benign marker is injected immediately downstream of the nominated Interface and is observed by the same acting handler used by admitted work.

### Authority present
The same receiver process, under the same execution identity, successfully performs a benign write to the protected state.

## Absence

### Interface absent
Both:
1. configuration evidence of a source-specific denial at the nominated Interface; and
2. a logged rejection of an attempt from the tested source.

### Execution Pathway absent
Not tested by I-1. Future X-row experiments must require:
1. configuration evidence that the nominated route is absent;
2. evidence that input was admitted; and
3. non-observation of a marker within a pre-registered window where the same marker is positively observed in baseline.

### Authority absent
Not tested by I-1. Future A-row experiments must require:
1. access-control state withholding the relevant control; and
2. a denial record for a same-identity attempt.

## Outcome

Failure of O is never used as evidence that I, X, or A is absent.
