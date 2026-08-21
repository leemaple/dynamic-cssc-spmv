# Dynamic CSSC for Mutable Encrypted SpMV

Research repository for an update-aware maintenance layer around ciphertext–ciphertext sparse matrix–vector multiplication (SpMV) using CSSC and OpenFHE BFV.

## Status

- Project direction: **GO**
- Original whole-block RM-aligned ELLPACK delta: **KILLED**
- Completed gates: **R0 + P0a PASS** at `eb15adf5da22f600a31d4b62897ed35c1ecde2e2`
- Current gate: **real CSSC publication state → causal Day 1 preflight**
- Day 1 status: **HOLD** until persistent strategy state and real global ColumnIndex /
  RowMap execution are merged; Day 2 remains downstream of the resulting operation plan
- Main functional mode: **F1-M**, with output-component leakage prevented by one-time zero-sum blinding
- OpenFHE baseline: **v1.5.1**, pinned by commit in `config/params_manifest.json`

The original v2.1 task specification is preserved verbatim in [`docs/task-v2.1-original.md`](docs/task-v2.1-original.md). The current machine-checkable contract is
[`docs/protocol-patch-v2.1b.md`](docs/protocol-patch-v2.1b.md); v2.1a remains only as
the historical correction trail. Audited R0/P0a evidence is permanently preserved in
the private GitHub release
[`r1-p0a-v21b-20260822`](https://github.com/leemaple/dynamic-cssc-spmv/releases/tag/r1-p0a-v21b-20260822).

## Repository gates

| Gate | Purpose | Workflow |
|---|---|---|
| P-1 | Freeze roles, leakage mode, dimensions, packing, and OpenFHE parameters | `ci.yml` |
| P0a | Probe actual BFV packed-slot rotation semantics | `p0a-rotation-probe.yml` |
| Day 1 | Run causal layout/cost simulation after its explicit HOLD conditions close | `day1-cost-model.yml` |
| P0b / Day 2 | Generate only required rotation keys and run OpenFHE microbenchmarks | `day2-microbench.yml` |
| Review pack | Produce a SHA-256-addressed audit bundle for an external expert | `review-bundle.yml` |

## Local quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python scripts/validate_manifest.py config/params_manifest.json
pytest -q
python -m dynamic_cssc.cli smoke --output-dir results/smoke --seed 20260821
```

The smoke run is a **model prediction**, not an OpenFHE measurement. Publication results must distinguish `predicted` and `measured` data.

## CI design

Fast Python validation runs on every push and pull request. OpenFHE compilation and cryptographic measurements are manual workflows because they are heavier and parameter-sensitive. Every research workflow uploads an immutable artifact containing raw data, manifests, logs, commit metadata, and checksums.

## Review checkpoints

External review is expected after:

1. P-1 + P0a slot-layout evidence;
2. held-out Day 1 Pareto result;
3. P0b/Day 2 measured constants and gate verdict;
4. minimal OpenFHE prototype;
5. paper experiment freeze.

See [`docs/review-checkpoints.md`](docs/review-checkpoints.md).
