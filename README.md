# Dynamic CSSC for Mutable Encrypted SpMV

Research repository for an update-aware maintenance layer around ciphertext–ciphertext sparse matrix–vector multiplication (SpMV) using CSSC and OpenFHE BFV.

## Status

- Project direction: **GO**
- Original whole-block RM-aligned ELLPACK delta: **KILLED**
- Current gate: **P-1 → P0a → Day 1 → P0b/Day 2**
- Main functional mode: **F1-M**, with output-component leakage prevented by one-time zero-sum blinding
- OpenFHE baseline: **v1.5.1**, pinned by commit in `config/params_manifest.json`

The original v2.1 task specification is preserved verbatim in [`docs/task-v2.1-original.md`](docs/task-v2.1-original.md). Engineering corrections are recorded separately in [`docs/protocol-patch-v2.1a.md`](docs/protocol-patch-v2.1a.md).

## Repository gates

| Gate | Purpose | Workflow |
|---|---|---|
| P-1 | Freeze roles, leakage mode, dimensions, packing, and OpenFHE parameters | `ci.yml` |
| P0a | Probe actual BFV packed-slot rotation semantics | `p0a-rotation-probe.yml` |
| Day 1 | Run causal layout/cost simulation on synthetic and temporal streams | `day1-cost-model.yml` |
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
