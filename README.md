# Dynamic CSSC for Mutable Encrypted SpMV

Research repository for an update-aware maintenance layer around ciphertext–ciphertext sparse matrix–vector multiplication (SpMV) using CSSC and OpenFHE BFV.

## Status

- Project direction: **GO**
- Original whole-block RM-aligned ELLPACK delta: **KILLED**
- Latest audited merged-source gates before this WIP: **R0 PASS + Phase 2 E4 PASS** at
  `fcb00e0d7f111f3ab5003c111b124df83ae11813`; P0a remains a narrower historical
  slot-layout PASS at `eb15adf5da22f600a31d4b62897ed35c1ecde2e2`
- Current gate: **strong-reference admission and complete accounting → full-baseline
  causal Day 1**
- Day 1 full-baseline status: **HOLD before dispatch**. The role-aware contract is
  14 fixed records = 13 selectable references + one client-lane ablation, with
  13 tuning records and two non-executed aliases. The repository-owned
  zero-argument catalog deliberately fails closed until the composite
  strong-reference registration anchor is installed; no partial-reference
  artifact is an allowed fallback. The ADR 0008 whole-query integration passed
  its `fcb00e0d`-bound witness in run `32581653504` (GitHub Actions artifact-wrapper SHA-256
  `c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`). That is
  narrow fixture-correctness evidence, not candidate registration; the strong candidate
  remains unregistered and Day 2 remains downstream of the resulting operation plan.
- Main functional mode: **F1-M**, designed to separate component outputs with
  one-time zero-sum blinding. Current evidence checks mechanism and correctness
  only; it does not establish a security proof or leakage-prevention claim.
- Outcome-blind structure pilot: **pre-freeze and permanently non-admissible**.
  Its fixed coverage is the three real datasets × T1/T2 × partitions 0–4,
  using exactly the first `floor(V/10)` canonical schema-valid events per
  dataset. It may size the resource envelope from aggregate structure, health,
  and resource facts only; it cannot dispatch candidates, inspect query or
  performance outcomes, mint evidence authority, or enter a Publication
  Evidence Lineage. Its only files are `structure-pilot-report.json` and
  `checksums.sha256`. Its manual workflow requires a pre-provisioned, empty,
  mode-`0700`, external scratch root bound identically through
  `PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT`, `TMPDIR`, and `SQLITE_TMPDIR`
  before Python starts. The report binds that root's closed policy and
  path/device/inode identity, but does not claim scratch occupancy or a
  transient scratch high-water. Its top-level wall-clock and process-RSS fields
  stop after final revalidation and scratch teardown, immediately before report
  serialization and installation; they do not measure those installation steps.
  The closed acquisition-bundle adapter is implemented, but
  production remains on **HOLD** while the checkout is dirty and the three real
  verified bundles are absent; no structure-pilot output currently exists.
- Publication Day1B implementation status: a tested first-wave per-unit producer
  closes 18 cells / 486 physical records, schedule-v2 streaming, canonical
  serialized-object ledgers, and per-cell resource observations. Its production
  entry point still fails before writing because the Day1 catalog, trace authority,
  resource policy, and repository execution adapter are intentionally uninstalled;
  no publication result exists.
- Analysis isolation status: a standalone runner now exercises a fresh detached
  checkout under exact CPython 3.12.13 with `-I -S`, an isolated bytecode cache,
  an empty approved third-party import set, source/import/lock revalidation, and
  no-replace atomic output installation. Its on-disk receipt is descriptive and
  cannot grant claim authority until the central evidence chain independently
  admits the completed run.
- OpenFHE baseline: **v1.5.1**, pinned by commit in `config/params_manifest.json`

The original v2.1 task specification is preserved verbatim in [`docs/task-v2.1-original.md`](docs/task-v2.1-original.md). The current machine-checkable contract is
[`docs/protocol-patch-v2.1b.md`](docs/protocol-patch-v2.1b.md); v2.1a remains only as
the historical correction trail. Audited R0/P0a evidence is digest-addressed and archived in
the GitHub release
[`r1-p0a-v21b-20260822`](https://github.com/leemaple/dynamic-cssc-spmv/releases/tag/r1-p0a-v21b-20260822).

## Repository gates

| Gate | Purpose | Workflow |
|---|---|---|
| P-1 | Freeze roles, leakage mode, dimensions, packing, and OpenFHE parameters | `ci.yml` |
| P0a | Probe actual BFV packed-slot rotation semantics | `p0a-rotation-probe.yml` |
| Phase 2 correctness witness | Bind and validate the real CSSC-base-plus-strong-delta query | `strong-whole-query-witness.yml` (manual; latest audited E4 PASS is bound to `fcb00e0d`, admission still pending) |
| Structure pilot | Size the outcome-independent resource envelope from the exact `floor(V/10)` structure prefix; never produce publication evidence | `publication-structure-pilot.yml` (manual, pre-freeze, non-admissible) |
| Day 1 | Produce complete role-aware causal artifacts only after repository admission; fail closed otherwise | `day1-cost-model.yml` |
| Historical P0b exploratory probe | Run the isolated OpenFHE raw-block mechanism over every supplied exact rotation; the workflow keeps the legacy 11-block setting and lacks the registered R3 bindings, so it is not publication-authoritative Day 2 evidence | `day2-microbench.yml` |
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

Fast Python validation runs on every push and pull request. OpenFHE compilation and cryptographic measurements are manual workflows because they are heavier and parameter-sensitive. Every publication-authoritative workflow must upload a digest-addressed artifact containing raw data, manifests, logs, commit metadata, and checksums; retention is recorded separately and is not described as permanent. The Day 2 probe executable can emit raw blocks for mechanism testing, but the historical workflow does not produce or authorize the complete R3 archive.

## Review checkpoints

External review is expected after:

1. P-1 + P0a slot-layout evidence;
2. held-out Day 1 Pareto result;
3. P0b/Day 2 measured constants and gate verdict;
4. minimal OpenFHE prototype;
5. paper experiment freeze.

See [`docs/review-checkpoints.md`](docs/review-checkpoints.md).

## Publication plan

The manuscript is being developed as a cryptographic-engineering systems and
empirical-characterization paper, not as a new primitive or formal-security
claim. The current publication materials are:

- [`docs/paper/manuscript-draft.md`](docs/paper/manuscript-draft.md): methods-first
  manuscript with result sentences deliberately withheld behind evidence gates;
- [`docs/paper/publication-preregistration-draft.md`](docs/paper/publication-preregistration-draft.md):
  frozen candidate roles, three-real-dataset sampling frame, T1/T2 transforms,
  fixed-corpus paired analysis, and stop/fallback rules;
- [`docs/paper/publication-roadmap.md`](docs/paper/publication-roadmap.md):
  dependency-ordered path from strong-reference admission through measured
  calibration, real-stream execution, R4, and the submission package;
- [`docs/paper/claim-ledger-draft.md`](docs/paper/claim-ledger-draft.md):
  sentence-level design, correctness, and empirical claim gates;
- [`docs/paper/references.bib`](docs/paper/references.bib): primary-source citation
  database for the venue-formatted manuscript;
- [`docs/research/dynamic-cssc-novelty-related-work-boundary.md`](docs/research/dynamic-cssc-novelty-related-work-boundary.md):
  claim-by-claim novelty boundary against primary prior art;
- [`docs/research/publication-venues-datasets-preregistration.md`](docs/research/publication-venues-datasets-preregistration.md):
  official-source venue, licensing, dataset, and sampling rationale; and
- [`docs/reviews/zcode-max-publication-audit-2026-08-23.md`](docs/reviews/zcode-max-publication-audit-2026-08-23.md):
  independent ZCode GLM-5.3 Max submission audit and adjudicated blockers.

The primary target is the *Journal of Cryptographic Engineering*. Synthetic
Day 1 evidence cannot populate the publication verdict; that verdict requires
the preregistered 30 paired real-source trace units, measured OpenFHE
calibration, complete serialized protocol-object accounting within the frozen
transaction scope, mixed-circuit correctness, and R4 or an explicitly narrower
conclusion. Evaluation keys are inventoried separately; HTTP/TLS, filesystem,
artifact-container, and workflow framing are outside that scope.
