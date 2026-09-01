# Validation-scaling Stage-1 implementation review

Date: 2026-09-01 (Asia/Shanghai)

Status: implementation candidate; source tag and formal dispatch forbidden

Authority: `false`

## 1. Immutable parent

This implementation descends directly from the reviewed and pushed annotated
tag `validation-scaling-stage0-v2`, which peels to commit
`9a8699693425098b56e2f745b553fa8a5816fbc3` and tree
`ff69b24db74f4dfcf318d04e0e9da89b08a749e5`. The five frozen Stage-0 object
bytes remain identical. The source candidate commit/tree, exact CI run, and
independent material-review record will be inserted only after the candidate is
committed and those gates finish.

No registered formal seed has been run while preparing this record. Local
checks cover syntax, static contracts, exact arithmetic, and lightweight
failure paths only. The one real successful sentinel lifecycle is explicitly
GitHub-Actions-only and uses seeds read from the test-only disjoint sentinel
factory, never a registered seed.

## 2. Exact eight-path change set

Only these paths may differ from Stage 0:

1. `.github/workflows/validation-scaling-study.yml`;
2. `docs/reviews/validation-scaling-stage1-review.md`;
3. `schemas/validation-scaling-evidence-v1.schema.json`;
4. `scripts/run_validation_scaling_study.py`;
5. `scripts/validate_validation_scaling_study.py`;
6. `src/dynamic_cssc/validation_scaling_study.py`;
7. `tests/test_validation_scaling_study.py`; and
8. `tests/test_validation_scaling_workflow.py`.

The workflow and tests reject a ninth path and byte-compare the four listed
Stage-0 objects plus their detached manifest against the annotated Stage-0
tag.

## 3. Deep-module boundary

`dynamic_cssc.validation_scaling_study.__all__` contains exactly:

- `produce_validation_scaling_seed_shard`; and
- `replay_validation_scaling_seed_shard`.

The caller supplies only exact plan bytes, one ordinal, an operation-owned
mode-0700 empty scratch root, and for replay the byte-exact producer
`payload.zip`. Seed values, query-vector domain, strategy/rho order, source
trace, shard identity, machine plan, compile bindings, clocks, nested private
archive, and replay target remain behind the module. Production seed values are
decoded only from the exact hash-bound Stage-0 plan; no Stage-1 source file
duplicates a registered seed literal.

## 4. Evidence and attack closure

| Axis | Candidate behavior | Gate |
|---|---|---|
| Public inputs | Exact bytes/types, ordinal 1--3, nonempty replay bytes | fail closed before trace generation |
| Scratch | Absolute, direct, empty, mode 0700; destroyed after ownership on success or failure | lightweight local tests |
| Compile counter | Same original binding required; one shared wrapper; mutation detected; both bindings restored | lightweight local tests plus successful sentinel CI |
| Canonical payload | ZIP-STORED, fixed member order/time/mode/system, no comment/extra/link/duplicate | local reorder and nonregular-member attacks plus CI attack matrix |
| Producer private material | Nine exact nested one-day Route A handoffs | successful sentinel CI only |
| Replay redaction | Only row, final cell, semantic projection, replay receipt, and producer binding | successful sentinel CI only |
| Semantic equality | Producer/replay projection excludes all measurements and is byte-identical | local projection test plus successful sentinel CI |
| Timing fields | Exact 17-field rows; primary operation timings separated from supporting stages | schema/source tests |
| Outer artifact | Binary-UTF8-sorted exact set `execution-receipt.json`, `payload.zip`; physical order nonauthoritative | runner and independent validator |
| Aggregate | Independent six-artifact decoder, 54-cell completeness, exact compile bounds, stable integer medians, `Fraction` OLS, nine-place half-even display | exact-source CI pending |
| Provider state | One dispatch/attempt, six successful dependency jobs, seven artifacts, no aggregate self-terminal claim | fixture-driven local gates; formal provider observation pending |

Missing, extra, repeated, reordered, linked, unsafe-mode, oversized,
noncanonical, hash-mismatched, retargeted, semantically divergent, incomplete,
or wrong-role evidence is rejected. The independent validator does not call the
new deep module's private payload decoder.

## 5. Current verification

Local allowed checks at the time this record was opened:

- Python compilation: PASS;
- Ruff on all five Python implementation/test files: PASS;
- focused lightweight suite: `57 passed, 1 skipped`;
- Draft 2020-12 evidence-schema metaschema validation: PASS (`31` definitions);
- skipped item: the single successful sentinel producer/replay lifecycle,
  deliberately reserved for GitHub Actions;
- formal study workflow dispatches: `0`;
- formal result cells: `0`.

The exact-source CI run ID, its full-suite count, successful sentinel status,
artifact digest, and the independent material-review verdict remain `PENDING`.

## 6. Manual-trigger reachability gate

GitHub accepts `workflow_dispatch` only when the workflow path already exists
on the repository default branch. This exact source candidate intentionally
descends from Stage 0 rather than current `main`, so the source tag alone is not
a reachable manual trigger.

After the exact source candidate passes CI and before the sole formal dispatch,
the reviewed bytes of `.github/workflows/validation-scaling-study.yml` must be
installed unchanged on `main` through a separate authority-false control-plane
commit. The controller must verify byte equality between that default-branch
file and the annotated source-tag file before dispatch. Installing the dormant
manual workflow is not an experiment, result, or permission to bypass the
source-tag/CI/material-review gates. The exact default-branch commit and blob
identity remain `PENDING`.

## 7. Claim boundary

Implementation, static tests, CI, source tagging, and review do not constitute
experimental evidence. Even a complete aggregate may support only the frozen
validation-scaling claim seam: exact-source 54-cell semantic conformance,
per-cell compile-depth bounds, and descriptive current-source GitHub-runner
producer/replay lifecycle scaling. It cannot rank strategies, reverse either
predecessor performance NO-GO, grant campaign authority, claim native OpenFHE
performance, or report a speedup against an unmeasured source.

`validation-scaling-source-v2` must not be created until exact-source CI and
one same-packet independent material review both report `P0=0, P1=0`. The
formal workflow must not be dispatched before that annotated tag is verified,
and it may be dispatched exactly once at attempt one.
