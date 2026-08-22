# External review checkpoints

Each checkpoint is exported as a workflow artifact named `review-pack-<stage>-<sha>`.

## R0 — Repository and protocol freeze

Contains the original task, v2.1a patch, parameter manifest, role/leakage freeze, source tree, and passing unit-test report.

Latest audited freeze: **PASS** at `eb15adf5da22f600a31d4b62897ed35c1ecde2e2`
(run `32514351610`; 105 tests; 74/74 internal checksums). The permanent private
release is [`r1-p0a-v21b-20260822`](https://github.com/leemaple/dynamic-cssc-spmv/releases/tag/r1-p0a-v21b-20260822);
the R0 ZIP SHA-256 is
`1c3a5f14f87991212b6bc36afe8ab5a4484f638c7a9469591d1b98531140e3b1`.

## R1 — P0a

Contains decrypted slot permutations, the direct rotation-key inventory, the logical rotation plan, compiler/OpenFHE provenance, and raw logs.

Audited gate: **PASS** at the same commit (run `32514435923`). All 27 requested
direct rotations are valid permutations of all 8192 slots. The evidence scope is
`p0a-layout-semantics-only`: it does not freeze a mixed-workload parameterization
or synthesize cross-row operations. The R1 ZIP SHA-256 is
`8e818195d61793f72b05fd2191b297decccd70427e6f1507bb7446f139faf4f9`.

## R2 — Day 1

Contains workload provenance, warm-up/tuning/held-out boundaries, event-window trace, strategy counts, `Span80(K)`, raw CSV/JSON, plots, and a non-expert explanation.

## R3 — Day 2

Contains P0b key plan, raw microbenchmark repetitions, medians/P95, predicted-vs-measured labels, Pareto plots, and the three-level gate verdict.

## R4 — Minimal prototype

Contains end-to-end OpenFHE results, correctness vectors, output-leakage mode, memory/communication accounting, and comparison against all strong reference implementations.
