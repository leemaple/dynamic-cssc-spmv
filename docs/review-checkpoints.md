# External review checkpoints

Each checkpoint is exported as a workflow artifact named `review-pack-<stage>-<sha>`.

## R0 — Repository and protocol freeze

Contains the original task, v2.1a patch, parameter manifest, role/leakage freeze, source tree, and passing unit-test report.

Latest audited freeze: **PASS** at `69bd6eb7d593bb33bd59b84bae409994219fa2f5`
(run `32508675883`; 22 tests; 62/62 internal checksums). The permanent private
release is `r1-p0a-20260822`; the R0 ZIP SHA-256 is
`3be48683e183b8f9e3caa9b2115c4a15d485874db6bf53181c796182551bb526`.

## R1 — P0a

Contains decrypted slot permutations, the direct rotation-key inventory, the logical rotation plan, compiler/OpenFHE provenance, and raw logs.

Audited gate: **PASS** at the same commit (run `32508734242`). All 27 requested
direct rotations are valid permutations of all 8192 slots. The evidence scope is
`p0a-layout-semantics-only`: it does not freeze a mixed-workload parameterization
or synthesize cross-row operations. The R1 ZIP SHA-256 is
`08abe505d5eec61f646d517a6e6349b2cc76b9cb07f8d8a92d0b98527e3732f9`.

## R2 — Day 1

Contains workload provenance, warm-up/tuning/held-out boundaries, event-window trace, strategy counts, `Span80(K)`, raw CSV/JSON, plots, and a non-expert explanation.

## R3 — Day 2

Contains P0b key plan, raw microbenchmark repetitions, medians/P95, predicted-vs-measured labels, Pareto plots, and the three-level gate verdict.

## R4 — Minimal prototype

Contains end-to-end OpenFHE results, correctness vectors, output-leakage mode, memory/communication accounting, and comparison against all strong reference implementations.
