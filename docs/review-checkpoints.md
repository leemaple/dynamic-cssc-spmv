# External review checkpoints

Each checkpoint is exported as a workflow artifact named `review-pack-<stage>-<sha>`.

## R0 — Repository and protocol freeze

Contains the original task, v2.1a patch, parameter manifest, role/leakage freeze, source tree, and passing unit-test report.

## R1 — P0a

Contains decrypted slot permutations, the direct rotation-key inventory, the logical rotation plan, compiler/OpenFHE provenance, and raw logs.

## R2 — Day 1

Contains workload provenance, warm-up/tuning/held-out boundaries, event-window trace, strategy counts, `Span80(K)`, raw CSV/JSON, plots, and a non-expert explanation.

## R3 — Day 2

Contains P0b key plan, raw microbenchmark repetitions, medians/P95, predicted-vs-measured labels, Pareto plots, and the three-level gate verdict.

## R4 — Minimal prototype

Contains end-to-end OpenFHE results, correctness vectors, output-leakage mode, memory/communication accounting, and comparison against all strong reference implementations.
