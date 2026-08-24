# External review checkpoints

Each checkpoint is exported as a workflow artifact named `review-pack-<stage>-<sha>`.

## R0 — Repository and protocol freeze

Contains the original task, v2.1a patch, parameter manifest, role/leakage freeze, source tree, and passing unit-test report.

Latest audited freeze: **PASS** at
`fcb00e0d7f111f3ab5003c111b124df83ae11813` (run `32580113632`; 750 tests;
artifact SHA-256
`8eb299c760e429740f36b3ecb42b365e690d8f2e027925ae4eb9018a0991ec13`).
The earlier private historical release
[`r1-p0a-v21b-20260822`](https://github.com/leemaple/dynamic-cssc-spmv/releases/tag/r1-p0a-v21b-20260822)
remains the historical R0/P0a archive and must not be treated as current-source
coverage.

## R1 — P0a

Contains decrypted slot permutations, the direct rotation-key inventory, the logical rotation plan, compiler/OpenFHE provenance, and raw logs.

Audited gate: **PASS** at the historical P0a commit
`eb15adf5da22f600a31d4b62897ed35c1ecde2e2` (run `32514435923`). All 27 requested
direct rotations are valid permutations of all 8192 slots. The evidence scope is
`p0a-layout-semantics-only`: it does not freeze a mixed-workload parameterization
or synthesize cross-row operations. The R1 ZIP SHA-256 is
`8e818195d61793f72b05fd2191b297decccd70427e6f1507bb7446f139faf4f9`.

## E4 — Phase 2 whole-query correctness

Contains the real CSSC-base-plus-strong-delta fixture, property-contract records,
typed bindings, runtime trace, OpenFHE build evidence, direct and typed-oracle
outputs, provenance, and strict checksums.

Latest audited merged-source gate before the current WIP: **PASS** at
`fcb00e0d7f111f3ab5003c111b124df83ae11813` (run `32581653504`; 35/35
property-contract records; artifact SHA-256
`c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`).
Its scope is one pinned correctness fixture. It does not register the strong
candidate or authorize complete-cost, parameter-safety, security, or performance
claims.

## R2A — Historical synthetic Day 1 count workflow

Contains workload provenance, warm-up/tuning/held-out boundaries, event-window trace,
`Span80(K)`, raw CSV/JSON, plots, and a non-expert explanation. Production must first
resolve the zero-argument repository admission catalog. It emits no partial-reference
fallback: every accepted cell must prove 14 fixed records, 13 selectable references, one
client-lane ablation, 13 tuning records, 16 total records including aliases, and exact
rotation inventories. Only after all 21 shards / 189 cells validate may the suite state
`complete_reference_set=true`; all measured-cost, security, performance, and
gate-eligibility claims remain separately false. This 21/189 topology is a
synthetic pipeline/count checkpoint and cannot populate the publication
verdict.

## R2B — Publication Day 1B

Contains the 30 preregistered real-source trace units and all 540
`(unit, freshness, rho)` cells. Each cell has 27 physical inputs: 13
tuning-prefix reference records and 14 held-out fixed records (13 references
plus one ablation), for exactly 14,580 physical records. The analyzer alone
derives the tuning-selected and diagnostic-oracle aliases. Every trace, accepted
group range, SET*→TICK→QUERY-RUN schedule, query vector, serialized protocol
object, replay receipt, source acquisition receipt, and Behavior Set inventory
is digest-bound and independently rehashed before admission. R2B remains HOLD
until its repository role, resource policy, acquisition chain, complete catalog,
and runtime-isolation receipt are installed.

## R3 — Day 2

Contains the Day1A-authorized exact key plan, three complete warm-up blocks,
exactly 14 complete whole measurement blocks over the frozen 14-primitive
profiles/cases, raw per-case timings, host/compiler/OpenFHE identities, the
canonical calibration projection, and its pre-dispatch and post-run evidence
anchors. The raw-block-capable historical `day2-microbench.yml` still lacks the
registered key plan, fixed-host provenance, profile and post-run anchors, and
canonical R3 archive, so it is not R3.

Run `32712608022` at `f11e97d` is a retained, checksummed mechanism check only:
it has 11 measurement blocks and explicitly fails the publication raw-block
contract. Its historical `R3-Day2` package label does not confer R3 status;
future exploratory packages use the unambiguous `Day2-exploratory` label.

## R4 — Minimal prototype

Contains end-to-end OpenFHE results, correctness vectors, output-leakage mode, memory/communication accounting, and comparison against all strong reference implementations.
