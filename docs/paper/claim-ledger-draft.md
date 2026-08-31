# Claim–Evidence Ledger Draft

> **Rule:** an empirical result sentence may enter the manuscript only after
> this ledger names the exact experiment (S1), evidence-freeze (S2), and
> analysis (S3) snapshots, ADR 0010 compatibility receipt, workflow run,
> admitted artifact digest, validator status, and figure/table generated from
> that artifact. A Route C design or stop-decision sentence may instead cite
> exact S1/S2 source conformance and the exact terminal workflow disposition,
> but it must remain visibly non-empirical. `HOLD` is an evidence state, not a
> request to soften wording until it sounds publishable; `CLOSED` means the
> frozen lineage can never release that claim.

Latest audited merged-source baseline before this WIP: R0 run `32580113632`, artifact ID
`9477692484`, GitHub Actions outer-wrapper SHA-256
`8eb299c760e429740f36b3ecb42b365e690d8f2e027925ae4eb9018a0991ec13`,
at signed merged-main commit
`fcb00e0d7f111f3ab5003c111b124df83ae11813`. The locally rehashable embedded
review-pack ZIP SHA-256 is
`ccbf4ac6da200bfe2497b698039d66da7e86ff7babf799c64805034299883cb9`.
The downloaded review pack's
inner sidecar, ZIP CRC, 121-entry `SHA256SUMS`, clean provenance, and 750-case
JUnit all verify. This R0 evidence does not authorize later registration or
performance claims.

Historical pre-pivot Terminal Registration Freeze lineage (not the active Route
A lineage): experiment source S1
`b658e2178b210c2cc0012fc61957a3b3a92953bb`; registration run `33070626218`;
installed registration-anchor SHA-256
`7c46266560e51ea2f756b28267225a21a8e96fce0a69707e00805794e9f309a9`;
Behavior Set SHA-256
`d64dcfcd48e183736d4a6565cca8d698dbeef700d4cec0af4594b7258016d2b7`; and
data-only S2 `bb83d4e42209e24df0c71df3eea5df7cbff7e1d5`. Exact-head S2 CI run
`33073232432` passed 2118 tests with 2 skipped. This lineage authorizes only
the preserved historical repository-admission statements below. It does not
authorize a complete-reference Day 1A result, a performance result, or a
security claim.

## Current Route C lineage — 2026-08-30

The final implementation candidate
`baefc8cc183816c51ce42573bafde8178173044d` was independently reviewed by
ChatGPT Pro and ZCode GLM-5.3 Max with no unresolved P0/P1. It entered main as
the tree-identical Experiment Source Snapshot S1
`ee58627bb5752c6ac1ee2c5132c6574f9cb66552`. Exact-S1 CI run `33258436732`
passed 2,403 tests with 2 expected runner-dependent skips; exact-main PRE-S1
run `33259569284` passed 583 tests and both pinned OpenFHE 1.5.1 ordinary and
strong real-query smokes. Descriptive registration run `33259894587` was
reinspected with authority false, after which the data-only registration anchor
formed Evidence-Freeze Snapshot S2
`c7ff6820d9323f1850c1c5c57fd9070db88db120`; S2 CI run `33260167517` passed.

The only permitted qualification run, `33261434612`, started from exact S2. q1
completed, q2 independent replay was still running at the frozen 45-minute
computational deadline, and q3--q6 never executed. The external controller
cancelled only that exact run. q5 never started, so no guarded qualification
bundle, q6 record, live dispatch capability, acquisition artifact, formal
shard, terminal admission, aggregate, or S3 analysis exists. The sole provider
artifact was one-day `q1-simulator-pre-replay-handoff` ID `9717884587`, 621,877,534
bytes, provider digest
`sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`;
it is permanently NON-EVIDENCE and cannot support a paper result.

## Route C terminal disposition

The one-shot qualification selected the preregistered Route C. It may not be
rerun in this lineage, and the acquisition plus 16-unit formal campaign may not
be dispatched without the capability that q5/q6 never produced. Earlier
14-candidate, Day 1A/Day 2/Day 1B, 15%-improvement, R2B/R3/R4, and current Route
A performance claims are **RETIRED OR CLOSED**, not waiting for a convenient
rerun. Historical rows below remain only to preserve provenance.

The active Route C ledger is:

| ID | Permitted wording | Minimum evidence | Current state |
|---|---|---|---|
| RC-D1 | We present a version-bound protocol around static CSSC that jointly binds logical matrix state, global-column query reorganization, private `RowMap`-aware reconstruction, and overlap-scoped masking. | Frozen definitions, role/threat boundaries, P1--P4 proof text, bounded novelty matrix, exact-S1 source-conformance record, and exact-S1 tests | RELEASED at design/source-conformance scope only; no `first`, security, end-to-end admission, or performance claim |
| RC-C1 | Under the frozen acceptance predicate, every enumerated typed/canonical-byte field must match its authoritative binding or the path rejects before authority can be minted. | P1 case analysis, exact-S1 predicate-to-source mapping, retained-byte rehash and substitution negatives | RELEASED as a conditional definition-level proposition; deliberate hash-collision resistance and formal-run acceptance remain outside scope |
| RC-C2 | Under a complete embedded component decomposition and total OutputPlan, reconstruction over overlap, disjoint blocks, and implicit zeros equals the direct logical matrix-vector product. | P2 proof, exact-S1 component/oracle mapping and registered tests | RELEASED as a definition-level proposition under its stated premises; no accepted formal-run result |
| RC-C3 | In one uncompromised durable ledger, overlap masks cancel modulo `t`, reservations occur before sampling, and a prepared batch is consumed once under the frozen identity. | P3 cancellation proof, ledger state-machine invariant, exact-S1 mapping and registered negative tests | RELEASED only as cancellation and ledger-local invariants; no simulation security, rollback/cloning, cross-device, or new-primitive claim |
| RC-C4 | The fixed `c=128` segment construction and private leader merge reconstruct correctly under the frozen segment invariants. | P4 reduction proof, 127/128/129 boundary tests, direct oracle and exact-S1 mapping | RELEASED as a construction-correctness proposition; no optimal-width or performance claim |
| RC-O1 | The exact one-shot qualification missed its frozen gate, minted no authority, and selected Route C before formal execution. | Exact S2, run `33261434612`, provider terminal job states, q1 artifact metadata, controller cancellation record | RELEASED as workflow provenance and a stop decision only; q1/q2 timing is not a simulator/native estimator or paper performance result |
| RA-E1 | Any synthetic strategy-cost or serialized-byte comparison from the frozen formal matrix. | Six accepted shards, aggregate and compatible S3 analysis, none of which exists | CLOSED — formal synthetic campaign not dispatched; no wording permitted |
| RA-E2 | Any SNAP ordered-event strategy-cost conclusion. | Admitted acquisition, four accepted shards, aggregate and compatible S3 analysis, none of which exists | CLOSED — acquisition and ordered-event campaign not dispatched; no wording permitted |
| RA-E3 | Any current-source OpenFHE strategy latency/resource/serialized-byte result. | Six accepted native artifacts, aggregate and compatible S3 analysis, none of which exists | CLOSED — formal native campaign not dispatched; PRE-S1 smokes cannot substitute |

The two earlier cancelled diagnostics and the sole qualification's q1/q2 timing
attribution are permanently excluded from RA-E1--RA-E3.

## Current-source E4 conformance replication — 2026-08-31

This is a separately preregistered deterministic functional replication, not a
reopening of legacy empirical claim E4 or either stopped performance lineage.
The immutable source is lightweight tag
`current-source-e4-conformance-20260831-v1` at
`844fb062d78f5095f14599c6c71a27cb6034f001`. The sole current run is
`33386130654`; the sole artifact is `9755741401`, with raw provider digest
`sha256:5978b7d9f75048939c9761243e224abb588ed82c2abc64e051523a7a598a1383`.
The independent audit verified exact provider identity, all-success steps, the
complete workflow inventory, the create-once tag, the exact 19-file ZIP,
strict checksums, every machine-plan JSON pointer, and detached-source
PROVENANCE rehashing.

| ID | Permitted wording | Minimum evidence | Current state |
|---|---|---|---|
| CS-E4-C1 | At the exact tagged source, all 35 records in the prespecified eight-case deterministic property contract passed. | Run `33386130654`; artifact `9755741401`; strict raw-ZIP audit; property evidence with seed `20260822`, 35 records, and zero failures | RELEASED for that exact source and deterministic corpus only |
| CS-E4-C2 | At the exact tagged source, the prespecified pinned-OpenFHE whole-query witness for one fixed 4096-by-8193 CSSC-base-plus-strong-delta fixture decrypted to `[(0, 128), (4095, 5)]` and matched both independent plaintext oracles. | Same run/artifact/raw digest; valid decryptions; exact vector; typed-oracle and direct-SpMV matches; exact source/provenance rehash | RELEASED for one fixed fixture, one segment width, and OpenFHE 1.5.1 at the recorded commit only |
| CS-E4-N1 | No candidate admission, complete-reference, mixed-circuit-safety, security, deployment, performance, speedup, ranking, population, or universal-correctness conclusion follows from CS-E4-C1/C2. | Artifact authority flags all false; preregistered claim boundary; preserved terminal performance dispositions | PERMANENT NON-CLAIM |

## Design and attribution claims

| ID | Permitted wording | Minimum evidence | Current state |
|---|---|---|---|
| D1 | We implement a version-bound mutable maintenance layer around published static CSSC. | Protocol v2.1b, accepted ADRs, exact S1, source-conformance record and registered tests | RELEASED as a design/implementation statement at exact S1; not a performance claim |
| D2 | A Publication Window candidate binds logical state, components, query metadata, OutputPlan, and prepared queries to one version before acceptance. | Exact-S1 state/property tests plus P1 source-conformance mapping | RELEASED as a fail-closed interface and conditional proposition; no S3/end-to-end result exists |
| D3 | The private OutputPlan distinguishes overlapping coordinates, disjoint blocks, and implicit zeros. | Canonical plan tests, plaintext oracle, P2 source-conformance mapping | RELEASED at definition/source-conformance scope |
| D4 | Overlap-only F1-M uses reserve-before-sample bindings in the stated SQLite ledger model; strong disjoint returns use encrypted-zero dummies. | P3 proof, exact-S1 ledger/lifecycle tests and source-conformance mapping | RELEASED only at cancellation and ledger-local-invariant scope; all broader security claims remain prohibited |
| D5 | The strong path uses fixed `c=128` pages and private client leader merging. | P4 proof, exact-S1 boundary/oracle tests and source-conformance mapping | RELEASED as a construction-correctness statement; performance and security claims remain prohibited |
| A1 | CSSC supplies static layout, ColumnIndex reorganization, RowMap recovery, and aggregation. | Gao et al. primary source and local source audit | E0; cite and do not claim |
| A2 | The non-power-of-two schedule is our corrected CSSC/HElib-compatible interpretation, not verified author code. | CSSC Algorithm 4 audit and cited HElib totalSum source | E0/E1; use explicit caveat |
| A3 | We make no first encrypted sparse SpMV/SpMM, encrypted-index or hidden-position, double-ciphertext sparse computation, dynamic encrypted-data, versioned-commitment/freshness/replay, or random output-share/mask claim. | Primary-source gap audit covering CSSC, Lodia, 2DPP, CipherSkip, SparseE, Ferguson/D'Agata, Rhombus, d-DSE, CKKS-Auth Tree, encrypted databases, and secure aggregation | Frozen non-claim; the permitted novelty boundary is only the update-aware CSSC integration stated in D1--D4 |

## Legacy correctness and completeness claims (pre-Route A)

| ID | Future wording | Required artifact | Current state |
|---|---|---|---|
| C1 | The exact Phase 2 base-plus-strong-delta fixture decrypts to the typed and direct plaintext result. | Run `32581653504`, artifact SHA `c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe` | PASS at `fcb00e0d`; one fixture only |
| C2 | The strong c=128 candidate is an admitted Day 1 reference. | Zero-argument repository composite registration gate binding correctness, accounting, report schema, tests, and frozen policy | PASS for exact S1/S2 registration scope via run `33070626218`; formal Day 1A complete-reference evidence remains HOLD |
| C3 | The fixed-reference set is complete. | 14 fixed records, 13 references, one ablation, exact rotation/accounting completion proof and replay receipts | HOLD |
| C4 | The admitted mixed circuit decrypts correctly with adequate parameter margin. | Pinned worst-profile OpenFHE gate with raw decryption/noise evidence | HOLD |
| C5 | End-to-end execution matches the logical oracle at the qualifying adjacent rho grid points. | R4 artifact on exact experiment snapshot S1, admitted at S2 and analyzed at S3 through an ADR 0010 compatibility receipt | HOLD |

## Legacy empirical claims (retired from Route A)

| ID | Future wording | Required analysis | Current state |
|---|---|---|---|
| E1 | Candidate X changes predicted operation counts on the synthetic proxy. | Accepted role-aware Day 1A artifact; explicitly predicted and synthetic | HOLD; do not generalize |
| E2 | Report prespecified descriptive residuals against a separately frozen held-out component target; do not claim prediction accuracy or a pass threshold. | Day 2 raw repetitions plus a premeasurement-frozen target, residual formula, aggregation, and failure treatment | HOLD; no residual contract or accuracy claim is currently authorized |
| E3 | The tuning-selected maintenance procedure is non-dominated at qualifying adjacent rho grid points in the preregistered sole T2-at-0.1-s family. | Day 1B on all 15 fixed-corpus units with complete serialized costs and 15-of-15 non-domination against the 13 references; comparator fixed to `periodic-repack/windows=1` | HOLD |
| E4 | On the fixed three-dataset corpus, the tuning-selected procedure improves the time-equivalent diagnostic over recompress-every-window by a median of at least 15% at two adjacent prespecified rho grid points. | All 15 paired effects strictly positive at both points, the unweighted median over exactly 15 effects at least 15%, complete outcomes, calibration-classification stability, non-domination, and exact provenance; partition-resampling interval is descriptive only, with no p-value or population inference | HOLD |
| E5 | The direction/magnitude is reported across the prespecified secondary T1 and 1.0-s panels. | Per-unit points and descriptive Stack Overflow/Simplewiki/NYC TLC full-panel summaries; secondary panels cannot authorize or rescue E3/E4 | HOLD; never say universal or infer a population |
| E6 | The system has end-to-end latency/memory/communication behavior Y. | R4 raw wall-clock, memory, serialized bytes, correctness, and provenance | HOLD |

## Permanent non-claims

- no new homomorphic-encryption primitive;
- no first/only claim for encrypted indices, hidden nonzero positions,
  ciphertext--ciphertext sparse multiplication, dynamic encrypted data,
  versioned commitments, freshness/replay rejection, or canceling/random output
  shares in isolation;
- no formal, malicious, adaptive, collusion, side-channel, or traffic-analysis
  security theorem;
- no author-code reproduction;
- no universal or state-of-the-art superiority;
- no complete cost from normalized proxy counts;
- no independent-sample claim for windows, queries, or seed reruns within one
  source-partition trace; and
- no primary real-data verdict from LDBC or synthetic workloads.

## Evidence fields for any future empirical result

No current Route C empirical result satisfies these fields because no formal
artifact, aggregate, or S3 analysis exists. The template is retained only to
prevent a future lineage from silently reusing the present qualification.

```text
claim_id:
manuscript_sentence_sha256:
experiment_source_git_sha:
evidence_freeze_git_sha:
analysis_source_git_sha:
behavior_set_sha256_by_evidence_role:
evidence_compatibility_receipt_sha256:
workflow_file_sha256:
run_id:
artifact_id:
outer_artifact_sha256:
inner_manifest_sha256:
validator_status:
dataset_trace_ids:
analysis_script_sha256:
figure_or_table_paths:
human_review_status:
```
