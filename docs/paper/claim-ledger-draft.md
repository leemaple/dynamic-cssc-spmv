# Claim–Evidence Ledger Draft

> **Rule:** a result sentence may enter the manuscript only after this ledger
> names the exact experiment (S1), evidence-freeze (S2), and analysis (S3)
> snapshots, ADR 0010 compatibility receipt, workflow run, artifact digest,
> validator status, and figure/table generated from that artifact. `HOLD` is an evidence state,
> not a request to soften wording until it sounds publishable.

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

## Design and attribution claims

| ID | Permitted wording | Minimum evidence | Current state |
|---|---|---|---|
| D1 | We implement a version-bound mutable maintenance layer around published static CSSC. | Protocol v2.1b, accepted ADRs, current typed implementation and tests | E1; implemented, not a performance claim |
| D2 | Each accepted Publication Window binds logical state, components, query metadata, OutputPlan, and prepared queries to one version. | Current state/property tests plus a commit-bound R0 rerun for experiment snapshot S1 and an ADR 0010 S1/S2/S3 compatibility receipt | E1 until rerun; E2 only for the exact audited S1 Behavior Set and admitted artifact |
| D3 | The OutputPlan distinguishes overlapping coordinates, disjoint blocks, and implicit zeros. | Canonical plan tests, plaintext oracle, Phase 2 fixture | E4 for the frozen fixture |
| D4 | Overlap-only F1-M uses reserve-before-sample bindings in the stated SQLite ledger model; strong disjoint returns use encrypted-zero dummies. | R0 property contract covers reserve/reject/crash/concurrency; the Phase 2 fixture covers encrypted random/dummy execution while explicitly reporting `persistent_ledger_exercised=false` | Ledger mechanism E1/E2; fixture correctness E4; persistent end-to-end/R4 and all security claims HOLD |
| D5 | The cloud-segmented strong path uses fixed c=128 pages and private client leader merging. | Phase 2 whole-query artifact plus repository admission | Fixture E4 PASS; candidate registration HOLD |
| A1 | CSSC supplies static layout, ColumnIndex reorganization, RowMap recovery, and aggregation. | Gao et al. primary source and local source audit | E0; cite and do not claim |
| A2 | The non-power-of-two schedule is our corrected CSSC/HElib-compatible interpretation, not verified author code. | CSSC Algorithm 4 audit and cited HElib totalSum source | E0/E1; use explicit caveat |
| A3 | We make no first encrypted sparse SpMV or first dynamic encrypted database claim. | Related-work boundary review | Frozen non-claim |

## Correctness and completeness claims

| ID | Future wording | Required artifact | Current state |
|---|---|---|---|
| C1 | The exact Phase 2 base-plus-strong-delta fixture decrypts to the typed and direct plaintext result. | Run `32581653504`, artifact SHA `c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe` | PASS at `fcb00e0d`; one fixture only |
| C2 | The strong c=128 candidate is an admitted Day 1 reference. | Zero-argument repository composite registration gate binding correctness, accounting, report schema, tests, and frozen policy | HOLD |
| C3 | The fixed-reference set is complete. | 14 fixed records, 13 references, one ablation, exact rotation/accounting completion proof and replay receipts | HOLD |
| C4 | The admitted mixed circuit decrypts correctly with adequate parameter margin. | Pinned worst-profile OpenFHE gate with raw decryption/noise evidence | HOLD |
| C5 | End-to-end execution matches the logical oracle at the qualifying adjacent rho grid points. | R4 artifact on exact experiment snapshot S1, admitted at S2 and analyzed at S3 through an ADR 0010 compatibility receipt | HOLD |

## Empirical claims

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
- no formal, malicious, adaptive, collusion, side-channel, or traffic-analysis
  security theorem;
- no author-code reproduction;
- no universal or state-of-the-art superiority;
- no complete cost from normalized proxy counts;
- no independent-sample claim for windows, queries, or seed reruns within one
  source-partition trace; and
- no primary real-data verdict from LDBC or synthetic workloads.

## Evidence fields to fill for every released result

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
