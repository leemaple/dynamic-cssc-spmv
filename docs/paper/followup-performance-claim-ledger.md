# Follow-up performance claim ledger

> **State:** Stage-1 draft; all empirical claims are HOLD. This ledger is
> additive to, and does not modify, the closed Route A/Route C ledger.

## Permanent ancestry statement

`33261434612` remains the only qualification in the predecessor lineage. Its
q1/q2 observations and artifact `9717884587` (provider digest
`sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`)
are permanently non-evidence. q3--q6 appeared only as zero-step cancelled job
nodes after cancellation; they performed no computation or guard. The follow-up
exists because an outcome-informed engineering repair changed the execution
source; it is not a rerun or completion of that experiment.

## Claim map

| ID | Exact claim | Minimum evidence | Current state |
|---|---|---|---|
| FU-P1 | The follow-up preserves the predecessor's outcome-bearing inner scientific/resource/admission semantics except the five preregistered fresh-seed replacements, while a new outer envelope separates authority and evidence identity without changing inner payload bytes. | Exact predecessor hashes, follow-up baseline and outer-envelope plan, semantic-delta validator, Stage-1 review | HOLD |
| FU-P2 | The repaired implementation preserves the version, canonical-byte, ledger, F1-M, typed-execution, and direct-oracle boundaries. | PR #42 diff, focused tests, exact-head CI, Pro/ZCode closure | RELEASEABLE as implementation provenance only; not performance evidence |
| FU-Q-GO | The sole follow-up qualification closed q1--q5 within 45.00 minutes and q1--q6 within 55.00 minutes. | Exact follow-up S1/S2; sole qualification run identity; successful q1--q6 records and guards; provider `startedAt`/`completedAt` values; both deadline calculations; external-controller qualification-GO calculation record. A later formal-capability decision is not required for this factual claim. | HOLD; qualification not dispatched |
| FU-Q-NOGO | The sole follow-up qualification failed or missed either frozen gate and no formal capability was minted. | Exact follow-up S1/S2; sole run identity; provider terminal states for every executed prefix; explicit pending/skipped/zero-step/absent states for downstream jobs; applicable controller observation/cancel/failure record; proof that no formal capability was minted. A correctly unexecuted downstream guard is not required. | HOLD; qualification not dispatched |
| FU-FORMAL-OUTCOME | After a factual FU-Q-GO, the follow-up either closed pre-campaign NO-GO at the fresh provider/resource reread, or a minted formal capability opened one campaign that reached terminal admission or closed formal NO-GO at an exact unit/guard/budget boundary. | For pre-campaign closure: exact post-GO controller reread, resource/provider failure record, and proof no formal capability was minted. For a campaign: formal capability mint/atomic-consumption record, append-only unit ledger, exact provider identities and terminal states, terminal admission or exact failure/cancellation record, and proof of no second campaign. | HOLD; formal campaign not dispatched |
| FU-E1 | Descriptive synthetic costs for the three fixed strategies at S/M and the registered rho values. | Six admitted synthetic shard artifacts, exact replay, terminal admission, aggregate | HOLD |
| FU-E2 | Descriptive ordered-event costs for the frozen SNAP a2q two-partition T1/T2 matrix. | Admitted acquisition plus four admitted ordered-event shard artifacts, second-download guard, terminal admission, aggregate | HOLD |
| FU-E3 | Native OpenFHE latency, operation inventories, and exact retained-package bytes for six fixed cases. | Six admitted native artifacts with three fresh-key producers, exact package replay, native guards, terminal admission, aggregate | HOLD |
| FU-E4 | A bounded descriptive comparison across admitted follow-up cells, without inferential or superiority claims. | All 17 pre-aggregate artifacts, terminal admission, isolated compatible analysis, claim-to-artifact table | HOLD |

## Permanent non-claims

The follow-up cannot release any of the following from this design:

- a before/after speedup caused by the performance repair;
- a claim that the predecessor experiment passed after repair;
- performance superiority, a universal best strategy, or statistical
  population inference;
- a fitted scaling law or extrapolation beyond S/M;
- formal security, malicious/adaptive security, side-channel resistance, or
  privacy equivalence across layouts;
- first/only/global novelty; or
- any empirical sentence supported only by diagnostics, CI, registration,
  qualification, external-model review, or a non-evidence handoff.

## Failure closure

The sole qualification releases exactly one of FU-Q-GO or FU-Q-NOGO. An early
NO-GO is supported by the exact executed prefix plus downstream non-execution;
it never requires nonexistent q1--q6 guards. If FU-Q-GO is factual but the
post-GO provider/resource reread fails, no formal capability is minted and
FU-FORMAL-OUTCOME records pre-campaign NO-GO. If a later formal unit or terminal
admission fails, FU-Q-GO likewise remains unchanged and FU-FORMAL-OUTCOME records
in-campaign NO-GO. FU-E1--FU-E4 remain on HOLD unless the complete terminal
admission requirements for each are satisfied.

No outcome authorizes a second qualification, replacement seed, relaxed
threshold, or reuse of partial artifacts. A qualification NO-GO or formal
campaign NO-GO also ends this publication lineage: no third
same-estimand/same-threshold study may be tuned, dispatched, or used to support
this paper.
