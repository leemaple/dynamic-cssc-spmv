# ADR 0006: Advance independent persistent strategy snapshots

- Status: Accepted
- Date: 2026-08-22

Day 1 advances one independent persistent snapshot per maintenance strategy through every
ordered Publication Window. Warmup and tuning windows change state even when their costs
are excluded from held-out metrics. Each transition validates the complete candidate
matrix version, publishes version-matched CSSC components, and requires decoding those
components to reproduce the logical state before it commits.

This replaces the static initial-layout `WindowShape` proxy. A general event-sourced replay
framework was rejected because it adds checkpoint, cache, and projector machinery that the
experiment does not need. The minimal causal selector is a tuning-only `TunedFixedPolicy`:
its configuration is frozen before held-out evaluation and continues from its own
post-tuning snapshot. `BestFixed-Offline-Oracle` remains a diagnostic bound and is never a
selector input. Online cross-strategy switching remains out of scope until migration or
parallel-maintenance costs are modeled.

`ReservedSlack-CSSC` uses frozen contract A: a row reserves
`ceil(beta * max(1, nnz))` lanes, with total physical capacity clamped to the matrix
column count. `beta = 0` reserves no lanes. For `beta > 0`, even an empty logical row
deliberately owns a physical reserved lane and incurs its complete publication and query
cost. This intentionally overrides implicit-zero reconstruction for that row; the lane is
real reserved capacity, not a fabricated logical contributor.

## Packed-COO identity and baseline boundary

The implemented packed-COO candidate is `Packed-COO-Client-Lane-Delta`, with canonical
candidate ID `packed-coo-client-lane-delta/capacity=<actual capacity>`. Fixed COO segment
lanes are evaluated at the Cloud and returned without cloud-side row aggregation; the
clients use the version-bound OutputPlan to reorder and merge them into logical outputs.
The internal representation and update accounting remain packed COO.

This is not the original `Packed-COO-HYB-Delta` strong baseline. That baseline requires
the Cloud to perform segmented aggregation by logical row. Under the v2.1b F1-M
Hidden-RowMap contract, the Cloud does not receive the RowMap, and neither the original
task nor the protocol patch defines an executable schedule that lets it derive those
segments without the hidden row labels. The strong cloud-segmented baseline is therefore
deferred and unimplemented; the client-lane candidate must not be relabeled as HYB to
make the reference set appear complete.

The client-lane cost path fully charges returned result ciphertexts, decryptions, client
reorder elements, client modular additions, and the F1-M one-time mask ciphertexts,
encryptions, additions, random elements, and mapped elements. Bandwidth cost remains
deferred. Consequently Day 1 artifacts must report `complete_reference_set=false`, list
`strong-packed-coo` as a missing/deferred baseline, and remain in full-baseline HOLD.
They do not support claims that all fixed references, a six-reference comparison, or a
complete baseline suite has been implemented.

The partial-reference artifact policy in the preceding paragraph is historical and is
superseded by ADR 0009. The current production contract fails closed before writing R2
output until the strong candidate is admitted; after admission it requires the exact
role-aware complete set.
