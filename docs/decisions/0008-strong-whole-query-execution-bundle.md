# ADR 0008: Bind the strong baseline as one whole-query execution bundle

- Status: Accepted for Phase 2 implementation; candidate registration deferred
- Date: 2026-08-22

Phase 2 compiles one real `PublishedComponent` CSSC base and one
`SegmentedDeltaState` strong delta into a single deterministic
`StrongExecutionBundle`. The bundle owns the typed public Cloud DAG, the private
OutputPlan routes and global ColumnIndex operands, their version and tamper-evident
bindings, and counts derived from that DAG. Independently authorized base and delta
execution paths were rejected because they could disagree on reconstruction, bindings,
or accounting without ever constituting one auditable query.

Query preparation uses the bundle's private global ColumnIndex data, and the typed
plaintext oracle executes the same whole-query plan. Every returned ciphertext has
exactly one visible F1-M addition: logical-coordinate overlap receives a random zero-sum
operand, while a disjoint return receives an exact encrypted-zero dummy. Both kinds are
bound to the query and bundle, persisted as exact commitments under a ledger-issued
batch token, and atomically verified and consumed before evaluation. Changes to private
routes, global ColumnIndex data, or versions must therefore fail binding validation
rather than alter a valid prepared query.

A future strong-reference receipt is admissible only when it matches an independently
loaded trust anchor and a SHA-bound builder/property-contract gate; fixture coverage or a
caller-supplied capability is not authority. The successful Phase 1 primitive receipt is
deliberately a negative fixture for this admission path and cannot authorize Phase 2.

This decision does not register the strong candidate. `complete_reference_set=false`
remains mandatory, and no performance, security, end-to-end, or formal claim is enabled.
Registration still requires a v2 pinned OpenFHE whole-query witness, the corresponding
report/accounting update, and tuning-prefix evidence for the frozen `c=128` family.

ADR 0009 supersedes the mandatory-false artifact policy without weakening this admission
boundary. Before the composite anchor is installed, production fails before emitting R2;
after admission, completeness is derived from the exact role catalog rather than accepted
as input.
