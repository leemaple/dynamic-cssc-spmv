# ADR 0007: Build an anonymous fixed-segment primitive before registering the strong baseline

- Status: Accepted for the Phase 1 primitive; candidate registration deferred
- Date: 2026-08-22

The strong packed-COO path uses a public, power-of-two physical segment width `c`.
Every allocated segment contains entries for exactly one logical row, but the Cloud sees
only fixed public page and segment shapes plus opaque ordinal identifiers. A segment may
have a non-power-of-two active-payload region of at most `c` lanes; the remaining lanes
are explicit zeros. For example, the primitive witness exercises the boundary of a
127-lane active-payload region inside a physical segment of width `c=128`: it touches
offset 126 and proves offset 127 is zero. This does not define a `c=127` candidate.

The Cloud executes one page-wide SIMD program with the same fixed-stride multiply,
relinearize, rotate-and-add reduction, segment-start mask, F1-M operand addition, and
return schedule for every public page shape. Each segment is reduced only into its own
post-reduction leader lane. If two opaque segments contribute to the same hidden logical
row, their leader lanes remain distinct, even when they share one page ciphertext and one
page Output Share; Client B combines them using the version-bound OutputPlan. Asking the
Cloud to merge those leaders would disclose row-equivalence unless a separate oblivious
routing construction were specified. This fixed-segment definition resolves the
ambiguity recorded in ADR 0006 without exposing a RowMap to the Cloud.

For this primitive, every returned share has an identical visible F1-M ciphertext-add
schedule. A share that needs no random overlap mask uses an encryption of zero as an
opaque dummy operand. This changes operational ciphertext and addition counts, but it
does not change ADR 0005's logical rule: random zero-sum values are sampled only for
logical-coordinate overlap, and disjoint blocks still concatenate without a random mask.
Production integration must account separately for fixed dummy operands and random mask
elements, bind every operand to the query, version, OutputPlan digest, component, and
block, and retain the persistent ledger for every random zero-sum mask binding.

The Phase 1 OpenFHE witness is a fresh-key, fixed-input primitive correctness test. Its
masks are test operands, not a production mask-generation path, and it makes no ledger,
security, end-to-end, performance, or complete-baseline claim. A strong candidate may not
enter the Day 1 registry until all of the following are present:

1. a production-safe builder from public shapes to the typed Cloud program;
2. a whole-query plan joining the real CSSC base and the strong delta;
3. versioned OutputPlan and F1-M operand bindings with complete accounting;
4. a pinned OpenFHE witness whose execution trace and provenance match that plan; and
5. an explicit protocol/report-schema update for the fixed dummy-operand schedule.

Until those gates pass, `Packed-COO-Client-Lane-Delta` remains a separate ablation,
`Packed-COO-Cloud-Segmented-Delta` remains unregistered, and Day 1 continues to report
`complete_reference_set=false` and full-baseline HOLD.
