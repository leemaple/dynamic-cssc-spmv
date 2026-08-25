# Use window-weighted equivalence accounting for Day 1B

- Status: Accepted
- Date: 2026-08-25

## Context

Day 1B estimates the update and query terms later priced by the independently
measured Day 2 primitive calibration. It is not a throughput trial in which the
same public query must be encrypted, evaluated, and serialized once for every
scheduled arrival.

The previous preparatory worker protocol nevertheless expanded every query
arrival into a separate F1-M binding, preparation transition, serialized-object
receipt, and potentially a full OpenFHE launch. That interpretation is not
operationally compatible with the preregistered domain. A trace contains exactly
131,072 accepted groups. Across the nine rho values, two freshness settings, and
14 physical candidates, it implies 530,097,064 query arrivals per trace unit and
15,902,911,920 across 30 units. The rho=100 cell alone contains 13,107,200 query
arrivals before phase filtering. These numbers are determined entirely by the
pre-outcome schedule and were established before any held-out execution.

Repeating an identical public query millions of times at one unchanged layout
does not add a new causal state or a new compute-cost observation. It only
repeats the same typed operation inventory and protocol-object size classes.
Treating those repetitions as independent executions would turn a deterministic
cost-model study into an infeasible traffic generator without strengthening the
paper's estimand.

## Decision

Day 1B uses the frozen execution basis
`window-weighted-equivalence-v1`.

For each candidate and publication window, the worker advances the persistent
layout exactly once. If the window contains queries, it derives the typed query
plan and its protocol-object size classes once for that exact layout. Primitive
counts, logical F1-M route counts, and charged communication bytes are then
multiplied by the window's exact integer `query_count`. No binary floating point
or sampled arrival count is used.

An F1-M serialized equivalence-class receipt therefore carries a positive,
controller-bound multiplicity. Its multiplicity must equal the exact contiguous
query range covered by the corresponding window batch. The registry still
checks the OutputPlan-derived random/dummy route cardinality, canonical route
order, nonoverlapping contiguous query ranges, representative payload digest,
and charged byte count. Receipt/frame/resource caps govern materialized
equivalence classes and controller scratch, not the logical multiplicity being
priced.

In particular, `serialized_payload_bytes_per_cell_maximum` is the physical
worker-stream ceiling reviewed in the resource amendment. It must never be
compared with the multiplicity-weighted logical F1-M charge. That charge is an
exact derived metric whose closed semantic envelope comes from the accepted-group
count, frozen rho, OutputPlan route cardinality, retained phases, and anchored
Day 2 ciphertext sizes; it does not allocate or retain the priced bytes. Applying
an administrative payload cap to it would censor high-rho cells while consuming
no corresponding resource.

The exact identity is

```text
logical_charged_byte_count
  = sum over retained phase p and F1-M kind k of
      anchored_ciphertext_bytes(k)
      * sum over query windows w in p of routes_k(w) * query_count(w).
```

All factors are strict integers bound respectively by the Day 2 serialized-size
profile, typed query-plan route stream, and frozen event schedule. The resulting
totals can exceed `2^53`; JSON producers and consumers must preserve exact integer
semantics and must not pass charge totals through IEEE-754 binary64 values.

`HELDOUT_RECORD_SCHEMA` remains
`dynamic-cssc-publication-heldout-record-v4`. Its frozen measurement kind has
always required component-complete protocol serialization, including all five
query-transaction categories. Before this decision, the preparatory Day 1B
producer incorrectly omitted the two F1-M categories from the physical record's
`query_serialized_bytes`; the dual-source ledger now substitutes their exact
controller-anchored charges and validates the record total as the sum of all
five categories. This is a conformance correction, not a redefinition of v4.
At the correction point the Day 1 registration, Day 2 post-run, and Day 2
profile anchor sets are all empty, and no admissible Day 1B artifact carries the
omission. Tests freeze that precondition before the first anchor installation.

The worker receipt gains an open, exact-key input-binding document, so its shape
change propagates through the enclosing exact-key unit contract. Production and
private-fixture Day 1B unit schemas therefore advance from v1 to v2 together.
The heldout fragment schemas stay at v1 because their shape and already-declared
record semantics do not change. The serialization ledger is independently
self-describing and advances from v1 to v2 for its new dual-source fields.

The v2 unit manifest is also the unit-level authority for the Day 2 size tuple.
It opens the Day 1B source Git identity, Day 2 experiment source identity, outer
archive and serialized-size-profile digests, the ordinary ciphertext byte size,
the two category-specific F1-M ciphertext byte sizes, and the rotation/evaluation
key byte sizes. Every one of the 252 worker contracts, including
controller-terminal null projections, must equal that unit document for the
archive, profile, and three contract-visible ciphertext sizes. Every retained
controller charge must independently equal the same unit authority; agreement
between a ledger and its own worker contract is not sufficient.

The v2 candidate catalog opens the ordered policy preimage for all 14 candidates:
candidate identity and role, strategy, packed-COO capacity, periodic-repack
period, reserved-slack beta, and the digest of exactly those six fields. The
opened list must reproduce the repository's 13-reference/one-ablation canonical
roster and order. Each worker candidate specification must then reproduce the
opened strategy, digest, role-derived retained phases, and strategy-derived F1-M
policy. A self-consistent worker contract cannot substitute a different policy
behind a stale catalog digest.

Controller lineage and route coverage are retained as open, exact-key preimages,
not unexplained roots. The controller-context document binds source, behavior,
registration and trace anchors, worker identities, unit/cell/candidate facts,
the preparatory trace source Git identity, the complete three-phase audit, and
schedule/query/accounting commitments. Each of the 252 opened contexts must
reproduce the unit manifest's trace source Git identity; a rehashed manifest
cannot retarget that identity while retaining its worker evidence. The
route-coverage document binds that context, the Day 2 archive/profile, and the
per-phase query-window, query, random-route, and dummy-route counts. These small
documents are independently recomputable from the frozen trace, policy, and
repository code. The only intentionally unexpanded route payload is the
per-window route stream itself: `element_stream_sha256` commits to that stream,
but the unit artifact does not retain enough rows to replay the stream from the
hash alone. Charge classes are nevertheless recomputed from the opened phase
counts and unit Day 2 size authority for every receipt, including terminal
receipts.

Opening those preimages advances the F1-M controller summary to v4, route
coverage to v2, worker input binding to v7, and enclosing worker receipt to v8.
The retained unit, ledger, controller summary, context, route, worker-input, and
worker-receipt schema identifiers are pairwise distinct so an exact-key parser
cannot silently accept one document family as another.
Those schema changes do not authorize execution or publication; the existing
all-false unit authority boundary remains in force.

The representative receipt proves an accounting size class; it does not claim
that billions of fresh masks were generated or consumed during the experiment.
Consequently, a batch with multiplicity greater than one is forbidden from
setting either materialized-ledger transition flag. Receipt-level phase
random/dummy route totals are logical totals (the sum of exact multiplicities),
whereas binding and equivalence-class counts remain counts of materialized
descriptors.
In particular, a worker may materialize zero F1-M descriptors while the
controller still derives nonzero logical random/dummy route counts. The worker
registry counts validate whatever descriptors were physically streamed; they
are not a second authority for the controller's multiplicity-weighted charge.
F1-M correctness, route coverage, and no-reuse semantics remain separate
algorithmic obligations under ADR 0005 and the single-use ordinary-query
lifecycle. The real OpenFHE runner smoke verifies the complete typed execution
path, while formal Day 2 measures the frozen primitive profiles and retains its
category-specific ciphertext/evaluation-key sizes in the archive-bound
serialized-object size profile used to price Day 1B's exact multiplicities.
Random-zero-sum and encrypted-zero-dummy F1-M charges use their separately
measured fresh-encryption byte lengths. The reviewed post-run anchor and
zero-argument repository authority carry those exact sizes into Day1B. Day 1B
may not substitute fixture bytes, caller values, or an unanchored OpenFHE
profile.

The execution basis is part of every worker input-binding digest. A worker or
artifact that declares full query-arrival replay, omits the basis, changes a
multiplicity, leaves a query-range gap, overlaps ranges, or disagrees with the
controller's schedule fails closed.

## Consequences

- Candidate state evolution and causal selection are unchanged.
- The rho grid and 131,072-group trace target remain unchanged; no smaller
  fallback dataset or post-outcome retuning is introduced.
- Operation totals and charged communication totals remain exact integer sums
  for the scheduled workload, while runtime scales with distinct layout/window
  states rather than duplicate query arrivals.
- Resource-policy values must be measured against the weighted worker and its
  materialized equivalence classes. The permanently non-admissible structure
  pilot cannot supply candidate-execution scratch values.
- Day 1B remains blocked until the weighted production adapter, profile binding,
  controlled scratch measurement, and normal evidence anchors are installed.

## Rejected alternatives

- Raising frame and receipt caps to billions preserves the category error and
  does not make full OpenFHE replay scientifically useful.
- Reducing rho or the accepted-group target changes the estimand and discards a
  preregistered operating regime.
- Treating repeated encrypted payloads as byte-identical is false; the worker
  may aggregate only an admitted size class and must charge its multiplicity.
- Reusing one F1-M mask across arrivals would violate ADR 0005. Weighted
  accounting aggregates cost and size, not cryptographic randomness in an
  actual deployment.
