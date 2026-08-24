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

The representative receipt proves an accounting size class; it does not claim
that billions of fresh masks were generated or consumed during the experiment.
Consequently, a batch with multiplicity greater than one is forbidden from
setting either materialized-ledger transition flag. Receipt-level phase
random/dummy route totals are logical totals (the sum of exact multiplicities),
whereas binding and equivalence-class counts remain counts of materialized
descriptors.
F1-M correctness, route coverage, and no-reuse semantics remain separate
algorithmic obligations under ADR 0005 and the single-use ordinary-query
lifecycle. The real OpenFHE runner smoke verifies the complete typed execution
path, while formal Day 2 measures the frozen primitive profiles and ciphertext/
evaluation-key sizes used to price Day 1B's exact multiplicities. Day 1B may not
substitute fixture bytes or an unanchored OpenFHE profile.

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
