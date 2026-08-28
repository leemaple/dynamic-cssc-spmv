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
change propagates through the enclosing exact-key unit contract. The initial
dual-source change advanced the production and private-fixture Day 1B unit
schemas from v1 to v2 and the independently self-describing serialization
ledger from v1 to v2. The subsequent controller-count closure advances both
unit schemas to v3 and the ledger to v3. The heldout fragment schemas stay at
v1 because their shape and already-declared record semantics do not change.

The v3 input carries a controller-owned expected-count preimage for every
retained phase. That preimage opens the frozen primitive names and serialized
category taxonomy, exact update/query primitive vectors, logical protocol-object
multiplicities, and the multiplicities that the worker must physically stream.
For every non-F1-M category the logical and worker multiplicities are identical.
For the two F1-M ciphertext categories, the logical multiplicities must equal
the independently opened controller route totals while the formal weighted
worker multiplicities are exactly zero. The one-time key inventory is either
absent or occurs exactly once in the first retained phase. Counting serialized
equivalence classes therefore cannot conceal a lower logical multiplicity.
The zero-worker rule is checked at the repository worker-seed boundary and by
the artifact verifier immediately after reopening the input contract, before
any complete, failed, or controller-terminal outcome branch. A null quantity
projection therefore cannot use consistent downstream rehashing to substitute
the generic materialized-F1-M fixture mode for the formal weighted mode.

The controller accounting and phase documents advance to v2. Each phase now
opens the primitive inputs needed by the nine serialized categories, including
metadata units, update/query/result ciphertexts, both F1-M route kinds, and a
realized version-publication count. A version publication is charged exactly
once for an update-bearing window and never for a no-update window. The expected
count document binds the accounting digest, candidate policy, phase set, and
category order. The worker must match its primitive vectors and accumulated
protocol-object multiplicities to that pre-dispatch document; the unit verifier
also binds the opened primitive vectors to the physical record and every ledger
row to the same logical/worker count pair.

The three metadata categories use canonical fixed-width, big-endian binary
framing rather than variable-length JSON. All records share an exact 16-byte
header with magic `D1BMETA1`, record kind, zero flags, schema version, and total
byte count. A ColumnIndex synchronization entry is 64 bytes; patch and full-sync
use one fixed-position `entry_kind` byte and otherwise share the same layout and
size-class identity. An update-side version-plan publication is 144 bytes and is
materialized only for the actual version transitions counted above. A query-side
version-plan binding is 136 bytes and retains its per-query multiplicity. Exact
length, reserved-zero bytes, integer ranges, digest widths, and rejection of
trailing bytes are part of the framing contract. This closes the prior metadata
size-class ambiguity without treating distinct logical objects as byte-identical.

The v3 unit manifest is also the unit-level authority for the Day 2 size tuple.
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

Opening the controller and route preimages advanced the F1-M controller summary
to v4 and route coverage to v2. Adding the controller expected-count document
advanced the enclosing worker receipt to v9. Binding the three fixed-width
metadata size classes advances the expected-count document to v2, the worker
input binding to v9, and the serialization ledger to v4; the unchanged
expected-phase-count document remains v1.
Binding the one-time combined evaluation-key class advances the expected-count
document to v3, the worker input binding to v10, the serialization ledger to
v5, the worker receipt to v10, the unit to v4, and the preparatory behavior set
to v18.
The retained unit, ledger, controller summary, context, route, worker-input, and
worker-receipt schema identifiers are pairwise distinct so an exact-key parser
cannot silently accept one document family as another.
Those schema changes do not authorize execution or publication; the existing
all-false unit authority boundary remains in force.

The expected-count v2 preimage opens one canonical size-class digest, transaction,
and serialized byte count for ColumnIndex synchronization (64 bytes), update
version publication (144 bytes), and per-query version binding (136 bytes).
Patch and full-sync ColumnIndex entries remain one class because their framing
differs only at the fixed `entry_kind` byte. A complete ledger must carry the
same class digest and charge exactly `multiplicity * serialized_byte_count`;
the artifact parser independently checks every retained representative receipt
against the category width. These checks bind preparatory accounting to framing
without claiming that the production runner has emitted the representative.

The single one-time evaluation-key taxonomy category is also frozen as one
combined frame, not split into new accounting categories. The frame has an
88-byte `D1BKEY01` header containing the big-endian length and SHA-256 of the
full rotation-key inventory, followed by the big-endian length and SHA-256 of
the eval-mult key set; the two raw segments follow in that order. Its size class
binds both measured Day 2 segment lengths and the Day 2 archive/profile roots.
No crypto context, public key, label, or optional payload is admissible. The
generic OpenFHE runner now emits that exact frame plus a same-context typed
receipt, but remains non-authorizing. The production-adapter seam must still
bind a verified Day 2 plan authority and runtime-admission capability before
treating that frame as a formal representative.
The formal worker input opens the Day 2 segment lengths and class digest. Its
streaming parser validates the header, both segment digests, and exact end of
frame without retaining the raw key payload. Exactly one representative is
required in the first retained phase, and its object receipt and ledger must
charge the controller multiplicity at `88 + rotation_bytes + eval_mult_bytes`;
later retained phases carry no such representative.

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
algorithmic obligations under ADR 0005 and the single-use ordinary and strong
query lifecycles. The real OpenFHE runner smoke verifies both complete typed
execution paths, while formal Day 2 measures the frozen primitive profiles and retains its
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

### Pre-S1 controller-only F1-M equivalence-class correction

Before the first Day 1 registration or Day 2 anchor was installed, a second
conformance error was found in the enclosing worker total.  The input binding
included controller-only F1-M registry rows in
`expected_serialized_equivalence_class_count`, while the formal weighted mode
correctly froze both worker-streamed F1-M multiplicities at zero.  A complete
worker could therefore either omit F1-M frames and fail the total, or emit them
and violate the formal zero-worker rule.

The corrected identity counts only equivalence classes that the worker must
physically stream.  Controller-only F1-M rows remain mandatory as the exact
window/range/route and Day 2 charged-size-class proof, but contribute zero to
the worker spool-line total and must never appear as worker frames.  Generic
materialized protocol fixtures still count and observe every F1-M class.  A
mixed materialized/controller-only preimage is rejected, and formal mode now
rejects the first stray F1-M frame before it can mutate the observation ledger.

The same-replay controller emits one bounded cardinality row for every retained
window so the registry can prove exact coverage of the controller audit.  A
zero-query row binds only its phase/window/range, first query ordinal, exact
candidate-state version, and `query_count=0`; its OutputPlan, private-plan, and
execution-binding fields are `null`, its returned/masked share counts are zero,
and it carries no F1-M route or size-class object.  It therefore does not compile
or claim a query plan.  Only a query-bearing window derives the typed plan and
positive-multiplicity size classes described by this decision.

This correction advances the worker input binding and receipt from v10 to v11,
the production and private-fixture Day 1B unit from v4 to v5, the serialization
ledger from v5 to v6, and the current preparatory behavior set from v30 to v31.
It also introduces the internal same-replay window-plan stream at v1 and advances
the now-nullable F1-M window-cardinality row from v2 to v3, its canonical set
from v3 to v4, and the enclosing cardinality-derivation root from v4 to v5.
At the correction point the Day 1 registration, Day 2 post-run, Day 2 profile,
and evidence-compatibility anchor sets are empty.  The historical descriptive
strong-reference receipt is not a Day 1B publication anchor.  No admissible
Day 1B artifact is rewritten or reinterpreted.

The preparatory v31 source surface exposes the exact typed compilation used for
each query-bearing window through a synchronous, output-only query-execution
sink, but the only public sealing seam now owns that sink and the replay call.
The caller supplies one exact frozen candidate, window stream, domain, and
canonical query-vector bytes; it cannot separately supply typed carriers,
accounting, candidate role, retained phases, or a plaintext modulus. The seam
derives the candidate policy and role-retained phases, freezes the modulus at
65,537, creates a private collector, and finishes it against the accounting
returned by that same replay invocation.

Every v31 query-execution binding commits the candidate ID, role, policy digest,
retained phases, and modulus together with the compact descriptor and ordinary
or strong carrier identities. The collector independently reconstructs the
existing compact query-window root and retains exactly one private typed
carrier: the first query-bearing window in the first role-retained phase
(tuning-prefix for reference candidates, held-out for the ablation). It
reconstructs that representative's logical matrix directly from the carrier
and evaluates the frozen query vector with the plaintext oracle only for that
representative. Non-representative windows retain neither a private carrier nor
logical state/output digests, so the work remains proportional to distinct
layouts and performs no OpenFHE execution. Claim or abandonment consumes the
process-local capability and releases its carrier reference even on validation
failure. Its receipt explicitly denies worker, dispatch, formal, publication,
complete-cost, and production authority.

The v31 candidate-cell core passes that same-replay capability as a mandatory
adapter input and accepts a launch only after the capability reaches its exact
consumed terminal state. The launch carries the collector-minted replay
receipt; construction fails unless its candidate, policy, retained phases,
accounting root, query-vector root, and modulus agree with the independently
bound worker contract. A controller failure after capability issuance abandons
the capability before propagating the error. This closes replay-to-worker
continuity without granting production or dispatch authority.

The same v31 surface retains the native request/result language at v4 and
advances the enclosing runtime receipt to v7. One private deep launcher now
admits either an ordinary or strong execution capability, owns scratch and
READY/DONE verification, and dispatches through thin kind-specific adapters.
Separate anchored entry points accept only the opaque single-use Day 2 plan
capability, consume it inside the launcher before request construction, use its
exact plan for key generation and verification, and bind the plan receipt into
the runtime receipt. The native smoke still executes the explicitly
non-anchored pre-admission paths. A production candidate-cell adapter and its
scratch authority remain later gates.

The v31 surface composes those two single-use capabilities in one additional
pre-admission boundary. It claims the representative retained by the same
replay, prepares its exact ordinary or strong private lifecycle, and passes the
opaque Day 2 plan capability directly into runtime v7. The returned joint
receipt binds the replay receipt, representative query binding, lifecycle
authorization, anchored runtime receipt, reconstructed-output digest, and an
ordered digest of every retained serialized-payload receipt. Failure consumes
or abandons both capabilities. This still grants no worker, dispatch, cost,
performance, security, or publication authority.

The v31 surface also preserves the formal Day 2 rotation-plan digest in the
final read-only calibration authority and introduces a single-use key-plan
capability. Its public issuer accepts only canonical plan bytes and obtains the
final authority from the zero-argument repository seam before and after
issuance. The bytes must be the exact preimage of the post-run anchored digest;
callers cannot submit an authority object or Boolean. The receipt sets only
`day2_direct_key_plan_authorized=true`; runtime, held-out dispatch, cost,
performance, publication, and security authority remain false. Claim or
abandonment releases the retained plan bytes. Because both repository Day 2
anchor sets are currently empty, this closes a typed future seam without
granting a capability now.

### Private production invocation issuer (Behavior Set v32)

Behavior Set v32 installs one private composition boundary between the existing
representative OpenFHE execution capability, the Linux anonymous expected-F1-M
registry, and the existing streaming worker decoder. It does not add a public
adapter or dispatch seam. The issuer consumes both single-use capabilities and
independently verifies the candidate, role, policy, retained phases,
accounting/window/query roots, query-vector digest, modulus, zero-reset fact,
Day 2 outer archive, runtime build and stable runtime identity, exact resource
limits and observations, closed serialized-payload taxonomy, canonical
`D1BKEY01` frame, and anchored per-category byte lengths. Failure consumes or
closes every capability and anonymous scratch object it has claimed.

The resulting process-local invocation binding carries a private typed
admission, not a caller Boolean or a new serialized authority. The existing
worker decoder sets `runtime_state_continuity_verified` and
`production_execution_admissible` only after all three phases complete in one
nonterminal transcript with zero retry, zero reset, exact schedule audits,
Linux scratch isolation, complete weighted query-range coverage, and zero
worker-materialized F1-M size classes. Fixture issuers and controller-terminal
paths remain false. Consequently v32 changes only the DAY1B Behavior Set
version; the unit, worker input-binding, worker receipt, runtime receipt, native
request/result, and artifact schemas remain unchanged.

The repository-owned production adapter remains an unconditional `HOLD`, and
the preparatory workflow still has no semantic inputs, producer invocation,
artifact upload, or dispatch authority. This boundary therefore proves that
already frozen typed facts can be composed without granting publication,
performance, cost, security, or held-out execution authority.

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
