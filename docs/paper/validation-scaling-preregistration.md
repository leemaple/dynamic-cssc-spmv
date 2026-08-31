# Preregistration: current-source validation-depth scaling

Status: **Stage-0 v2 amendment candidate; no implementation or study dispatch
is authorized by this document.**

Study ID: `dynamic-cssc-validation-scaling-2026-09-01`.

Version 2 preserves the research question, estimand, 54-cell matrix, formal
seeds, query-vector seed, ordering, two-operation public interface, timeouts,
one-dispatch rule, and claim boundary from immutable v1. Before any registered
seed was executed, it closes five implementation ambiguities found by direct
source inspection: private-artifact retention, complete `compile_query`
instrumentation, provider-terminal timestamp ownership, sentinel-only testing,
and exact OLS serialization. Immutable v1 remains an audit ancestor and is not
relabelled as v2.

## 1. Why this is a different study

Two earlier performance lineages are terminal and remain closed. Primary Route
A run `33261434612` missed its frozen 45-minute gate. The later follow-up run
`33348855548` terminated before checkout or seed admission. Neither may be
rerun, repaired in place, or treated as a pilot for the original strategy-cost
estimand.

The present study asks a different, independently useful systems question:

> For the current semantics-preserving deep lifecycle interface, how do
> producer and independent-replay validation-bearing lifecycle durations scale
> with exact query count while canonical outputs and compile-depth bounds remain
> invariant?

It does not ask which maintenance strategy wins, whether either earlier gate
would pass, or whether a formal Route A campaign should be admitted. Results
from this study cannot mint qualification, campaign, admission, or publication
authority for either predecessor.

## 2. Outcome-informed history disclosed before execution

The diagnosis in
`docs/reviews/route-a-followup-performance-diagnosis-2026-08-30.md` observed
that the old q1 producer spent 2,451.120 seconds and that repeated deep
validation caused ten `compile_query` calls per ordinary query and four per
strong query. The current interface reduced this to one construction plus one
independent binding. A non-evidence S-scale pilot at rho 1 reported 12.009,
10.976, and 27.055 seconds for the three strategies. Those values motivated
this scaling question. They are disclosed rather than hidden, are excluded
from every result and fit, and cannot be used as baselines or speedup evidence.

No further timing pilot may be run after this Stage-0 object is frozen. Tests
may use disjoint sentinel seeds only and may assert structure, exact bytes,
failure behavior, and synthetic clocks rather than observed study timing.

## 3. Frozen matrix

The study uses scale `S` from the inherited Route A machine plan, with 512
accepted update groups. The only direct rho values are
`1/100`, `1/10`, and `1`; they deterministically yield 5, 51, and 512 queries.
The three fixed strategy identities are:

1. `periodic-repack/windows=1`;
2. `padding-reuse`; and
3. `packed-coo-cloud-segmented-delta/segment-width=128`.

The three formal seeds are derived before implementation by taking the first
four bytes of SHA-256 over the ASCII label
`dynamic-cssc-validation-scaling-v1|formal-{ordinal}`, interpreting them as a
big-endian integer, and applying `& 0x7fffffff`:

| Ordinal | Seed | Full derivation digest | Strategy order | Rho order within every strategy |
|---:|---:|---|---|---|
| 1 | 602539264 | `23ea050059f9cd247b134c4e3bcbc24965e3044169c38afb35d98a3f0ab5616f` | periodic, padding, strong | `1/100`, `1/10`, `1` |
| 2 | 1712223489 | `660e7501e62f4aace24772c58fe2d410f6391e51e9f5c15e04fb9f8389bec99e` | padding, strong, periodic | `1/10`, `1`, `1/100` |
| 3 | 834605787 | `31bf12db59aa04fb7455d6c8403003420c915638e57096d1b2481ebf1d8c45ab` | strong, periodic, padding | `1`, `1/100`, `1/10` |

Both orders are frozen before observation. Strategy order makes every strategy
the first, second, and third strategy block exactly once. Rho order makes every
query count the first, second, and third cell within each strategy exactly once,
so query count is not identical to within-strategy process position. The fixed
query vector seed is `1832337970`, derived analogously from the exact ASCII
label `dynamic-cssc-validation-scaling-v1|query-vector`, with digest
`6d374232ca5867d81caa6289bfc6d9fc57b5738a0c011bbee1467244abd4f66a`.

There are 27 producer cells and 27 independent-replay cells: 54 measured cells
in total. Producer and replay execute in distinct GitHub jobs. Replay may read
only the exact provider-uploaded producer package for its seed.

## 4. Deep module and measurement seam

The implementation module
`src/dynamic_cssc/validation_scaling_study.py` exposes exactly two public
operations:

1. `produce_validation_scaling_seed_shard(*, plan_bytes, seed_ordinal,
   scratch_root)`; and
2. `replay_validation_scaling_seed_shard(*, plan_bytes,
   producer_package_bytes, seed_ordinal, scratch_root)`.

`plan_bytes` must equal the exact Stage-0 plan bytes, `seed_ordinal` must be the
strict integer 1, 2, or 3, and `scratch_root` must be a fresh empty directory
owned and destroyed by the operation. The operation derives every seed,
strategy, rho, order, target, and expected artifact identity internally. Matrix
iteration, exact profile construction, `compile_query` counting, scratch
ownership, canonical archive construction, checksums, stage clocks, and failure
cleanup remain behind the seam. Callers cannot pass a `skip_validation`, success
Boolean, timing result, seed value, rho, strategy, order, or caller-selected
matrix.

The compile-count adapter owns exactly two live bindings:
`dynamic_cssc.query_compiler.compile_query` and
`dynamic_cssc.simulator.compile_query`. Before installation it requires both
bindings to be the same original function. It installs one shared wrapper in
both locations before either cell clock starts, increments once per wrapper
entry, calls the original function with byte-for-byte identical arguments, and
preserves its return value or exception. Both bindings are restored in `finally`
after the clocks stop. The dynamic strong path imports the wrapped
query-compiler binding. Adapter setup and removal are excluded from timing; the
constant per-call counter increment is intentionally included in every measured
cell. Tests must prove that omitting either binding is detected rather than
silently accepted as an exact count.

For a producer cell, `operation_wall_nanoseconds` and
`operation_process_nanoseconds` start immediately before calling
`dynamic_cssc.route_a_evaluation.evaluate_route_a_synthetic_cell` and stop
immediately after it returns. They include that complete function's trace
validation, window construction, state transitions, query compilation and
lifecycle, oracle checks, ledger closure, canonical cell construction, and
cell validation. They exclude source-trace generation, scratch-directory
creation, counter installation/removal, producer-cell archive construction,
seed-package construction, provider upload, and queue time.

For a replay cell, those clocks start immediately before calling
`dynamic_cssc.route_a_replay.replay_route_a_synthetic_cell` and stop immediately
after it returns. They include producer-archive inspection and rehash, external
target validation, read-only ledger replay, query compilation and lifecycle,
oracle and semantic comparison, final-cell construction, and replay-receipt
serialization. They exclude provider download, source-trace generation,
scratch-directory creation, counter installation/removal, replay-seed-package
construction, provider upload, and queue time. Receipt serialization is thus
inside the replay operation and is not claimed as a separate timer.

Producer-cell archive construction is measured outside the producer operation
with its own per-cell wall and process nanoseconds; its two fields are null for
replay cells. Construction of the single provider artifact for a seed is a
per-job wall/process observation and never appears in a cell row or an OLS fit.
The existing canonical cell fields `producer_state_transition_seconds`,
`producer_result_assembly_seconds`, and `replay_seconds` are converted exactly
to integer nanoseconds and reported as supporting stage observations, with null
used for the inapplicable role. The primary fit uses only operation wall time.

Production public operations are never executed successfully by tests because
they derive the registered formal seed internally. The module contains one
private, non-exported engine over an exact internal domain. A named test-only
factory may construct only a disjoint sentinel domain and must reject all three
formal seeds and the registered query-vector seed. Full successful package,
replay, cleanup, counter, and synthetic-clock tests use that private domain.
Public-operation tests cover strict inputs and failure paths that terminate
before production trace generation. A repository sweep rejects registered
seeds outside the four Stage-0 objects and the single production-domain
constructor. No public seed, strategy, rho, order, matrix, clock, or validation
override is added.

The semantic document for both roles is the closed projection of the canonical
cell over exactly `schema_version`, `identity`, `evaluation`, `counts`,
`window_query_counts`, `primitive_counts`, `rotation_inventory`,
`serialized_object_multiplicities`, `serialized_bytes`, `correctness`, and
`bindings`; `measurements` is excluded. The projection is encoded by
`dynamic_cssc.route_a_results.canonical_route_a_document` (sorted keys, compact
ASCII JSON, no floats, one terminal LF). Producer and replay projection bytes
must be byte-identical, and `semantic_projection_sha256` is SHA-256 over those
exact bytes. Timing never enters a semantic digest.

The implementation counts calls to the real `compile_query` function while
preserving its inputs and return value. Every cell must satisfy

\[
Q \le C \le 2Q,
\]

where \(Q\) is the exact query count and \(C\) is the observed compilation-call
count. This is a structural validation-depth gate, not a wall-time theorem.

## 5. Execution and evidence chain

The Stage-0 tag is the fixed annotated tag `validation-scaling-stage0-v2`; the
source tag is the fixed annotated tag `validation-scaling-source-v2`. All five
Stage-0 objects must remain byte-identical between those tags. The source tag is
made only after implementation, tests, exact-source CI, and independent
material review pass. From Stage 0 to the source tag, changed paths are limited
to exactly:

- `.github/workflows/validation-scaling-study.yml`;
- `docs/reviews/validation-scaling-stage1-review.md`;
- `schemas/validation-scaling-evidence-v1.schema.json`;
- `scripts/run_validation_scaling_study.py`;
- `scripts/validate_validation_scaling_study.py`;
- `src/dynamic_cssc/validation_scaling_study.py`;
- `tests/test_validation_scaling_study.py`; and
- `tests/test_validation_scaling_workflow.py`.

The source verifier must reject any other changed path and must compare the
exact five Stage-0 file bytes against the Stage-0 tag; JSON-schema success alone
is never sufficient. The workflow uses `ubuntu-24.04`, CPython `3.12.13`,
hash-locked `requirements-ci.txt`, one thread for NumPy/BLAS/OpenMP, and
`PYTHONHASHSEED=0`.

One workflow dispatch creates exactly:

- three producer artifacts, one per seed;
- three independent replay artifacts, one per seed; and
- one aggregate artifact after all six seed jobs succeed.

Each producer artifact contains the exact private cell handoffs required by
`replay_route_a_synthetic_cell`; its provider retention is therefore exactly one
day, matching the nested handoff manifests. Each replay artifact and the
aggregate have 90-day retention. A replay artifact is redacted and must not
contain a private preparation document, ledger snapshot, producer-cell archive,
or nested replay-cell archive. It contains only the closed timing rows, final
cells, semantic projections, replay receipts, exact producer bindings, and its
canonical manifest. The aggregate consumes all six seed artifacts in the same
run before any producer expires. It does not extend, delete, or reupload a
private producer handoff.

Producer and replay jobs have 40-minute safety timeouts; aggregate has 20
minutes. These are operational ceilings, not acceptance thresholds and not
derived from either predecessor's 45/55-minute gates. The aggregate job must
independently rehash every provider-downloaded object, validate exact
run/ref/head/attempt identity, require all 54 cells, verify producer/replay
semantic equality and every compile-depth gate, and reject missing, extra,
duplicate, reordered, unsafe, or noncanonical members.

Seed packages record process-owned `operation_started_utc` and
`package_finished_utc`; these are not GitHub terminal times. After all six
dependency jobs are terminal, the aggregate reads the provider Jobs API and
records each dependency job's database ID, exact name, `startedAt`,
`completedAt`, and success conclusion. It rejects a missing, future, reversed,
non-success, or identity-mismatched interval. It never claims to contain its own
terminal `completedAt` or conclusion. The final independent result audit reads
the aggregate job and workflow terminal metadata after the run completes.

The formal inventory is exactly one workflow run at attempt 1 for the source
tag. Any second dispatch, rerun attempt, job non-success, timeout, missing or
extra artifact, semantic mismatch, or incomplete matrix makes this study
terminal NO-GO. No partial timing row or fit may be reported.

## 6. Frozen analysis

For every strategy, role, and rho, report all three seed observations plus
median, minimum, and maximum wall and process seconds. Separately for each
strategy and role, fit

\[
T(Q)=\alpha+\beta Q
\]

by unweighted ordinary least squares to the three rho-level median wall times.
Every source observation remains a strict integer number of nanoseconds; the
three-seed median is the middle integer after stable numeric sorting. The fit is
computed with exact rational arithmetic over integer \(Q\) and those median
nanoseconds. \(\alpha\), \(\beta\), and \(R^2\) are each serialized as a closed
object containing a reduced signed strict-integer numerator and a strict
positive denominator; JSON floats are forbidden. If total sum of squares is
zero, residual sum of squares must also be zero and \(R^2\) is exactly `1/1`.
Otherwise \(R^2=1-\mathrm{SSE}/\mathrm{SST}\). Human seconds and
seconds-per-query strings are derived only after evidence validation with
decimal round-half-even at nine places and never feed a statistic or digest.

Report \(\alpha\), \(\beta\), and \(R^2\) without a pass threshold, p-value, or
claim of asymptotic complexity. Because no zero-query cell exists, \(\alpha\)
is labeled an extrapolated descriptive intercept and never an observed fixed
cost. Producer and replay are reported separately; runner variation prevents
interpreting their ratio as a controlled speedup.

All rows appear in the registered order. There is no outlier removal,
seed replacement, selective rerun, hypothesis test, or multiple-comparison
procedure.

## 7. Claim boundary

If and only if the complete evidence gate passes, this study may support:

- exact-source semantic conformance for this 54-cell matrix;
- exact compilation-call bounds for each cell;
- descriptive GitHub-hosted-runner validation-bearing lifecycle scaling; and
- separately labeled producer and independent-replay stage costs.

It may not support a strategy winner, comparative strategy superiority,
qualification or campaign GO, a speedup over the historical source, OpenFHE
native performance, deployment latency/throughput, a formal security theorem,
or general correctness. The E4 OpenFHE conformance witness remains a separate
single-fixture functional result.

## 8. Freeze sequence

1. Freeze this v2 preregistration, the machine-readable study plan, claim
   ledger, JSON schema, and detached Stage-0 manifest; commit them without
   implementation and create the annotated `validation-scaling-stage0-v2` tag.
2. Obtain ChatGPT Pro and ZCode GLM-5.3 Max same-packet review after the shared
   weekly quota resets; resolve every P0/P1 before implementation freeze. The v1
   review and amendment audit remain attached history, not authority for v2.
3. Implement the two-operation module, workflow, validator, and sentinel-only
   tests without changing this matrix, estimand, claims, or timeouts.
4. Obtain exact-source CI and same-packet independent review; create the
   annotated source tag.
5. Dispatch once, retain the complete provider inventory, independently audit
   the aggregate, and only then edit the manuscript.
