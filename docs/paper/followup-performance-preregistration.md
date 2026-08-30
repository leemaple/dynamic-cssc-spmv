# Follow-up performance preregistration after the closed Route A NO-GO

> **State:** Stage-1 review draft; permanently non-authorizing. This document
> freezes a new follow-up study before its seed/namespace/runner implementation.
> It does not reopen, continue, reinterpret, or rerun the closed Route A
> qualification. No workflow dispatch is permitted from this commit.

## 1. Why a separate study is necessary

The original Route A lineage ended at the sole permitted qualification run
`33261434612`. The producer q1 completed, but independent replay q2 was still
running when the frozen 45-minute q1-through-q5 deadline arrived at
`2026-08-29T16:37:45Z`. The external controller cancelled that exact run; the
provider subsequently exposed q3--q6 only as zero-step `cancelled` job nodes,
so none of their computation or guards ran. No dispatch capability was minted,
and the acquisition plus 16-unit formal campaign never started. The only
provider artifact was one-day q1 transport object `9717884587`, named
`q1-simulator-pre-replay-handoff`, with 621,877,534 bytes and provider digest
`sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`.
It was explicitly `NON-EVIDENCE`. Those facts are final and remain reportable
only as provenance and a stop decision.

The exact q1 stage ledger was nevertheless permitted for engineering diagnosis.
It showed that repeated deterministic query-lifecycle validation, rather than
archive writing, dominated the failed operational path. The bounded repair was
implemented in commits `e204bb90fcfce0b2e9f3082fc2849c2de41e3b4b` and
`5b5d1468bfe3cac324819747388a2c897101f2bb`, then merged through PR #42 as
`4f328afc079b328c31f2e0790cb65cdf96fcc1d7`. Both ChatGPT Pro and ZCode
GLM-5.3 Max returned `PASS` with P0/P1/P2 = `0/0/0` on the hardening successor;
push and pull-request CI each passed 2,416 tests with two expected
runner-dependent skips. Exact-merge main CI `33277015441` subsequently passed
the same 2,416 tests with two expected skips and produced R0 artifact
`9722079150`, provider digest
`sha256:a25a1f33ad47e54ce757b5084fa21896e48615991160546a730f876bc9127a12`.
These CI results support implementation provenance only; none is experimental
evidence.

This repair was outcome-informed: the predecessor failure and non-evidence
timing breakdown influenced which implementation work was attempted. Therefore
the repaired system cannot be substituted into the old confirmatory lineage.
The study defined here is an explicitly post-failure follow-up with fresh seeds,
new run and artifact identities, new source/evidence snapshots, and a new
one-shot qualification. The paper must disclose that chronology.

## 2. Frozen research question and contribution boundary

The question is unchanged:

> Under identical causal update streams, publication boundaries, query
> schedules, public parameters, initial states, and complete accounting, how do
> three fixed maintenance mechanisms characterize the bounded-scale cost of
> version-bound mutable CSSC-based homomorphic SpMV?

The three mechanisms remain exactly:

1. `periodic-repack/windows=1`;
2. `padding-reuse`; and
3. `packed-coo-cloud-segmented-delta/segment-width=128`.

The protocol contribution remains the same four-condition combination:
version-bound mutable CSSC publication; true global-column query
reorganization; private `RowMap`-aware multi-component reconstruction; and
overlap-scoped canceling masks with durable no-reuse bindings. The follow-up
adds no novelty claim. In particular, it claims neither a new HE primitive nor
formal security, performance superiority, a universal best strategy, a
before/after optimization speedup, or first/only/global novelty.

## 3. Exact inherited scientific contract

The scientific base is the predecessor plan at
`config/route-a-publication-plan.json`, SHA-256
`ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c`,
and its preregistration, SHA-256
`6b53a73c6973a4be53d195f5d9407e7e023ae3a5617bce57b4a40a7033a32f79`.
All strategy semantics, roles, matrix dimensions, OpenFHE parameters, causal
windowing, rho values, measurement classes, artifact admission rules,
independent replay, ordered-event transformation, native case shape, formal
dispatch order, analysis restrictions, and resource budgets are inherited
without relaxation.

The machine-readable delta is
`config/followup-performance-study.json`. Only these scientific values change:

| Domain | Closed predecessor | Follow-up |
|---|---:|---:|
| Qualification seed | `20260821` | `20260901` |
| Formal synthetic seeds | `20260822..20260824` | `20260902..20260904` |
| Native snapshot seed (`/openfhe/snapshot/formal_seed`) | `20260822` | `20260902` |
| Plaintext context seed (`/plaintext_context_cells/0/seed`) | `20260822` | `20260902` |
| Deterministic query-vector seed | `2026082302` | `2026090202` |

Applying exactly those five replacements to the exact predecessor plan, then
serializing finite JSON with lexicographically sorted keys, compact separators,
ASCII escaping, and one terminal LF, gives SHA-256
`0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e`.
This digest is a machine-checkable **predecessor comparison baseline**, not an
executable plan, authority record, lineage, or outer evidence namespace. The
machine JSON classifies every one of the predecessor plan's 21 top-level keys.
Its predecessor `authority`, `lineage`, and plan `schema_version` are ancestry
only. All outcome-bearing scientific, resource, timing, evidence-count, and
admission semantics remain exact except the five seed replacements; the new
outer identity layer below has explicit precedence and cannot change an inner
scientific payload.

The values are consecutive date-coded integers frozen here before any generator
or evaluator is run with them. Until an exact authorized use, Stage 2 may only
parse, compare, and hash-bind them as opaque scalars. Tests and smokes must use
explicit disjoint sentinel seeds and may retain no trace, vector, snapshot, or
cell derived from a registered study seed. Because qualification itself executes
query-bearing cells, qualification seed `20260901` and the global query-vector
seed `2026090202` may first enter their respective workload and query-vector
generators only inside the sole qualification. After qualification GO, formal
workload/snapshot/plaintext-context seeds `20260902..20260904` may first enter
their builders/evaluators only in their exact formal units. The same already
observed global query-vector seed `2026090202` may then re-enter the generator
only for each authorized formal domain; each domain produces and binds its own
vector bytes, so qualification vector bytes cannot be substituted into a
different formal domain. Any earlier use invalidates the entire study ID: it
cannot be repaired by substituting a seed. The SNAP a2q object,
mapping/partition transform, T1/T2 semantics, and ordered-event matrix remain
unchanged because the predecessor formal acquisition never ran.

The inner scientific payloads retain their exact inherited schema identifiers,
reserved-column namespace, canonical byte domains, and source paths. Those
legacy `route-a` strings describe shared scientific payload semantics and mint
no authority. Each new object is instead wrapped by
`dynamic-cssc-followup-performance-evidence-envelope-v1`, binding the study,
Stage-1 plan, materialized baseline, S1/S2 source identities, unit/attempt,
inner role/digest, and false authority. Workflows, artifacts, registration
anchors, Behavior Sets, provider records, and controller capabilities use the
outer root `dynamic-cssc-followup-performance-v1`. Any predecessor object lacks
that exact outer envelope and rejects before inner decoding or execution. The
only operative controller is
`followup-performance-live-dispatch-controller-v1`; all controller/lineage
identities embedded in the predecessor baseline are nonoperative ancestry.

## 4. Outcome-informed boundary

The predecessor q1 stage ledger, the external stop time, and bounded local
diagnostics may justify the existence and implementation shape of the repair.
They may not be included in a strategy table, pooled with follow-up observations,
used as a before/after denominator, or cited as evidence that the new
qualification will pass. The local 512-query timings are implementation
diagnostics only.

The repair applies to shared lifecycle validation infrastructure, but its
observed feasibility and relative effect were not outcome-blind. Accordingly:

- the follow-up is described as post-failure and outcome-informed;
- all performance sentences require fresh, admitted follow-up artifacts;
- no claim says the original experiment succeeded after repair; and
- no analysis compares the closed partial q1 with the new campaign.

## 5. One-shot resource qualification

There is exactly one follow-up qualification attempt. It uses scale M, seed
`20260901`, the mixed insert/delete/modify workload, and rho values
`{0.01, 0.1, 1, 10}`. Its six-job serial shape, native planning probe, artifact
handoffs, guards, and controller decision function are inherited exactly; the
operative controller identity and program paths are the new follow-up-only
values frozen in Section 3, never the predecessor controller.

The q1-start through q5-completion computational path must be at most 45.00
minutes. The q1-start through q6-completion path must be at most 55.00 minutes.
These are the predecessor thresholds; neither is relaxed. Every qualification
artifact is permanently non-evidence.

Any timeout, correctness failure, provider failure outside the frozen handling
rule, identity mismatch, missing/extra artifact, guard failure, or deadline miss
produces a terminal follow-up NO-GO. The qualification cannot be rerun. Failure
authorizes neither a threshold change nor a second seed.

Qualification success is necessary but not sufficient for formal dispatch. A
fresh external controller must also verify the new Stage-1 plan, exact Stage-2
source S1, data-only S2 anchor, closed Behavior Sets, CI, registration, every
q1--q6 identity and timestamp, a hash-locked Linux/OpenFHE resource validation,
the outer-envelope and predecessor-rejection tests, and a non-authorizing q6
record before returning one nonserialized, single-use formal-dispatch
capability.

The authority path has two distinct, noninterchangeable capability types. CI,
PRE-S1 validation, descriptive registration, the data-only S2 anchor, and
independent review are authority-false **control workflows**, not qualification
or formal experiment dispatches; they consume no experiment capability. After
all Stage-2 prerequisites have terminally passed, a fresh external controller
read may mint exactly one nonserialized
`dynamic-cssc-followup-performance-qualification-dispatch-capability-v1`, bound
to the exact study, Stage-1 plan, S1, S2, seed, workload, rho set, and attempt
ordinal. Atomic consumption of that capability authorizes only the sole exact
qualification. It cannot authorize a formal unit or any predecessor run.

Only after q1--q6 all succeed inside both frozen deadlines and a fresh provider
and resource reread passes may the external controller mint the different
`dynamic-cssc-followup-performance-formal-dispatch-capability-v1`. It is bound
to the successful qualification identity and complete formal matrix, and its
single atomic consumption only opens the strictly serial formal campaign. It
cannot authorize a qualification rerun or second campaign. Both capability
types are live-memory decisions: neither is serialized, uploaded, or installed
in a registration anchor. Wrong-type, replayed, consumed, wrong-study,
wrong-S1/S2, wrong-attempt, and every predecessor capability reject before any
provider dispatch. Qualification non-success reaches terminal follow-up NO-GO
without a formal capability.

## 6. Formal matrix and budgets

If and only if the qualification closes GO, the formal campaign inherits the
strictly serial predecessor matrix:

- six synthetic shards: S and M for each of three fresh formal seeds;
- four ordered-event shards: two SNAP partitions times T1/T2;
- six native OpenFHE cases: S and M for each fixed strategy;
- one acquisition transform before formal shards; and
- terminal admission, aggregate, and isolated analysis after all 17
  pre-aggregate formal artifacts pass.

Synthetic rho values `0.01`, `0.1`, and `1` execute completely. Rho `10` is
only the previously registered exact query-linear projection and receives no
measured wall-time, RSS, scratch, or native-latency value. The six native cases
retain one discarded warm-up, three fresh-key producer repetitions, exact
retained-package replay of all three, and one guard.

The 12.00-hour acceptance budget, per-unit reservations, 60-minute universal
ceiling, 2.5-hour native segment, and at-most-one provider-classified whole-unit
replacement across the 17 eligible units remain unchanged. Overshoot fails; it
does not borrow from another segment or relax the plan.

## 7. Measurements and analysis

Every admitted cell retains the predecessor separation:

- directly measured Python producer state-transition/result-assembly time,
  replay time, peak RSS, and controlled scratch;
- exactly counted events, windows, queries, primitive operations, and object
  multiplicities;
- upper-bound projected non-native cryptographic bytes from the frozen formula;
- exact rho-10 rescaling only for registered linear quantities; and
- native-measured OpenFHE latency and exact retained-package bytes only in the
  six native cases.

The output is a bounded-scale descriptive characterization. All native raw
repetitions, medians, and ranges are reported. No p-value, inferential confidence
interval, fitted scaling law, performance-superiority claim, universal ranking,
or cross-machine generalization is permitted. Strategy comparisons remain
paired by identical event/query inputs but technical repetitions and fixed seeds
are not described as independent population samples.

Only independently replayed, guarded, terminally admitted follow-up artifacts
may support an empirical performance or result sentence. CI, unit tests,
registration, qualification, external-model review, and predecessor artifacts
do not substitute for a formal result. Design statements, implementation
provenance, and factual qualification/formal GO/NO-GO chronology instead follow
their separate claim-ledger evidence rules.

## 8. Stage-2 implementation boundary

After Stage-1 review, implementation may only:

1. support opaque binding of the new frozen seed domain without executing a
   registered seed before its authorized run;
2. create the closed study-plan schema and exact semantic-delta validator at
   `schemas/followup-performance-study-v1.schema.json`;
3. create the follow-up-only **outer** envelope, workflows, controller
   identities, artifact names, registration anchors, and Behavior Sets while
   leaving inherited inner scientific schemas and canonical domains unchanged;
4. update identity fixtures using only disjoint sentinel seeds; and
5. reject all predecessor runs, artifacts, anchors, and capabilities.

After this Stage-1 freeze it may not change strategy semantics, optimize query
lifecycle performance, alter runner image/dependencies/build/cache/parallelism,
setup or handoff topology, time accounting, the matrix/rho set, any resource
gate, the estimand/claim set, or an outcome-dependent seed, workload, snapshot,
or source. A needed change in one of those categories invalidates this Stage-1
object and requires a new preregistration review before implementation.

If this follow-up closes NO-GO, this publication lineage ends. A third study
with the same estimand and resource thresholds may not be preregistered, run, or
used to support this paper. Any genuinely independent future study must list the
complete prior NO-GO chain, disclose every outcome-informed delta, and establish
an independently motivated question rather than tune toward this gate.

## 9. Publication disposition

If the follow-up campaign is admitted, the anonymous manuscript may add its
fresh results and must preserve the predecessor failure as a separate disclosed
lineage. If qualification or formal admission fails, the current Route C
methods/evidence-boundary manuscript remains the only submission candidate and
the follow-up contributes no performance result.

The exact Stage-1 set is the machine plan, this preregistration, the follow-up
claim ledger, the bounded novelty-inheritance review, and detached
`config/followup-performance-stage1-manifest.json`, whose path/hash records bind
the four substantive files without self-reference. The manifest orders paths by
binary UTF-8, records exact SHA-256, byte count, and LF count for each object,
and hashes the canonical compact sorted-key JSON serialization of its `objects`
array plus one terminal LF. The manifest itself is bound later by the immutable
Stage-1 Git tree and identical external-review packet, avoiding a recursive
self-digest. These objects mint no authority. Their next gate is exact-file
pre-implementation review by the configured independent reviewers, followed by
an immutable Stage-1 commit if and only if no P0/P1 finding remains.
