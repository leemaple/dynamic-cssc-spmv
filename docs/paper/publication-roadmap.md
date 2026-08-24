# Publication Roadmap

> **Status date:** 2026-08-24 (Asia/Shanghai)
>
> **Target A:** *Journal of Cryptographic Engineering*
>
> **Target B:** *The Journal of Supercomputing*
>
> **Fallback:** IEEE Access for a strong reproducible boundary result

This roadmap orders the remaining work needed for a defensible submission. It
does not authorize a workflow run or a claim by itself. Every empirical stage
must be executed from a clean, reviewed experiment-source commit and must
retain its exact source SHA, run ID, artifact digest, raw records, and
checksums. Because provider artifact digests exist only after execution, a
later clean evidence-freeze/analysis commit is expected. It may consume the
older artifact only through the ADR 0010 role-specific Behavior Set comparison;
it must not relabel the later commit as the experiment source or require an
impossible self-referential SHA.

One publication-scale campaign uses one Publication Evidence Lineage. Its
coverage-complete, outcome-blind feasibility pilot and resulting resource
amendment occur before the lineage begins. All behavior-bearing code, workflows,
policies, preregistration terms, sampling/decision rules, and analyzers are then
frozen at a clean pre-anchor `S1`. The separate Day-1 registration-anchor change
is the Terminal Registration Freeze and the lineage's last behavior-freeze
action. Later commits may only append closed, repository-owned data-only anchors
at the shared compatibility-anchor path, the one Day-2 pre-dispatch
profile-anchor path authorized by ADR 0011, and the Day-2 post-run
calibration-anchor path, without deleting or changing any earlier anchor record.
The Day-1 registration anchor and historical strong anchor are frozen before or
at this boundary. The profile schema and producer are frozen there, but its
binding is installed in one data-only commit after formal Day1A and before any
held-out or Day-2 outcome.

## 1. Current evidence boundary

At merged main `fcb00e0d7f111f3ab5003c111b124df83ae11813`:

- R0 passed in run `32580113632` with 750 tests;
- the Phase 2 whole-query witness passed in run `32581653504`; and
- the Phase 2 artifact SHA-256 is
  `c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`.

That evidence establishes one pinned correctness fixture. It does not establish
strong-candidate registration, complete accounting, mixed-circuit parameter
safety, performance, security, or the publication verdict.

## 2. Dependency-ordered execution plan

### Phase A — complete the strong reference contract

Deliverables:

1. freeze the `c=128`, never-fold, no-compaction strong policy;
2. emit a canonical role-aware catalog with 14 fixed candidates, 13 selectable
   references, and one client-lane ablation;
3. account exact query DAG nodes, relinearizations, CI patch/full-sync entries,
   random F1-M ciphertexts, encrypted-zero dummies, and exact rotation indices;
4. validate a report schema with 14 fixed records, 13 tuning aggregates, and two
   aliases; and
5. keep the production registry fail-closed until commit-bound accounting and
   policy evidence exist.

Completing Phase A does not by itself authorize immediate installation of the
Day-1 registration anchor. Phase A must first join the remaining workflow,
preregistration, resource, and analysis behavior in the clean pre-anchor `S1`
described below. The later terminal registration commit and `S1` are recorded
separately, and a repository-generated compatibility receipt must prove exact
equality of every role-specific behavior path, entry mode/type, and Git blob
while confining later changes to monotonic additions at the frozen data-only
paths. Correctness evidence alone is never a transferable registration
authority.

### Phase B — causal count evidence (Day 1A)

The runner must:

- advance all 14 independent persistent states through identical windows;
- tune only the 13 reference candidates on the chronological tuning prefix;
- emit the client-lane candidate only as an ablation;
- exclude the ablation from both selection and the held-out oracle;
- bind exact rotation inventory, role sets, serialized reports, traces, replay
  receipts, checksums, and source SHA; and
- stay `gate_eligible=false` and `complete_cost_claim_allowed=false`.

Day 1A is count evidence and pipeline validation. It does not choose the paper's
final winner because measured primitive costs and byte-accurate bandwidth costs
do not yet exist.

The complete-suite aggregator emits a canonical fixed-record count bundle, an
exact-index rotation inventory, and a narrowly scoped Day1A receipt. The receipt
authorizes only synthetic causal count evidence and independently compares the
suite's slot domain with the publication manifest. Historical
`config/experiment_plan.json` version 0.2.0 uses a 512-by-512 matrix, 2048
effective slots, and 128-row partitions, so its receipt must set
`day2_direct_key_plan_authorized=false`. The separately frozen formal
`config/experiment_plan_publication.json` version 0.3.0 and
`.github/workflows/day1a-publication-cost-model.yml` use the matching
4096-by-8193, 4096-effective-slot, 4096-row-partition publication domain and are
the sole route eligible to set `day2_direct_key_plan_authorized=true`. Neither
route authorizes a complete cost, performance, paper-verdict, or security claim.

### Phase C — measured primitive and communication model (P0b / Day 2)

Generate keys only for the exact inventory from Day 1A. Measure every priced primitive
used by an admitted DAG, including the frozen composite
`EvalMult-with-relinearization`, direct rotation indices or their declared decomposition,
plaintext masks, ciphertext additions, encryption/decryption, and serialization. Record
the exact relinearization count and require it to equal ciphertext multiplications, but do
not price it a second time outside the composite operation. Store exactly 14
complete, outcome-independent whole measurement blocks with no optional
stopping. Precede them with exactly three complete, archived warm-up blocks;
each covers the same profiles/cases and is structurally and arithmetically
validated, but none contributes to the calibrated projection. Each measurement
block contains all 14 primitives in the deterministic
SHAKE256/Fisher--Yates order derived from seed `2026082302`, its block ordinal,
and a calibration-only domain. Store every raw case timing, warm-up decision,
host/compiler/OpenFHE identity, CPU affinity, and uncertainty summary.
The closed publication vocabulary is `client_merge`, `client_reorder_element`,
`decrypt`, `deserialize_ciphertext`, `encode`, `encrypt`,
`eval_add_ciphertext`, `eval_mult_plaintext_mask`,
`eval_mult_with_relinearization`, `eval_rotate`, `mask_map_element`,
`mask_random_element`, `query_vector_pack`, and `serialize_ciphertext`.
Use the per-primitive median of the 14 raw block values as the point estimator;
the analyzer rejects arbitrary names, precomputed summaries, missing/extra
blocks, and means. Per-operation seconds are serialized as a unique canonical
exact rational (minimal terminating decimal, otherwise reduced `n/d`) so an
otherwise valid operation count cannot make the evidence pipeline undefined.

Each block measures the complete Day1A-authorized exact rotation-index/profile
set. `eval_rotate` and any other multi-profile primitive project to the
preregistered per-block maximum per-operation time over the complete admitted
case set; this is a conservative upper envelope, not a claim that all calls
have the same realized latency.

Before designating the clean pre-anchor `S1`, freeze the exact profile schema,
three-warm-up rule, rotation-plan derivation, producer, validator, and all Day-2
and analyzer behavior. After `S1` registration evidence is installed as the
Terminal Registration Freeze and the selected formal Day1A receipt/inventory is
monotonically anchored in one shared compatibility record with
`role=day1-registration`, experiment source equal to the Terminal Registration
Freeze, and artifact digest equal to the selected receipt, install the canonical
profile-policy binding in exactly one later reviewed data-only commit. It binds
only already frozen artifact identities,
contains no future source SHA, and must precede every formal Day1B held-out or
Day-2 run. It is not a Day-2 or analyzer Behavior Set member and may never be
removed or retargeted. At dispatch, the zero-argument seam obtains the actual
clean profile-bearing source identity and frozen Day-2 Behavior Set digest from
the hardened verifier, and rejects a nonempty Day-2 post-run anchor set. After
the run, a later evidence-freeze commit adds the v3 archive/raw/profile/
rotation-plan/contract-bindings/projection binding in the separate Day-2
post-run anchor without modifying the profile, validator, or any behavior blob.
Post-run compatibility rejects any Day-2 experiment source that did not already
contain the unique profile.

The existing `day2-microbench.yml` remains a historical isolated probe, not this
publication contract. Its executable can exercise every caller-supplied exact
rotation index and emit outcome-independent raw blocks over the closed
14-primitive vocabulary, but the workflow still consumes the legacy 11-repeat
manifest value and does not consume Day1A's registered key inventory, bind the
fixed host and toolchain, produce the canonical R3 member set, or install either
evidence anchor. Those remaining producer and authority steps must be completed
before any calibration input gains authority.

Within the preregistered protocol-object transaction scope, the complete cost
model must include:

- Client A to Client B column-index synchronization;
- Client B to Cloud query ciphertexts and any key material under the declared
  amortization rule;
- Cloud to Client B result ciphertexts;
- random and encrypted-zero F1-M operands;
- metadata, framing, and version/plan bindings; and
- client reorder and modular merge work.

### Phase D — acquisition and trace freeze

Acquire only after the transform code and acquisition manifest are reviewed.
Run the transform from a clean exact-HEAD checkout with raw inputs and outputs
outside the checkout. Install the downloader environment separately with
`pip install --require-hashes -r requirements-acquisition.txt`; install the
publication-only parser environment with
`pip install --require-hashes -r requirements-publication.txt`. The locked
CPython 3.12.13 transport/parser dependencies, accepted wheel platform tags,
`pyarrow==25.0.1`, and preregistered `America/New_York` TZif SHA-256 are distinct
parts of the acquisition and transform identities.
The repository-owned downloader/CI transaction—not a caller-authored local
manifest—must fetch each exact URL by `GET`, require status 200 and the exact
final URL, reject redirects, require identity/absent content encoding and absent
content range, and bind normalized contract-relevant response headers and the
downloaded bytes to the receipt. Every data object requires one positive exact
`Content-Length`. A terms page may instead record a genuinely absent header as
`null` and use the frozen clean-transfer cap of 2,097,152 bytes; a present header
remains positive, at most the cap, and exact. Only the two exact Stack Overflow
terms URLs use the fixed `curl_cffi==0.16.1` `chrome150` HTTP/2 adapter with the
explicit Mac Chrome 150 user-agent, hash-locked CA/runtime, no ambient proxy, and
no fallback. It is a disclosed fingerprint, not a real-browser claim.
Until that authority exists, local byte/hash validation is descriptive and the
transport receipt must state `runtime_execution_isolation_verified=false`,
`formal_authority_granted=false`, and
`acquisition_network_authority_verified=false`.
Both acquisition and trace publication use the same inode-bound,
descriptor-relative no-replace directory installer. It verifies the exact
staging artifact before installation, rehashes the installed same-inode
directory, rejects identity drift or a destination collision without returning
a success receipt, preserves rejected installation evidence, and binds ordinary
pre-install failure handling to the invocation-owned root inode. Incomplete
staging trees are retained whole under random diagnostic quarantine names; the
producer never recursively unlinks or removes them through reusable pathnames.
This is a running-process atomic namespace guarantee, not a sudden-power-loss
durability claim. The trace-preparation acquisition consumer must reopen and
reverify one descriptor-bound exact-tree snapshot of that acquisition bundle.
The production trace manifest v7 must additionally carry a closed acquisition
binding v2 over the acquisition transaction v3 SHA-256, source-set SHA-256, and
embedded exact central ACQUISITION Behavior Set v2 inventory; TRACE uses Behavior
Set v2. Before its S2
post-run anchor and compatibility receipt are installed and revalidated,
`formal_authority_granted`, `acquisition_network_authority_verified`,
`post_run_anchor_verified`, `evidence_compatibility_verified`, and
`claims_authorized` must all remain `false`.

| Corpus | Frozen role | Required acquisition record |
|---|---|---|
| SNAP Stack Overflow | primary real | the exact three official typed `a2q`, `c2q`, and `c2a` objects, the full reviewed terms-page set, retrieval UTC/final URLs/status/media types/optional validators, byte counts, per-object/page SHA-256, and admitted downloader receipt; the untyped union object is insufficient |
| MediaWiki History Simplewiki 2026-07 | primary real | exact all-history object, locally retained CC0 terms page, retrieval UTC/final URL/status/media type/optional validators, byte counts, local SHA-256 values, and admitted downloader receipt |
| NYC TLC yellow taxi 2022 | primary real | exact 12 Parquet objects plus zone lookup, full reviewed terms-page set (no-fragment fetch URLs plus separate section anchors), retrieval UTC/final URLs/status/media types/optional validators, per-object/page SHA-256, and admitted downloader receipt |
| LDBC SNB Interactive v2 SF30 | auxiliary synthetic | exact snapshot/update objects, spec/release identity, per-object SHA-256 |

For each real dataset, use exactly the first `floor(V/10)` events of its closed,
canonical, chronological schema-valid corpus only to freeze row/column
identities and eligibility. Do not inspect candidate outcomes during acquisition
or the structure-only pilot.

### Phase E — publication experiment (Day 1B)

Primary sampling frame:

```text
3 real datasets × 2 semantics × 5 disjoint source partitions = 30 paired traces
```

Each unit uses the fixed 4096-by-8193 domain, a group-atomic microbatch threshold
of 64 visible SETs (at most 65 for a completing two-SET T2 group), coefficient
bound 7, 131,072 accepted raw events, a continuous 10/30/60 state history,
freshness 0.1 s and 1.0 s, primary bandwidth 1000 Mb/s, and the nine frozen
query/update ratios. Each paired unit also binds one deterministic length-8193
ternary query vector generated from seed `2026082302`, with coordinates 0 and
8192 forced to +1 and -1; it is reused across all cells and candidates in that
unit. Observed targets occupy the prefix-ranked column identities and every
remaining coordinate is an explicit semantic-zero reserved column. Reserved
columns remain in the length-8193 vector and in full-domain byte/cryptographic
accounting; occupancy is reported but is not a pass threshold. A mapping with
zero observed target identities remains ineligible. The sole confirmatory
family is T2 at 0.1 s; T1 and the
1.0 s panels are prespecified secondary robustness analyses and cannot
authorize, replace, or rescue the headline. T2 uses a 32,768-event window. A common smaller trace tier
is not authorized: 65,536 events would leave the entire tuning phase before the
first T2 expiry. If the 131,072-event target is infeasible in a prefix-only
pilot, held-out execution stops until a reviewed amendment freezes a common tier
with `floor(N/10) <= 32,768 < floor(4N/10)`.

Before held-out dispatch, run a coverage-complete, outcome-blind structure-pilot
campaign over the three real datasets × `{T1,T2}` × partitions
`{0,1,2,3,4}`. For each dataset, let `V` be the number of events in its closed,
canonical, chronological schema-valid corpus. The pilot mapping/transform input
is exactly ordinals `[0, floor(V/10))`. A preparatory pass may scan the suffix
only to establish the schema-valid count `V` and validate canonical order;
mapping, T1/T2 transformation, and serialization code must never consume a
suffix record.

The pilot exists only to validate parser/schema and all 30 structural paths,
establish aggregate mapping/cardinality and eligibility facts, observe
completion and parser/adapter error codes, measure elapsed time, observe the
process-lifetime resident-memory high-water and live-coordinate cardinality,
record runtime health, and verify prefix-derived structural serialization
completeness. Canonical events stream through one per-dataset disk-backed
SQLite store that is closed and deleted before the next dataset; mapping is
disk-aggregated and transformation uses a transient counting/round-trip sink,
so prefix events, transition records, and serialized chunks are not retained.
Only aggregate serialization counts and bytes may enter the report; no
transition payload artifact may be retained. Its
output directory contains exactly two regular files:
`structure-pilot-report.json` and `checksums.sha256`, with the latter binding
only the former. No raw identifier or mapping table may be emitted.

Resource-field interpretation is closed.
`process_high_water_rss_bytes_before_report_install` is the process-lifetime
`ru_maxrss` high-water sampled after final input/source revalidation and
scratch-workspace teardown, immediately before report installation.
`analysis_wall_clock_ns` begins immediately before the exclusive scratch claim
and ends at that checkpoint. Report validation/serialization, checksum
construction, staging writes and `fsync`, and atomic installation are excluded
from both fields. Dataset and cell RSS fields remain cumulative checkpoints,
not per-unit increments.
`canonical_store_bytes_after_index` is the main SQLite file size at the
post-index checkpoint. It excludes source snapshots, SQLite temp/query files,
filesystem allocation, and other transient scratch; it is not a scratch peak
and cannot by itself justify a scratch cap.
`prefix_transition_serialized_bytes` is cumulative transient canonical byte
volume, not retained output. The report binds each dataset to verified
acquisition transaction, source-set, central acquisition Behavior Set, and
derived binding digests, and records the SQLite library version plus the
verified `temp_store=FILE` policy. Production uses one workflow-fixed,
pre-provisioned external scratch root: absolute/canonical, current-user-owned,
mode `0700`, writable, empty and exclusively claimed, and disjoint from the
repository, acquisition, and output trees. `PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT`,
`TMPDIR`, `SQLITE_TMPDIR`, and Python's process-start temporary-directory cache
must bind the same path. The core pins the directory device/inode, creates a
unique child workspace, places the canonical stores there, and requires clean
teardown. Cleanup removes only matching store/source-snapshot inodes and
matching empty directories; it preserves replacements or foreign contents and
enters `HOLD`. Stale contents, retargeting, or competing ownership is a global
no-write `HOLD`. The report exposes only the closed scratch policy and the
path/device/inode-bound root identity, not a scratch-occupancy measurement.

SQLite must be at least 3.35, expose exactly the frozen `TEMP_STORE=1` compile
option, and read back `temp_store=FILE`. The environment binding is a requested-location policy,
not proof of the effective SQLite physical temporary directory or byte
occupancy; SQLite may retain small temporary structures in its page cache.
Unsupported SQLite is a global no-write `HOLD`. Closed expected scan failures
emit `parser-failed` or
`canonical-scan-failed` plus ten blocked cells; authority, source, safety, or
binding drift remains a global no-write `HOLD`.

The pilot must not import the publication schedule or Day1B producer, dispatch
a candidate or real publication run, or compute, serialize, log, or display any
candidate identity, operation/communication cost, effect, rank, Pareto or
dominance result, rho/freshness value, query vector/schedule/count/result, or
held-out/confirmatory classification. It creates no evidence role, authority,
anchor, compatibility receipt, or publication artifact. Both files are
pre-freeze, permanently non-admissible, and non-promotable.

At `S1`, the existing TRACE Behavior Set freezes the pilot's execution-bearing
module, CLI, and workflow paths. This detects later drift in the mechanism that
informed the resource amendment; it does not give the pilot a new
`EvidenceRole`, attest its output, or make either output file admissible.

After inspecting only those allowed fields, commit an outcome-independent
amendment freezing the exact wall-clock, resident-memory, scratch/output-byte,
shard, concurrency, preemption, and retry limits. The pilot and amendment occur
before the clean pre-anchor `S1`, before the Terminal Registration Freeze, and
before the Publication Evidence Lineage begins. Candidate failures receive no
selective retry; a proven infrastructure preemption invalidates and permits at
most one identical whole-shard rerun.

Because the current pilot reports a post-index store checkpoint rather than a
controlled transient-scratch high-water, the amendment may not freeze a
scratch cap from that field alone. It must add a separately reviewed
controlled-scratch measurement or leave held-out dispatch on `HOLD`.

The preparatory Day1B worker receipt v2 now preserves one such measurement for
the controller's exact anonymous registry/spool pair: the maximum checkpointed
sum of both inode sizes, updated before the cap comparison and retained on an
over-cap failure. It is deliberately separate from candidate-execution
scratch, which remains the launcher-owned `controller_observed_peak_scratch_bytes`
observation. The controller measurement alone does not verify production
scratch-root creation isolation, does not set either numeric limit, and does
not authorize dispatch.

The next-path `dynamic-cssc-publication-day1b-resource-amendment-v1` decoder is
now defined as a resource-only seam. It accepts only canonical frozen limits,
measurement-method tokens, no-retry invariants, pilot/review digests, and a
previously reviewed schema-source Git/Behavior-inventory binding; authority and
worker/runtime identity are structurally absent. Its non-self-referential
semantic digest and immutable decoded record do not install values or lift the
repository `HOLD`. A real amendment file still requires its own reviewed
pre-`S1` path plus a DAY1B Behavior Set version bump.

The final selector is recomputed from measured compute costs plus serialized
communication at the primary bandwidth. Day 1A's normalized proxy selector is
not carried forward as the publication decision. The primary held-out contrast
is this tuning-selected procedure versus
`periodic-repack/windows=1` (recompress every window), in the sole T2-at-0.1-s
confirmatory family. All four semantics-by-freshness panels are still reported.

Implementation checkpoint: the first-wave per-unit producer now has a tested
closed path for 18 cells, 252 singular candidate-by-cell worker receipts, 486
physical records, schedule-v2 RLE consumption, canonical serialized-object
ledgers, and per-candidate-by-cell controller resource observations. This is E1
implementation evidence only. It cannot dispatch until the trace and catalog
authorities, repository execution adapter, and outcome-blind resource policy
are installed, and it is not a 30-unit publication artifact.

The repository now also carries a PRE-S1 preparatory DAY1B source inventory,
closed empirical-null/authority-false `PENDING-FREEZE` resource-policy document, and a
manual no-input validation workflow. These freeze the current validator,
protocol, scheduling, provenance, and artifact-installation source surface; they
do not freeze empirical limits, authorize dispatch, publish an artifact, or
grant a claim. A controller-owned pre-admission OpenFHE runtime now consumes the
single-use ordinary-query authorization immediately before launch, owns and
removes exclusive private scratch, binds the runner/source/compiler identity,
verifies result and serialized-object bytes, and records resource observations
with authority fields false. The production two-path seam verifies this source
and then stops on the pending policy before catalog, trace, anchor, worker, or
output access. The workflow performs only hash-locked source-contract tests,
static validation, and a real non-authorizing runtime smoke; it neither invokes
the producer nor fetches or uploads publication data.

The sole numeric exception in that pending document is the already
preregistered, non-empirical protocol invariant
`protocol_invariants.candidate_retry_count=0`, paired with
`selective_candidate_retry_allowed=false`. It does not fill an empirical
resource limit or authorize execution; every empirical numeric and method
choice remains `null`.

The remaining Day1B `HOLD` set is explicit: an outcome-blind resource amendment,
a controlled-scratch high-water and isolation method, linked-library/build
admission, a production candidate-cell worker adapter that composes the verified
OpenFHE runtime with the Day1B controller, the TRACE post-run anchor, and the
Day-1 registration anchor.
Source inventory is not dispatch authority. Any
future file containing actual runner identities or frozen policy values must be
introduced by a reviewed pre-S1 path/schema and DAY1B Behavior Set version bump,
then re-frozen before the Terminal Registration Freeze; it cannot be spliced
into this preparatory schema after outcomes.

### Phase F — statistics, mixed-circuit safety, and R4

- replay the same 30 units with the frozen measured cost model;
- report every trace-level paired effect, failures, and infeasible candidates;
- report all 15 fixed-corpus effects and the median/IQR at every rho, plus a
  10,000-resample dataset-stratified source-partition weighting interval that is
  explicitly descriptive rather than a confidence interval;
- compute no sign test, p-value, Holm adjustment, or population-level
  inference from the deterministic source partitions;
- require all 15 effects to be strictly positive, at least 15% paired-median
  improvement, and all-unit non-domination at two adjacent prespecified rho
  grid points in the sole confirmatory family;
- resample one shared sequence of Day 2 whole-block ordinals in 10,000
  calibration replicates, preserving cross-primitive covariance, reselect the
  tuning winner, and recompute every fixed-unit effect and Pareto relation;
  withhold the headline unless every replicate exactly preserves the
  positivity/threshold/non-domination/gate classifications and adjacent-pair
  set;
- run the worst admitted mixed circuit and record decryption/noise evidence; and
- execute R4 on the qualifying adjacent grid points, or narrow the manuscript explicitly to
  measured-component evidence.

A standalone analysis-isolation runner now has tested fresh-checkout,
exact-interpreter, import-origin, lock-identity, source-stability, and atomic
installation checks. Its inner on-disk receipt remains descriptive: central
post-run admission is still required, and no statistics artifact is rewritten
to manufacture runtime authority. `ANALYZER` has no post-run compatibility
phase; its authority exists only for the exact analysis-source identity admitted
by the isolated same-run execution.

### Phase G — manuscript and release

Populate a result sentence only after its claim-ledger row points to an accepted
artifact. Produce the final figures from raw records, run independent Spec and
Standards reviews, perform an adversarial claim audit, archive code/data or a
license-safe reproduce-by-download path, and record the selected journal's AI
disclosure, data-availability statement, and artifact DOI.

## 3. Stop rules

The headline performance claim stops if any of the following is true:

- the role-aware complete reference set or accounting proof is unavailable;
- a required compute, communication, dummy, key, metadata, or client cost is
  unpriced;
- the qualifying adjacent grid points disappear after measurement;
- the effect appears only at one ratio, one source, one partition, or outside
  the sole T2-at-0.1-s confirmatory family;
- the tuning-selected procedure fails the exact held-out finite-corpus decision
  rule;
- correctness, replay, provenance, checksum, mixed-circuit, or R4 validation
  fails; or
- an exclusion or threshold would need to change after held-out inspection.

The allowed fallback is a benchmark/methodology and boundary-characterization
paper. The disallowed fallback is outcome-dependent retuning.

## 4. Immediate next checkpoint

Do not dispatch Day 1 or Day 2 from the current working tree. Execute the next
checkpoint in this order:

1. finish and review the remaining acquisition, trace, registration, Day-1,
   Day-2, resource-observation, and analysis behavior; run the complete
   short-test/format/provenance gates; commit only the intended files; and obtain
   exact-head CI evidence;
2. from a clean reviewed preparatory commit, run only the exact
   `3 × 2 × 5` structure pilot over each corpus's first `floor(V/10)`
   canonical schema-valid events; inspect only its allowed structural, health,
   resource, error, and aggregate prefix-serialization fields; retain only
   `structure-pilot-report.json` plus `checksums.sha256`; and commit the reviewed
   outcome-independent resource/preregistration amendment;
3. incorporate that amendment, freeze every behavior-bearing file and decision
   rule, rerun all gates, and designate the resulting clean exact-head commit as
   the pre-anchor `S1` for a new Publication Evidence Lineage;
4. generate the Day-1 registration evidence against that exact `S1`, then install
   its repository-owned registration anchor in one separate reviewed commit as
   the Terminal Registration Freeze; and
5. run formal publication-domain Day1A only after the registration history
   revalidates, monotonically anchor the selected receipt in a distinct
   `role=day1-registration` compatibility commit, and install the mechanically
   derived Day-2 profile binding in one later profile-only commit;
6. verify that unique profile installation and the still-empty Day-2 post-run
   anchor before any formal Day1B held-out or Day-2 dispatch; and
7. only then may later stages dispatch and monotonically append their closed
   post-run data anchors. They may neither delete nor alter an earlier record.

If anchor installation is wrong, an anchor must be withdrawn, or any behavior,
workflow, policy, preregistration, or analysis rule must change, abandon that
lineage. Start a fresh branch from its pre-anchor `S1`, apply and review the
change, establish a new `S1`, and regenerate every affected artifact; removing
and re-adding an anchor in the same lineage is not recovery. The existing
untracked `uv.lock` is user-owned and is excluded unless a separate reviewed
dependency decision explicitly adopts it.
