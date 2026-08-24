# Publication Experiment Preregistration Draft

> **Status:** DRAFT — no held-out publication result has been inspected.
>
> This file separates decisions that are already fixed by the protocol from
> decisions that must be frozen before the first publication-scale run. A field
> marked `PENDING-FREEZE` is not an invitation to choose it after seeing results.
> It must be resolved, reviewed, and committed before generating the held-out
> evidence bundle.

## 1. Paper lane and non-claims

The target is a systems/methodology and empirical-characterization paper about
version-consistent maintenance around the published static CSSC representation.
It is not positioned as a new cryptographic primitive, a formal-security paper,
or a claim of the first encrypted sparse matrix--vector multiplication system.
The primary submission target is the *Journal of Cryptographic Engineering*;
the performance-led backup is *The Journal of Supercomputing*. IEEE Access is
the broad continuous-publication fallback, while the *International Journal of
Information Security* is considered only if the leakage and threat analysis
becomes a co-equal contribution.

The initial submission package is frozen to a regular *Journal of
Cryptographic Engineering* article using the Springer Nature LaTeX template in
the journal's recommended `[iicol]` mode, with editable sources and a compiled
PDF, a 150--250-word abstract, 4--6 keywords, numeric citations, a data-
availability statement, and the required declarations. The official author
instructions checked on 2026-08-23 state no regular-article page or word cap;
the working manuscript target is at most 18 two-column pages before
supplementary material. The journal is hybrid. The default budget assumption is
the subscription route, for which the publisher states that no APC applies;
open access may be selected after acceptance only with author/funder approval
and does not alter any experiment or analysis decision. The publisher's current
optional open-access price is recorded in the venue research note rather than
treated as a fixed future charge.

The working contribution set is:

1. a publication/version/freshness contract that binds mutable logical state to
   query-visible CSSC components;
2. a RowMap-sensitive multi-component `OutputPlan` with explicit overlap,
   concatenation, and implicit-zero semantics;
3. CSSC-specific overlap-only F1-M integration with persistent no-reuse
   bindings;
4. an opaque-identifier fixed-segment strong-delta path and a fail-closed whole-query
   execution bundle; and
5. a causal evaluation protocol with independent persistent candidate states,
   tuning-prefix-only selection, and commit-bound evidence.

The manuscript must not claim formal security, malicious security, universal or
state-of-the-art superiority, author-code reproduction, complete cost, or
end-to-end performance unless a later gate explicitly authorizes that wording.

## 2. Research questions

- **RQ1 — Semantic correctness.** Do all admitted maintenance paths preserve the
  exact logical matrix and version-bound query result across ordered publication
  windows, including tombstone reuse, overflow, global column identifiers, and
  multi-component reconstruction?
- **RQ2 — Update/query trade-off.** At fixed freshness, where do admitted
  maintenance policies lie on the held-out update-communication versus
  query-cost frontier?
- **RQ3 — Calibration stability.** Do per-grid-point Pareto classifications predicted by typed
  operation counts survive measured OpenFHE calibration and the complete
  communication model?
- **RQ4 — Robustness.** Are the direction and practically meaningful magnitude
  of paired effects stable across datasets, update semantics, disjoint source
  partitions, freshness, and bandwidth profiles? Repeated-measurement seeds are
  sensitivity controls, not additional robustness units.
- **RQ5 — Prespecified diagnostics.** How do the frozen ablation and diagnostic
  panels change `C` and its update, query, serialization, masking, and client
  components? These panels are descriptive and do not identify a causal effect
  for mechanisms that were not isolated by a single-factor contrast.

RQ1 is a correctness gate. RQ2--RQ5 are empirical and remain unanswered until
their exact artifacts exist.

## 3. Fixed protocol and evidence identities

The following are fixed before any publication experiment:

- protocol version `2.1b`;
- functional mode `F1-M-hidden-rowmap`;
- static semi-honest, at-most-one-party corruption with no Cloud/client
  collusion;
- OpenFHE 1.5.1 source commit
  `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`;
- BFVRNS, ring dimension 8192, plaintext modulus 65537, effective single-row
  slot domain 4096;
- signed integer bounds from `config/params_manifest.json`;
- experimental seed namespace is distinct from cryptographic randomness;
- cryptographic masks use the operating-system CSPRNG and persistent
  reserve-before-sample no-reuse semantics; and
- strong segment width is exactly `c=128`. Other segment widths are outside the
  witnessed family and must not be swept in the publication experiment.

The `c=128` choice is a protocol identity, not a value selected from the
publication outcomes. It was frozen before real-stream evaluation because it
is a power of two, gives an exact seven-stage leader-reduction schedule, fits
32 complete segments in the 4,096-lane effective domain, and exercises the
127-active-plus-one-padding boundary covered by the pinned witness. Results may
be described only for this admitted point. They do not imply that 128 is
optimal or that another segment width behaves similarly.

Current commit-bound anchors:

- R0 run `32580113632` at merged main
  `fcb00e0d7f111f3ab5003c111b124df83ae11813`;
- Phase 2 whole-query run `32581653504` at the same commit; and
- Phase 2 GitHub Actions artifact-wrapper SHA-256 digest
  `c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`.

These anchors authorize only their stated scopes. They do not by themselves
authorize candidate registration, complete accounting, a performance verdict,
mixed-circuit parameter safety, or R4 claims.

One publication-scale campaign forms one Publication Evidence Lineage. Before
its Terminal Registration Freeze, every behavior-bearing source file, workflow,
repository policy, this preregistration, its sampling and decision rules, and
the analyzer must be reviewed and frozen in a clean pre-anchor `S1`. The Day-1
registration anchor installed from exact-`S1` evidence is the lineage's last
behavior-freeze action. After it, only repository-owned data-only anchors may be
added monotonically: every existing path, record, target, and identity must be
retained unchanged.

A malformed anchor installation, required behavior or rule change, or requested
anchor withdrawal invalidates the current lineage. Recovery starts a fresh
branch from the pre-anchor `S1`, applies the reviewed change, establishes a new
terminal freeze, and regenerates all affected evidence. Removing and re-adding
an anchor anywhere in the invalid lineage cannot restore publication authority.

## 4. Candidate roles and selection hygiene

The revised experiment emits 14 fixed-candidate records:

- 13 `reference` records that are eligible for tuning and held-out comparison;
- one `ablation` record for `Packed-COO-Client-Lane-Delta`, which is emitted and
  plotted but never selectable; and
- two aliases after evaluation: one tuning-selected fixed policy and one
  diagnostic held-out offline oracle. Aliases are not additional physical
  candidate executions.

The designated strong reference candidate is
`Packed-COO-Cloud-Segmented-Delta`, fixed at `c=128`; it becomes a selectable
reference only after the repository composite admission gate succeeds.
Its publication policy is fixed to no folding, no compaction, base reserved
slack beta zero, and the already specified base/strong reuse rules. Any
alternative changes the candidate identity and requires a separate ADR,
candidate ID, correctness witness, and accounting admission.

Selection uses warm-up and tuning prefixes only. The selected candidate ID is
frozen before the held-out suffix. The offline oracle is computed only after all
fixed held-out records exist and is diagnostic; it cannot enter selection or be
described as an online policy.

Selection is performed independently for each `(trace unit, semantics,
freshness, rho)` cell. On the tuning prefix, rank the 13 reference candidates by
the same fully serialized, measured-cost diagnostic `C(rho, 1000 Mbps)` defined
in Section 7, with canonical candidate ID as the only tie break. The selected ID
then remains fixed for that cell's held-out suffix. T1 and T2 are never pooled
during selection. The primary confirmatory contrast is the held-out
tuning-selected alias versus `periodic-repack/windows=1`, the frozen
recompress-every-window reference. Comparisons against the other fixed
references and the held-out oracle are secondary diagnostics and cannot replace
this comparator after unblinding. The sole confirmatory family is fixed before
publication-scale execution to `(semantics=T2, freshness=0.1 s)`. T1 and/or
freshness 1.0 s are prespecified secondary robustness panels: they are reported
in full but cannot authorize, replace, or rescue the headline claim.

## 5. Data, update semantics, and experimental units

### 5.1 Real-data requirement

The primary corpus is frozen to three independently sourced temporal datasets:

1. the Stanford SNAP Stack Overflow temporal interaction network, reconstructed
   as the ordered union of the official `sx-stackoverflow-a2q.txt.gz`,
   `sx-stackoverflow-c2q.txt.gz`, and `sx-stackoverflow-c2a.txt.gz` objects so
   the interaction type remains explicit;
2. the Wikimedia MediaWiki History Simple English Wikipedia all-history
   snapshot for 2026-07; and
3. the twelve official NYC TLC 2022 yellow-taxi Parquet files plus the taxi-zone
   lookup.

For the NYC adapter, the monthly role is defined by the pickup wall clock: the
pickup year and month must equal the `yellow-2022-MM` role or the row is rejected
and counted. A valid trip may cross a month boundary at drop-off. Naive local
times are interpreted in `America/New_York`; an ambiguous fall-back time uses
the first occurrence (`fold=0`), while a spring-forward wall time that fails an
UTC round trip is rejected and counted as nonexistent.

LDBC SNB Interactive v2 SF30 is an auxiliary synthetic/natural-delete panel and
does not enter the fixed-corpus primary decision. Exact official object URLs are
frozen in the transform and source register, and the transform rejects a missing
or additional role. Retrieval time, final URL, status, frozen media-type set,
byte count, and locally computed SHA-256 remain `PENDING-FREEZE` until
acquisition. The source-set manifest must also contain the exact reviewed set of
applicable official terms pages for the dataset; each page is retained outside
the checkout and checked by retrieval UTC, the no-fragment fetch URL, optional
`ETag`/`Last-Modified`, normalized media type, byte count, SHA-256, and any
separately recorded section anchor. Every source receipt binds the canonical
terms-set digest.

A caller-written local source-set manifest is only an attestation and is not an
accepted production trace input. The production trace entry point accepts only
a closed acquisition bundle; it independently rehashes that bundle's members,
source-set, transaction, raw bytes, terms bytes, and central ACQUISITION Behavior
Set inventory. Those checks still do not by themselves prove the URL-to-byte
acquisition history. Formal acquisition authority requires the repository-owned
downloader or CI transaction to fetch each exact URL with `GET`, require status
200 and the exact final URL, reject an unexpected redirect, request
`Accept-Encoding: identity`, reject any response `Content-Encoding` other than
absent/`identity`, reject `Content-Range`, record normalized contract-relevant
response-header observations, and emit a digest-bound receipt that cannot be
replaced by caller-supplied HTTP fields. A data-object response must carry one
positive decimal `Content-Length` equal to the retained byte count. For a terms
object only, `Content-Length` may be absent: true absence is recorded as `null`
and is never synthesized from the retained byte count; the response must end
cleanly after 1 through 2,097,152 bytes. Observing any byte beyond that cap
causes HOLD and prevents installation of the acquisition bundle; no accepted or
retained terms object exceeds the cap. A present terms-page `Content-Length`
remains positive, at most that cap, and exactly equal to the retained byte count.
Acquisition and trace directories are installed through one repository-owned,
inode-bound, descriptor-relative no-replace seam: the exact staging member set is
verified before installation, the installed same-inode directory is reverified,
and any staging identity drift or destination collision returns HOLD without a
success receipt. Identity-changed, rejected, and incomplete pre-install staging
trees are preserved under random diagnostic quarantine names after an
identity-bound root claim. The producer never recursively unlinks or removes a
staging tree by reusable pathname because POSIX has no portable
unlink/rmdir-if-inode operation.

Here, atomic installation means no-replace namespace publication during a
running process; it is not a claim that a just-returned directory is durable
across sudden power loss. The trace-preparation consumer of an acquisition
bundle must reopen that installed directory, bind one descriptor-backed
exact-tree snapshot, and repeat the closed semantic and digest validation
before use.

The two exact Stack Overflow terms URLs use only the repository-frozen
`curl_cffi==0.16.1` `chrome150` adapter, explicit Mac Chrome 150 user-agent,
HTTP/2, the hash-locked acquisition environment and CA bundle, no redirects,
retries, cookies, authentication, or ambient proxy, and no browser/profile
fallback. This is a disclosed HTTP fingerprint, not a claim that a real Chrome
browser executed. Other frozen URLs use the explicit no-proxy CPython urllib
adapter with the same frozen CA bundle. The current-process transport receipt is
descriptive: `runtime_execution_isolation_verified=false` and
`formal_authority_granted=false` remain mandatory until an isolated repository
runner, post-run anchor, and ADR 0010 compatibility verification admit the run.
Until then, no dataset result is evidence-bearing. The authoritative mapping,
license, and provenance rules are recorded in
`docs/research/publication-venues-datasets-preregistration.md`.

The production trace manifest uses
`dynamic-cssc-publication-trace-manifest-v7`. Its closed
`dynamic-cssc-trace-acquisition-binding-v2` `acquisition_binding` binds the
`dynamic-cssc-acquisition-transaction-v3` transaction SHA-256, source-set
SHA-256, and the embedded exact central
`dynamic-cssc-acquisition-behavior-set-v2` inventory; the trace execution set is
`dynamic-cssc-trace-behavior-set-v2`.
Until the S2 post-run anchor and Evidence Compatibility Receipt are installed
and independently revalidated, `formal_authority_granted`,
`acquisition_network_authority_verified`, `post_run_anchor_verified`,
`evidence_compatibility_verified`, and `claims_authorized` all remain `false`.

Synthetic workloads remain plumbing, mechanism, and sensitivity diagnostics.
They cannot issue the primary publication verdict.

### 5.2 Frozen update semantics

Two real-stream interpretations are evaluated separately:

- **T1 cumulative:** for coordinate `(u,v)`, let `N_uv(t)` be all accepted
  occurrences through logical time `t` and define
  `A_uv(t) = min(7, N_uv(t))`. A visible `0 -> 1` is Insert; a changing nonzero
  value is Modify; repeats after saturation at 7 are logged clipped no-ops. T1
  has no deletes.
- **T2 event window:** use the same coefficient rule over exactly `K=32,768`
  accepted raw events. If admission would exceed `K`, expire the oldest event
  first. A visible `1 -> 0` is Delete, a changing nonzero value is Modify, and a
  visible `0 -> 1` is Insert. Expiry and admission are separate transitions in
  the incoming event's accepted-event group, with expiry first. Every transition
  stores two raw-event identities: `trigger_event` is the incoming event that
  advances the window, while `subject_event` is the event whose contribution is
  changed. They are equal for admission; for expiry, `subject_event` is the
  oldest event removed from the window.

One accepted raw event is one indivisible scheduling and update-denominator
group. All transitions in a group share its accepted-event ordinal and logical
tick; T2 applies expiry before admission, and no query or publication boundary
may interleave them. The microbatch cap of 64 counts emitted logical SET
transitions, but it is a group-atomic soft cap: a two-transition T2 group that
crosses the boundary is completed before publication, so one window may contain
at most 65 such transitions. Clipped no-ops emit no SET but still count once in
the accepted-event denominator. After every complete accepted-event group, the
scheduler emits exactly one payload-free logical TICK. This TICK advances the
freshness clock but contributes neither an update nor a query, so a run of
clipped no-ops cannot defer or erase a time-based publication boundary. The
within-group event order is all SET transitions, then TICK, then queries.
Before processing a group at logical time `t`, close any pending half-open
Publication Window whose freshness deadline is `<= t`; the group at the exact
deadline starts the next window. This pre-group freshness close is part of the
frozen scheduler and never interleaves with the group's SET→TICK→query order.

For `rho=p/q` in lowest terms and zero-based accepted-event ordinal `a`, insert
exactly
`floor((a+1)p/q) - floor(ap/q)` queries after the complete group. Thus exactly
`floor(Np/q)` queries have arrived after `N` accepted raw events. Query
allocation uses exact integer/rational arithmetic and is independent of
transition outcomes, clipping, candidate identity, costs, and held-out results.
The analysis records `update_count` as the number of accepted-event groups in
the phase; all compute and publication costs induced by that group's zero, one,
or two visible transitions are charged to that update count.

Query contents use one outcome-independent vector per paired analysis unit,
reused for every query arrival, freshness setting, rho value, and candidate in
that unit. The production vector has length 8,193 and coefficients in
`{-1,0,1}`, with `x[0]=1` and `x[8192]=-1` as forced nonzero boundary probes.
Actual anti-alias exercise is asserted separately by the execution preflight and
R4 rather than inferred from those two values. Its frozen seed is `2026082302`.
The remaining coordinates are derived coordinate-wise by SHAKE256 over the
canonical domain `(schema, dataset id, dataset release, semantics, source
partition, mapping SHA-256, vector length, seed)` plus unsigned big-endian
64-bit coordinate and attempt counters.
Read one byte; reject 255; map residues 0, 1, and 2 to -1, 0, and 1. The canonical
`publication-query-vector.json` and its SHA-256 are bound to the trace manifest;
the cell binds both this vector identity and the scheduled-event-stream digest.
This deterministic vector is a public known-answer reproducibility control for
fixed-shape cost and correctness evaluation. It is not cryptographic randomness,
evidence for a natural query distribution, or evidence that a private production
query plaintext is hidden. The manifest therefore fixes
`evaluation_query_plaintext_public=true` and
`query_confidentiality_evidence_allowed=false`.

For both semantics, order events by normalized UTC timestamp, source-file
ordinal, and within-file ordinal. Historical timestamps are provenance; replay
uses a fixed logical clock of 128 accepted raw events/s. Dataset-specific
self-loop and directedness rules are frozen in the research plan and must be
implemented before acquisition. T1 and T2 results must not be pooled.

The transform runs only from a clean, exact-HEAD source checkout and records the
Git identity plus the SHA-256 of every behavior-bearing transform source. Raw
objects and generated traces live outside that checkout. Each source object is
opened without following symbolic links, copied once into a private read-only
snapshot while its byte count and SHA-256 are computed, and parsed only from that
snapshot. NYC TLC Parquet parsing is frozen to CPython 3.12.13,
`pyarrow==25.0.1`, and the SHA-256
`e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95`
of the `America/New_York` TZif bytes. The manifest records the accepted binary-wheel
platform tag, machine, and the absence of a container image identity. The parser is
installed from `requirements-publication.txt` with `--require-hashes`; a Python
patch-level, timezone database, unsupported-platform, or wheel mismatch fails closed
instead of selecting another parser.

### 5.3 Frozen sampling frame and paired analysis unit

One chronological `(dataset, semantics, source partition)` trace is one paired
analysis unit. The full robustness panel is therefore:

```text
3 real datasets × 2 semantics × 5 disjoint source partitions = 30 paired units
```

The sole confirmatory family uses the 15 T2
`(dataset, source partition)` units at 0.1 s freshness. The other three
semantics-by-freshness families remain prespecified secondary panels.

The five source partitions are assigned by
`SHA256(dataset_release || canonical_source_id) mod 5`, so they differ in source
entities and events rather than merely in a random seed. Windows and queries
within a trace are dependent observations and must not be treated as
independent samples. Query-vector, partition-resampling,
calibration-resampling, and cryptographic seeds are controls, not additional
paired analysis units.

For each real dataset, let `V` be the event count of its closed, canonical,
chronological schema-valid corpus. Use exactly event ordinals
`[0, floor(V/10))` only to freeze the mapping: select 4,096 rows and up to 8,193
observed columns by prefix event count with canonical-ID tie breaks, then
deterministically pad remaining columns. Apply this mapping to the remaining
stream. Target 131,072 accepted raw events per unit; require at least 65,536
emitted logical changes and a guaranteed
lower bound of 1,000 complete publication windows. This lower bound is computed
without rho/freshness assumptions as
`floor(logical_changes/(64+maximum_atomic_group_size-1))`; each Day1B cell also
records its realized window count. A partition failing the frozen eligibility rule
is reported as ineligible, not replaced after observing candidate outcomes.

## 6. Chronological split and operating grid

For `N` accepted raw-event groups after the mapping prefix, freeze common
half-open ordinal ranges for every freshness/rho cell of that trace:
`warm-up=[0,floor(N/10))`, `tuning=[floor(N/10),floor(4N/10))`, and
`held-out=[floor(4N/10),N)`. Publication windows are forcibly closed after the
last complete group at each boundary, so no group or window crosses a phase.
All candidate states advance continuously through all three ranges; excluding
warm-up/tuning costs from a summary does not permit resetting state. Each cell
receipt commits to these ranges, its exact arrival schedule, phase update/query
counts, and the per-unit query-vector identity. A split derived from the number of realized
Publication Windows is invalid because freshness and query placement can change
that count.

The current nine query/update ratios are frozen unless changed before any
publication run:

```text
0.01, 0.03, 0.1, 0.3, 1, 3, 10, 30, 100
```

The sole confirmatory freshness is 0.1 s, within the manifest maximum of one
second. The 1.0 s case is a prespecified secondary robustness panel. A 10 s
case is not currently authorized or required; it may be added only by a
separately frozen, pre-execution out-of-manifest sensitivity protocol and can
never enter the confirmatory gate.

Primary bandwidth is frozen to 1000 Mbps. The 100 Mbps and 10000 Mbps profiles
are not currently authorized or required; either may be added only by a
separately frozen, pre-execution descriptive sensitivity protocol. Bytes must
be derived from serialized protocol objects, not inferred from ciphertext
counts alone.

Publication dimensions are frozen to the 4096-by-8193 manifest domain, a
group-atomic microbatch threshold of 64 visible SETs (T1 at most 64; T2 at most
65 when a two-SET group completes), maximum row nonzeros 4,096, coefficient bound 7, and the
event-window transform above. The existing 512-by-512 Day 1 configuration is
explicitly a scaled synthetic proxy and cannot serve as the publication-scale
primary run. There is no smaller fallback tier. In particular, `N=65,536` is
forbidden because `floor(4N/10) < K=32,768`: tuning would observe no T2 expiry
while held-out would switch mechanisms. If the target is infeasible in a
prefix-only pilot, no held-out execution is authorized. A later, separately
reviewed preregistration amendment must choose one common outcome-independent
tier satisfying `floor(N/10) <= K < floor(4N/10)`, rerun all structural pilots,
and be committed before any candidate comparison.

The execution resource envelope is `PENDING-FREEZE`. Before any held-out
candidate execution, one outcome-blind amendment must commit the exact
per-candidate/cell wall-clock limit, resident-memory limit, scratch/output-byte
limit, shard/job limit, concurrency, preemption classification, and retry rule.
Only the following closed structure-pilot protocol may inform those values.

`config/publication-day1b-resource-policy.json` is currently the canonical
closed pending placeholder, not an executable policy. Every empirical limit,
measurement method, structure-pilot identity, amendment identity, worker/build/
runtime identity, and ordinary-query private-plan identity is `null`; selective
candidate retry is exactly zero; and every authority, dispatch, publication,
and claim flag is exactly `false`. The production two-path Day1B entrypoint
obtains the clean repository source internally, reads that exact Git-bound blob,
and stops at `HOLD` before opening a trace, resolving a candidate catalog,
launching a worker, or creating output. Filling any pending field or flipping a
flag is invalid rather than an implicit promotion to an active policy.

The sole numeric exception in the pending document is
`protocol_invariants.candidate_retry_count=0`. It records the already
preregistered, non-empirical zero-selective-retry protocol invariant (paired
with `selective_candidate_retry_allowed=false`); it is not a measured resource
choice and cannot activate the policy. Every empirical numeric limit and every
measurement-method choice remains `null`.

The `dynamic-cssc-day1b-preparatory-behavior-set-v1` inventory and manual
`.github/workflows/publication-day1b-preparatory.yml` freeze and validate only
the current pre-`S1` source surface. A successful workflow validation is not a
dispatch receipt or evidence artifact: the workflow has no semantic inputs,
does not fetch traces or held-out data, does not invoke the producer, uploads
nothing, and cannot install an anchor. Held-out dispatch remains forbidden
until an outcome-blind amendment freezes the measured limits and methods, a
controller-owned scratch high-water/isolation contract and full repository-owned
OpenFHE worker are installed, the ordinary-candidate query-preparation and
private-plan lifecycle is canonical, and the TRACE post-run plus Day-1
registration anchors are installed and revalidated. Introducing those facts
requires a reviewed pre-`S1` policy schema/path and DAY1B Behavior Set version
bump; this preparatory inventory cannot be upgraded in place after outcomes.

For each of the three real datasets, define `V` as the event count of its closed,
canonical, chronological schema-valid corpus. Execute exactly the 30 paths in
the Cartesian product of the three datasets, `{T1,T2}`, and source partitions
`{0,1,2,3,4}`. The mapping/transform input for both semantics is exactly the
prefix with ordinal range `[0, floor(V/10))`. A preliminary pass may scan the
suffix only to count schema-valid records and validate their canonical order;
row/column mapping, T1/T2 transformation, and serialization must not read any
suffix event. The prefix is outside the later 10/30/60 evaluation split.

The pilot's sole purposes are parser/schema and 30-path coverage, aggregate
structure/cardinality and eligibility checks, completion and parser/adapter
error reporting, elapsed-time measurement, process-lifetime high-water
resident-memory observation, bounded live-coordinate cardinality, runtime-health
observation, and canonical round-trip completeness for prefix-derived structural
records. Canonical events stream into one per-dataset disk-backed SQLite store;
the store is closed and deleted before the next dataset. Prefix mapping is
aggregated in that store, and the transform streams records into a transient
round-trip/counting sink without retaining prefix events, transitions, or
serialized chunks. T2's event window and live coordinate state are bounded by
`K`; T1's reported live-coordinate maximum is observational and may range up to
the frozen matrix cardinality.

The top-level `process_high_water_rss_bytes_before_report_install` is the
operating system's process-lifetime `ru_maxrss` high-water observed only after
the final input-binding and source-attestation revalidations and scratch
workspace teardown, at the checkpoint immediately before report installation.
The top-level `analysis_wall_clock_ns` spans from immediately before the
exclusive scratch-workspace claim through that same checkpoint. Report
validation and serialization, checksum construction, staging writes and
`fsync`, and atomic installation are outside both measurements. Dataset and
cell resident-memory fields remain cumulative process-lifetime checkpoints at
their named completion boundaries, not attributable per-unit increments.
`canonical_store_bytes_after_index` is only the main SQLite database-file size
immediately after indexing, and the top-level maximum is the maximum of those
three checkpoints. It excludes source snapshots, SQLite temporary/query files,
filesystem allocation effects, and other transient scratch, so it is not a
scratch high-water measurement and cannot alone freeze a scratch cap.
`prefix_transition_serialized_bytes` is cumulative transient canonical byte
volume checked by the sink, not retained output or scratch occupancy. Only
aggregate serialization counts and bytes may enter the report; no transition
payload artifact may be retained. A scratch limit remains `PENDING-FREEZE`
unless the amendment adds a separately reviewed controlled-scratch high-water
measurement.

The Day1B worker candidate-cell receipt v2 separately records
`controller_observed_registered_scratch_peak_bytes`. The controller updates
that value before every existing cap check as the monotonic maximum of the sum
of `st_size` for its exact two anonymous, inode-bound registry/spool members.
The update occurs before an over-cap failure is raised, so a fail-closed path
cannot erase the observed checkpoint peak. This field is governed by
`controller_registered_scratch_bytes_checkpoint_maximum`; it is not the
candidate-execution `controller_observed_peak_scratch_bytes` governed by
`scratch_bytes_per_candidate_cell`, and neither field may be substituted for
the other. The current pytest-only capability issuer still reports creation
isolation as false, so this measurement does not authorize production or lift
the resource-policy `HOLD`.

The reviewed next-path decoder schema is
`dynamic-cssc-publication-day1b-resource-amendment-v1`. It is deliberately
resource-only: its exact top-level contract contains the frozen numeric limits,
canonical measurement-method tokens, no-retry protocol invariants, the
permanently non-admissible pilot/report/review digests, and a binding to a
previously reviewed schema-source Git SHA and DAY1B Behavior inventory. It has
no authority or worker/runtime-identity field. Its semantic payload digest is
computed after removing only that digest field; the eventual complete file is
instead bound as an ordinary Git blob by the later DAY1B Behavior Set, avoiding
a future-commit self-reference. The decoder's existence neither installs an
amendment, supplies any measured value, reads a pilot report, nor changes the
zero-argument production `HOLD`. Installing a real amendment remains a separate
reviewed pre-`S1` path addition and DAY1B Behavior Set version bump.

Production execution additionally requires the manual workflow's fixed,
pre-provisioned `PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT`. The path must be
absolute and canonical, owned by the worker identity, mode `0700`, writable,
empty at claim time, and disjoint in both directions from the repository,
acquisition, and output trees. The workflow must set `TMPDIR` and
`SQLITE_TMPDIR` to that exact path before starting Python; the core verifies
both environment values and Python's cached temporary-directory selection,
pins the root device/inode, takes an exclusive ownership lock, creates one
unique workspace beneath it, and removes its workspace before releasing the
lock. Workspace, per-dataset store, and source-snapshot cleanup is
inode-bound and refuses recursive deletion when an owned pathname is replaced
or a directory is not empty. Missing configuration, stale contents, concurrent
ownership, path or inode retargeting, or incomplete cleanup is a global
no-write `HOLD`. The
report records only the closed scratch-root policy and a SHA-256 identity bound
to its canonical path and device/inode. Neither field measures scratch bytes.

The report records the runtime SQLite library version and verifies
`temp_store=FILE`. It also requires exactly the frozen SQLite
`TEMP_STORE=1` compile option; SQLite older than 3.35, a missing, ambiguous, or
different `TEMP_STORE` option, or failure to read back the FILE policy is a
global `HOLD` before acquisition verification or output. The environment binding governs
where Python source snapshots and SQLite FILE-policy temporary work are
requested, but SQLite exposes no supported proof of the effective physical
temporary directory and may retain small temporary structures in its page
cache without creating a file. The report therefore makes no claim about
actual SQLite temporary-file placement or occupancy. Each dataset scan
projects only the verified
acquisition transaction, source-set, and central acquisition Behavior Set
digests plus their derived binding digest. Expected parser or canonical-store
scan failures use the closed deterministic codes `parser-failed` or
`canonical-scan-failed` and still yield all ten blocked cells for that dataset;
source, authority, safety, or binding drift is a global `HOLD` with no files.
Aggregate facts may not contain raw source/target identities or a mapping table.
The output directory contains exactly two regular files:
`structure-pilot-report.json` and `checksums.sha256`; the checksum file binds
only the report.

The pilot implementation must not import the publication schedule or Day1B
producer and must not dispatch or simulate a candidate execution. Neither the
report, workflow log, nor any other channel may compute, serialize, display, or
retain candidate IDs/configuration, operation or communication costs, candidate
timings, effects, rankings, Pareto/dominance results, rho or freshness values,
query vectors/schedules/counts/results, cryptographic outputs, or held-out and
confirmatory classifications. The run creates no new `EvidenceRole`, evidence
authority, anchor, compatibility receipt, or other publication admission.

The existing TRACE Behavior Set must freeze these three execution-bearing paths
at `S1`: `.github/workflows/publication-structure-pilot.yml`,
`scripts/run_publication_structure_pilot.py`, and
`src/dynamic_cssc/publication_structure_pilot.py`. Their inclusion detects later
drift in the mechanism that informed the amendment; it neither assigns the pilot
a new role nor attests or admits its output.

Both output files are pre-freeze, permanently non-admissible, and
non-promotable: they must never be copied into, cited as, or converted into a
Publication Evidence Lineage artifact. Until their allowed fields have informed
an outcome-independent resource amendment and that amendment is committed, all
held-out execution is forbidden. The pilot, review, and amendment precede the
clean pre-anchor `S1`; `S1`, the Terminal Registration Freeze, and the eventual
Publication Evidence Lineage all occur afterward. The final policy applies
identically to all candidates and cells. Candidate timeout, resource exhaustion,
or deterministic process failure receives zero retries and is recorded as a
failed outcome; an independently identified infrastructure preemption
invalidates the entire shard, which may be rerun once from the same source
commit and inputs, never a single candidate selectively.

## 7. Outcomes and primary decision rule

For each fixed candidate and paired held-out trace, report at least:

- update-side compute counts and measured-time estimate per accepted raw-event group;
- serialized update/publication communication bytes per accepted raw-event group;
- query-side compute counts and measured-time estimate per query;
- serialized query, key, result, F1-M, metadata, and client-side movement;
- exact abstract rotation indices and the primitive key plan used for
  calibration;
- returned ciphertexts, decryptions, client reorder/merge work, random-mask
  ciphertexts, and encrypted-zero dummy ciphertexts; and
- peak persistent state and transient memory where the implementation can
  measure them reliably.

The primary comparison is paired Pareto behavior, not a single hand-weighted
score. For a bandwidth `b` and query/update ratio `rho`, the calibrated
time-equivalent diagnostic is

```text
C(rho, b) = Tu_compute + Bu / b + rho * (Tq_compute + Bq / b).
```

The update denominator in `C` is exactly one accepted raw-event group, including
a clipped no-op group. All work induced by that group's zero, one, or two SET
transitions accrues to the same denominator. It is not normalized per emitted
SET transition or per realized Publication Window.

For bandwidth `b` expressed in decimal megabits per second, convert bytes to
seconds as `8 * bytes / (b * 1,000,000)`. `Bu` and `Bq` are the exact lengths of
the canonical serialized protocol objects assigned to the corresponding
publication or query transaction, including metadata, F1-M random masks,
encrypted-zero dummies, and returned ciphertexts. They exclude HTTP/TLS,
filesystem, artifact-container, and workflow framing. Evaluation-key generation
and distribution are reported as a separate one-time inventory and are not
amortized into the primary `C`; an explicitly labeled sensitivity panel may show
per-query amortization for declared query counts.

The primary calibrated compute vocabulary is closed to these 14 quantities:
`client_merge`, `client_reorder_element`, `decrypt`,
`deserialize_ciphertext`, `encode`, `encrypt`, `eval_add_ciphertext`,
`eval_mult_plaintext_mask`, `eval_mult_with_relinearization`, `eval_rotate`,
`mask_map_element`, `mask_random_element`, `query_vector_pack`, and
`serialize_ciphertext`. Day 2 records exactly 14 complete whole measurement
blocks, with no optional stopping. Before them it records exactly three complete
warm-up blocks with the same 14 profiles, cases, operation counts, ordinal/order
checks, and positive raw timings; warm-up values are bound into the raw archive
but never enter the calibration projection or point estimator. Every measurement
block contains all 14 primitives in a
deterministic SHAKE256/Fisher--Yates order derived from operation-order seed
`2026082302`, the block ordinal, and a calibration-only domain. The point
estimate for each primitive is the median of its 14 block values; precomputed
summaries, arbitrary operation names, missing/extra blocks, and arithmetic
means are rejected. Relinearization is recorded explicitly but is priced
exactly once inside `eval_mult_with_relinearization`. Per-operation seconds use
a unique canonical exact-rational encoding: a minimal terminating decimal when
possible, otherwise a reduced positive `numerator/denominator` string. This
keeps every positive integer operation count representable without rounding.

For `eval_rotate`, every block measures every exact index/profile in the
Day-1A-authorized direct-key inventory. Its scalar block value is the maximum
per-operation time over that complete admitted case set, a preregistered
conservative upper envelope rather than an exact realized time for every call.
Any other primitive whose admitted ciphertext level/profile varies uses the
same complete-case, per-block maximum rule; otherwise the accounting vocabulary
must be expanded before measurement.

Before the clean pre-anchor `S1` is designated, the canonical repository profile
anchor freezes the exact profile set, three-warm-up rule, rotation plan, and
Day-1A receipt/inventory identities. The profile anchor itself belongs to both
the Day-2 and analyzer Behavior Sets; it may not be installed or changed after
the Terminal Registration Freeze. It contains no future or self-referential
source commit SHA. A zero-argument repository seam validates that frozen data
and obtains the actual S1 identity and Day-2 Behavior Set digest from the
hardened clean-source verifier at runtime.
After measurement, S2 may add a separate canonical post-run evidence anchor
binding that actual S1 and the archive/raw/projection digests. Neither anchor is
embedded in validator Python code; the validator remains in the Day-2 Behavior
Set, while only the post-run anchor data is evidence-only under ADR 0010.

The accepted analysis input binds exactly 30 trace units and 540
`(unit, freshness, rho)` cells. Every unit commits to the trace manifest,
mapping, accepted-event stream, canonical accepted-group range receipt, replay
receipt, and source bundle. Every cell commits to its full SET*→TICK→QUERY*
scheduled-event artifact, exact phase counts, and unit query-vector artifact;
every measurement record commits to its cell binding. These
digests are necessary internal-consistency links, not self-authorizing evidence:
the publication workflow must independently rehash the referenced artifacts and
bind the experiment-source, evidence-freeze, and analysis-source Git identities
before a verdict can enter the claim ledger. These identities need not be equal:
the provider artifact digest necessarily appears after the experiment. Any
difference is accepted only through a repository-generated ADR 0010 receipt
that compares the exact, role-specific path/mode/type/blob Behavior Set and
allows only monotonic additions at the shared compatibility-anchor path and the
Day-2 post-run calibration-anchor path.
An earlier role remains valid when a later role appends its own admitted record
to a shared anchor, but every earlier record and identity must remain unchanged.
The preregistration and analyzer decision Behavior Set must remain byte-for-byte
and mode-for-mode frozen; it is not an analysis-only allowlist. The `ANALYZER`
role has no post-run compatibility phase and cannot gain authority from a
post-run compatibility anchor; analysis depends on the exact `S3` identity and
same-run isolated runtime admission. An ancestor relationship, a producer-
supplied file list, or a caller Boolean is insufficient.

For each unit, define the primary relative effect as
`(C_recompress - C_selected) / C_recompress`, where `C_recompress` is
`periodic-repack/windows=1` and `C_selected` is the tuning-selected held-out
alias for that same cell. The sole confirmatory family is T2 at 0.1 s; T1 and
the 1.0 s families are secondary and cannot supply positive headline
authority. Within the sole confirmatory family, the selected policy must have a
paired median relative reduction of at least 15% in `C(rho, 1000 Mbps)` at two
or more adjacent prespecified rho grid points. At each qualifying grid point,
all 15 fixed-corpus unit effects must be computable and strictly positive, and
the tuning-selected point must be non-dominated on the primary
update-bytes/query-time plane in all 15 units. The
candidate identity may differ between trace units because it is selected only
from each unit's tuning prefix; the reported estimand is therefore the frozen
tuning procedure, not one universally best layout. A single isolated rho point
is never sufficient.

All quantities in this decision are exact rationals derived from canonical
integer counts, serialized byte lengths, and canonical raw-timing rational
strings; binary floating point, epsilon comparisons, and post hoc rounding are
not used. `C_recompress` must be strictly positive. An effect is positive if and
only if `C_recompress - C_selected > 0`; equality, including an exact zero, is a
failure. The practical threshold is the exact rational `3/20`. With exactly 15
effects, the pooled equal-weight median is the eighth value after exact
nondecreasing ordering and passes if and only if it is at least `3/20`.

For Pareto classification, the selected point is represented by the exact pair
`(serialized update bytes per accepted raw-event group, calibrated query time
per query at 1000 Mbps)`. A frozen reference dominates it if the reference is
less than or equal on both coordinates and strictly less on at least one;
coordinate equality is exact and has no tolerance. The selected point is
non-dominated only when none of the 13 frozen references dominates it. An
adjacent rho pair means any consecutive pair in the single ordered frozen list
`(0.01, 0.03, 0.1, 0.3, 1, 3, 10, 30, 100)`; both members must independently
pass the complete rho rule. No interpolation, continuous interval, skipped-grid
pair, or left-versus-right preference is permitted.

If no candidate passes, the paper falls back to a benchmark/methodology result;
the experiment is not retuned on the held-out data.

## 8. Fixed-corpus decision and sensitivity

The sole confirmatory decision is conditional on this fixed three-dataset
corpus; the five deterministic source-entity partitions per dataset are not
treated as independent draws from a population. For every one of the nine rho
grid points, report the paired median, IQR, and all 15 per-unit effects. Also
report a central 95% type-7 interval from 10,000 dataset-stratified
source-partition resamples, with seed `2026082301`, only as a descriptive
sensitivity to partition weighting. It is not a confidence interval, carries
no population-inference authority, and is not an additional decision
criterion. No sign test, p-value, Holm adjustment, or other null-hypothesis test
is computed from these deterministic partitions.

A rho point satisfies the frozen finite-corpus rule only if all 15 effects are
computable and strictly positive, their median is at least 15%, every selected
point is non-dominated, and the complete-catalog/accounting gates pass. The
headline calculation requires two adjacent prespecified rho grid points in the
sole T2-at-0.1-s family. The other three panels are reported in full but cannot
authorize, replace, or rescue that result. For the deliberately conservative
complete-catalog gate, an incomplete candidate in any prespecified secondary
panel may veto the claim but can never provide positive authority. If any
required unit is ineligible, publish descriptive results but do not issue the
fixed-corpus result. A timeout, execution failure, infeasible state, or missing
window is a failed outcome for that unit, not a missing observation to impute
or drop.

Deterministic operation counts conditional on one trace do not create repeated
statistical evidence. Day 2 repetitions quantify measurement noise on the
benchmark host; they do not create new corpus units. Separately run 10,000
calibration-sensitivity replicates, also with seed `2026082301`. Each replicate
resamples one shared sequence of the 14 whole-block ordinals, thereby preserving
the measured cross-primitive covariance, and recomputes every primitive median,
reselects the tuning winner for every cell with the canonical-ID tie break, and
then recomputes all 15 fixed-unit effects and Pareto relations. It does not
resample the deterministic source partitions. For each rho, the replicate's
15-of-15-positive, median-threshold, all-unit-non-domination, and combined-gate
classifications must match the point-calibration classifications in all 10,000
replicates; the complete set of adjacent passing pairs must also match in all
10,000. The central 95% spread of replicate medians is reported only as a
descriptive calibration-magnitude sensitivity. Any classification mismatch
withholds the headline.

## 9. Required gates before the held-out verdict

1. R0 passes at the exact experiment source SHA.
2. The strong correctness receipt is admitted through a repository-owned,
   zero-argument gate; callers cannot inject capabilities.
3. Strong accounting, role-aware 14-record reporting, exact rotation inventory,
   and serialized byte accounting pass their property and replay tests.
4. The complete candidate catalog contains 13 references plus one ablation. Before
   composite registration, production fails closed without emitting an R2 artifact;
   after registration, `complete_reference_set=true` is derived only when every
   per-cell role, record, accounting, and rotation-inventory gate passes.
5. Day 1A emits replayable count evidence without inspecting a publication
   verdict. Its canonical count bundle and exact-index inventory may authorize
   a Day 2 key plan only when the receipt proves that the suite and publication
   matrix, effective-slot, and row-partition domains are identical; the current
   512-by-512/2048-slot/128-row-partition exploratory plan therefore remains
   ineligible for the 4096-by-8193/4096-slot/4096-row-partition publication key
   plan.
6. P0b/Day 2 consumes Day 1A's exact key inventory, stores exactly 14 complete
   whole measurement blocks under the frozen order/stop rule, and passes
   operation-profile and provenance checks. The current historical
   `day2-microbench.yml` does not satisfy this step: it lacks the raw-block
   schema, full 14-primitive coverage, and registered exact-index key-plan
   binding.
7. A mixed-circuit decryption/noise gate covers the worst admitted circuit.
8. Day 1B replays the identical traces with frozen measured costs.
9. R4 executes every grid point belonging to any qualifying adjacent pair, or
   the manuscript clearly limits itself to predicted/measured-component evidence.
10. Publication-authoritative analysis runs in a fresh detached checkout of S3
    with user site packages and caller `PYTHONPATH` disabled, an isolated
    bytecode cache, exact CPython 3.12.13, and no `.pth`/`sitecustomize`
    injection. The approved third-party distribution set for this analysis
    process is exactly empty; the two hash-locked requirement files are still
    identity-bound inputs, while the separate acquisition/parser process owns
    the pinned PyArrow dependency. A closed
    `dynamic-cssc-runtime-execution-isolation-receipt-v1` records the interpreter,
    lock/wheel identities, import origins and hashes, invocation, and identical
    hardened Git attestations before and after analysis. A missing or mismatched
    receipt fails the evidence chain rather than becoming a caller Boolean. The
    receipt and four installed statistics artifacts remain descriptive and are
    never rewritten. Central final admission must consume the live runner result,
    rehash the installed receipt/checksum and all four artifacts, and return an
    ephemeral non-Boolean capability. Any persisted audit projection has no
    replayable success bit. The `ANALYZER` role may not use a post-run
    compatibility anchor; until a claim gate consumes that capability under the
    exact `S3` identity in the same isolated run, runtime isolation and the final
    claim remain `HOLD`.
11. The final claim ledger maps every results sentence and figure to an exact
    source SHA, run ID, artifact digest, and validation status.

## 10. Stop and fallback rules

Stop the performance claim, without held-out retuning, if any of the following
occurs:

- the complete reference set is unavailable;
- any required query, output, key, metadata, F1-M, dummy, client, primitive, or
  serialized-communication field remains null or unpriced;
- the qualifying adjacent grid points disappear after measurement;
- the only apparent advantage occurs at one rho point, one dataset, one source
  partition, or outside the sole T2-at-0.1-s confirmatory family;
- the tuning-selected advantage disappears on held-out traces;
- correctness, replay, checksum, source-provenance, or candidate-role validation
  fails; or
- at any required R4 grid point, exact decrypted output/version/plan binding
  fails or realized operation/serialized-byte accounting differs from the
  Day1B-bound contract.

Allowed fallback: a reproducibility/methodology and benchmark-characterization
paper that reports negative or boundary results. Not allowed: changing the
primary metric, candidate role, split, dataset exclusion, or practical-effect
threshold after held-out inspection.

## 11. Freeze checklist

Before publication-scale execution, replace every `PENDING-FREEZE` above and
record:

- final target-venue format and any APC/length approval (the JCEN regular-
  article format and subscription-route budget assumption above are the frozen
  initial choice; recheck publisher instructions immediately before submission);
- exact dataset object URLs, licenses/terms decisions, checksums, and acquisition
  receipts;
- dataset-specific preprocessing implementation and rejected-event counts;
- query-vector seed `2026082302`, partition/calibration-resampling seed
  `2026082301`, and their distinct domains;
- candidate IDs, roles, aliases, and selection eligibility;
- primary estimand, practical threshold, fixed-corpus decision rule, and
  descriptive resampling method;
- benchmark hardware, OS, compiler, CPU affinity, OpenFHE build flags, warm-up,
  repetitions, and raw-sample schema;
- workflow time/cost budget and explicit dispatch authorization; and
- archival repository/DOI location and artifact retention plan.

The outcome-blind pilot and its resource amendment occur before every item above
is frozen into the pre-anchor `S1`. Only then may exact-`S1` Day-1 registration
evidence be anchored as the Terminal Registration Freeze. Only that committed,
reviewed, history-valid sequence may authorize the first held-out publication
run.
