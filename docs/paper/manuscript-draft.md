# Version-Bound Maintenance for Mutable Homomorphic Sparse Matrix--Vector Multiplication

> **Manuscript status:** methods-first working draft. Bracketed result fields are
> deliberately unset. No performance, complete-reference, security, or
> end-to-end claim may be filled without the gate named beside it.

## Abstract

Compressed sparse layouts make homomorphic sparse matrix--vector multiplication
practical for static patterns, but updates also change value placement, query-
reorganization metadata, and encrypted-output-to-row mappings. Full
recompression at each freshness boundary can dominate update cost; auxiliary
components trade publication work for query work and observable structure.

We present an update-aware layer around the published Compressed Sparse Sorted
Column (CSSC) representation. Freshness-bounded Publication Windows bind each
query to an immutable matrix version, global-column metadata, and a private
RowMap-sensitive reconstruction plan. For multi-component layouts, the plan
distinguishes overlaps from disjoint blocks and drives overlap-scoped one-time
zero-sum masking with persistent no-reuse bindings. A fixed-segment delta lets
the Cloud execute a public page-wide schedule while the client privately merges
segment leaders. A typed bundle binds the CSSC base, delta, operands, routes,
and operation graph and fails closed on version or plan substitution.

Our evaluation advances persistent strategy snapshots through a chronological
warm-up/tuning/held-out split, excludes an offline oracle from selection, and
separates predicted counts, measured OpenFHE unit costs, and end-to-end evidence.
A commit-bound OpenFHE 1.5.1 witness at
`fcb00e0d7f111f3ab5003c111b124df83ae11813` validates one base-plus-delta query
fixture; it is not evidence for later source changes. Candidate admission,
complete accounting, real-stream comparison, and calibrated performance remain gated.
The final manuscript will report **[R2B/R3/R4 result sentence withheld until the
corresponding commit-bound artifacts pass]**.

**Keywords:** homomorphic encryption; sparse matrix--vector multiplication;
mutable sparse matrices; cryptographic engineering; reproducible evaluation

## 1. Introduction

Encrypted sparse linear algebra sits at an awkward boundary between cryptography
and data layout. Homomorphic encryption hides values but makes data movement and
permutation expensive. Sparse formats reduce arithmetic on zeros, yet they also
turn a matrix's support into layout metadata and require a client to align the
encrypted query with physical value lanes. CSSC addresses the static case by
sorting rows, packing capacity-fitting rectangles, and retaining the metadata
needed to recover logical outputs. Its own stated limitation is a static sparse
pattern.

A mutable matrix cannot be handled by changing values alone. An insertion may
consume padding, create an overflow component, change a row permutation, or force
new query-reorganization metadata. A deletion may leave reusable physical
capacity without changing the logical matrix dimension. Meanwhile, a query must
not combine a new matrix component with an old column-index array or reconstruct
shares using a plan from another version. These are system-level consistency
requirements, not details of the underlying homomorphic primitive.

The naive policy republishes a fully recompressed CSSC layout after every batch.
Alternative policies retain slack, patch local regions, append a delta, or
periodically fold auxiliary state into the base. Their relative merit depends on
the update/query ratio, freshness deadline, layout history, communication
bandwidth, and the exact encrypted output path. Evaluating each window from a
fresh initial layout, selecting with held-out information, or omitting returned
ciphertexts and masking work can reverse the apparent ranking.

This paper therefore asks a narrower, auditable question: how should mutable
CSSC state be published, queried, reconstructed, and compared without breaking
version semantics or overstating evidence?

### Contributions

1. **Version-bound publication semantics.** We define Publication Windows and a
   commit rule that binds logical state, CSSC components, global-column query
   metadata, the reconstruction plan, and prepared queries to one version.
2. **Explicit multi-component reconstruction.** We introduce a private
   RowMap-sensitive `OutputPlan` that distinguishes overlap summation, disjoint
   block concatenation, and implicit zeros.
3. **Scoped masking integration.** We derive overlap-only F1-M operands from the
   plan and bind every random mask to a persistent, reserve-before-sample
   five-field identity. The underlying canceling-mask idea is prior art; the
   contribution claimed here is its versioned CSSC integration.
4. **A designated strong fixed-segment reference path.** We define public fixed-width
   segment/page shapes, cloud-side leader reduction, private leader merging, and
   a deterministic whole-query execution bundle. We do not claim a new HE
   primitive or a formal security proof.
5. **Causal, fail-closed evaluation.** We maintain independent candidate states,
   tune only on a chronological prefix, expose ablations separately from
   selectable references, and bind every reported claim to an evidence level and
   digest-addressed artifact.

## 2. Background and Related Work

### 2.1 Static encrypted sparse matrix--vector multiplication

CSSC is the direct substrate of this work and must be credited for row sorting,
left-aligned sparse rectangles, `Value`, global `ColumnIndex`, `RowMap`, chunked
query reorganization, and static aggregation [@gao2026cssc]. Our implementation
is an independent pseudocode-derived reconstruction; we did not use or verify
an author implementation. Lodia's low-diagonal construction [@yu2025lodia], diagonal-packing
reordering [@mutluergil2026diagonal], FHE-DNN sparse encodings
[@ferguson2025unstructured], and Rhombus's two-party MVM protocol
[@he2024rhombus] prevent any claim that this is the first double-ciphertext,
sparsity-aware, or privacy-preserving homomorphic MVM system.

The CSSC aggregation pseudocode has a non-power-of-two ambiguity. We use a
corrected `totalSum`-compatible stored-power/prefix graph that preserves the
paper-derived abstract count
`floor(log2 w) + popcount(w) - 1`. We present this as a compatibility correction,
not as a new aggregation algorithm or verified author-code behavior; the
`totalSum` connection is grounded in the HElib SIMD reduction literature
[@halevi2014algorithms].

The closest methods are not interchangeable experimental baselines:

| Work | Principal representation or setting | Mutable support? | Relation to this paper |
|---|---|---:|---|
| CSSC [@gao2026cssc] | Sparse-coordinate compression with `ColumnIndex`/`RowMap` | No | Direct static substrate; its published layout and reorganization are not our contribution. |
| Lodia [@yu2025lodia] | Low-diagonal decomposition for batched FHE SpMV | No | Establishes earlier sparsity-aware encrypted SpMV; different decomposition and leakage/cost interface. |
| Diagonal Packing [@mutluergil2026diagonal] | Row/column reordering to reduce occupied cyclic diagonals | No | HE-aware static compiler optimization; no mutable CSSC publication or reconstruction. |
| Ferguson et al. [@ferguson2025unstructured] | Sparse FHE encodings for DNN matrix multiplication | No | Demonstrates prior FHE sparsity exploitation under a PPML workload. |
| Rhombus [@he2024rhombus] | Coefficient-encoded MVM for semi-honest two-party inference | No | A different PPML protocol and packing objective; not a dynamic sparse-layout baseline. |
| Damie et al. [@damie2025secure] | Secret-shared sparse matrix multiplication in MPC | Not this protocol | Shows secure sparse arithmetic outside FHE; incomparable without a common threat and cost model. |
| This work | Version-bound CSSC base plus designated maintenance components (admission pending) | Yes | Studies publication, query recompilation, private reconstruction, and causal costs; claims no static-format or primitive novelty. |

### 2.2 Mutable sparse layouts

Reserved slack, padding reuse, COO/HYB overflow, row-local growth, base/delta
organization, periodic compaction, and format selection all have substantial
plaintext sparse-matrix and storage-system precedent, including SELL-C-sigma
[@kreutzer2014sellcsigma], GPU HYB/COO practice [@bell2008spmvcuda], LSM-trees
[@oneil1996lsm], Dynamic-CSR [@king2016dynamiccsr], and dynamic format selection
[@stylianou2022morpheus]. They are comparison families in this paper, not
independent novelty claims. Our narrower concern is their interaction with
encrypted query preparation, version consistency, private reconstruction, and
complete cost accounting.

### 2.3 Dynamic encrypted data systems and masking

Dynamic SSE, encrypted databases, ShieldDB, and oblivious transaction systems
already study updates, client state, epochs, padding, and leakage. They do not
instantiate the same ciphertext--ciphertext CSSC query, but they prevent broad
claims that batching or versioned updates are new. Canceling one-time masks also
predate this work. We therefore state the exact leakage and recipient roles and
avoid the terms `simulation-secure` or `prevents leakage` without a separate
proof [@cash2014dynamic; @vo2021shielddb; @crooks2018obladi;
@bonawitz2017secureagg]. Authorized homomorphic database updates also predate
this work and delimit any claim about encrypted mutability
[@parbat2023authorized].

## 3. System and Threat Model

The system has Client A, which owns the mutable matrix; Client B, which owns the
query and secret key and receives the result; and a semi-honest Cloud evaluator.
At most one party is corrupted and the Cloud does not collude with either client.
The model excludes malicious behavior, adaptive corruption, availability,
side-channel, traffic-analysis, and collusion claims.

Client B is authorized to learn the versioned global column indices, component
RowMaps, complete reconstruction plan, and final result. The Cloud is authorized
to learn public parameters, ciphertext shapes and counts, public page/segment
shapes, the operation schedule, opaque identifiers, query/version identifiers,
and plan digests. The interface classifies matrix/query plaintexts, global
column metadata, RowMaps, full plans, mask plaintexts, and unblinded component
outputs as forbidden-to-Cloud fields, and the typed serializers do not emit
them. This is an access-control and serialization requirement, not a proof that
all leakage is prevented or that the implementation realizes a
simulation-based notion.

## 4. Design

### 4.1 Publication Windows

Updates accumulate until a query arrival, freshness deadline, microbatch bound,
or explicit publication event closes the current window. The transition first
applies every net update to a candidate logical state, validates matrix and value
bounds, constructs or patches physical components, decodes them back to the same
logical state, and only then publishes the next version. A failed transition
cannot partially advance the visible state.

For the publication experiment, accepted raw events form atomic scheduling
groups. All visible SET transitions are applied first, followed by a payload-free
logical clock TICK and then the group's exactly scheduled queries. The TICK is
emitted even for clipped no-ops, so freshness advances without fabricating an
update. Before a group at logical time `t` is processed, any pending half-open
window whose deadline is at or before `t` is closed; the deadline group therefore
belongs to the next window. No close may split the group's SET→TICK→query
sequence. One deterministic bound-one ternary query vector is frozen per paired
trace unit and reused across candidates and cells. Its seed, generation method,
and values are public, so it is a known-answer correctness/cost control rather
than evidence for a production-query distribution, cryptographic randomness, or
query-plaintext confidentiality.

### 4.2 Versioned query reorganization

Each CSSC value lane stores an original matrix-column identifier or a padding
sentinel. Client A sends versioned plaintext column metadata to Client B. Client
B gathers one aligned vector per encrypted value chunk and encrypts it. The
matrix column domain is independent of the ciphertext-slot domain; reducing a
global column identifier modulo the slot count changes the function and is
forbidden.

### 4.3 OutputPlan and F1-M

The plan maps `(component, output block, physical lane)` to a logical output
coordinate. Client B initializes the public-length result to zero, reorders each
decrypted share, sums only equal logical coordinates, and concatenates disjoint
horizontal blocks. A coordinate with no physical contributor is an implicit
zero.

For contributor multiplicity greater than one, Client A samples a modular
zero-sum mask tuple. The binding
`(query, version, plan digest, component, output block)` is reserved in the
durable SQLite ledger before sampling. Duplicate use is rejected within that
ledger model. Repository rollback, database cloning or compromise, and
cross-device coordination are outside the present evidence. A disjoint strong-path return uses an
encrypted-zero dummy to retain a uniform visible operation position; it is not a
random mask and is accounted separately.

### 4.4 Strong fixed-segment delta

The strong path retains a real CSSC base and places overflow into fixed-width
power-of-two segments, currently frozen to `c=128`. A segment contains entries
from one logical row. The public typed plan uses uniform shapes and opaque
ordinal IDs, while the Cloud-visible leakage also includes published counts,
schedule and timing, query/version identifiers, and binding digests. We do not
claim segment unlinkability.
The Cloud multiplies aligned value/query ciphertexts, applies the fixed reduction
schedule, selects segment leaders, adds one F1-M operand per return, and returns
page shares. Client B uses the private plan to merge leaders that map to the same
logical row.

The current policy does not authorize cloud-side merging of segments that share
a logical row. Same-row-equivalence fields are carried only in Client B's typed
plan; this is an interface access-control requirement, not a proof that segment
relationships cannot be inferred. The publication identity for
folding/compaction is frozen separately; changing it creates a different
candidate.

The segment width 128 is fixed before real-stream evaluation rather than tuned:
it yields a seven-stage power-of-two reduction, places 32 complete segments in
the 4,096-lane effective domain, and is the exact 127-active-plus-one-padding
boundary covered by the pinned witness. We make no optimality or
cross-segment-width claim.

## 5. Implementation and Evidence

At merged-main commit `fcb00e0d`, the Python implementation supplied typed persistent states, a common query
compiler, exact operation graphs, private operand/route bindings, a plaintext
oracle, SQLite no-reuse commitments, canonical artifacts, and a separate deterministic replay
validator. The encrypted path uses BFV-family batching, whose original scheme
lineage is Fan--Vercauteren [@fan2012somewhat], through OpenFHE 1.5.1 pinned by
source commit [@openfhe151].

At merged main `fcb00e0d`, R0 passed 750 tests and the Phase 2 whole-query witness
passed in run `32581653504`. The witness exercises a 4096-by-8193 fixture,
global-column anti-aliasing, the 127-of-128 segment boundary, the unused second
BFV batching row, explicit no-relinearize/relinearize transitions, random and
dummy F1-M operands, and equality with both typed and direct plaintext oracles.
Its GitHub Actions artifact-wrapper SHA-256 digest is
`c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`.

This evidence is deliberately narrow. It does not establish complete candidate
costs, candidate registration, mixed-circuit parameter safety, security,
performance, or an end-to-end deployment.

Generative-AI systems assisted literature discovery, code and test generation,
adversarial review, and drafting during development. Their outputs are neither
source authority nor experimental evidence. Human authors must independently
verify cited primary sources, inspect the final code, reproduce the admitted
artifacts, and accept responsibility for every claim and released result.

## 6. Evaluation Methodology

Before inspecting publication held-out results, we will freeze the complete
experiment and this currently pending preregistration draft. Each candidate
owns an independent persistent state advanced through
the same chronological accepted-event groups. Common half-open group-ordinal
ranges define 10% warm-up, 30% tuning, and 60% held-out phases for every
freshness/rho cell, with atomic window closure at each boundary. The selected
candidate ID is chosen independently within each frozen
`(trace unit, semantics, freshness, rho)` cell from that cell's tuning prefix,
then fixed for its held-out suffix. The held-out offline
oracle is a diagnostic bound only.

Once the repository composite admission gate succeeds, the experiment emits 14
fixed records: 13 selectable references and one client-lane ablation. The
designated strong cloud-segmented `c=128` candidate then fills the previously
missing reference role, while the client-lane packed-COO path remains a separately plotted,
non-selectable ablation. Synthetic traces test mechanisms; the publication
verdict uses three officially linked temporal sources selected under a recorded
terms assessment:
the three official typed SNAP Stack Overflow interaction objects
[@snap_stackoverflow_temporal_network; @paranjape_motifs_in_temporal_networks],
the Wikimedia MediaWiki History Simple English Wikipedia all-time object in
version 2026-07 [@wikimedia_mediawiki_history_simplewiki_2026_07], and the 12
NYC TLC 2022 monthly yellow-taxi Parquet objects plus the unversioned official
zone lookup as linked and accessed on 2026-08-23; acquisition-time local hashes
and an independently admitted URL-to-byte acquisition receipt remain pending
[@nyc_tlc_yellow_trip_records_2022; @nyc_tlc_yellow_trip_data_dictionary]. If it
is separately frozen, acquired, and executed, LDBC SNB Interactive v2 SF30 will
be reported only as a synthetic natural-delete auxiliary panel, never as part
of the fixed-corpus primary decision [@ldbc_snb_interactive_v2].

For each real source, two deterministic transforms--cumulative recurrence and a
32,768-event sliding window--are applied to five disjoint source-entity
partitions. The full robustness panel therefore contains 30 paired trace units,
not 30 independent domains and not random reruns of one trace. The sole
confirmatory family is fixed in advance to T2 at 0.1 s freshness and contains
15 paired `(dataset, source-partition)` units. T1 and the 1.0 s freshness panels
are prespecified secondary robustness analyses and cannot authorize, replace,
or rescue the headline. Each unit targets
131,072 accepted raw events in the 4096-by-8193 manifest domain and uses the
same candidates, queries, and continuous 10/30/60 state history.

Primary results use complete serialization accounting within the preregistered
protocol-object transaction scope, measured OpenFHE calibration, all 15
fixed-corpus unit effects, and a descriptive
10,000-resample dataset-stratified partition-weighting sensitivity. Evaluation
keys are reported as a separate one-time inventory; HTTP/TLS,
filesystem, artifact-container, and workflow framing are excluded from this
transaction scope. A headline improvement concerns the tuning-selected
procedure relative to the frozen
recompress-every-window candidate `periodic-repack/windows=1` in the sole
T2-at-0.1-s confirmatory family. It requires at least a 15% paired median
reduction, strictly positive effects and non-domination in all 15 units at two
adjacent prespecified rho grid points, and calibration-classification
stability. The partition-resampling interval is descriptive, not a confidence
interval; no sign test, Holm adjustment, or population inference is claimed.
Full details and stop rules appear in
`publication-preregistration-draft.md` and must be frozen before execution.

Calibration archives exactly three complete warm-up blocks and then consumes
exactly 14 outcome-independent whole measurement blocks. Warm-up blocks cover
the same profiles and cases but do not enter the projection or estimator; each
measurement block contains the closed 14-primitive vocabulary in a deterministic
SHAKE256/Fisher--Yates order derived from seed `2026082302`, its block ordinal,
and a calibration-only domain. The per-primitive median across those 14 blocks
is the point estimate. Per-operation seconds retain exact arithmetic through a
canonical terminating-decimal-or-reduced-fraction encoding. The nested
sensitivity analysis resamples one shared
block-ordinal sequence, preserving cross-primitive covariance, recomputes all
primitive medians, reruns
the 13-reference tuning selection for every cell with a canonical-ID tie break,
then recomputes the corresponding fixed held-out effects and Pareto relations
on the same 15 units. It does not resample deterministic partitions in this
calibration loop. Thus it propagates timing, selector, and dominance
instability instead of holding the point-estimate winner fixed. Every analyzed
cell is digest-linked to its source bundle, mapping, accepted-event stream,
split, and replay receipt; a later workflow must independently rehash those
objects before any empirical claim is released.

## 7. Results

### 7.1 Correctness gates

**Latest audited fact:** R0 and the narrow Phase 2 fixture pass at `fcb00e0d`.
For any later evidence role, drift in that role's frozen Behavior Set requires a
new run; evidence-only and analysis-only snapshots require the separate S1/S2/S3
compatibility receipt defined by ADR 0010.

**Withheld:** strong registration, mixed-circuit, and R4 results.

### 7.2 Causal count results

**[Populate only from an accepted R2B artifact whose exact 14/13 candidate-role
contract, replay receipts, trace checksums, and rotation inventory verify.]**

### 7.3 Measured calibration and end-to-end validation

**Exploratory mechanism check only:** GitHub run `32712608022` at `f11e97d`
completed all 14 primitive profiles over eight caller-supplied exact rotation
indices. The independently rehashed probe document has SHA-256
`8b7db293687484bdf27e5f703bfb9e237fdaba3e3f6c8d736b33ce4c4e068207`.
It contains three warm-up blocks but only 11 measurement blocks and explicitly
sets `publication_raw_block_contract_satisfied=false`; the historically named
`R3-Day2` package is therefore permanently non-R3 and supplies no manuscript
estimate or claim.

**[Populate only from accepted Day 2, calibrated replay, mixed-circuit, and R4
artifacts. Include all 14 whole raw measurement blocks, their exact
index/profile cases, and uncertainty, not only medians.]**

## 8. Limitations

The threat model is narrow and provides no formal security theorem. Client B
learns layout and reconstruction metadata; the Cloud learns shapes, counts,
schedules, timing, opaque identifiers, and digests. The current witness covers
one frozen fixture and one segment width. Unit microbenchmarks do not imply
end-to-end latency or noise safety. Synthetic traces do not imply robustness on
real update streams. A negative or boundary empirical result remains a valid
outcome; held-out retuning is prohibited.

## 9. Conclusion

Mutable encrypted sparse computation requires more than an updatable container:
matrix state, query reorganization, encrypted execution, and reconstruction must
commit to the same version and be evaluated under complete causal costs. This
work supplies that explicit contract around CSSC and a witnessed strong-delta
execution path. The final empirical conclusion is intentionally deferred until
the complete, preregistered evidence chain passes.

## Data and code availability

The publication artifact will contain the frozen source-object register,
acquisition receipts, local hashes, transform and rejection summaries, derived
trace manifests, query vector, scheduled-event programs, raw calibration
blocks, Day1B records, replay receipts, analysis inputs and outputs, and the
exact source identities needed to verify them. Raw publisher objects will be
redistributed only where the recorded terms permit; otherwise the artifact will
provide exact official URLs, downloader code, byte hashes, and reproducible
derivation instructions. No empirical artifact or archival DOI is claimed by
this working draft. This section must be replaced with the accepted repository
release and archival DOI before submission.

## Statements and declarations

**Funding.** [The human author or authors must supply the applicable funding
statement before submission.]

**Competing interests.** [The human author or authors must confirm and supply
the competing-interest declaration before submission.]

**Author contributions.** [Insert the verified CRediT roles and author names;
an AI system must not be listed as an author.]

**Use of generative AI.** Generative-AI systems assisted literature discovery,
implementation and test generation, adversarial review, and manuscript
drafting. Human authors must independently verify every source, inspect and run
the released code and experiments, approve the final wording, and accept full
accountability for the work. The exact disclosure will be rechecked against the
publisher policy at submission.

## References

The citation database for this working manuscript is
[`references.bib`](references.bib). The venue-formatted manuscript must render
every citation above and preserve DOI/arXiv links; this draft must not be
submitted with citation keys left unresolved.
