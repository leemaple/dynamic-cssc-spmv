# Route A preregistration: version-bound mutable homomorphic CSSC

> **State:** review draft. Before runner implementation, the exact
> preregistration, canonical machine plan, commit-bound primary-source novelty
> review, and claim ledger must pass local and independent advisory review and be
> committed together. After implementation but before source acquisition,
> qualification, or empirical execution, the exact behavior-source diff and tests
> must separately pass source review, exact-head CI, descriptive registration,
> and the terminal data-only anchor gate. No Route A experiment is authorized
> before both stages close.
>
> **Supersession boundary:** this is a new, narrower claim set created after the
> terminal Day 1A operational NO-GO. It does not relax or reinterpret the old
> 300-minute gate. The old full-system claim remains failed.

## 1. Paper lane

### 1.1 Frozen contribution

> We present a version-bound protocol for mutable CSSC-based homomorphic SpMV
> that jointly binds logical matrix state, global-column query
> reorganization, private `RowMap`-aware multi-component reconstruction, and
> overlap-scoped canceling masks; we establish its functional correctness properties and
> characterize bounded-scale costs in a reproducible OpenFHE implementation,
> without claiming performance superiority.

The scientific object is the protocol semantics and its functional properties.
Repository governance, CI, registration, replay, and artifact code are methods
for making the evaluation reproducible; they are not claimed as scientific
novelty.

### 1.2 Permanent Route A non-claims

Route A makes none of the following claims:

- faster than Full-Repack, PaddingReuse, LocalRepack, or another dynamic format;
- a universal or tuning-selected best maintenance policy;
- a 15% or other threshold improvement on held-out data;
- a result on three datasets, 15 confirmatory units, or 30 paired units;
- a general algorithmic lower bound or an implementation-independent negative
  performance boundary;
- a new homomorphic-encryption primitive;
- simulation-based, malicious, adaptive, collusion, side-channel, access-pattern,
  or traffic-analysis security;
- complete support hiding or segment unlinkability;
- production readiness; or
- empirical authority from unit tests, CI, PRE-S1, external-model reviews, either
  cancelled diagnostic, or a NON-EVIDENCE transport artifact.
- a fitted scaling law, asymptotic exponent, or extrapolation beyond the two
  registered synthetic sizes;
- quantified cryptographic or privacy overhead relative to plaintext execution;
- privacy equivalence among the three strategies, whose public layouts and
  leakage surfaces differ;
- robustness across datasets, applications, or historical arrival-time
  dynamics; or
- statistical independence of technical repetitions, deterministic source
  partitions, or fixed formal seeds.

### 1.3 Retired old-paper requirements

The following are removed from the active Route A paper rather than deferred:

- the 14/13/1 candidate catalog as an empirical selection family;
- tuning-prefix winner selection and the offline oracle;
- the full 7 workload × 3 freshness × 9 rho Day 1A matrix;
- full Day 2 calibration as a prerequisite for a winner claim;
- all three real sources, five partitions per source, and both semantics as a
  30-unit campaign;
- the 15-unit confirmatory family and 15% adjacent-rho decision rule;
- the full production adapter/TRACE/Day 1B/R4 path as a submission prerequisite;
  and
- R2B/R3/R4 result placeholders in the abstract and conclusion.

## 2. Protocol definitions and propositions

### 2.1 System and malformed-input model

The protocol has three cryptographic parties plus a non-authorizing evidence
validator. Client A is the publisher and owns the mutable plaintext matrix,
versioned CSSC metadata, component RowMaps, complete OutputPlan, and F1-M
reservation/sampling ledger. Client A samples and encrypts the F1-M operands.
Client A and Client B are both authorized to read the complete OutputPlan;
`private` means private from the Cloud, not private between those two clients.
Client A gives Client B the versioned global `ColumnIndex` metadata; Client B
owns the query plaintext and is the sole secret-key owner. Client B generates
the secret/public/evaluation-key set, gives the public key to Client A and the
Cloud, and gives the evaluation keys only to the Cloud. Client A encrypts F1-M
operands under that public key. Client B uses the versioned indices to
reorganize and encrypt each prepared query, receives the complete OutputPlan,
and reconstructs the final result, but never receives the individual
random-mask plaintexts. The `ColumnIndex`, RowMaps, and OutputPlan are private
from the Cloud. The Cloud receives the public/evaluation keys, encrypted
operands, and registered public execution program and returns encrypted
component results.

The evidence validator is a separate repository-owned, fail-closed software
role, not the Cloud or a fourth cryptographic party. Inside the private
admission boundary it may read and rehash every enumerated retained canonical
object, including RowMap, OutputPlan, and disposable test-secret-key bytes.
It emits only typed validity, digests, and redacted receipts; private object or
secret-key bytes never enter the Cloud-facing interface or a formal artifact.

P1 is evaluated in a malformed/stale-package model: a test may replace one or
more enumerated binding fields or retained byte objects before admission. It is
not a malicious-security theorem. The Cloud-visible leakage includes public
component/page/segment shapes and counts, operation schedule and timing,
ciphertext/key/result sizes, opaque component identifiers, version and query
identities, and binding digests. Access patterns, traffic, host compromise,
side channels, rollback, database cloning, cross-device ledger coordination,
and deliberate hash collisions are outside the claims. Strategy costs therefore
must not be interpreted as comparisons at an equal privacy level.

### 2.2 Version-bound published state

For publication version `v`, define

\[
\mathcal{P}^{(v)} =
\left(
A^{(v)},
\{C_k^{(v)}\}_{k=1}^{K_v},
\{CI_k^{(v)}\}_{k=1}^{K_v},
\{RM_k^{(v)}\}_{k=1}^{K_v},
O^{(v)},
Q^{(v)},
B^{(v)}
\right),
\]

where `A` is logical matrix state, `C` the physical components, `CI` the global
column-index lanes, `RM` the component RowMaps, `O` the private OutputPlan, `Q`
the prepared-query binding, and `B` the immutable identity/digest bundle. A
query is admissible only when all members bind the same version, query identity,
parameter manifest, and canonical plan digest.

### 2.3 Proposition P1 — binding soundness

Let `B^(v,q)` be the authoritative canonical binding for publication version
`v` and query `q`. For every execution package submitted to the registered
admission interface, acceptance implies exact equality with `B^(v,q)` for the
version, logical-state identity, ordered component identities, ordered global
`ColumnIndex` identities, ordered component `RowMap` identities, OutputPlan and
private-plan identities, prepared-query and query-vector identities, plaintext
modulus, parameter-manifest identity, execution-plan identity, and ordered
serialized-payload inventory. A mismatch in any enumerated field rejects before
result-capability or formal-artifact minting.

The property is over typed values and retained canonical bytes: every
enumerated retained object is rehashed by that private admission process before
its digest is compared. Resistance to a deliberately
constructed SHA-256 collision is outside this functional proposition. Section
4.2 tests at least one substitution from every enumerated field class; those
tests sample the implementation of the universal admission predicate and do not
turn nine examples into a broader cryptographic theorem.

### 2.4 Proposition P2 — multi-component reconstruction correctness

For each physical component `k`, define its logical-coordinate matrix
`A_k^(v)` and embedding operator `E_k`. The registered decomposition must be
complete:

\[
A^{(v)} = \sum_{k=1}^{K_v} E_k\!\left(A_k^{(v)}\right) \pmod t.
\]

Assume each component execution decrypts to `A_k^(v)x` in its declared physical
lanes; every physical output lane maps to exactly its declared logical
coordinate; `O^(v)` is total over the logical output rows and contains no
unapproved duplicate contributor; and P3 masks have been cancelled. Applying
`O^(v)` must:

1. sum all contributions mapped to the same logical output coordinate;
2. concatenate disjoint horizontal output blocks in logical order; and
3. insert zero for logical rows with no materialized contribution.

The reconstructed vector must equal

\[
y^{(v)} = A^{(v)}x \pmod t.
\]

### 2.5 Proposition P3 — F1-M cancellation and ledger-scoped no-reuse

**P3a — algebraic cancellation.** Let the canonical component-identity order of
an overlap group at logical row `r` be
`G_r=(k_1,\ldots,k_g)` with `g>=2`. Client A independently samples

\[
m_{r,k_1},\ldots,m_{r,k_{g-1}} \overset{\$}{\leftarrow} \mathbb{Z}_t
\]

from fresh operating-system cryptographic randomness and sets

\[
m_{r,k_g}=-\sum_{i=1}^{g-1}m_{r,k_i}\pmod t.
\]

Therefore the prepared random masks satisfy

\[
\sum_{k\in G_r} m_{r,k}=0\pmod t.
\]

Client A encrypts these operands without disclosing the individual mask
plaintexts to Client B. Client B's reconstruction nevertheless cancels their
sum without changing `y_r`. Contributor groups of size zero or one receive no
random F1-M mask; any required encrypted-zero dummy remains a separate object
class.

**P3b — ledger-scoped no-reuse.** Client A's ledger assigns every random operand
the exact durable
reservation key
`(query_id, version_id, output_plan_digest, component_id, output_block_id)`.
All keys for a query are atomically reserved in one SQLite ledger before random
sampling. The prepared batch additionally binds `private_plan_digest`,
`execution_binding_digest`, the modulus, exact operand commitments, and a unique
commitment token; verification consumes that token once. A duplicate key,
duplicate token, mismatched commitment, or second consumption rejects. This
claim is confined to one uncompromised durable ledger and does not cover
repository/database rollback, cloning, compromise, or cross-device
coordination. Encrypted-zero dummy operands are accounted separately and are
not random masks.

### 2.6 Proposition P4 — fixed-segment reconstruction

For the fixed `c=128` strong path, each logical row's active auxiliary entries
are placed in ordered physical segments of exactly 128 lanes. Every segment
belongs to one logical row; its final unused lanes are explicit zeros. The
public fixed rotate-and-add reduction places each segment sum in the
predetermined segment-start leader lane. Client B uses the private OutputPlan to
map and merge leaders belonging to the same logical row. The reconstructed
vector must equal the direct plaintext product.

The boundary tests instantiate 127 entries as one segment with one zero lane,
128 entries as one full segment, and 129 entries as one full segment plus a
second one-entry segment whose leader is merged with the first. Tombstone,
padding, disjoint-component, and overlapping-component cases are tests of this
proposition rather than additional unstated segment rules.

### 2.7 Definition-level proof and source-conformance obligations

P1--P4 are conditional functional propositions, not conclusions inferred from a
finite test matrix. They may enter the manuscript as general statements only
after four written proof obligations and an exact-S1 source-conformance review
close:

1. **P1:** a case analysis over the closed admission predicate must show that
   equality of every enumerated typed value and every retained canonical byte
   string is a necessary conjunct, and that the implementation cannot mint a
   result capability or formal artifact before all conjuncts pass. The source
   review maps every proof conjunct to the exact validator branch and rejection
   path.
2. **P2:** a linear-algebra proof must establish completeness of the component
   decomposition, each embedding, totality of `OutputPlan`, and equality of
   overlap summation, disjoint concatenation, and implicit-zero insertion to the
   direct logical product for any admitted number of components.
3. **P3:** the modular cancellation derivation must be accompanied by a state-
   machine invariant for atomic reserve-before-sample, commitment, and single
   consumption in one uncompromised ledger. The proof includes the
   `unit_attempt_ordinal` in the evaluation-lane digest, so the sole provider
   replacement cannot reuse a query or five-field reservation identity.
4. **P4:** an induction or equivalent algebraic argument must cover leader
   placement and private merging for any number of canonical 128-lane row-owned
   segments. The 127/128/129 and tombstone/padding cases remain implementation
   boundary tests, not the proof itself.

The proofs, exact source-conformance record, registered tests, independent
replay, and guards are jointly necessary. If the proofs are not completed, the
only permitted correctness wording is that the registered cases passed; the
word `establish` and the universal RA-C1--RA-C4 formulations remain HOLD.

## 3. Fixed methods under comparison

Exactly three fixed strategy identities enter cost characterization. Their total
behavior is frozen here rather than selected after execution:

| Exact identity | Insert and overflow | Modify/delete | Compaction/fold | Query endpoint and reconstruction | Failure rule |
|---|---|---|---|---|---|
| `periodic-repack/windows=1` | Apply the complete causally closed window, then have Client A recompress and re-encrypt the whole logical matrix as one ordinary CSSC base | Incorporated into the same complete republish | Full fold on every update-bearing Publication Window; no auxiliary component persists | Query the exact new base version and reconstruct its declared logical rows | Any registered trace that cannot be republished is a Route C failure; no fallback |
| `padding-reuse` | Reuse the lowest same-row tombstone, then the lowest same-row natural-padding lane, under the total order below; reconstruct and re-encrypt its enclosing CSSC value ciphertext chunk and republish changed global-column metadata; if capacity is exhausted, rebuild and re-encrypt every CSSC chunk in the affected fixed horizontal row partition | Modify replaces the owning encrypted chunk; delete replaces it with a zero lane and marks that lane as a reusable tombstone | Only the affected partition is rebuilt on overflow; no periodic or outcome-triggered global compaction | Query the exact one-component CSSC version and reconstruct its declared logical rows | Any registered trace that cannot complete this rule is a Route C failure; no fallback |
| `packed-coo-cloud-segmented-delta/segment-width=128` | Reuse the lowest eligible base tombstone, base natural-padding lane, auxiliary tombstone, or unused lane in an existing row-owned segment, in that priority order; only then allocate one new row-owned fixed 128-lane segment and use lane zero | Modify/delete replaces the exact enclosing encrypted base chunk or 128-lane segment; deletion writes a zero lane and leaves reusable capacity in its owning structure | No outcome-triggered fold or compaction; auxiliary segments retain fixed public shape | Query the exact CSSC base plus segment pages; Cloud emits fixed leaders and Client B privately maps/merges them | Any registered trace that cannot complete this rule is a Route C failure; no fallback |

All three strategies consume identical ordered events, Publication Windows,
query arrivals, query vectors, value bounds, and logical endpoints. Every cell
is retained. There is no tuning, ranking, winner, offline oracle, optional
stopping, silent fallback, selective retry, or removal of an infeasible cell.
Static CSSC and the retired LocalRepack, ReservedSlack, Mini-CSSC, and client-lane
catalog entries are not part of the formal Route A result set. The three-item
panel is a preregistered set of representative mechanisms, not an exhaustive
dynamic-SpMV design space; LocalRepack is excluded to avoid reopening the
retired catalog, not because of an observed outcome.

Here and in the machine plan, a base `patch` is never an array-like ciphertext
slot write. It means Client A reconstructs and re-encrypts the exact enclosing
CSSC value ciphertext chunk, republishes that ciphertext, and republishes every
changed `ColumnIndex` or tombstone-metadata object. A segment patch analogously
replaces the exact enclosing encrypted 128-lane segment and its changed
metadata. No strategy performs Cloud-side `ct[slot]=value` or uses an additive
correction ciphertext. A changed `ColumnIndex` invalidates every prepared-query
binding for the earlier publication version. All replacement encryption,
metadata, invalidation, serialization, and communication enter matched
accounting.

Physical choice is total, not implementation-defined. Within each priority
class, eligible lanes are ordered by `(component-kind priority, component
ordinal, object ordinal, lane ordinal)`, all zero-based, and the least lane is
chosen. Client A reconstructs every replacement from its authoritative logical
matrix and current canonical layout, never from Cloud-returned or partially
decrypted bytes. A base-chunk plaintext preimage is exactly 8,192 elements of
`Z_65537`: canonical CSSC value lanes occupy indices `0..4095`; unused,
tombstone, and indices `4096..8191` are zero. A segment preimage is the exact
128 canonical row-owned segment lanes followed by zeros through lane 8,191.
A signed value `a` is encoded as `a mod 65537`. `ColumnIndex`, tombstone,
RowMap, and OutputPlan metadata are separate canonical objects; they are never
implicit in the ciphertext preimage.

Matched per-cell accounting includes, where applicable, matrix-side compression
and encryption, metadata publication, query reorganization/packing/encryption,
Cloud operations, random F1-M and encrypted-zero dummy work, returned
ciphertexts, decryption, private reconstruction, serialization, and
communication bytes. Evaluation-key construction and inventory are reported as
a separate one-time quantity and are never silently charged to only one
strategy. Because leakage differs across strategies, neither cost nor the
three-point trade-off plot is a privacy-equivalent ranking.

Serialized-byte authority is fixed before implementation and is never chosen
after seeing formal output. For synthetic and SNAP cells, canonical metadata
bytes are the exact bytes actually emitted by the simulator or deterministic
transform. Cryptographic-object bytes are a **serialized-byte upper-bound
projection**: for each closed category, exact multiplicity is multiplied by the
S1-frozen type-derived maximum serialized-byte formula for that category. The
ordered categories are update column-index synchronization, publication
ciphertexts, update version/plan metadata, query ciphertexts, result ciphertexts,
F1-M random-mask ciphertexts, F1-M encrypted-zero dummy ciphertexts, query
version/plan metadata, and separate one-time evaluation-key material. The
category list, transaction scope, input types, integer formula, and formula implementation path,
mode, type, and Git blob enter the S1 Behavior Set and the qualification
comparability vector. These projected bytes are labeled
`serialized-byte-upper-bound-projection`, never `native-measured`. The six
OpenFHE cases instead report actual retained serialized bytes by category for
each recorded native package. Evaluation-key bytes remain a separate one-time
inventory and are never folded into one strategy's recurring total. No formal
OpenFHE size receipt may be retroactively substituted as the authority for a
synthetic or SNAP byte projection.

## 4. Mandatory correctness and substitution matrix

All cases run on the final Route A source. Legal cases must equal both the typed
plaintext oracle and a direct matrix-vector multiplication. Illegal substitutions
must fail closed before an admissible result or artifact is installed.

### 4.1 Legal cases

1. insertion absorbed by natural padding;
2. insertion overflowing to an auxiliary component;
3. deletion followed by same-coordinate tombstone reuse;
4. repeated Modify operations with the correct net value;
5. overlapping outputs requiring summation and F1-M cancellation;
6. disjoint horizontal output blocks requiring concatenation;
7. a logical implicit-zero output row;
8. a global column identifier greater than 4,096, proving that global columns
   are not reduced modulo the slot domain;
9. fixed-segment boundaries with 127, 128, and 129 active entries; and
10. a zero-query update window, which must not compile a query plan.

### 4.2 Illegal substitutions

1. wrong publication version;
2. wrong logical-state identity or ordered component identity;
3. wrong global `ColumnIndex` identity or retained canonical bytes;
4. wrong component `RowMap` identity or retained canonical bytes;
5. wrong OutputPlan, private plan, plan digest, or execution-plan identity;
6. wrong prepared-query or query-vector identity or retained canonical bytes;
7. wrong plaintext modulus or parameter-manifest identity;
8. repeated reservation key, repeated commitment token, cross-scope F1-M
   identity, or mismatched prepared commitment; and
9. reordered, truncated, duplicated, or rehashed-with-different-bytes serialized
   payload inventory.

For P1, the suite contains at least one outcome-independent replacement from
each numbered field class and holds every non-target field fixed. P3b additionally
tests reserve-before-sample, atomic all-or-none reservation, exact prepared-batch
verification, and single consumption. P4 uses the exact segment construction
rule in Section 2.6.

Any legal mismatch or illegal acceptance selects Route C immediately.

## 5. Synthetic bounded-scale matrix

### 5.1 Fixed domain

| Field | S | M |
|---|---:|---:|
| Rows | 256 | 1,024 |
| Columns | 8,193 | 8,193 |
| Accepted updates | 512 | 2,048 |
| Initial nonzeros per row | 8 | 8 |
| Effective BFV slots | 4,096 | 4,096 |
| Partition rows | 256 | 1,024 |

Both sizes deliberately keep a column domain larger than the 4,096-slot domain.
The matrix coefficient bound is exactly `[-7,7]`; the plaintext modulus is
`t=65537`; the physical BFV batch has 8,192 lanes and the experiment uses the
first 4,096 as effective slots; padding-reuse reserves no synthetic slack; and
the strong base uses the registered `reserved_slack_beta=0` before fixed
segments. Every update-bearing Publication Window contains at most 64 logical
SET transitions, except that a two-transition T2 accepted-event group may
finish atomically at 65. A query requires the latest closed version. A pending
half-open window closes before an event group whose logical time is at or beyond
its one-second deadline; no boundary may split an accepted-event group.

The canonical machine plan is
`config/route-a-publication-plan.json`, whose exact retained-file SHA-256 is
`fc89b08e2151aaac03653d97293aeaadab1f3b015d18419817c2bee4d313cd79`.
The file is reviewed together with this document. The runner must reject any
plan whose retained bytes do not match that digest; changing the file requires
a new preregistration review and digest.

### 5.2 Fixed workload, ratios, and seeds

- workload: `mixed-insert-delete-modify` only;
- freshness: `1 s` only;
- rho grid: `{0.01, 0.1, 1, 10}` using exact rational scheduling;
- formal suite seeds: `{20260822, 20260823, 20260824}`; and
- resource-qualification seed: `20260821`, which never enters paper results.

For a formal seed `s`, the initial matrix uses CPython `3.12.13`
`random.Random(s)` and the registered `generate_initial_matrix` rule; the event
stream uses `random.Random(s+1)`, `query_every=0`, and the existing
`mixed-insert-delete-modify` selector intervals: insert below `0.45`, modify
from `0.45` below `0.80` when the row is nonempty, and delete otherwise when
possible. In the insert branch, failure to find a new column in a nonempty/full
row modifies one selected existing coordinate; if no new or existing coordinate
exists, it emits no event and skips the iteration. When either non-insert branch
selects an empty row, it deterministically falls back to inserting a newly
selected column; only a failure to find any new column emits no event and skips
that iteration. The required S/M accepted-SET counts must still be exact or
Route A selects C. The preregistered Route A wrapper path is
`src/dynamic_cssc/route_a_workloads.py`; it assigns accepted SET ordinal `i` the
exact rational timestamp `i/100` seconds. A skipped iteration neither consumes
an accepted ordinal nor advances logical time. Queries are inserted only by the
rational scheduler below. The final source
registration binds the exact behavior-source blob digests for this generator,
the scheduler, and all three strategy policies; a source change requires a new
source review, registration, and lineage. A new plan digest is required only
when the retained machine-plan bytes change.

All selection order is fixed. Existing coordinates are sorted by ascending
column before `rng.choice`. New-column selection makes at most 2,048
`rng.randrange(8193)` draws and returns the first absent coordinate; if none is
found, it forms the ascending available-column list and uses one `rng.choice`,
or returns null when empty. Modified-value candidates preserve delta order
`(-1,+1,+2)`, discard zero and values outside `[-7,7]`, then use one
`rng.choice` (or retain the current value if the list is empty). For each
ascending row, initial construction calls `rng.sample(range(8193),8)` once and,
in that returned order, `rng.randint(1,7)` once per coordinate. The Route A
wrapper must implement those semantics explicitly and its exact blob enters S1;
dictionary iteration order is not an alternate tie-break.

One formal synthetic shard is one `(scale, workload, seed)` unit containing all
four rho values and all three fixed strategies. The formal matrix therefore has
`2 scales × 1 workload × 3 seeds = 6` producer/replay shards and
`6 × 4 × 3 = 72` strategy-cells.

No cell may be removed after execution. The `rho=10` cell does not execute a
second state-transition path; it uses the exact query-linearity transformation
from `rho=1` only after event/window equivalence and the source receipt prove the
same non-query trajectory. The other three rho cells execute their complete
state-transition paths.

The preceding sentence is implemented as one mandatory rule, not an option:
`rho=10` **shall** be produced only by the registered exact query-linearity
transformation from the same strategy's `rho=1` result. Before qualification, a
machine eligibility validator must prove exact base-event, Publication Window,
state-transition, version, and non-query primitive identity; a frozen whitelist
then permits only the exact paths in
`rho10_projection.allowed_result_field_paths` of the canonical machine plan to
change. That array exhaustively names evaluation provenance, total/window query
counts, the 16 query-linear primitive fields, exact-index rotation counts, five
query-side object multiplicities, five query-side serialized-byte fields, and
the six measurement fields made unavailable, plus the closed target-only
identity, correctness, and binding leaves below. Integer quantities and each
ordered count vector are multiplied by ten. Four cryptographic query-byte upper-
bound categories are multiplied by ten; query version/plan metadata is instead
recomputed as target multiplicity times the S1-frozen per-object maximum
canonical-metadata byte formula, avoiding any assumption that decimal ordinals
have source-identical length. The six measurement fields become null/unavailable;
the target provenance becomes the fixed exact-projection value. Wildcards and later category additions are forbidden. If the validator,
complete-path check, or direct-equivalence property tests fail, Route A selects
C; it never switches to a full `rho=10` execution after seeing results.

The `rho=10` cell is only an aggregate exact-accounting projection. It creates
no query-ID document, prepared query, ciphertext, mask, result, decryption,
reconstruction, or ledger object and makes no P1--P3 or native-execution claim;
those objects exist only in the fully executed `rho=1` source cell. Its
`identity.rho` is exactly `"10"`. Its closed `correctness` object records
`execution_performed=false`, `oracle_equality=null`,
`binding_acceptance=null`, `claim_authority=false`, and `source_rho="1"`.
Its closed `bindings` object contains only the exact source-`rho=1` document
SHA-256, exact machine-plan SHA-256, transform ID, and null `query_id_root`,
`prepared_query_root`, and `ledger_root`. It can never inherit the source cell's
execution booleans or query/ledger roots. Conversely, a directly executed
`rho=1` source has `execution_performed=true`, successful oracle/binding values,
null source/transform projection fields, and required SHA-256 query, prepared-
query, and ledger roots; every cell document itself remains non-self-authorizing.

Source and target must validate against the exact S1 blob of
`schemas/route-a-strategy-cell-v2.schema.json`, whose closed top-level,
correctness, and binding keys are fixed by the machine plan, with no extra keys.
The whitelist must exhaust every differing leaf; all remaining fields are
object-equal or byte-equal to the `rho=1` source. The envelope is a closed
canonical JSON object containing exactly schema version, the source and target
document SHA-256 values, machine-plan SHA-256, and transform ID
`rho1-to-rho10-exact-query-linearity-v1`; its schema is
`dynamic-cssc-route-a-rho10-integrity-envelope-v1`. Copied source evidence is
provenance for the projection, never target correctness.

For `rho=p/q` in lowest terms and zero-based accepted-event ordinal `a`, the
scheduler inserts exactly

\[
\left\lfloor\frac{(a+1)p}{q}\right\rfloor-
\left\lfloor\frac{ap}{q}\right\rfloor
\]

queries after the complete accepted-event group. Scheduling uses exact integer
arithmetic and is independent of strategy state and timing.

If the scheduler emits `m` queries after one accepted-event group, they form one
ordered query batch attached to one query-bearing Publication Window with
`query_count=m`. The first query closes any pending update window; all `m`
queries bind the same latest immutable publication version and receive distinct
consecutive zero-based ordinals and distinct `query_id` values within an
evaluation lane. The evidence-shard identity binds the plan, source, scale or
partition, seed or mapping digest, semantics, workload, and freshness. A
separate evaluation-lane document adds exact strategy identity, rho, process
role, process ordinal, and `unit_attempt_ordinal`: the nominal unit attempt is
zero and the sole permitted provider replacement is one. Simulator producer
lanes use role `simulator` and null;
OpenFHE warm-up uses `openfhe-warmup,0`; the three recorded packages use
`openfhe-recorded,{0,1,2}`. Ordinals start at zero for each lane, advance in
Publication Window order, and never reset within that lane. A query-ID document
contains exactly `schema_version`, `evaluation_lane_identity_sha256`, and
`global_query_ordinal`; its lowercase SHA-256 hex is the ID. All identity
documents use canonical ASCII JSON with sorted keys, compact separators,
`ensure_ascii=true`, `allow_nan=false`, no floats, and one LF.

The payload-free logical tick is an ordering event at the **same exact rational
time** as its complete accepted-event group; it never advances to the next
clock quantum and never closes a Publication Window by itself. Microbatch
closure remains exclusively the registered pre-group `g` rule. When `m>0`, the
first query closes exactly one current window, and that same query-bearing
window contains every pending SET transition, including all SETs from the
complete current group, together with `query_count=m`. The scheduler must not
split those updates into an update-only window followed by a separate query-only
window. A query-only window is possible only when the complete group emitted no
SET and no prior SET is pending. When `m=0`, the tick creates no closure.

The exact `close_reason` vocabulary is
`{one-second-deadline, pre-group-microbatch, query, finite-trace-end}`.
Publication version zero is the initial closed version, and `window_ordinal`
starts at zero and advances for every emitted window. Every window containing at
least one SET has `version_after=version_before+1`. A query-only window instead
has `version_after=version_before`; it does not republish, run a strategy
transition, or create update-side cryptographic work, and all queries in it bind
that exact already-closed version. Its ordered SET-reference list is empty, and
both event-group range endpoints equal the current query-triggering group; no
synthetic group is created.

Every event-group range is inclusive. For an update-bearing window, the first
endpoint is the accepted group containing its earliest referenced SET. When a
`query` or `finite-trace-end` action closes the window after a group, the last
endpoint is that closing group; when `one-second-deadline` or
`pre-group-microbatch` closes it before a group, the last endpoint is the
immediately preceding accepted group. Every intervening or trailing no-change
group lies inside that range, but only actual SET transitions appear in the
ordered reference list; leading no-change groups before the earliest referenced
SET are outside it. References are ordered by accepted-group ordinal and then
transition ordinal within the group. The query-only exception remains the
single current query-triggering group described above.

After the final complete accepted-event group, if one or more SET transitions
remain pending, the scheduler closes exactly one `finite-trace-end` update-only
window after that group's SET, tick, and scheduled-query sequence. Its close
reason is `finite-trace-end`; the control action occurs at that final group's
same exact rational time, without advancing the clock or creating another event group. It
contains all and only pending SET transitions in canonical order, has
`query_count=0`, a null first query ordinal, and
`version_after=version_before+1`; its first event-group ordinal is the pending
window's start group and its last is the final accepted group even if
intervening or final groups emitted no SET. It never compiles a query plan. If no
SET remains pending, no finite-trace-end window is emitted; an empty terminal
window is forbidden. Every accepted SET transition occurs in exactly one closed
Publication Window, with no missing, duplicate, fabricated, or reordered
reference. The same rule applies to synthetic and SNAP semantic traces.

Because attempt ordinal enters the lane digest, a provider replacement derives
new query IDs and therefore new five-field F1-M reservation identities rather
than sampling a second mask under an old identity. Independent replay is not a
new evaluation lane. For synthetic, SNAP, and OpenFHE evidence it reuses the
exact producer lane and query IDs from the same unit attempt solely to
rehash and verify the retained prepared-query, reservation, mask, result, and
exactly-once consumed-token records before re-executing the prescribed
deterministic transition/oracle or retained-package verification. Replay is
read-only with respect to that ledger: it never reserves, samples, consumes, or
mutates a token. A missing, unconsumed, duplicate, or mismatched producer record
rejects. The discarded OpenFHE warm-up is not replayed; it uses its own lane,
query IDs, fresh masks, and complete reservation/consumption lifecycle in the
producer. For a directly executed batch of `m`, every query ID has its own prepared-query
binding, encryption, F1-M reservation/operands, result, decryption,
reconstruction, and consumed token. The batch receipt atomically binds the
ordered `m`-ID array and rejects partial consumption.

Reuse is limited to public immutable metadata, the separately reported one-time
evaluation-key inventory, and identical plaintext-vector values used as a
known-answer input. Every directly executed scheduled query incurs its own prepared-query binding,
query encryption and accounting, F1-M reservation and encrypted operands,
returned result, decryption, and reconstruction. Query ciphertexts, random
masks, F1-M operands, result ciphertexts, or consumed commitment tokens are not
reused across query IDs. The object-free `rho=10` aggregate projection is the
only exception and is governed solely by the closed projection contract above.

One public deterministic ternary query vector is bound to each shard and reused
for all of its rho values and strategies. It has length 8,193, seed
`2026082302`, `x[0]=1`, `x[8192]=-1`, and all remaining coordinates in
`{-1,0,1}`. Its domain object contains the schema, seed, length, and either
synthetic `(kind, scale, formal_seed)` or real-source
`(kind, object_sha256, mapping_sha256, partition, semantics)` identity. Encode
that object as ASCII JSON with sorted keys, compact separators, `allow_nan=false`,
and one trailing LF. The domain schema is
`dynamic-cssc-route-a-query-vector-domain-v1`; its `kind` member is the literal
JSON pair `"kind":"synthetic"` or `"kind":"snap-a2q"`. In the real-source
domain, `object_sha256` equals both the mapping document's
`raw_object_sha256` and the acquisition receipt's `compressed_sha256` over the
same exact response-body bytes. For coordinate and attempt unsigned 64-bit big-
endian integers, coordinates `1` through `8191` start at `attempt=0` and read
`b=SHAKE256(domain_bytes || uint64_be(coordinate) ||
uint64_be(attempt)).digest(1)[0]`; if `b==255`, increment the attempt and retry;
otherwise set the value to `(-1,0,1)[b % 3]`. Coordinates `0` and `8192` are not
sampled and remain the fixed endpoints above. The final vector document contains
exactly `schema_version`, `domain_sha256`, and the ordered 8,193-element
`values` array, encoded as the same canonical ASCII JSON plus one LF. The vector
SHA-256 is over those exact document bytes and enters every relevant binding.
This is a reproducibility control, not cryptographic randomness or evidence of
a natural query distribution.

### 5.3 Reported synthetic measurements

For each directly executed strategy-cell, report:

- exact update, query, and Publication Window counts;
- primitive-operation inventory;
- exact emitted canonical metadata bytes and S1-frozen per-category
  cryptographic serialized-byte upper-bound projections;
- producer state-transition and result-assembly wall time;
- independent-replay wall time as evidence overhead, not strategy cost;
- peak RSS and controlled scratch high-water observation;
- plaintext-oracle equality; and
- source/plan/manifest/trace/replay/guard digests.

Measurement classes remain disjoint:

- **directly measured:** state-transition/result-assembly time, replay time,
  peak RSS, and scratch for `rho in {0.01,0.1,1}`;
- **exactly counted:** events, windows, updates, queries, primitive operations,
  and object multiplicities;
- **upper-bound projected:** synthetic/SNAP cryptographic bytes from exact
  multiplicity times the S1-frozen type-derived maximum formula, kept distinct
  from exact emitted metadata bytes and native-measured OpenFHE package bytes;
- **exactly rescaled:** only the registered query-linear counts and byte
  quantities for `rho=10`; and
- **unavailable:** measured `rho=10` wall time, RSS, scratch, or native latency.

Synthetic primitive inventories are simulator/accounting outputs, not measured
OpenFHE costs. Native cryptographic operations and latency are reported only by
the Section 7 cases; they are never blended into one undifferentiated column.

Two plaintext context cells are frozen inside existing formal shards:
`(synthetic M, seed=20260822, rho=1)` and
`(real partition=0, T1, rho=1)`. Each applies the identical scheduled SETs to a
canonical plaintext coordinate map and computes direct `Ax mod t` at the same
query arrivals on the same runner. Their time and RSS are descriptive context,
not a fourth strategy, a speedup denominator, or a quantified privacy overhead.
Their bytes/results are rehashed and replayed with the containing shard.

Wall-clock values are descriptive measurements of the pinned Python/OpenFHE
implementation on `ubuntu-24.04`. With only S and M, plotted connecting lines
are visual guides: no scaling law, exponent, trend extrapolation, p-value,
independent-population inference, speedup headline, or cross-machine
generalization is permitted.

## 6. One-source ordered-event matrix with synthetic logical time

### 6.1 Source identity and redistribution boundary

Use only the official SNAP Stack Overflow answer-to-question object:

`https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz`

The acquisition receipt records final URL, byte count, response metadata,
retrieval UTC, and locally computed SHA-256. The raw file is not redistributed;
the artifact contains downloader/transform source, attribution, local digest,
and derived trace digests. The paper labels it precisely as the official SNAP
`a2q` temporal object, not the three-object typed union and not a population
sample of all Stack Overflow activity.

The acquisition receipt is closed schema
`dynamic-cssc-route-a-snap-acquisition-receipt-v2`: exactly schema version,
`unit_attempt_ordinal`, requested URL, final URL, HTTP status, UTC retrieval time at whole-second
RFC3339 `...Z` precision, compressed byte count, compressed SHA-256, and a
response-header object containing exactly `content-length`, `content-type`,
`etag`, and `last-modified` (missing values are JSON null). It is encoded as
canonical ASCII JSON with `ensure_ascii=true`, sorted keys, compact separators,
`allow_nan=false`, no JSON floats, and one LF.

Here and in every downstream mapping/trace object, `raw_object_sha256` means the
lowercase SHA-256 of the exact downloaded HTTP response-body bytes **before**
gzip decompression. Those bytes and their length are exactly the byte domain of
the receipt's `compressed_sha256` and `compressed_byte_count`, so the two SHA-256
fields must be equal rather than merely related. The producer handoff and formal
acquisition artifact contain no raw source bytes. Instead, the independent
acquisition guard performs a second download, requires the exact byte count and
digest to match the producer receipt, recomputes the transform, rehashes every
derived canonical object, and only then emits the formal acquisition artifact.
Any source drift or unavailable second download selects C.

The nominal acquisition attempt has `unit_attempt_ordinal=0`; the sole permitted
provider replacement has ordinal one. If attempt zero completed a response-body
observation and recorded `compressed_byte_count` and `compressed_sha256`, attempt
one must download byte-for-byte the same object before any transform or
admission. Only when attempt zero never completed any raw-object observation may
attempt one establish the first digest. Both attempts remain in the controller
ledger, but only the final successful guarded attempt can enter the admitted
formal set.

### 6.2 Outcome-independent transform

1. Decompress the single gzip object to bytes; split on byte `0x0a`; discard only
   the final empty sentinel when the stream ends in `0x0a`; and remove at most
   one terminal `0x0d` from each resulting record. Every remaining record gets
   its zero-based physical `within_file_ordinal` before filtering and is decoded
   with strict UTF-8. Empty records are blank; a record is a comment only when
   its first byte is `0x23` (`#`). A valid data record matches exactly three
   decimal tokens with one or more ASCII spaces or tabs between them, no leading
   or trailing bytes, no leading `+`, source/target IDs in
   `[1,2^64-1]`, and timestamp in `[0,2^63-1]`. IDs have no leading zero;
   timestamp is `0` or has no leading zero. Blank/comment/malformed/self-loop
   lines consume a file ordinal, are counted separately, and enter neither
   prefix nor suffix.
2. Canonical identities are ASCII
   `stack-overflow:user:` followed by the positive decimal ID left-padded to 20
   digits. Sort eligible non-self-loop records by
   `(unix_timestamp, within_file_ordinal)`; the object has file ordinal zero.
3. Reserve exactly the first 1,000,000 eligible records as a structure-only
   mapping prefix; none enters measured execution. Fewer than 1,000,000 selects
   Route C.
4. Assign a canonical source identity to partition `0` or `1` by interpreting
   `SHA256(ASCII("route-a-snap-a2q-v1") || 0x00 ||
   ASCII(canonical_source_id))` as an unsigned big-endian integer modulo 2. The
   salt bytes are exactly
   `bytes.fromhex("726f7574652d612d736e61702d6132712d763100")`;
   `0x00` denotes one NUL byte, not two printable backslash characters.
5. In each partition, select exactly 1,024 row identities by descending prefix
   event count with binary-ASCII canonical-ID tie-break. Fewer qualifying rows
   selects Route C.
6. Conditional on those rows, select target identities by the same order. If at
   least 8,193 are observed, take exactly the first 8,193. Otherwise fill to
   exactly 8,193 only when at least 7,374 are observed (deficit at most 819).
   Reserved IDs are ASCII `route-a:reserved-column:` plus an eight-digit ordinal;
   this namespace cannot collide with observed `stack-overflow:user:` IDs. A
   larger deficit selects Route C.
7. Apply the frozen mapping to the suffix and accept exactly the first 4,096
   in-rectangle eligible records. If either partition cannot meet eligibility,
   Route A stops; no time interval, alternate prefix, mapping, partition salt,
   or source is substituted.
8. Accepted record ordinal `i` is one indivisible event group at exact rational
   logical time `i/128` seconds. Historical timestamps determine source order
   and remain provenance, but historical interarrival times are not evaluated.

For each partition, the mapping document contains exactly its schema version,
raw-object SHA-256, partition, mapping-prefix eligible-record count and identity
SHA-256, ordered 1,024 row identities, ordered 8,193 column identities,
reserved-column count, and ordered reserved-column identities. Its bytes are
ASCII JSON with sorted keys, compact separators, `allow_nan=false`, and one LF;
`mapping_sha256` is the SHA-256 of those exact bytes. This document is the only
mapping object accepted by the query-vector domain and downstream bindings.
The prefix identity is SHA-256 over the ASCII domain bytes
`route-a-snap-prefix-v1` followed by one `0x00` and, in sorted prefix order, each
record encoded as four unsigned 64-bit big-endian integers: source ID, target ID,
timestamp, and `within_file_ordinal`.

The transform is also machine-closed, not merely described by this prose. After
the first 1,000,000 globally sorted eligible records, the runner scans the
remaining global order once. A record enters its source partition only when its
source is in that partition's frozen 1,024-row map and its observed target is in
that partition's frozen column map; reserved columns never match raw records.
It takes the first 4,096 such records per partition and stops only after both
counts close, otherwise Route C. Row and conditional target frequency ties use
binary-ASCII canonical-ID order after descending count.

Each partition's accepted-trace document has closed schema
`dynamic-cssc-route-a-snap-accepted-trace-v1` and contains exactly schema,
raw-object digest, mapping digest, partition, count, and ordered records. Each
record contains accepted ordinal, physical file ordinal, source/target IDs,
historical timestamp, and mapped row/column ordinals. Each `(partition,
semantics)` semantic-event document has schema
`dynamic-cssc-route-a-snap-semantic-event-trace-v1`, binds the accepted trace
and mapping, and records ordered atomic groups with rational logical time,
source provenance, optional expired occurrence, ordered SET transitions, and a
typed no-change reason. Rationals are integer numerator/denominator pairs; JSON
floats are forbidden.

Each `(shard,rho)` window document has schema
`dynamic-cssc-route-a-window-trace-v1`, binds the semantic-event trace and
shard, and records rational rho/freshness plus ordered windows: versions before
and after, close reason, event-group range, ordered SET references, first query
ordinal, and query count. This window object is strategy-independent canonical
input; each strategy and OpenFHE process still derives its own evaluation lane,
query IDs, and cryptographic objects. These three documents use the same
canonical ASCII-JSON rule as the acquisition receipt, and their SHA-256 values
cover their exact bytes.

### 6.3 Two semantics and fixed cells

Measured suffix execution starts from a fully empty logical state. The logical
matrix is the all-zero `1024 × 8193` matrix; the T1 occurrence map, T2 occurrence
map, and T2 FIFO are all empty. The first 1,000,000-record mapping prefix affects
only the frozen row/column identity maps. It initializes no matrix value,
occurrence count, tombstone, Publication Window, or FIFO state.

- `T1 cumulative`: `A_uv=min(7,N_uv)` under the registered coefficient bound
  seven; repeats after saturation are logged no-ops.
- `T2 event window`: retain exactly the most recent `K=1,024` accepted record
  occurrences in FIFO order. Before admitting record `i`, expire the unique
  oldest occurrence if the queue is full, decrement its coordinate
  multiplicity, and remove the coordinate at zero; then admit `i`, increment its
  coordinate, cap the visible value at seven, and append it. Expiry precedes
  admission inside the same atomic group. Each changed value emits its exact
  logical SET; a capped/no-change operation is logged but emits no SET. No query
  or Publication Window boundary may split the group.
- rho grid: `{0.1, 1}`.
- strategies: the same three fixed identities.

The exact rational query formula in Section 5.2 applies after each complete
group. At time `i/128`, the scheduler first closes any pending window whose
one-second deadline is at or before that time, then executes expiry/admission,
one payload-free logical tick, and the scheduled queries in that order.

Microbatch closure is pre-group and never splits an atomic group. Let `s` be the
current window's SET count and `g` the next group SET count. For `g=0`, the
microbatch rule does not close the window. For `g=1`, close before the group iff
`s+1>64`. For `g=2`, close before the group iff `s+2>65`. Then append the whole
group. Thus `63→65` is allowed, while `64→66` closes first. Any other `g` is
outside this plan and selects Route C.

The matrix contains `2 partitions × 2 semantics = 4` producer/replay shards and
`4 × 2 × 3 = 24` strategy-cells. T1 and T2 are never pooled. Partitions are
deterministic finite-corpus units, not independent draws from a population.
The paper calls this one official real-source ordered-event case study under a
controlled arrival clock; it must not imply multi-source or historical-timing
robustness.

## 7. Current-source OpenFHE matrix

The final paper source builds OpenFHE `1.5.1` from exact commit
`1306d14f8c26bb6150d3e6ad54f28dfe1007689e` with `BFVRNS`, ring dimension
8,192, plaintext modulus 65,537, batch size 8,192, effective slots 4,096,
`HEStd_128_classic`, `HYBRID` key switching,
`HPSPOVERQLEVELED` multiplication, and multiplicative depth 2. The runner image
is `ubuntu-24.04`; CPython is `3.12.13`; `BUILD_JOBS=2` and
`OMP_NUM_THREADS=2`.

OpenFHE is configured with Ninja, Release, C++17, extensions off, OpenMP on,
native optimization off, and its unit tests/examples/benchmarks off; the project
runner uses Ninja Release and the content-addressed OpenFHE install prefix.
Exact compiler/CMake/Ninja versions, complete compile commands, CPU model,
runner image release, rotation-key plan, query-vector digest, and serialized
object inventory are retained by the manifest. The current
`mixed_workload_parameterization=unfrozen` HOLD must be replaced in the final
source parameter manifest by the already frozen Route A parameters above and
pass mixed-circuit decrypt-correctness before qualification; the HOLD cannot
authorize a formal case.

The build location and accounting are fixed. Each formal OpenFHE case producer
builds the pinned source inside launcher-owned scratch after its critical-path
clock starts. That build, dependency/cache behavior, content-addressed runner
binary and libraries, build-package upload, and replay download all count both
toward the case's specific 25-minute gate, the universal 60-minute ceiling, and
the 2.5-hour OpenFHE segment. Replay does
not rebuild: it rehashes and uses the exact retained producer build package.
Qualification builds inside its own 45-minute NON-ADMISSIBLE critical path.

Six query-bearing native cases are mandatory—one for every fixed strategy and
scale:

| Strategy | S | M |
|---|---|---|
| `periodic-repack/windows=1` | required | required |
| `padding-reuse` | required | required |
| `packed-coo-cloud-segmented-delta/segment-width=128` | required | required |

The formal native workload therefore contains exactly

\[
6\ \text{cases}\times(1\ \text{discarded warm-up}
+3\ \text{producer evaluations}+3\ \text{exact replays})=42
\]

native evaluations. This count includes discarded warm-ups and evidence replay;
the three producer measurements per case remain the reported technical
repetitions.

Every case uses the synthetic formal seed `20260822`, `rho=1`, the terminal
accepted-event prefix (512 for S and 2,048 for M), and the query emitted after
the last accepted group. The deterministic scheduler selects the immutable
publication version serving that query; no earlier/later convenient version may
be substituted. The case binds the exact strategy state, ordered component
inventory, query vector, version, query ordinal, OutputPlan, execution plan, and
all retained canonical input bytes before native execution.

One OpenFHE case is one producer/replay/guard shard. Its producer job runs one
discarded warm-up process followed by three recorded fresh-key processes; the
producer uploads exactly one one-day NON-EVIDENCE handoff containing the build,
manifest, warm-up receipt, and all three separately framed retained packages.
The dependent replay job independently downloads and rehashes that handoff and
re-executes/verifies all three recorded packages before one guard admits exactly
one case artifact. Producer
repetitions use fresh disposable keypairs relative to one another. Each retained
test package contains its disposable test secret/public/evaluation keys,
canonical request, encrypted operands, and expected plaintext-oracle binding.
Replay generates no new keypair; it runs the deterministic Cloud-evaluation
path on those exact retained ciphertext and evaluation-key bytes. It requires
exact package identity and operation inventory, a valid output ciphertext, and
exact decrypted equality to both oracles. Output-ciphertext byte equality is not
an acceptance predicate; package/input byte identity and decrypted semantic
equality are. Thus the 25-minute specific gate is per complete case shard, not
per child process; 60 minutes remains only a universal absolute ceiling that
the tighter gate can never reach.
Every recorded repetition must:

- decrypt exactly to the typed and direct plaintext oracles;
- report actual `EvalMult`, `EvalAdd`, `EvalRotate`, key, mask, and reconstruction
  operations as applicable;
- report serialized ciphertext/key/result/metadata bytes;
- report end-to-end wall time, peak RSS, controlled scratch, and output digest;
- bind the exact registered strategy and plan identities; and
- pass independent payload rehash, replay, and final guard admission.

Zero-query windows for all three strategy identities are tested separately for
the absence of query-plan compilation and are not performance cells.

Mechanism coverage is predeclared. Both strong S and strong M snapshots must
contain a nonempty auxiliary segment; strong M must additionally contain an
actual overlap contributor group that exercises F1-M; and padding-reuse M must
exercise an actual padding or tombstone replacement. If the registered terminal
snapshots do not meet those conditions, Route A selects C. No earlier or later
snapshot may be substituted.

The three recorded processes are technical repetitions under one fixed case,
not independent population samples. Report every raw value plus median and
range; do not compute inferential confidence intervals or p-values. Every
reported quantity is labeled `native-measured`, `exact-simulator-count`, or
`exact-algebraic-projection`. Native latency is never added to predicted
full-stream cost as if both were the same measurement type.

## 8. Evidence lineage

Route A uses a fresh lineage whose source ancestry excludes the disposable
diagnostic anchor. The sequence is:

1. Stage 1, before runner implementation: jointly review and commit the exact
   preregistration, canonical machine plan, primary-source novelty review, and
   claim ledger; if a pre-implementation review exposes an execution ambiguity,
   commit only a narrowly reviewed clarification and rebind the same four-file
   packet before any runner implementation commit; if prior work covers the
   combination, select C.
2. Implement only the bounded runner, schemas, workflows, Behavior Sets,
   compatibility verifier, guards, tests, and analyzer against that commit.
3. Stage 2, before source acquisition or execution: review the exact
   behavior-source diff and tests, pass exact-head Linux CI, and designate one
   clean pre-anchor Experiment Source Snapshot `S1`. Its closed inventories
   include every Route A behavior source, workflow, schema, role-specific
   Behavior Set, registration/compatibility/guard path, analyzer, and the exact
   Stage-1 document blobs.
4. Generate the descriptive registration archive only from exact `S1` and
   independently reinspect it.
5. Create the terminal Evidence-Freeze Snapshot `S2` by adding only that
   reviewed registration data anchor to exact `S1`; no source, workflow,
   schema, mode, policy, analyzer, or documentation blob may change.
6. Produce the repository-owned ADR 0010 compatibility receipt with replace
   refs disabled, proving exact closed Behavior-Set path/type/mode/blob equality
   from `S1` to `S2` and rejecting missing or extra behavior entries.
7. Dispatch the workflow control plane from the exact terminal `S2` head so it
   can read the registration anchor and compatibility receipt, but run source
   acquisition, qualification computation, and every formal producer/replay/
   guard behavior only from a fresh detached exact-`S1` checkout. Every run and
   artifact records provider workflow head `S2`, experiment source `S1`, and the
   exact ADR 0010 compatibility receipt; the control plane rejects any behavior
   import or executable outside the attested `S1` tree. Later compatible
   descendants may add only monotonic data anchors and never become the
   experiment source.
8. Run acquisition and the complete formal matrix only in the registered serial
   budget order.
9. For every shard: producer → exactly one one-day NON-EVIDENCE handoff →
   independent replay → guard → exactly one formal artifact.
10. The acquisition guard first emits exactly one guarded formal
   acquisition/transform artifact without raw source bytes. Terminal admission
   then independently rehashes and admits the exact pre-aggregate set of that
   one acquisition artifact plus 16 shard artifacts; only afterward may the one
   aggregate be created and admitted. Missing, extra, duplicate, or wrong-kind
   input rejects.
11. Analyze only accepted artifacts in a detached, exact-compatible Analysis
   Source Snapshot `S3`. Every analyzer path, entry mode/type, and Git blob must
   equal the analysis Behavior Set frozen at `S1` through an ADR 0010
   compatibility receipt; the analysis run and output report `S1`, `S2`, and
   `S3` separately.

Changing any behavior-bearing source, plan, measurement, transform, or schema
after registration invalidates later authority and requires a new reviewed
lineage. External-model reviews remain advisory.

The expected **admitted** formal set is exact: 1 final-successful-attempt
acquisition/transform artifact containing receipts and derived traces but no raw
source bytes, 6 final-successful-attempt synthetic shard artifacts, 4 ordered-
event shard artifacts, 6 OpenFHE case artifacts, 1 aggregate artifact, and 1
accepted analysis-output bundle. Each admitted attempt has exactly one one-day
NON-EVIDENCE handoff: one for acquisition/transform and one per shard. If the
sole provider retry is used, every provider object from its failed attempt is
retained under that attempt ordinal but is permanently NON-ADMISSIBLE diagnostic
material and does not increase the expected admitted count. The terminal guard
accepts only the final successful attempt for each unit and rejects duplicate
admissible identities. The one qualification run
is permanently NON-ADMISSIBLE and, on GO, produces exactly the six one-day provider
artifacts named in the machine plan and zero formal artifacts. Missing,
additional, duplicated, or
self-consistently rehashed shard identities fail admission.

## 9. Resource qualification and hard stops

### 9.1 One non-admissible qualification

Before formal dispatch, run exactly one M-scale synthetic unit with workload
`mixed-insert-delete-modify`, seed `20260821`, all four rho values, and all three
strategies. The qualification is one strictly serial DAG—never parallel—in this
exact order:

1. `qualification-simulator-producer`;
2. `qualification-simulator-independent-replay-and-guard`;
3. `qualification-native-case-shaped-producer`;
4. `qualification-native-independent-replay-and-guard`; and
5. `qualification-combined-guard`; followed by
6. `qualification-postrun-resource-admission`.

The native producer uses strong M, seed `20260821`, `rho=1`, and the terminal
query. It builds the pinned source, runs one discarded warm-up and three
recorded fresh-key processes, then serializes the build and three retained test
packages. The independent native replay job downloads and rehashes that exact
handoff, creates no keypair, replays all three packages, and guards the same
case-shaped bundle used formally. It must contain a nonempty auxiliary segment,
an actual overlap group, and the F1-M random-mask path; otherwise Route A selects
C before timing is interpreted.

On GO the DAG uploads exactly six one-day provider artifacts, all permanently
NON-ADMISSIBLE: `q1-simulator-pre-replay-handoff`,
`q2-simulator-guarded-receipt`,
`q3-native-pre-replay-build-plus-three-retained-packages`,
`q4-native-guarded-case-bundle`, `q5-combined-guard-bundle`, and
`q6-postrun-resource-admission-record`. A failed or cancelled run may contain
only the exact completed prefix and is never GO. Their contents are closed by
the machine plan. The qualification produces zero formal artifacts.

Operational GO requires the combined guard to complete successfully within
45.00 minutes from the simulator-producer job's provider `startedAt` through
the combined-guard job's `completedAt`. This wall clock includes every dependent
job's queue gap, setup, handoff, build, replay, and guard. At the exact threshold,
if the combined guard is not successful, the controller requests cancellation
of only that exact run, records controller detection, provider API acknowledgement,
and provider completion lag separately, dispatches nothing further, and selects
C. The scale, matrix, order, or threshold is not changed
after observing qualification.

The combined-guard artifact deliberately contains no self-referential final
`completedAt`, `C_q`, or resource verdict. Only after job 5 is terminal does the
read-only job 6 query the provider API, verify final identities, timestamps, and
conclusions for jobs 1–5, compute the 45-minute decision and `C_q`, and upload
the post-run record. That record also binds job 6's run/job identity,
`startedAt`, observation time, and frozen deadline, but cannot contain or assert
job 6's own future `completedAt`, final conclusion, or 55-minute total-path
decision. Job 6 is outside `C_q` and the 45-minute computational critical path.
Its provider job timeout is 5.00 minutes and its wall-clock deadline is exactly
job 5 `completedAt + 10.00 minutes`, including its queue and handoff; therefore
the complete qualification wall clock is accepted only when the external live
controller later observes job 1 `startedAt` through job 6 `completedAt` at no
more than 55.00 minutes. A job-6 non-success, timeout, provider failure, missed
wall-clock deadline, or failed external verification cancels only the exact
qualification run, selects C, and cannot be rerun. Its artifact is
authority-false and cannot carry a replayable dispatch capability. Only after
job 6 is terminal-success may the external controller independently read job
6's provider `completedAt` and conclusion, re-read the record and all provider
state, verify the 55-minute decision, and return a nonserialized, ephemeral
operational capability. Formal dispatch remains forbidden without that fresh
check. Neither job 6 nor the live check is paper evidence.

That external role is exactly `route-a-live-dispatch-controller-v1`. Its
production program is frozen at S1 as
`scripts/control_route_a_publication.py`, backed by the deep module interface at
`src/dynamic_cssc/route_a_controller.py`; tests use an in-memory provider-
snapshot adapter. It reads the GitHub Actions API, never browser UI state. The
closed run fields are database ID, event, head SHA, head branch, attempt, status,
conclusion, created time, and updated time; job fields are database ID, name,
`startedAt`, `completedAt`, status, and conclusion; q6 artifact fields are ID,
name, provider digest, size, expiry, and workflow-run head SHA. Missing, extra-
identity, stale, retargeted, or inconsistent observations fail closed. Its only
positive output is a single-use, in-process, nonserialized ephemeral capability.

No Route A S/M-scale, three-strategy, or native-case timing was observed before
freezing this gate. The only prior native observation is non-authorizing PRE-S1
run `33138110298`: its pinned OpenFHE build step took 196 seconds and its two
tiny ordinary/strong smoke step took 2 seconds total. Those fixtures are not
Route A S/M cases and cannot predict their latency. The qualification gate's
sole quantitative workload input is the retired 4,096-row, 6,000-update,
14-candidate diagnostic, whose complete producer shard took
17,494.257326 seconds, almost all in its five full-rho state-transition cells.
A deliberately simple planning projection applies only
three predeclared reductions—`2048/6000` updates, `3/14` strategies, and `3/5`
full-rho cells—giving 767.748 seconds (12.796 minutes) for a producer and 25.592
minutes for producer plus same-work replay. Numerically, `45/25.592=1.758`; this
is only a gross gate-to-simulator-projection ratio. The remaining 19.408 minutes
must also contain all setup and queue gaps, the pinned OpenFHE build, the full
case-shaped native producer/package/replay/guard path, all five artifact
operations, and the combined guard. It is not a measured margin. The projection
is an administrative stop-loss rationale, not paper evidence, a fitted cost
model, or a promise that qualification will pass. The old 300-minute failure
remains unchanged.

The native planning rule is frozen but deliberately non-authorizing. Let `C_q`
be the sum of GitHub job API `startedAt`→`completedAt` durations for the native
producer job, native replay/guard job, and the **entire** combined-guard job.
It therefore includes checkout/runtime setup, dependencies and build, terminal
snapshot construction/import, warm-up, three producer evaluations, build and
three-package manifest/serialization/upload/download/rehash, three replays,
oracle/payload validation, native guard, same-schema NON-ADMISSIBLE case-bundle
assembly/upload/rehash, and terminal combined validation. Because job 6 runs
after all three API durations are final, it can evaluate the planning
screen

\[
6C_q \le 9{,}000\ \text{seconds}.
\]

Before GO, emit the exact structural vector for the probe and all six
deterministic formal case plans: ordered operation types/counts, rotation-key
indices, key/ciphertext multiplicities, component/page/segment/overlap topology,
canonical input bytes, type-derived maximum serialized-package bytes, and job/
build topology. Future randomized ciphertext sizes use the type-derived bound,
not unknowable pre-dispatch exact bytes. Any operation or mechanism class absent
from both this probe and the PRE-S1 real-runner smokes selects C. Count/byte
dominance is only disclosed; it is **not** a runtime theorem. Passing the screen
does not replace the formal 25-minute per-case and 2.5-hour cumulative acceptance
gates. Failure of decrypt correctness, mechanism coverage, the screen, or the
overall 45-minute gate selects C. Qualification timing is not paper data and
cannot amend the budget.

### 9.2 Formal budgets

- every formal unit is below the universal 60.00-minute critical-path ceiling;
  the tighter unit gates are 20.00 minutes for acquisition/transform, 50.00
  minutes for each synthetic shard, 40.00 minutes for each ordered-event shard,
  and 25.00 minutes for each OpenFHE case;
- complete acquisition-through-analysis formal campaign acceptance threshold:
  12.00 hosted runner-hours;
- no selective candidate or cell retry;
- at most one whole-unit retry across the entire campaign, only for the single
  acquisition/transform unit or one of the 16 fixed formal shards, after a
  provider-classified infrastructure preemption, with nominal
  `unit_attempt_ordinal=0`, sole replacement ordinal one, and both attempts
  retained;
  terminal admission, aggregation, and analysis are never retry-eligible; and
- no behavior/source repair or performance optimization after S1.

A runner-hour is the sum of GitHub job API `startedAt`→`completedAt` durations
for every Route A acquisition/transform, formal producer, handoff upload and
download, replay, guard, artifact admission, OpenFHE case, aggregation, analysis,
and permitted retry job. Environment setup, cache misses, native builds,
dataset transform, and artifact transfer inside those jobs remain charged.
Ordinary source CI, descriptive registration, and the separately reported
NON-ADMISSIBLE qualification are outside the formal 12-hour sum; no experimental
or analysis job may be relabeled as cache preparation to escape it.

Every eligible formal unit carries a canonical
`dynamic-cssc-route-a-unit-attempt-identity-v1` document containing exactly its
schema, logical unit-identity SHA-256, `unit_attempt_ordinal`, provider run ID,
and provider run attempt. Nominal ordinal is zero; the sole provider replacement
is one; no other value is legal. This identity enters every handoff, receipt,
formal artifact, evaluation lane, and terminal-admission record.

Formal dispatch is strictly serial and fixed: after qualification GO, run the
acquisition/transform unit; six OpenFHE cases in machine-plan strategy order
with S before M; six synthetic shards with S before M and ascending seed; four
ordered-event shards by partition with T1 before T2; then admission, aggregate,
and analysis. No two formal Route A jobs run in parallel. One unit's critical
path is its first producer job `startedAt` through its guard job `completedAt`,
including queue gaps and handoff; its charged runner seconds are instead the sum
of each constituent job's API duration, counted once.

Before a unit or child job starts, the controller recomputes an append-only
ledger of every charged job ID, stage, `startedAt`, `completedAt`, conclusion,
segment seconds, campaign seconds, and remaining reservation. It refuses a new
unit unless its complete frozen reservation and the untouched 30-minute
terminal segment remain. A child job receives the unit's shared remaining
ledger/deadline and cannot start another stage after it expires. At a unit,
segment, or campaign threshold, the controller requests cancellation of only
the exact active run, dispatches nothing further, retains and charges any
provider cancellation lag, and selects C.

| Budget segment | Exact units | Maximum runner-hours |
|---|---:|---:|
| Synthetic formal shards | 6 nominal producer/replay/guard chains | 5.0 |
| Acquisition/transform plus ordered-event formal shards | 20 min + 4 × 40 min | 3.0 |
| OpenFHE formal cases | 6 nominal producer/replay/guard chains | 2.5 |
| Admission, aggregate, and accepted analysis bundle | exact terminal jobs | 0.5 |
| One permitted provider-preemption retry | provider failure/replacement seconds charged beyond the original unit reservation | 1.0 |
| **Total** | all charged jobs | **12.0** |

The nominal reservations exactly close the four ordinary segments:
`6×50=300` minutes synthetic, `20+4×40=180` minutes acquisition/ordered,
`6×25=150` minutes OpenFHE, and 30 minutes terminal. The remaining 60 minutes
is retry reserve only. The 12-hour value is an **acceptance threshold**, not a
promise that GitHub billing cannot exceed it: provider cancellation latency is
outside repository control. Any observed overshoot is charged, reported, fails
Route A, and cannot authorize another job.

An infrastructure retry is permitted only when the GitHub API/log itself records
an Actions service/internal error, runner assignment failure, or loss/shutdown of
the hosted runner without a project command exit code. A timeout, user/agent
cancellation, nonzero process exit, assertion, resource-gate failure, artifact
validation failure, code/data error, or unclassified interruption is not
provider preemption. Both failed and replacement job durations count; if the
classification or one-hour reserve is insufficient, Route A selects C.

The sole replacement target must be one of exactly 17 enumerated units: the
single acquisition/transform unit, six OpenFHE shards, six synthetic shards, or
four ordered-event shards. Qualification, registration, CI, terminal admission,
aggregation, analysis, and every other job are ineligible. For that sole allowed
provider replacement, let the failed unit's unspent
ordinary reservation remain available and let retry remainder equal
`3600 seconds` minus all provider-failure/replacement seconds already charged
beyond ordinary unit reservations. The replacement may dispatch only if those
two amounts cover the unit's full original reservation; otherwise Route C.
Every failed-attempt handoff, partial artifact, log, and provider identity is
retained under its attempt ordinal but is permanently NON-ADMISSIBLE. Only the
final successful guarded attempt may occupy the unit's expected formal identity
or enter aggregate admission. A replacement producer uses a distinct
evaluation-lane digest, query ID, prepared-batch identity, and five-field F1-M
reservation key because `unit_attempt_ordinal` is part of the lane. Its replay
reuses only that same replacement lane; it never imports the failed attempt's
ledger identity.

For the acquisition unit, both attempt receipts also carry attempt ordinal. If
attempt zero completed a response-body observation, attempt one's
`compressed_byte_count` and `compressed_sha256` must match it byte-for-byte
before transform or admission. If no complete observation existed, attempt one
may establish the first source identity. Thus retry cannot silently select a
new source object or reuse an already sampled query/mask identity.

Retry reserve is never borrowed for a timeout, correctness failure, ordinary
overrun, or new work. Any qualification correctness failure or any later
behavior defect selects C immediately; there is no source-changing repair or
second qualification in this lineage.

Peak RSS is measured from Linux `wait4`/`ru_maxrss` for each owned child process
and reported in KiB with the process identity. Controlled scratch is one
launcher-created, non-followed directory; allocated bytes (`st_blocks*512`) are
summed after each registered stage and the maximum is reported. No background
system-wide sampler or unrelated process enters either quantity.

## 10. Figures, tables, and falsifiers

### 10.1 Required outputs

1. protocol diagram: updates → Publication Window → immutable version → global-
   column query reorganization → encrypted execution → private OutputPlan
   reconstruction;
2. reconstruction diagram: overlap sum, disjoint concatenation, implicit zero,
   and overlap-only F1-M;
3. correctness/fail-closed matrix table;
4. bounded S/M raw-point plot for publication time, query-linear accounting,
   and serialized bytes, with every seed and no fitted/extrapolated scale law;
5. publication-vs-query trade-off plot for the three fixed strategies, without a
   global-winner, Pareto-frontier, or privacy-equivalence label;
6. one-source T1/T2 cost-decomposition plot;
7. six-case OpenFHE correctness and resource table; and
8. evidence-boundary table separating historical context, CI/PRE-S1, formal
   current-source artifacts, and analysis outputs.

The two plaintext context cells appear in a descriptive table, not as speedup
bars. The evidence-boundary table is placed in methodology or the artifact
appendix and is not presented as a scientific contribution.

### 10.2 Falsifying outcomes

Route A stops and becomes C if any of the following occurs:

- a legal ordinary or strong output differs from either plaintext oracle;
- an illegal version/query/plan/payload substitution is accepted;
- an F1-M identity can be reused or masks do not cancel exactly;
- current-source ordinary or strong OpenFHE cannot finish on the ordinary runner;
- resource qualification or any formal critical path exceeds its frozen gate;
- the campaign exceeds 12 runner-hours before complete artifact acceptance;
- completing the minimum matrix requires a second evidence or adapter hierarchy;
- the three registered strategy implementations produce identical ordered
  component-state evolution **and** identical preregistered cost vectors in
  every ordered-event cell, contradicting the registered distinct-mechanism
  contracts; or
- the pre-implementation primary-source novelty gate is absent, unresolved, or
  finds prior work already covers the full combined Route A contribution.

If a particular fixed strategy is slower, fails to dominate, or has an
unfavorable trade-off while remaining correct and within the resource gate, that
is reported and is not itself a stop condition.

SparseE's publicly available material is a time-dependent novelty boundary. If
its full text becomes public before formal dispatch, dispatch pauses until the
commit-bound novelty review is reopened. If it becomes public after immutable
formal runs have already been dispatched, those exact runs are not cancelled
solely for that publication event, but no not-yet-dispatched shard may start;
result interpretation, aggregate acceptance, manuscript claims, and submission
pause until the review is repeated. A final availability check is mandatory
immediately before submission.

## 11. Existing evidence disposition

The historical `fcb00e0d` fixture, old R0 test counts, issuer CI/PRE-S1 runs, and
both cancelled diagnostics may appear only in a repository engineering history
or a short manuscript provenance paragraph. They are excluded from estimators,
plots, tables of results, and current-source correctness claims.

Every number in the Route A abstract, results, discussion, and conclusion must be
regenerated from the fresh formal lineage defined here. The old diagnostic
timings may motivate the internal resource budget but are not paper data.

## 12. Minimum publication target and schedule

The authorized target is a methods/protocol workshop or short-paper submission.
A cryptographic-engineering journal is a stretch target only if all current-
source OpenFHE, ordered-event, correctness, artifact, and bounded-cost evidence is
complete and the functional propositions are presented rigorously.

After the novelty matrix and this preregistration pass review:

- week 1: commit the reviewed four-file Stage-1 packet, then implement strictly
  against the already frozen canonical plan by reusing the existing compiler/
  OpenFHE/replay/guard deep modules; complete the bounded orchestrator, proof and
  property matrix, schemas, exact source review, exact-head CI, descriptive
  registration, and terminal S2 gate;
- week 2: only after Stage-2 closure, run the sole synthetic qualification; only
  on GO, acquire the one official object and execute/replay the already frozen
  deterministic transform as the first formal unit. No transform, schema, plan,
  or policy edit is permitted after acquisition;
- week 3: if qualified, run and independently admit the complete formal campaign;
- week 4: generate figures, independently recompute at least P2 or P3a from
  accepted artifacts, rewrite/render Word and PDF, and package the submission.

The bounded Route A attempt is planned for three to four weeks; two-week
completion is not an execution or submission assumption. This schedule assumes
the existing query compiler, OpenFHE runner, replay/guard, and private evidence
interfaces can be reused without a new adapter/receipt hierarchy. If that
assumption fails, Route C is selected. Four weeks is a planning boundary, not an
acceptance promise. If the formal campaign is incomplete after three execution
weeks, freeze accepted material as a technical report or stop rather than expand
scope.

## 13. Freeze checklist

Before any Route A run, record:

- [ ] a commit-bound primary-source novelty matrix covering the complete
  combined contribution, with a PASS decision before runner implementation and
  explicit HOLD on every `first`, `only`, global-novelty, patent-novelty, and
  formal-security formulation;
- [ ] exact contribution and non-claim text in manuscript and claim ledger;
- [ ] exact strategy IDs, sizes, workload, rho values, seeds, real-source object,
  partitions, semantics, and query vector identity;
- [ ] exact total behavior and matched cost boundary for every strategy;
- [ ] exact OpenFHE source/build/parameter identities, retained-package replay
  mode, mechanism-coverage cases, and build/budget location;
- [ ] exact correctness and substitution cases;
- [ ] written P1--P4 definition-level proofs plus an exact-S1 predicate/source-
  conformance review before any universal correctness wording is released;
- [ ] exact producer/replay/guard/formal-artifact schemas;
- [ ] exact emitted-metadata byte rule, S1-frozen per-category type-derived
  maximum serialized-byte formulas, and permanent separation from native bytes;
- [ ] exact canonical plan path, canonical bytes, and SHA-256 inserted in this
  preregistration;
- [ ] exact qualification derivation, native planning rule, formal resource
  gates, budget segments, the PRE-S1 timing disclosure, and the declaration that
  no hidden Route A S/M or native-case timing was observed;
- [ ] exact stop and retry rules;
- [ ] exact `route-a-live-dispatch-controller-v1` program/module paths, provider-
  API field set, in-memory test adapter, and single-use capability contract in
  the S1 Behavior Set;
- [ ] exact expected set of one guarded acquisition/transform artifact, 16 shard
  artifacts, one aggregate, and one analysis output bundle, including terminal
  admission of the exact 17-artifact pre-aggregate set;
- [ ] independent local and advisory review with no unresolved P0/P1;
- [ ] the exact four-document preregistration packet, including any narrowly
  reviewed clarification amendment, committed before runner implementation;
- [ ] the separately reviewed source/CI/registration/data-anchor freeze after
  implementation and before source acquisition or execution; and
- [ ] a current SparseE/full-text and first/only wording check immediately before
  submission.
