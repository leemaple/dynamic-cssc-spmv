# Methods and Claim–Evidence Skeleton

> **Paper-writing status.** This is a methods-first skeleton, not a results draft.
> It permits design and protocol descriptions that are supported by the frozen
> contract and accepted ADRs. It keeps performance, complete-reference,
> end-to-end, formal, and security-effectiveness claims on HOLD until the exact
> gates and artifacts listed below exist for the manuscript commit.

## 1. Scope and source hierarchy

This skeleton uses the following local sources, in descending order of authority:

1. the CSSC paper evidence audits derived from the authors' PDF, TeX, and the
   cited Halevi--Shoup `totalSum` source
   ([query reorganization](../research/cssc-query-reorganization.md),
   [aggregation schedule](../research/cssc-query-aggregation-schedule.md));
2. the machine-oriented protocol contract
   ([protocol v2.1b](../protocol-patch-v2.1b.md));
3. accepted design decisions
   ([ADR 0003](../decisions/0003-f1m-hidden-rowmap.md),
   [ADR 0005](../decisions/0005-output-plan-overlap-blinding.md),
   [ADR 0006](../decisions/0006-persistent-strategy-snapshots.md),
   [ADR 0007](../decisions/0007-anonymous-fixed-segment-primitive.md), and
   [ADR 0008](../decisions/0008-strong-whole-query-execution-bundle.md));
4. current repository status and evidence policy
   ([README](../../README.md), [architecture](../architecture.md), and
   [review checkpoints](../review-checkpoints.md)); and
5. the earlier, commit-scoped
   [ZCode paper-claim audit](../reviews/zcode-paper-claim-audit.md).

Where these sources disagree, Section 9 records the disagreement. A manuscript
must not silently choose the version that enables the stronger claim.

The CSSC citation of record is Gao et al., *Efficient Privacy-Preserving Sparse
Matrix-Vector Multiplication Using Homomorphic Encryption*, arXiv:2603.04742 /
*Information Sciences* 739 (2026) 123180. The `2025/1935` identifier in the
parent directory refers to a different paper and must never enter the manuscript,
bibliography, artifact title, or contribution narrative.

## 2. Attribution boundary

### 2.1 Published CSSC substrate: cite, do not claim

The following belong to the published static CSSC method:

- the Compressed Sparse Sorted Column layout, including nonzero-count-based row
  sorting and capacity-fitting chunk construction, plus `Value`, `ColumnIndex`,
  `RowMap`, and chunk metadata;
- `ColumnIndex` as the original matrix-column address for each value lane, with
  a padding sentinel rather than a chunk-local or slot-domain address;
- the implication that Client B prepares one aligned encrypted query vector per
  CSSC value chunk;
- physical-to-logical row recovery through `RowMap`; and
- per-chunk aggregation, masking of invalid lanes, and cross-chunk summation in
  the static single-matrix query.

The repository reconstruction is derived from published pseudocode. No author
code was located, so use **independent pseudocode-derived reconstruction**, never
“reproduction of the authors' implementation.”

### 2.2 Our method candidates: describe at design/protocol level

The defensible project-specific method candidates are:

- update-aware Publication Windows and version-matched Published Components;
- version/freshness binding for layouts, per-chunk global `ColumnIndex`
  metadata, query preparation, and reconstruction;
- the RowMap-sensitive `dynamic-cssc-output-plan-v1` OutputPlan for multiple
  components and output blocks;
- logical-coordinate contributor multiplicity, implicit-zero reconstruction,
  overlap-only zero-sum blinding, and persistent no-reuse bindings;
- independent persistent strategy snapshots and a tuning-only fixed policy;
- the anonymous fixed-segment cloud primitive and client merge of leaders whose
  logical-row equivalence is hidden from the Cloud;
- the single whole-query execution bundle that binds the real CSSC base, strong
  delta, typed Cloud DAG, private routes, operands, counts, and commitments; and
- fail-closed evidence separation among design, predicted proxy, measured unit
  evidence, and end-to-end evidence.

These are extensions around CSSC, not a renaming of CSSC internals. The named
maintenance strategies are comparison families unless a separate novelty review
supports a stronger attribution statement. `BestFixed-Offline-Oracle` is a
diagnostic comparison bound, not an online algorithm.

## 3. Proposed Methods section

### 3.1 Problem setting and publication boundary

Model a mutable sparse matrix as a sequence of committed logical versions. Updates
accumulate inside a Publication Window. Closing a window produces a new version,
whose components, metadata, OutputPlan, and query-preparation inputs must agree on
one `version_id` before the version becomes queryable.

State the window-closing causes explicitly, such as query arrival, freshness
deadline, microbatch policy, or a publication decision. Do not treat the window
as an arbitrary simulator epoch: it is the causal boundary between mutable logical
state and immutable query-visible state.

Every accepted transition must validate the full candidate matrix version and
decode its published components back to the intended logical state before commit.
An update that violates the frozen per-row support or coefficient domain is not
publishable under the contract.

### 3.2 Static CSSC encoding and query reorganization

For each component, sort physical rows as prescribed by CSSC, retain the map to
logical rows, and carve capacity-fitting column-major rectangles into value
chunks. Each physical value lane carries an aligned original-matrix column
address or a padding sentinel.

Client A sends the version-matched plaintext `ColumnIndex` metadata to Client B.
For each value chunk, Client B gathers the dense query in plaintext:

```text
q_chunk[lane] = 0                         if CI[lane] is padding
q_chunk[lane] = q[CI[lane]]               otherwise
```

Client B then encrypts the aligned chunk and sends it to the Cloud. The global
matrix-column domain and ciphertext-slot domain are independent: a valid column
identifier may lie outside the effective slot range, but each gathered chunk must
fit the effective slots. Taking `ColumnIndex` modulo the slot count changes the
function and is forbidden.

Count Client-A-to-Client-B metadata synchronization separately from per-query
Client-B-to-Cloud ciphertext upload. The published CSSC communication table does
not close the cost of transmitting the full per-lane global index representation,
so the manuscript must use the repository's actual serialized bytes when that
evidence exists.

### 3.3 CSSC-compatible reduction and the non-power-of-two caveat

Let a product ciphertext encode a column-major chunk of height `h` and width `w`.
The CSSC paper prints a bit-decomposed reduction whose abstract rotation and
intra-chunk addition node count is

```text
f(w) = floor(log2(w)) + popcount(w) - 1.
```

That formula is exactly derivable from the paper's loop; it is not, by itself,
evidence of author-code behavior, primitive key-switch count, latency, or noise.

For non-power-of-two `w`, the paper-literal set-bit branch is incorrect. It adds
the current accumulator to its own rotation, which repeats coefficients. The
CSSC paper cites Halevi--Shoup `totalSum`; the compatible correction retains the
original product ciphertext and uses it as the unrotated addend in that branch:

```text
original = product
acc = original
...
if current lower bit of w is one:
    acc = original + Rot(acc, h)
```

The cited HElib correction preserves the paper-derived abstract node count and works
for general widths. It must be described as a **corrected CSSC/HElib total-sum
interpretation**, not as verified CSSC-author code and not automatically as our
novel algorithm.

The repository now realizes that interpretation through one stored-power/prefix
CSSC-compatible DAG. It stores reusable power-of-two partial sums, combines the
required binary prefixes, and records an explicit direct shift on every rotation
node. The resulting DAG has `f(w)` abstract rotations and intra-chunk additions.
Both the simulator and the strong execution adapter now use this common executable
DAG, so their schedule and abstract operation accounting agree at the DAG boundary.

Keep four cases distinct:

| Reduction | General-width correctness | Abstract cost | Attribution / role |
|---|---|---|---|
| Paper-literal Algorithm 4 | No, when the set-bit branch is reached | `f(w)` nodes | Published pseudocode, with defect |
| Cited HElib corrected `totalSum` | Yes | `f(w)` nodes | Semantic correction supplied by the cited source |
| Stored-power/prefix corrected DAG with explicit direct shifts | Yes | `f(w)` nodes | Current repository common compiler used by simulator and strong adapter |
| Direct rotations of the original product | Yes | `w-1` nodes | Historical repository alternative; no longer the current schedule |

Padding the chunk width to the next power of two is a fifth possible design, but
CSSC does not specify it and it requires a separate slot-capacity check. Do not use
the power-of-two strong-delta segment primitive as proof that CSSC chunk widths are
power-of-two.

Report separately: abstract rotation nodes, primitive rotations/key switches after
key decomposition, intra-chunk additions, plaintext mask multiplications, and
cross-chunk additions. The common DAG closes predictor/adapter schedule identity only
at the abstract executable-DAG level. Direct-key realization, primitive key-switch
count, time, and noise remain unmeasured, and a current successful witness is pending.

### 3.4 Independent causal maintenance snapshots

Advance one persistent strategy snapshot through every ordered Publication Window.
Warm-up and tuning windows mutate that strategy's state even when their costs are
excluded from held-out summaries. Freeze the tuned fixed policy before held-out
evaluation and continue from its own post-tuning state.

Do not select the per-window cheapest strategy using held-out information. Do not
feed the offline oracle into the selector. Online cross-strategy switching is out
of scope until migration or parallel-maintenance costs are modeled.

The client-lane packed-COO candidate remains an ablation: the Cloud returns segment
lanes and clients merge them under the OutputPlan. It is not the strong
cloud-segmented packed-COO reference and cannot make the reference set complete.

### 3.5 Versioned OutputPlan and reconstruction

For each version, define a private mapping

```text
(component_id, output_block_id, physical_lane) -> logical_coordinate.
```

Client A and Client B receive the complete RowMap-sensitive OutputPlan. The Cloud
receives only its canonical digest and opaque identifiers. Client B initializes a
public-length logical output vector to zero, reorders decrypted shares by the
plan, adds contributors only when they map to the same logical coordinate, and
concatenates disjoint horizontal output blocks.

A coordinate without a physical contributor remains an implicit zero. A reserved
physical lane is different: it is real capacity and must incur the publication and
query operations defined by its strategy.

### 3.6 F1-M overlap-only blinding

For contributor multiplicity `m > 1`, Client A samples `m-1` independent uniform
elements in the plaintext ring and sets the final share mask to their negative
modular sum. A singly contributed coordinate remains unmasked; disjoint horizontal
blocks remain concatenated and are never added merely because their ciphertexts
were returned.

Bind every random mask to

```text
(query_id, version_id, output_plan_digest, component_id, output_block_id).
```

Client A atomically reserves this binding in a persistent ledger before drawing
mask randomness from the operating-system CSPRNG with unbiased rejection sampling.
A reservation is treated as consumed after a crash. The reproducibility seed is
simulation-only and must never seed protocol masks.

The strong fixed-segment program keeps one visible ciphertext-addition position per
returned share. An overlap uses a random zero-sum operand; a disjoint return uses
an encrypted-zero dummy. Dummy operands change operational counts but do not change
the logical rule that random masks exist only for overlapping coordinates.

Scope the intended effect precisely: F1-M is designed to prevent the decrypting
recipient from separating overlapping component contributions beyond their final
sum. It does not hide the full OutputPlan from Client B, hide the result from Client
B, provide malicious security, or prove simulation-based security.

### 3.7 Anonymous fixed-segment strong path

Allocate public fixed-width, power-of-two physical segments. Each segment contains
entries from one logical row, while the Cloud sees only public page/segment shapes
and opaque ordinals. The Cloud performs the same page-wide program and reduces each
segment to its own leader lane.

Leaders from different opaque segments remain separate even if they contribute to
the same hidden logical row. Client B merges them under the version-bound OutputPlan.
Cloud-side merging would reveal row equivalence unless an additional oblivious
routing construction were specified.

Compile the real CSSC base and strong delta into one deterministic execution bundle.
The bundle owns the typed Cloud DAG, private routes, global-column operands,
versions, commitments, and DAG-derived counts. Any mutation of private routes,
column metadata, or versions must fail binding validation rather than alter a
previously valid prepared query.

The Phase 2 whole-query witness passed at `fbd9712`, but manifest-bound changes were
then merged at `5bf0e51`. No successful witness covers that current implementation.
The integration and workflow are implemented, but the strong candidate remains
unevidenced for the current implementation and unregistered.

### 3.8 Correctness and parameter boundaries

State integer correctness as a centered-lift sufficient condition: bound the absolute
row sum before publication, accumulate all component values modulo the plaintext
modulus, and centered-lift only after the final component sum. This condition is not
a noise-budget proof or a mixed-circuit parameter claim.

The deterministic exact-layout preflight must exercise multiple output ciphertexts
and at least one actual global column address outside the effective slot range. A
dimension that permits such an address is insufficient unless a real nonzero uses it
and the test rejects modulo-slot reconstruction.

Mixed-circuit parameters remain unfrozen. P0a rotation-layout evidence says nothing
about multiplication depth, noise margin, wall-clock performance, or end-to-end
decryption correctness.

## 4. Threat and leakage scope

The protocol model is static semi-honest corruption of at most one of Client A,
Client B, and the Cloud, with no Cloud/client collusion. It makes no malicious,
adaptive-corruption, availability, side-channel, traffic-analysis, or collusion
claim.

| Party | Authorized knowledge in F1-M | Must remain hidden from that party |
|---|---|---|
| Client A | Matrix, updates, CSSC metadata, complete plans, public parameters | Client B's secret key and plaintext query |
| Client B | Query, secret key, versioned global indices, complete plans, final result | No claim hides matrix support or plan routes from Client B |
| Cloud | Public parameters; ciphertext shapes/counts; public page/segment shapes; operation schedule; opaque IDs; query/version IDs; canonical plan digest | Values, query plaintext, secret key, `ColumnIndex`, component `RowMap`, full OutputPlan, mask plaintexts, and unblinded component values |

Do not pool Public-RowMap and Hidden-RowMap results. Shape, count, schedule,
identifier, and timing leakage are within the stated Cloud ACL; the design does not
claim to eliminate them.

## 5. Evidence ladder

| Level | Evidence admitted | Claims it can support | Claims it cannot support |
|---|---|---|---|
| E0 — primary-source interpretation | Author PDF/TeX and cited algorithm source, with conflicts disclosed | Attribution and reconstructed algorithm semantics | Author-code behavior or implementation correctness |
| E1 — design/code inspection | Contract, ADR, typed code, tests present in tree | “specified,” “designed,” or “implemented” at a named commit | A gate passed, measured cost, or executed protocol correctness |
| E2 — commit-bound CI receipt | Passing workflow artifact, provenance, manifest, raw logs, checksums | Only the artifact's explicit evidence scope | Later commits or a broader circuit/protocol |
| E3 — causal predicted artifact | Replayed Day 1 suite with persistent snapshots and complete receipts | Predicted-proxy behavior for the admitted candidate set | Measured speed, complete-reference verdict when the set is partial |
| E4 — pinned cryptographic witness | Successful independently validated primitive or whole-query artifact | Correctness of that exact witness and binding | Security, end-to-end deployment, candidate registration by itself |
| E5 — measured unit evidence | Pinned Day 2 raw repetitions and key plan | Unit measurements for the exact profiles | End-to-end latency or unfrozen mixed-circuit safety |
| E6 — end-to-end review artifact | Full protocol execution, correctness vectors, leakage-mode demonstration, accounting, provenance | Narrow claims expressly tested by R4 | Formal security unless a separate proof is supplied |

Evidence never flows upward by implication. In particular, E2 P0a evidence cannot
be used as E5 or E6 evidence, and an E4 fixture cannot authorize a candidate registry.

## 6. Claim-to-gate and artifact matrix

`<sha>` below is the exact source commit evaluated by the manuscript. A paper claim
must cite both its source commit and immutable artifact digest.

| Future manuscript claim | Minimum required gate | Exact required workflow artifact / content | Current status |
|---|---|---|---|
| Protocol roles, ACL, and v2.1b freeze are enforced | R0 on manuscript `<sha>` | [`ci.yml`](../../.github/workflows/ci.yml): `r0-freeze-<sha>` plus `review-pack-R0-<sha>`, manifest, tests, logs, and checksums | Historical R0 exists for an earlier commit only; current-HEAD claim HOLD |
| Packed BFV slot permutations match the logical rotation plan | P0a/R1 on manuscript `<sha>` | [`p0a-rotation-probe.yml`](../../.github/workflows/p0a-rotation-probe.yml): `r1-p0a-<sha>` plus `review-pack-R1-P0a-<sha>`, raw layouts, plan, build provenance, and checksums | Historical scoped PASS only; do not generalize |
| Exact publication layout preserves global-column query semantics | Current-commit deterministic preflight inside R2 | [`day1-cost-model.yml`](../../.github/workflows/day1-cost-model.yml): `r2-day1-<sha>-<seed>` with `results/day1/SUITE_STATUS.json`, preflight PASS, replay receipts, and `SHA256SUMS` | Not run; workflow contract exists, but no R2 artifact exists |
| Maintenance evaluation is causal across windows | R2 causal replay | Same `r2-day1-<sha>-<seed>`; status must declare persistent strategy snapshots and all independent replay receipts must verify | Not run; workflow contract exists, but no R2 artifact exists |
| Predicted trade-offs for the current partial candidate set | R2 causal replay with strict labeling | Same R2 artifact; must say predicted proxy, `complete_reference_set=false`, missing `strong-packed-coo`, and no gate-eligible full-cost verdict | Not run; therefore no predicted trade-off result currently exists |
| Anonymous fixed-segment primitive executes correctly | Phase 1 pinned witness | [`strong-packed-coo-witness.yml`](../../.github/workflows/strong-packed-coo-witness.yml): `strong-packed-coo-witness-success-<sha>` with passing `RUN_STATUS.json`, witness, bindings, provenance, validation log, and checksums | Narrow primitive evidence only; no registration/security/performance claim |
| Real CSSC base plus strong delta execute one bound query correctly | Phase 2 pinned whole-query witness | [`strong-whole-query-witness.yml`](../../.github/workflows/strong-whole-query-witness.yml): `strong-whole-query-witness-success-<sha>`; `RUN_STATUS.json` must be pass/evidence-valid and all witness, property-contract, binding, provenance, manifest, validation, and checksum files must verify | Passed at `fbd9712`, then superseded by manifest-bound changes merged at `5bf0e51`; no successful witness covers the current implementation |
| Strong packed-COO is an admitted reference candidate | Registration gate after Phase 2 | Successful Phase 2 artifact **plus** independent trust anchor, SHA-bound builder/property contract, report/accounting schema update, registry entry, and tuning-prefix evidence for the frozen segment family | HOLD; witness success alone is insufficient |
| Full fixed-reference comparison or full-baseline ranking | Complete-reference R2 rerun | A revised Day 1 contract and `r2-day1-<sha>-<seed>` that admit the registered strong candidate and state `complete_reference_set=true`; current workflow intentionally enforces false | HOLD; no current result may use this wording |
| F1-M blinding works in encrypted whole-query execution | R4 minimal prototype | `review-pack-R4-<sha>` containing encrypted masks/dummies, ledger/batch-token trace, correct decryption/reconstruction vectors, leakage mode, communication/memory accounting, provenance, and checksums | HOLD; plaintext/domain design or Phase 2 witness is insufficient |
| Measured unit costs calibrate the operation-count model | P0b/Day 2 plus frozen mixed-circuit correctness gate | [`day2-microbench.yml`](../../.github/workflows/day2-microbench.yml): `r3-day2-<sha>` and `review-pack-R3-Day2-<sha>` with raw repetitions, key plan, profiles, provenance, and checksums; additionally, a named mixed-circuit artifact | HOLD; the mixed-circuit workflow/artifact contract is not yet specified in the cited sources |
| End-to-end correctness, communication, memory, or latency | R4 on manuscript `<sha>` | `review-pack-R4-<sha>` containing full OpenFHE execution, correctness vectors, raw accounting, all strong references, manifest, logs, provenance, and checksums | HOLD; no dedicated R4 workflow contract is specified here |
| Formal or simulation-based security | Separate proof and proof-review gate | A versioned proof artifact defining ideal functionality, leakage, simulator, and theorem assumptions; R0--R4 artifacts are not substitutes | Not claimed; no such gate/artifact is defined |

Artifact names follow [review-checkpoints](../review-checkpoints.md) and the linked
workflow definitions. Where the sources name a gate but not an executable workflow
or exact artifact schema, the matrix marks that gap instead of inventing evidence.

## 7. Current HOLD and permanent exclusions

Until the corresponding row in Section 6 passes, HOLD every strategy-win or ranking
claim; every measured, calibrated, bandwidth, memory, latency, complete-reference,
strong-registration, end-to-end, mask-effectiveness, mixed-circuit, parameter-safety,
formal-security, or simulation-based-security claim. Also HOLD current-HEAD validation
based only on the earlier R0/P0a receipts. “Implemented” must remain distinct from
“validated” and “measured.”

Permanently exclude claims based on a chunk-local or modulo-slot `ColumnIndex`, one
query ciphertext for the whole CSSC matrix, arbitrary addition of disjoint output
blocks, server-side plaintext masking in Hidden-RowMap F1-M, relabeling client-lane COO
as the cloud-segmented reference, attributing our dynamic/version/OutputPlan/F1-M/causal
state to CSSC, reproducing unlocated author code, or citing `2025/1935` as CSSC.

## 8. Threats to validity and leakage limitations

| Threat | Required manuscript limitation |
|---|---|
| Construct | The common DAG aligns simulator and strong adapter at the abstract executable-DAG level, but an abstract rotation is not a measured primitive key switch; direct-key realization, primitive key-switch count, time, and noise remain unclosed. |
| Internal | Causality requires strategy-local snapshots, state changes through excluded windows, decode-and-verify, and independent replay receipts. |
| Comparison | Client-lane packed COO is not the strong cloud-segmented reference; the current reference set is partial. |
| External | Synthetic workloads, one seed, and one manifest do not establish robustness across matrices, update processes, freshness policies, platforms, or HE parameters. |
| Protocol | Client B learns global indices and the full plan; the Cloud learns shapes, counts, schedules, IDs, timing, and the digest; F1-M does not hide all access or traffic patterns. |
| Evidence | Historical receipts are commit/version-bound; private, superseded, or cross-run bundles need independent provenance checks. |

## 9. Source contradictions and unresolved decisions

| Conflict | Required treatment |
|---|---|
| CSSC alternately calls sparsity public and hidden from the Cloud. | Present F1-M's ACL as our project decision; do not claim CSSC has a consistent support-hiding model. |
| Algorithm 1/Figure 3 send `ColumnIndex` to Client B, but nearby prose sends it to the Cloud. | Disclose that v2.1b freezes the Algorithm 1 interpretation. |
| CSSC does not freeze a unique key holder/result recipient. | Attribute Client B's key, plan, and reconstruction role to this project. |
| Algorithms 1 and 2 expose inconsistent chunk/map interfaces. | Call ours an independently specified reconstruction, not a verified author API. |
| Literal non-power reduction conflicts with cited `totalSum`; figure/table counts also do not close. The new audit derives `f(w)` from the loop while the older ZCode audit calls it heuristic. | The shared stored-power/prefix DAG now closes simulator/adapter schedule identity at the abstract level; still use “paper-intended corrected-totalSum abstract count,” never “exact author implementation or primitive-key cost.” |
| ZCode at `e2b411e` says snapshots were documentation-only; current README/workflow contracts describe causal persistent snapshots. | Treat this as a temporal conflict; only a current-commit R2 artifact with replay receipts retires the finding. |
| ADR 0007 lists whole-query integration as missing; ADR 0008/README later call it implemented. The Phase 2 witness passed at `fbd9712`, then manifest-bound changes were merged at `5bf0e51`. | Use “implemented; the prior witness was superseded, no successful witness covers the current implementation, and the candidate remains unregistered.” |
| R0/P0a are bound to `eb15adf5da22f600a31d4b62897ed35c1ecde2e2`, earlier than current development. | Keep their scope historical; rerun for the manuscript commit. |
| v2.1a/v2.1b artifacts have similar names and checkpoint history. | Admit only v2.1b evidence whose manifest, commit, run, and checksum agree. |
| Mixed-circuit and R4 gates are named without dedicated workflow/schema contracts. | Keep the associated claims on HOLD until those contracts are specified and run. |

## 10. Minimal SCI/EI assembly order

1. Introduction: mutable encrypted SpMV motivation, without empirical superiority.
2. Background: attributed CSSC plus disclosed source ambiguities.
3. System/threat model: roles, ACL, versions, and leakage limits.
4. Method: causal publication, query reorganization, corrected reduction, OutputPlan,
   F1-M, fixed segments, and the whole-query bundle.
5. Evidence methodology: causal split, oracle hygiene, ladder, and provenance.
6. Evaluation: only Section 6 artifact-backed claims, with predicted and measured
   evidence visibly separate and no cross-mode/version/commit pooling.
7. Threats, related work, and conclusion: no “first” without a novelty review; restate
   only claims whose gate status is no longer HOLD.
