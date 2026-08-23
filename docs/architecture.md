# Architecture

## Research pipeline

```text
P-1 protocol 2.1b manifest
    ↓
P0a actual BFV layout probe
    ↓
257x521/256 global-ColumnIndex preflight
    ↓
Day 1 causal layout/count simulator
    ↓ required rotation indices
P0b key plan + Day 2 measured unit costs
    ↓
held-out Pareto gate
    ↓
minimal OpenFHE prototype
```

## Functional modes

- **F1-M Hidden-RowMap** is the default publication mode.
- **F1-L** is allowed only as an explicitly weaker leakage experiment.
- **F2** is an extension requiring cloud-side physical output alignment.

## Protocol 2.1b invariants

- The stated semi-honest threat model assumes at most one corrupted party and no
  Cloud/client collusion. The manifest carries an explicit per-party leakage ACL;
  no formal-security claim is currently authorized.
- Client A sends versioned plaintext ColumnIndex metadata to Client B for every CSSC
  chunk. Client B generates an aligned reorganization-vector ciphertext per chunk;
  the typed Cloud interface omits ColumnIndex values and component RowMaps. This
  access-control rule is not a proof that other declared leakage cannot reveal
  relationships.
- Client A and Client B both receive the complete versioned, RowMap-sensitive OutputPlan;
  its Cloud-facing projection contains its canonical digest and opaque identifiers. The
  other declared Cloud leakage includes published shapes/counts, schedule/timing,
  query/version identifiers, and binding digests. Client B uses the complete plan to
  reorder and combine decrypted Output Shares.
- Output reconstruction uses `dynamic-cssc-output-plan-v1`. Only logical-coordinate
  overlap is zero-sum masked; disjoint Output Blocks are concatenated unmasked. Logical
  coordinates with no physical contributor reconstruct as implicit zeros.
- Client A atomically reserves each five-field mask binding in a persistent ledger before
  drawing masks from the operating-system CSPRNG with unbiased rejection sampling.
- Every published matrix version enforces at most 4,096 nonzeros per row, so the centered
  bound is `B=4096*7*1=28672` and `2B=57344<t=65537`.
- The reproducibility seed is simulation-only. Mixed OpenFHE circuit parameters remain
  unfrozen until an end-to-end decryption-correctness gate passes.

## Strategy classes

The implemented fixed-candidate set includes PaddingReuse, ReservedSlack,
Mini-CSSC-Delta, `Packed-COO-Client-Lane-Delta`, Strict LocalRepack, and PeriodicRepack.
The packed-COO client-lane candidate returns evaluated segment lanes for OutputPlan-guided
client reconstruction; it is not the strong cloud-segmented Packed-COO baseline.

ADR 0007 defines a Phase 1 opaque-identifier fixed-segment primitive: the Cloud reduces
inside each public fixed-width segment, while same-row-equivalence fields are carried only
in Client B's typed plan. This is an interface ACL, not a segment-unlinkability claim. The
ADR 0008 whole-query integration and its v2
pinned workflow are implemented. The latest audited Phase 2 fixture is bound to and passed at
`fcb00e0d` in run `32581653504`, establishing narrow bound-query correctness but not
registration, complete cost, security, or performance. The strong candidate remains
unregistered until its accounting, evidence, and tuning-prefix gates pass. The role-aware
Day 1 contract is already implemented as 14 emitted fixed records: 13 selectable
references, including the strong candidate, and one client-lane ablation. Production does
not fall back to a partial reference set: the zero-argument repository catalog fails closed
while the composite registration anchor is absent, so no R2 artifact is admissible. After
registration, a successful R2 artifact must prove the exact 14/13/1 role split, 13 tuning
records, 16 total records including aliases, and `complete_reference_set=true`. Until that
artifact exists, no current result may be described as a complete fixed-reference
comparison.

Candidate contributions: causal maintenance selection, new overflow layout,
cloud/client merge selection, version/freshness protocol, and explicit Hidden-RowMap
F1-M result/decrypt/reorder/merge/mask accounting, with bandwidth deferred. An offline
held-out oracle is a comparison bound, not a candidate algorithm.
