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

- The semi-honest security claim assumes at most one corrupted party and no Cloud/client
  collusion. The manifest carries an explicit per-party leakage ACL.
- Client A sends versioned plaintext ColumnIndex metadata to Client B for every CSSC
  chunk. Client B generates an aligned reorganization-vector ciphertext per chunk;
  ColumnIndex values and component RowMaps remain hidden from the Cloud.
- Client A and Client B both receive the complete versioned, RowMap-sensitive OutputPlan;
  the Cloud receives only its canonical digest. Client B uses the complete plan to reorder
  and combine decrypted Output Shares.
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

The strong cloud-segmented Packed-COO baseline has no defined executable schedule under
the v2.1b F1-M Hidden-RowMap contract and is deferred. The current set is therefore a
partial reference set: repository status and generated Day 1 artifacts use
`complete_reference_set=false`, name `strong-packed-coo` as the missing baseline, and keep
the Day 1 full-baseline verdict on HOLD. No current result may be described as an
all-fixed-reference or six-reference comparison.

Candidate contributions: causal maintenance selection, new overflow layout,
cloud/client merge selection, version/freshness protocol, and explicit Hidden-RowMap
F1-M result/decrypt/reorder/merge/mask accounting, with bandwidth deferred. An offline
held-out oracle is a comparison bound, not a candidate algorithm.
