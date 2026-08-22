# Protocol contract v2.1b

This contract supersedes the v2.1a patch without modifying the original task. Its
machine-readable counterpart is `config/params_manifest.json` version 0.2.0.

## Threat and leakage contract

The parties are Client A, Client B, and the Cloud. The protocol assumes static
semi-honest behavior, corruption of at most one party, and no Cloud/client collusion;
it makes no malicious-security claim. Client A owns the matrix, updates, CSSC metadata,
component RowMaps, and component ColumnIndex metadata. Client B owns the query and BFV
secret key, receives the complete versioned RowMap-sensitive OutputPlan needed for
reconstruction, and receives the final logical result.

The Hidden-RowMap ACL permits the Cloud to observe public parameters, ciphertext shapes
and counts, opaque component/output-block identifiers, the operation schedule, and
query/version identifiers, including the canonical OutputPlan digest needed to bind
encrypted masks. It forbids the Cloud from observing matrix/update values,
the query vector, the secret key, component RowMaps or full OutputPlan, component
ColumnIndex metadata, mask plaintexts, or unblinded component outputs. Client A and
Client B may both read the complete component RowMaps and OutputPlan; this permission
does not make either structure public. Results from a Public-RowMap mode must not be
pooled with Hidden-RowMap results.

## Versioned query reorganization

Each CSSC value chunk retains global ColumnIndex addresses; it is not modeled as a
contiguous column block. Client A sends the corresponding plaintext ColumnIndex metadata
to Client B. For every published matrix version, Client B uses that version's
ColumnIndex metadata to construct one aligned query-reorganization vector ciphertext per
CSSC chunk. ColumnIndex delivery must be version-synchronized and its communication cost
must be counted. The Cloud receives the ciphertext shape, not the ColumnIndex values.

The frozen matrix has 4,096 rows and 8,193 columns while one BFV batching row exposes
4,096 effective slots. This deliberately exercises global ColumnIndex values outside a
single slot domain. It does not assert contiguous `ceil(cols / slots)` column blocking.

## Output reconstruction and blinding

An OutputPlan in `dynamic-cssc-output-plan-v1` format identifies every Result Component
and Output Block and maps its physical lanes to logical output coordinates. Client A
sends the complete version-bound plan to Client B, which uses it to reorder and combine
decrypted shares. Client B initializes the public-length logical output vector to zero;
any coordinate absent from every physical share remains an implicit zero and creates no
result ciphertext or mask. For a logical coordinate with contributor
multiplicity `h > 1`, Client A samples `h - 1` independent uniform elements of `Z_t` and
uses the negative modular sum for the final contributor. A coordinate with multiplicity
one is concatenated/reordered and is not masked merely because another ciphertext was
returned. The machine contract names these rules `logical-coordinate-overlap-only` and
`concatenate-unmasked`.

The canonical OutputPlan digest uses `sha256-canonical-json-v1`. Every mask is bound to
the exact tuple

```text
(query_id, version_id, output_plan_digest, component_id, output_block_id)
```

All three parties may observe this digest so the Cloud can associate each encrypted mask
with the evaluation it serves. The digest is a commitment identifier, not permission to
receive the RowMap-sensitive OutputPlan preimage.

Client A maintains a persistent per-query binding ledger. It atomically checks and
reserves a binding before mask generation, rejects duplicates, and treats a reserved
binding as consumed after a crash. This is the operational premise for the no-reuse
claim.

Cryptographic mask randomness comes from the operating-system CSPRNG. Sampling in
`Z_t` uses unbiased rejection sampling. The reproducibility seed is scoped only to
synthetic workload generation and policy replay and must never seed masks.

## Integer correctness

All published versions enforce at most 4,096 nonzeros per row. With
`|A_ij| <= 7`, `|x_j| <= 1`, and at most 4,096 terms per output,

```text
B = 4096 * 7 * 1 = 28672
2B = 57344 < t = 65537.
```

Component values are summed modulo `t`; centered lifting happens once, after the final
component sum. An update that would violate the per-row nonzero or value bound cannot be
published under this manifest.

## Gates and evidence scope

Before Day 1, a deterministic 257-by-521 preflight with 256 effective slots must exercise
both multiple output ciphertexts and a global ColumnIndex beyond the slot range; reducing
ColumnIndex modulo the effective-slot count is forbidden. The three
OpenFHE estimator profiles remain mutually exclusive calibration contexts. Mixed-circuit
parameterization is explicitly unfrozen, and no formal mixed-workload claim is permitted
until the mixed-circuit decryption-correctness gate is frozen and passes.
