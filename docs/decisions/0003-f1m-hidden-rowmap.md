# ADR 0003: F1-M Hidden-RowMap as default

- Status: Accepted
- Date: 2026-08-21

The default endpoint is client decryption. Split base/delta outputs must not reveal their
overlapping logical-coordinate contributions. Client A therefore derives one-time
encrypted zero-sum masks from the canonical OutputPlan and maps them into each Result
Component and Output Block. Disjoint Output Blocks are concatenated without masks.

The security claim assumes a semi-honest, at-most-one-party corruption model with no
Cloud/client collusion. Component RowMaps and ColumnIndex metadata stay hidden from the
Cloud. Client A sends versioned plaintext ColumnIndex metadata to Client B so that Client
B can build one query-reorganization vector ciphertext per CSSC chunk. This transfer is
part of communication accounting.

Client A also sends Client B the complete versioned RowMap-sensitive OutputPlan. Client B
requires this plan to restore logical row order and combine decrypted Output Shares. Both
clients may read it; the Cloud may not. The machine contract freezes format
`dynamic-cssc-output-plan-v1`, masking scope `logical-coordinate-overlap-only`, and the
disjoint-block rule `concatenate-unmasked`.

Each mask is bound to `(query_id, version_id, output_plan_digest, component_id,
output_block_id)`. Client A must atomically reserve the binding in a persistent ledger
before drawing unbiased `Z_t` values from the operating-system CSPRNG. Server-only
plaintext masking is allowed only in a separately labeled Public-RowMap leakage mode.
