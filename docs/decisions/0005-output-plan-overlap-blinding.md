# ADR 0005: Bind F1-M blinding to logical-coordinate overlap

- Status: Accepted
- Date: 2026-08-22

Hidden-RowMap F1-M derives masks from an OutputPlan rather than from the number of returned ciphertexts. Client B initializes the public-length logical output vector to zero, so a coordinate with no physical contributor remains an implicit zero without a fabricated ciphertext. For each logical coordinate with contributor multiplicity `h > 1`, Client A samples `h - 1` independent uniform values in `Z_t` and completes the final share with their negative sum; coordinates with one contributor remain unmasked and disjoint horizontal blocks are concatenated. Each encrypted mask is bound to the query, version, canonical OutputPlan digest, Result Component, and Output Block. This keeps the full RowMap-sensitive plan away from the Cloud, prevents accidental addition of disjoint blocks, and charges only ciphertexts that actually carry overlapping coordinates.
