# v2.1a protocol and accounting patch

This file does not rewrite the original v2.1 task. It fixes the F1-M blinding protocol and associated cost accounting before implementation.

## 1. Frozen roles

- **Client A** owns the matrix, CSSC metadata, base/delta RowMaps, and update state.
- **Client B** owns the query vector, holds the BFV secret key, and receives the final result.
- **Cloud** evaluates ciphertexts and does not collude with either client.

## 2. Why the original server-only blinding is disabled

When base and delta components have different physical row permutations, the cloud cannot create logical-domain masks that cancel after client-side RowMap restoration unless it knows those RowMaps. The original CSSC leakage model does not reveal RowMap to the cloud. Therefore the repository default is **Hidden-RowMap F1-M** below.

## 3. Hidden-RowMap F1-M

For every query, Client A samples one-time logical masks

\[
r_0,\ldots,r_g\in\mathbb Z_t^m,\qquad \sum_{\ell=0}^{g}r_\ell=0\pmod t.
\]

For component \(\ell\), Client A maps \(r_\ell\) into that component's physical output layout, encrypts it under Client B's public key, and uploads the mask ciphertext to the cloud. The cloud performs ciphertext addition. Client B decrypts each component, restores its logical row order, sums in \(\mathbb Z_t\), and applies centered lifting only once to the final sum.

Masks are bound to `(query_id, version_id, component_id, output_block_id)` and are never reused.

## 4. Optional Public-RowMap mode

A separate experiment may reveal component RowMaps to the cloud and use plaintext masks. It must be labeled as a different leakage mode and must not be merged with Hidden-RowMap results.

## 5. Cost accounting

All split-output F1-M strategies must include:

- mask generation and logical-to-physical mapping;
- encoding and encryption, or explicit Public-RowMap plaintext construction;
- A→Cloud mask traffic;
- cloud additions;
- result ciphertext download;
- decryptions, RowMap restoration, modular summation, and mask lifecycle management.

The mask count is the total number of output ciphertexts, not merely `g + 1`.
