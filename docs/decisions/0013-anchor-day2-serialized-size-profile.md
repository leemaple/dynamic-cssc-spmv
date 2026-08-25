# Anchor the formal Day 2 serialized-object size profile

- Status: Accepted
- Date: 2026-08-25

## Context

The formal OpenFHE Day 2 probe measures the exact binary serialization length
of an admitted BFVRNS ciphertext. The producer previously discarded that value
before building the R3 archive, so Day1B had no repository-authoritative byte
size with which to price ciphertext multiplicities. Moreover, neither theory
nor a generic ciphertext length is sufficient evidence that the two F1-M
construction categories have identical serialized lengths. Substituting a
fixture length, a ciphertext count, a cross-category assumption, or a
caller-supplied value would break the frozen serialized-object accounting
contract.

The same run also retains exact serialized rotation-key and multiplication-key
sizes in `generated-key-inventory.json`. Those values and the ciphertext length
must describe one internally consistent formal run.

## Decision

The formal probe now constructs three fresh ciphertexts under the same fixed
BFVRNS CryptoContext: the generic probe plaintext, a nontrivial modular
zero-sum F1-M plaintext, and an all-zero F1-M dummy plaintext. Each is encrypted
through the same fresh public-key path and serialized independently.

The R3 archive contains one canonical v2
`serialized-object-size-profile.json`. It binds:

- the exact OpenFHE `SerType::BINARY` byte lengths for the generic,
  random-zero-sum F1-M, and encrypted-zero-dummy F1-M ciphertexts;
- the frozen measurement-method and serialization-format tokens;
- the frozen fresh-BFVRNS fixed-context construction-profile token;
- the exact generated-key inventory digest; and
- the measured serialized rotation-key inventory and multiplication-key byte
  lengths.

The archive manifest and producer-validation document bind the new member. The
descriptive inspector validates its closed schema, positive strict integers,
generated-key digest, and equality with the key sizes in the generated-key
inventory.

The post-run anchor schema is v6. Its reviewed binding carries the size-profile
digest and all five exact byte lengths (three ciphertext classes and two key
classes) in addition to the existing archive, profile, rotation, contract,
isolation, and calibration digests. The previous v4 empty anchor set remains
readable solely as the pre-run historical state; nonempty v4 and all v5 anchors
are invalid. The final zero-argument repository Day 2 authority exposes the
anchored lengths as read-only properties.

Before any held-out trace is opened, the Day1B repository gate must consume
that final authority and derive an internal typed size capability. The public
Day1B API cannot accept byte sizes, profile digests, or authority flags from a
caller. The production worker contract and receipts must ultimately bind this
capability before execution.

## Consequences

- Formal Day2 no longer discards a measured value needed by Day1B.
- Day1B cannot use ciphertext count as a byte proxy or silently substitute
  fixture serialization lengths.
- Key and category-specific ciphertext sizes come from one archive and one
  post-run anchor.
- The size profile is evidence, not a pre-dispatch tuning input: it is available
  only after formal Day2 and its reviewed post-run anchor.
- Existing empty v4 history remains auditable without allowing an obsolete
  nonempty binding.

## Rejected alternatives

- Adding only one generic `ciphertext_bytes` to a result table leaves no closed
  archive member, generated-key consistency check, or category-specific F1-M
  construction evidence.
- Copying the value into the pre-dispatch Day2 profile is temporally impossible
  because that profile must be installed before measurement.
- Letting the Day1B adapter measure or accept its own ciphertext size creates a
  second, unanchored calibration path.
