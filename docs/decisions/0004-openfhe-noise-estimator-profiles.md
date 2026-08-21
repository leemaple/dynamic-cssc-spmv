# ADR 0004: Separate OpenFHE BFV noise-estimator profiles

- Status: Accepted
- Date: 2026-08-21

Pinned OpenFHE 1.5.1 rejects a BFVRNS context when more than one of
`multiplicativeDepth`, `evalAddCount`, and `keySwitchCount` is non-zero. The manifest
therefore freezes separate multiply-only, add-only, and key-switch-only reference
profiles. P0a uses the key-switch-only profile. These profiles are calibration contexts,
not evidence that a mixed SpMV circuit is formally parameterized; that claim remains
forbidden until a mixed-circuit decryption-correctness gate is frozen and passes.
