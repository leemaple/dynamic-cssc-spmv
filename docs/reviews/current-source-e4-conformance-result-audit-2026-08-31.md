# Current-source E4 conformance result audit — 2026-08-31

## Disposition

**PASS for the preregistered bounded current-source conformance question.**
This record releases no performance, security, admission, deployment,
population, or universal-correctness claim. The two earlier performance
lineages remain terminal NO-GO.

## Immutable source and provider identity

- Lightweight tag: `current-source-e4-conformance-20260831-v1`
- Direct tag ref before dispatch and after completion:
  `844fb062d78f5095f14599c6c71a27cb6034f001`
- Peeled commit before dispatch and after completion:
  `844fb062d78f5095f14599c6c71a27cb6034f001`
- Tag object type: `commit`, not an annotated tag
- Workflow: `.github/workflows/strong-whole-query-witness.yml`
- Run: `33386130654`
- Event/ref/head/attempt: `workflow_dispatch` /
  `current-source-e4-conformance-20260831-v1` /
  `844fb062d78f5095f14599c6c71a27cb6034f001` / `1`
- Run conclusion: `completed/success`
- Job: `correctness-witness` (`99469043424`),
  `2026-08-31T11:15:37Z`--`2026-08-31T11:19:49Z`, `success`

Every one of the 15 provider-visible job steps, including setup and post steps,
completed successfully. The upload step completed `success`. The complete
workflow-path inventory after completion contains exactly the two disclosed
historical runs `32567669739` and `32581653504` plus this one current run; no
extra current attempt or rerun exists.

## Provider artifact

- Artifact ID: `9755741401`
- Name:
  `strong-whole-query-witness-success-844fb062d78f5095f14599c6c71a27cb6034f001`
- Provider size: `32,598` bytes
- Provider digest:
  `sha256:5978b7d9f75048939c9761243e224abb588ed82c2abc64e051523a7a598a1383`
- Created: `2026-08-31T11:19:42Z`
- Expires: `2026-09-30T11:19:40Z`
- Expired at audit: `false`
- Provider workflow-run binding: run `33386130654`, exact tag, exact source
  SHA above

Exactly one artifact exists for the run.

## Independent raw-ZIP audit

The controller downloaded the provider ZIP through the artifact API without
executing any member. Its independently computed raw SHA-256 is
`5978b7d9f75048939c9761243e224abb588ed82c2abc64e051523a7a598a1383`,
exactly equal to the provider digest.

The ZIP contains exactly the 19 preregistered regular files and no extra,
duplicate, encrypted, unsafe-path, directory-counted, symlink, or other
non-regular member. `SHA256SUMS` contains exactly 18 strict entries and verifies
every other file. `witness.json.sha256` independently verifies `witness.json`.

All eight JSON files parse as strict UTF-8 JSON with no duplicate key or
non-finite number. Every machine-plan RFC 6901 pointer resolves literally to
its frozen expected value. The dynamic `/github_run_id` and
`/source_git_sha` values equal the provider run and exact tagged source.

A fresh, independently cloned detached checkout of the lightweight tag was
used for rehashing. All five machine-plan fixed files, the three direct
PROVENANCE source fields, and all 14 property-contract source files match their
recorded SHA-256 values. The four property artifacts, archived manifest,
bindings, and witness also match their PROVENANCE digests.

## Bounded scientific result

`RUN_STATUS.json` reports `pass`, `evidence_valid=true`, all four stage outcomes
`success`, pinned OpenFHE commit
`1306d14f8c26bb6150d3e6ad54f28dfe1007689e`, and the exact run/ref/head above.

The real OpenFHE 1.5.1 BFVRNS witness used the fixed 4096-by-8193
CSSC-base-plus-strong-delta fixture, segment width 128, active payload 127,
padding offset 127, and global column 8192. It reported valid decryptions and
the exact centered sparse vector:

```text
[(0, 128), (4095, 5)]
```

That vector exactly equals both the typed Python plaintext oracle and the
independent direct SpMV oracle. The deterministic property contract reports
eight input cases, 35 records, seed `20260822`, and zero failures. Its JUnit
record likewise reports 35 tests, zero failures, zero errors, and zero skips.

The artifact itself retains all authority flags as false for candidate
registration, complete-reference status, end-to-end correctness, formal
parameters, performance, and security. The only positive sentence permitted
from this audit is the version-bound, single-fixture conformance statement
recorded in the manuscript and claim ledger.
