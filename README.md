# Dynamic CSSC for Mutable Encrypted SpMV

Research implementation and evidence package for a version-bound maintenance
layer around ciphertext--ciphertext sparse matrix--vector multiplication using
CSSC and OpenFHE BFV.

## Current publication state

The active paper is a **Route C methods and evidence-boundary manuscript**. It
does not report a comparative performance winner.

- External-review packet: [`route-c-external-review-v1`](https://github.com/leemaple/dynamic-cssc-spmv/tree/route-c-external-review-v1)
- Exact reviewed commit: `f4fe461ace07bceaf674a9cad61f98bd74f67531`
- Independent final review marker: [`route-c-external-review-v1-pro-pass`](https://github.com/leemaple/dynamic-cssc-spmv/tree/route-c-external-review-v1-pro-pass)
- ChatGPT Pro narrow closure verdict: `PASS`, P0 = 0, P1 = 0, external circulation ready
- ZCode GLM-5.3 Max manuscript verdict: `PASS`, P0 = 0, P1 = 0

The reviewed manuscript makes protocol, conditional functional-correctness,
source-conformance, reproducibility, and fail-closed evidence-boundary claims.
It makes no formal-security, end-to-end admission, comparative-performance, or
state-of-the-art superiority claim.

## Authoritative experiment outcome

The final implementation candidate
`baefc8cc183816c51ce42573bafde8178173044d` entered `main` as the tree-identical
Experiment Source Snapshot S1
`ee58627bb5752c6ac1ee2c5132c6574f9cb66552`. Exact-S1 CI run `33258436732`
passed 2,403 tests with two expected runner-dependent skips. Exact-main PRE-S1
run `33259569284` passed 583 tests and both pinned OpenFHE 1.5.1 ordinary and
strong real-query smokes. Descriptive registration run `33259894587` did not
mint authority. The data-only registration anchor then formed Evidence-Freeze
Snapshot S2 `c7ff6820d9323f1850c1c5c57fd9070db88db120`; S2 CI run
`33260167517` also passed.

The sole permitted, permanently non-admissible qualification run `33261434612`
started from exact S2. q1 completed, but q2 independent replay was still
running at the frozen 45-minute computational deadline. The external controller
cancelled only that exact run. q3--q6 did not run, q5 never started, no dispatch
capability was minted, and acquisition plus the 16-unit formal campaign were
not launched.

The only provider artifact was the one-day
`q1-simulator-pre-replay-handoff`, artifact ID `9717884587`, provider digest
`sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`.
It is permanently **NON-EVIDENCE** and cannot support a strategy-cost or native
OpenFHE result.

Under the frozen preregistration, this outcome selected Route C. The
qualification may not be rerun in this lineage, and partial q1/q2 observations
may not be repackaged as paper performance evidence.

## What the repository contributes

The implementation closes four coupled interfaces around static CSSC:

1. a Publication Window binds logical matrix state, physical components,
   versioned global-column query metadata, complete `OutputPlan`, and prepared
   queries;
2. query reorganization uses the version's true global column identities rather
   than physical lane ordinals;
3. private reconstruction handles overlap, disjoint output blocks, and implicit
   zeros under one complete plan;
4. overlap-scoped F1-M masking uses a durable reserve-before-sample ledger, while
   the fixed `c=128` strong path exposes a public segment schedule and retains a
   private leader merge.

The Cloud interface is intentionally narrow: it receives typed public programs,
permitted identifiers, and encrypted operands, but not matrix/query plaintexts,
component RowMaps, the complete OutputPlan, individual mask plaintexts, or
unblinded component outputs. Client B does learn the versioned layout and
reconstruction metadata. The stated threat model is static semi-honest with at
most one corrupted party and no Cloud/client collusion; no broader security
theorem is claimed.

## Reproducing source-level verification

Python 3.11 or newer is required for ordinary development. The frozen CI and
PRE-S1 records above identify their exact environments and the pinned OpenFHE
source. A local source-level verification can be started with:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python scripts/validate_manifest.py config/params_manifest.json
pytest -q
python -m dynamic_cssc.cli smoke --output-dir results/smoke --seed 20260821
```

The CLI smoke is a model prediction, not a cryptographic performance
measurement. Green tests, CI, PRE-S1, descriptive registration, and historical
smokes do not substitute for the formal artifacts that were never authorized.

Do not dispatch the historical publication workflows in an attempt to recreate
the closed Route A campaign. Their fail-closed behavior and terminal disposition
are part of the research record.

## Paper and review package

- [`docs/paper/manuscript-draft.md`](docs/paper/manuscript-draft.md): authoritative English Route C manuscript source
- [`docs/paper/manuscript-draft.docx`](docs/paper/manuscript-draft.docx): rendered English review document with editable equations
- [`docs/paper/paper-idea-detailed-zh.md`](docs/paper/paper-idea-detailed-zh.md): Chinese technical companion, not an equivalent submission manuscript
- [`docs/paper/paper-idea-detailed-zh.docx`](docs/paper/paper-idea-detailed-zh.docx): rendered Chinese technical companion
- [`docs/paper/claim-ledger-draft.md`](docs/paper/claim-ledger-draft.md): sentence-level claim/evidence permissions
- [`docs/paper/references.bib`](docs/paper/references.bib): primary-source bibliography
- [`docs/reviews/route-c-external-review-packet-2026-08-30.md`](docs/reviews/route-c-external-review-packet-2026-08-30.md): exact packet hashes and QA record
- [`docs/reviews/chatgpt-pro-route-c-manuscript-review-2026-08-30.md`](docs/reviews/chatgpt-pro-route-c-manuscript-review-2026-08-30.md): initial commit-bound manuscript review
- [`docs/reviews/zcode-glm53-max-route-c-manuscript-review-2026-08-30.md`](docs/reviews/zcode-glm53-max-route-c-manuscript-review-2026-08-30.md): independent GLM-5.3 Max review
- [`docs/research/route-c-manuscript-citation-audit-2026-08-30.md`](docs/research/route-c-manuscript-citation-audit-2026-08-30.md): all-used-key primary-source citation audit
- [`docs/research/route-c-submission-venue-review-2026-08-30.md`](docs/research/route-c-submission-venue-review-2026-08-30.md): current official-source venue, deadline, format, and fee comparison
- [`docs/paper/submission-metadata-and-release-checklist.md`](docs/paper/submission-metadata-and-release-checklist.md): remaining author-owned metadata, licensing, release, and submission stop conditions

The immutable review tag, not the moving branch, is the authoritative external
packet.

## Evidence layers

| Layer | Exact object | What it can establish |
|---|---|---|
| S1 | `ee58627bb5752c6ac1ee2c5132c6574f9cb66552` | Experiment source, frozen behaviors, source conformance, and conditional functional propositions |
| S2 | `c7ff6820d9323f1850c1c5c57fd9070db88db120` | Data-only registration anchor and exact pre-execution freeze |
| Qualification | Run `33261434612` | The frozen deadline was missed, no authority was minted, and Route C was selected |
| Formal campaign | Not dispatched | No synthetic, ordered-event, native, terminal, aggregate, or S3 performance result exists |
| Review packet | Tag `route-c-external-review-v1` | Exact manuscript, Word documents, bibliography, figures, ledger, audits, and hashes |

Historical R0/P0a and implementation evidence remains in the repository for
provenance. It is not current empirical evidence. The earlier R0/P0a bundle is
preserved in release
[`r1-p0a-v21b-20260822`](https://github.com/leemaple/dynamic-cssc-spmv/releases/tag/r1-p0a-v21b-20260822).

## Availability and release boundary

The source and review packet are publicly reachable through the immutable tags
above. No archival DOI or admitted empirical artifact is claimed. The repository
currently has no top-level license file; public visibility must not be read as a
license grant. A submission release therefore still requires human decisions on
author order and affiliations, funding, competing interests, CRediT roles,
AI-use disclosure, software/data license, venue, and archival repository/DOI.

The paper's data-and-code availability statement must be updated only after
those release decisions are complete. Until then, cite the exact immutable tag
and claim ledger rather than a moving branch.
