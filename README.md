# Dynamic CSSC for Mutable Encrypted SpMV

Research implementation and evidence package for a version-bound maintenance
layer around ciphertext--ciphertext sparse matrix--vector multiplication using
CSSC and OpenFHE BFV.

## Current publication state

The active paper is a **Route C methods and evidence-boundary manuscript**. It
does not report a comparative performance winner.

- External-review packet: [`route-c-external-review-v2`](https://github.com/leemaple/dynamic-cssc-spmv/tree/route-c-external-review-v2)
- Exact reviewed content commit: `6973ba451fac7636b58b364fb0a67ca79e37c0c1`
- Tree-identical merge on `main`: `8d3bcad050ea0945133c2096ac0667d0de57af96`
- ChatGPT Pro closure verdict: `PASS`, P0 = 0, P1 = 0, P2 = 0
- ZCode GLM-5.3 Max closure verdict: `PASS`, P0 = 0, P1 = 0, P2 = 0

The reviewed manuscript makes protocol, conditional functional-correctness,
source-conformance, reproducibility, and fail-closed evidence-boundary claims.
It makes no formal-security, end-to-end admission, comparative-performance, or
state-of-the-art superiority claim.

## Authoritative experiment outcomes

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

A separately preregistered follow-up also reached terminal NO-GO. Its fresh
Experiment Source S1 was
`f8d89d6f98f289dc2e0c3414f7b4ed59b5d30f52`; its data-only S2 was
`e1e488f177dc8a469c6132a29537b041fbf1430b`. All five exact-S2,
authority-false controls passed. The sole follow-up qualification run
`33348855548` was then cancelled during hosted-runner setup after the external
controller failed to install its watcher-admission binding. No repository
checkout, registered seed, q1--q6 scientific stage, or artifact occurred. The
frozen one-shot rule therefore forbids a rerun, replacement-lineage
continuation, or formal campaign for that study.

An authority-false post-outcome drill subsequently reproduced a deterministic
provider-boundary defect: GitHub's create-commit response omitted the canonical
JSON message's final line feed, while the adapter required byte identity. The
same drill proved the production GraphQL `updateRefs` compare-and-swap path
works. This high-confidence same-code-path diagnosis does not recover the
missing historical nested exception and cannot reopen either study.

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
- [`docs/reviews/followup-performance-qualification-terminal-no-go-2026-08-31.md`](docs/reviews/followup-performance-qualification-terminal-no-go-2026-08-31.md): separately preregistered follow-up terminal disposition
- [`docs/reviews/followup-provider-cas-diagnosis-2026-08-31.md`](docs/reviews/followup-provider-cas-diagnosis-2026-08-31.md): authority-false provider message/CAS diagnosis
- [`docs/research/route-c-manuscript-citation-audit-2026-08-30.md`](docs/research/route-c-manuscript-citation-audit-2026-08-30.md): all-used-key primary-source citation audit
- [`docs/research/route-c-submission-venue-review-2026-08-30.md`](docs/research/route-c-submission-venue-review-2026-08-30.md): current official-source venue, deadline, format, and fee comparison
- [`docs/paper/submission-metadata-and-release-checklist.md`](docs/paper/submission-metadata-and-release-checklist.md): remaining author-owned metadata, licensing, release, and submission stop conditions

The immutable review tag, not the moving branch, is the authoritative external
packet.

## Evidence layers

| Layer | Exact object | What it can establish |
|---|---|---|
| Original S1/S2 | `ee58627b…` / `c7ff6820…` | Frozen original experiment source and data-only registration anchor |
| Original qualification | Run `33261434612` | The 45-minute deadline was missed; no authority was minted |
| Follow-up S1/S2 | `f8d89d6f…` / `e1e488f…` | Separately frozen source and data-only anchor after five clean controls |
| Follow-up qualification | Run `33348855548` | Cancelled before checkout/seed after watcher binding failed; zero artifacts |
| Formal campaigns | Not dispatched | No admitted synthetic, ordered-event, native, terminal, aggregate, or S3 performance result exists |
| Review packet | Tag `route-c-external-review-v2` | Exact manuscript, Word documents, bibliography, figures, ledger, audits, and hashes |

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
