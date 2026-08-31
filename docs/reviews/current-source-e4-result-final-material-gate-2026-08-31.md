# Current-source E4 result final material gate — 2026-08-31

## Exact reviewed object

- Commit: `a757cf429f6457f4beac9ae9b0790a74e7d1ff7a`
- Sole parent: `4487969e1bc05cc11dbd92e25363c89f3e03d99e`
- Tree: `7111c967ec7d4d98c449ac56967b0f6afe742aad`
- Branch used for the review: `codex/current-source-e4-result`
- Worktree at both review gates: clean
- Immutable annotated review tag:
  `route-c-current-source-e4-review-v1`
- Tag object: `dca3bcecbfd04d629adb92cb00fa101661e91ce4`
- Peeled tag target: `a757cf429f6457f4beac9ae9b0790a74e7d1ff7a`

The tag was created only after both external reviewers returned no unresolved
P0/P1 and exact-head CI completed successfully.  It binds the reviewed packet,
not a moving branch.  This note is a review-record-only successor and does not
alter the reviewed manuscript, evidence audit, claim ledger, or rendered
outputs.

## Result identity checked by both reviewers

Both reviews independently retained the following exact bounded result:

- source tag: `current-source-e4-conformance-20260831-v1`;
- source commit: `844fb062d78f5095f14599c6c71a27cb6034f001`;
- workflow run: `33386130654`;
- artifact: `9755741401`;
- raw/provider ZIP SHA-256:
  `5978b7d9f75048939c9761243e224abb588ed82c2abc64e051523a7a598a1383`;
- exact artifact inventory: 19 regular files and 18 strict
  `SHA256SUMS` entries;
- deterministic contract: 35 of 35 records passed at seed `20260822`;
- OpenFHE sparse output: `[(0, 128), (4095, 5)]`, equal to both the
  typed-plaintext and direct-plaintext oracles.

The only released interpretation is exact-source, single-fixture functional
conformance.  It is not performance, security, admission, deployment,
complete-reference, parameter-generality, population, or general-correctness
evidence.  The original and follow-up performance lineages remain terminal
NO-GO.

## Exact-head CI

GitHub Actions run `33391930451` completed `success` on attempt 1 for the exact
reviewed commit.  Its sole `python-gates` job and every visible step succeeded.
The unit-test result was `2667 passed, 2 skipped in 1453.16s`; both skips were
the expected unbuilt-real-runner cases at
`tests/test_publication_day1b_openfhe_execution.py:177`.  P-1, syntax,
predicted-only smoke, R0 creation, and upload all passed.

The sole R0 artifact is:

- ID: `9758576676`;
- name:
  `r0-freeze-a757cf429f6457f4beac9ae9b0790a74e7d1ff7a`;
- size: 10,001,806 bytes;
- digest:
  `sha256:4830276347199959bd6e550260c951676d42ea16ab4741b49294e17bc5d9fe63`;
- provider binding: run `33391930451`, branch
  `codex/current-source-e4-result`, head
  `a757cf429f6457f4beac9ae9b0790a74e7d1ff7a`;
- expired: false at the audit time.

No CI or provider artifact was downloaded or installed during the final
review.

## ChatGPT Pro material gate

- Channel: signed-in ChatGPT Pro project `矩阵向量乘法论文` through Ego Lite.
- Conversation:
  <https://chatgpt.com/g/g-p-6a843076849c8191ae260f5d4fb84e80-ju-zhen-xiang-liang-cheng-fa-lun-wen/c/6a957424-ab88-83ec-896f-412275afd793>
- Visible reasoning setting: Extra High.
- Initial verdict: `AMEND — P0=0, P1=1, P2=0`.
- Final narrow follow-up verdict: **`PASS — P0=0, P1=0`**.

The initial review independently downloaded and checked the E4 provider
artifact and found no evidence-identity, claim-boundary, manuscript, ledger, or
terminal-NO-GO discrepancy.  Its sole P1 was a transport limitation: the outer
review ZIP was not mounted in the reviewer runtime, so the exact rendered
binaries could not be inspected.

The permitted single counterevidence round attached the four binaries
individually.  Pro confirmed that all four were readable and materially
inspectable, that the English and Chinese DOCX/PDF outputs preserved the
reviewed Markdown content and bounded E4/terminal-NO-GO wording, and that the
English and Chinese PDFs contained 26 and 24 pages respectively.  It then
explicitly closed the sole transport P1.  The platform-added `(2)` suffix on
the first DOCX attachment was treated correctly as a display-name change, not
a content discrepancy.

## ZCode material gate

- Channel: local ZCode desktop application using the exact local review
  workspace `/private/tmp/dynamic-cssc-control-plane-drill.0RlouT`.
- Task: `Read-only review of commit a757cf4 conformance gate`.
- Model: `GLM-5.3`.
- Reasoning mode: `Max`.
- Permission mode: `Plan mode`.
- Verdict: **`PASS — P0=0, P1=0, P2=2`**.
- Tag decision: the immutable external-review tag may be created on the exact
  reviewed commit.

ZCode independently checked the clean HEAD/parent/tree, the source tag target,
all frozen result identities, the manuscript/Chinese/ledger/checklist claim
boundary, the two terminal performance lineages, the document-builder metadata
rules, exact-head CI, and committed document binaries.  Its PDF structure check
confirmed a 26-page US-Letter English page tree and a 24-page A4 Chinese page
tree.

The two non-blocking findings are recorded here:

1. The exact-head CI/R0 identities were not yet present in the reviewed tree;
   this review-record-only successor records them above and closes that P2.
2. The Chinese PDF contains 25 internal `/MediaBox` objects while its page tree
   has `/Count 24`.  The 24 rendered A4 pages match the page-by-page QA.  The
   extra object is a harmless renderer artifact and changes neither visible
   content nor a scientific claim; no document edit is required.

## Rendered-object binding

The final output hashes reviewed locally before the external gates were:

| Object | SHA-256 |
|---|---|
| `docs/paper/manuscript-draft.md` | `16c93bc7fcae906176db494d8fbd523e710b3174d660c25568906efac43655f1` |
| `docs/paper/manuscript-draft.docx` | `ba32990f6f5d55335952538d9ce39c5691009fb4afa9378adc695d7d7a5ecf7b` |
| `docs/paper/manuscript-draft.pdf` | `bc8b20d870f752b974b61a93998ff7fa267dd5f466ee6b9b28b7d8f62940b627` |
| `docs/paper/paper-idea-detailed-zh.md` | `4a9b73202fdf1fb5c5d62f60c4d54a1b9462dbdfa9f6c6183bd81b475f540b21` |
| `docs/paper/paper-idea-detailed-zh.docx` | `5b8d03ced610b041b861359524f49f436ad9a48de45dbd25136cb56ac7116a83` |
| `docs/paper/paper-idea-detailed-zh.pdf` | `f3e28c472547027e46f5cf255df216c684f47f63dc4349fd4b01b2e5e22742ab` |
| `docs/reviews/current-source-e4-conformance-result-audit-2026-08-31.md` | `211b74d9e67a83e93f3c9d4b407fada40c73a57b469321437385012872c743bd` |

Both DOCX packages passed ZIP integrity, retained editable OMML, and had blank
creator/last-modifier metadata.  The PDFs had no author metadata.  Page-by-page
visual QA accepted all 26 English Letter pages and all 24 Chinese A4 pages.

## Shared ZCode quota disposition

The BigModel Coding Plan usage page showed 94% weekly usage at the pre-gate
check, with the weekly allowance resetting at 2026-09-02 10:00 Asia/Shanghai.
All ZCode windows/projects share that allowance.  Therefore this was the one
quota-reserved final ZCode gate; no duplicate ZCode review was issued.  Interim
questions used repository evidence and ChatGPT Pro instead.

## Final disposition

**PASS — both configured external reviewers bound the exact reviewed packet
with P0=0 and P1=0, and exact-head CI succeeded.**  The reviewed packet is
appropriate for anonymous external circulation under its stated narrow claim.
The immutable review tag is now installed.  The remaining repository work is a
review-record-only merge to `main`; actual submission remains blocked on the
human-owned metadata, venue selection, license, declarations, and final
venue-formatted package listed in the submission checklist.
