# Route C anonymous CiC current-source submission audit — 2026-09-01

## Verdict

**LOCAL PACKAGE PASS; SUBMISSION-DRAFT EXTERNAL REVIEW HOLD.**

The anonymous *IACR Communications in Cryptology* source and PDF pass the
current local build, typesetting, citation-resolution, identity-leakage,
metadata, and full-page visual checks. The paper now includes the separately
stopped follow-up and the admitted current-source E4 result without turning
either qualification lineage into performance evidence.

This verdict is not an acceptance prediction, a formal-campaign result, or an
upload authorization. The exact venue package still requires the project's
same-packet ChatGPT Pro and ZCode review with no unresolved P0/P1 findings.
ZCode's shared weekly allowance was 96% consumed at the 2026-09-01 01:14 CST
quota-page refresh and resets on 2026-09-02 10:00 CST, so the candidate remains
local rather than spending the final allowance on a pre-freeze draft.

## Reviewed source and evidence boundary

- Package base: `main@8f864d5c76919902270dd23ae7d339fe193aaf0a`, tree
  `ae7e53bbcbddc83838b7dfd0ea25181e96fabe05`.
- Current English manuscript SHA-256:
  `16c93bc7fcae906176db494d8fbd523e710b3174d660c25568906efac43655f1`.
- Current-source material-review tag: `route-c-current-source-e4-review-v1`.
- Admitted functional source tag:
  `current-source-e4-conformance-20260831-v1`.
- The current-source material gate already received exact-packet ChatGPT Pro
  and ZCode GLM-5.3 Max closure with `PASS — P0=0, P1=0`.

The venue conversion preserves the reviewed protocol and result boundaries but
is a new presentation artifact. It compresses the current manuscript into the
CiC class, replaces identifying repository/provider values with typed blinded
tokens, and adds no new empirical observation.

The two performance lineages remain terminal NO-GO:

1. the primary qualification completed q1, was cancelled during q2 at its
   frozen stop, never started q5, and produced no admitted formal result; and
2. the separately preregistered follow-up passed its five authority-false
   controls, then stopped during provider setup before checkout, seed admission,
   any scientific stage, or artifact production.

The only positive current-source result is the narrow E4 conformance outcome:
one reviewed source, one fixed pinned-OpenFHE whole-query fixture, an eight-case
deterministic corpus with 35 of 35 records passing, and an independently
rehashed 19-file artifact. It does not support candidate admission, security,
deployment, comparative performance, speedup, or general correctness.

## Anonymous PDF

- Working output name:
  `output/pdf/route-c-cic-anonymous-current-source-draft.pdf`.
- PDF SHA-256:
  `463e0082f8d0a9e6c3b4cf07bc33e60c1869a64d33b04dbf1bd79b6c33deb971`.
- Format: official IACR `iacrcc` class 0.78 with `version=submission`.
- Pages: 21 A4 pages. References begin on page 18, so the body occupies pages
  1--18 and remains below the 20-page regular-paper body limit.
- Metadata author: `hidden for submission`.
- No encryption, form fields, JavaScript, empty pages, or extracted-text
  replacement characters.

Text extraction found no unresolved `[?]`, `??`, or `undefined` marker. All 26
cited keys resolve to exactly 26 bibliography entries. The extracted text and
hyperlink targets contain none of the scanned author/account values, public
repository URL, original provider run/artifact IDs, or exact E4 and follow-up
source identifiers. The deliberate `blinded-*` tokens remain internally typed
and consistent.

## Visual and TeX QA

All 21 pages were rendered at 120 dpi and inspected in four contact sheets.
Pages 15--18 were additionally inspected at original detail because they hold
the evidence-boundary figure, the two multi-page evidence tables, the follow-up
and current-source outcomes, the limitations, the conclusion, the AI-use
disclosure, and the beginning of the bibliography. No clipping, overlap,
unreadable table cell, or malformed page break was found.

The final TeX log has zero overfull boxes and no unresolved citation warning.
The only invalid-UTF-8 messages arise from comments inside Tectonic's cached
`listofitems.tex`; the PDF text contains zero replacement characters. Remaining
underfull warnings are confined to narrow table and bibliography cells and are
visually acceptable.

## Reproducible source package

- Tracked source: `docs/paper/submission/cic/`.
- Intended standalone archive:
  `output/submission/route-c-cic-anonymous-current-source-source-v1.zip`.
- Builder: Tectonic 0.17.0.
- Reproducibility epoch: `SOURCE_DATE_EPOCH=1788192000`.
- Official template archive SHA-256:
  `a37925cca6c62be3804141ee6f7a8faf8d656b3aba30b1f97f26b58b9a92bc3f`.
- Vendored class SHA-256:
  `871459a12bc0f41f1efe20b198b296e334af6bbb274d51ad37fa91a484cf5eca`.

The package `SHA256SUMS` covers every source, bibliography, class, style, and
image. The archive hash and clean-extraction reproduction result are filled in
only after the source commit is frozen; no placeholder hash is presented as a
completed artifact.

## Repository and CI closure

The publication-status update merged at exact main
`8f864d5c76919902270dd23ae7d339fe193aaf0a`. Its post-merge CI run
`33416926648` completed successfully:

- P-1 manifest and Python syntax gates passed;
- unit result: 2,667 passed and 2 expected runner-dependent skips in 1,182.02
  seconds;
- predicted-only smoke, R0 bundle creation, and upload passed; and
- R0 artifact `9768048656`, digest
  `sha256:8f06f1cc2ff817cdeb4952277ae910148a2abd0a1a9092297aa6939be0b35a68`,
  10,016,595 bytes, was unexpired at audit time.

That CI validates repository health at the package base. It does not substitute
for the venue-PDF review or for missing comparative-performance evidence.

## Venue boundary

The official CiC pages currently list Volume 3 Issue 4 submission for
2026-10-26. Initial submissions are anonymous PDFs, and the regular-paper limit
is 20 pages excluding the bibliography. The current package is therefore a
better author-blank preparation target than a single-anonymized venue that
requires a populated title page.

Before an actual upload, recheck the live Issue 4 portal, deadline convention,
class archive, article type, and generative-AI disclosure route. The human
authors must privately supply author order, affiliations, contact, conflicts,
funding, CRediT roles, and license decisions without adding them to the
double-blind PDF.

## Remaining stop conditions

Do not represent this candidate as submission-ready until all of the following
are closed:

1. Freeze an exact package commit and standalone source archive, verify its
   `SHA256SUMS`, reproduce the PDF from a clean extraction, and record both
   final hashes.
2. Send that exact immutable packet to ChatGPT Pro and ZCode GLM-5.3 Max at the
   strongest reasoning modes; close every P0/P1 or amend and refreeze.
3. Re-run the anonymity, citation, metadata, and page-render checks after any
   review-driven edit.
4. Confirm the live CiC Issue 4 portal and the code/evidence distribution route
   with identifying material withheld until unblinding.
5. Obtain human confirmation of the AI-use disclosure and private submission
   metadata. Author names may remain blank in this anonymous working PDF.
