# ZCode GLM-5.3 Max Route C manuscript review — 2026-08-30

## Review target

- Branch: `codex/route-c-paper`
- Commit: `f3d26d98600d0edd1aeeb1ce654871a4b4ecca21`
- Parent: `b5d3acfcd706f1708ba6d592a52c5e963130c5ee`
- Tree: `eb26c58596c86b70cc8c9b3312dcc3e517859f36`
- Authoritative Markdown SHA-256:
  `c14cfc5a64321daef7cd6687fb39325e1340e28d36cce8be4b9ff36d0ad79ab3`
- Review DOCX SHA-256:
  `3dbb430834a9300eec42cae61e32967a25293f2ea77812f9a61e4bb8492a5a2b`
- Bibliography SHA-256:
  `231c9fae15b98be60ccd042939d0c5eeb323764102d102ae890d1aa6e8d893ce`

The review ran through the ZCode CLI with `bigmodel/GLM-5.3` at the provider's
maximum reasoning level. It was read-only and did not edit files or dispatch
workflows.

## Verdict

**PASS. P0 = 0, P1 = 0, P2 = 6.**

The reviewer found the Route C methods/evidence-boundary manuscript defensible
for external circulation, found no accidental empirical or security overclaim,
and did not request a qualification rerun or a new positive-results lineage.

## Non-blocking findings

1. Define `C_q` at first use as the registered per-case native-runtime estimate,
   and define the phrase “Stage-1 maximum” rather than assuming the reader knows
   the registration stage.
2. Convert present-tense statements such as “cells execute directly” and “we
   report all raw points” into registered/future or counterfactual language,
   because the formal campaign did not run.
3. Add a caption and number to the closest-method comparison table.
4. Align the dated SparseE availability statement with the bibliography access
   date, and repeat the check immediately before submission.
5. Label the Chinese document explicitly as a technical-note companion rather
   than an equivalent manuscript.
6. Remove the four uncited legacy-corpus bibliography entries for LDBC SNB,
   Wikimedia MediaWiki History, NYC TLC trip records, and the NYC TLC data
   dictionary.

## Submission-gate items

- Human authors must provide funding, competing-interest, and CRediT statements.
- Replace working-copy availability text with a real repository release and
  archival DOI.
- Adapt the paper to the selected venue template and citation style.
- Repeat the SparseE/publication-availability check immediately before
  submission.
- Perform a final commit-bound adversarial review after all edits.

## Readiness estimate from the reviewer

- External-reviewable: immediately, or one to two working days after the P2
  cleanup.
- Submission-ready: three to ten working days, roughly one to three calendar
  weeks, assuming no new positive experiment lineage.

## Disposition

All six P2 items are addressed in the successor manuscript revision. The final
commit/ref and regenerated-DOCX hashes are recorded separately after build and
visual verification.
