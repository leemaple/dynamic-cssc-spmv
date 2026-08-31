# Route C submission metadata and release checklist

Status date: 2026-08-31

This checklist separates technical work that is already complete from
author-owned facts that must not be guessed by an AI system. The immutable tag
`route-c-external-review-v1` remains the reviewed 2026-08-30 baseline. The
current successor begins at exact S2
`e1e488f177dc8a469c6132a29537b041fbf1430b` and adds only the 2026-08-31
terminal follow-up disclosure and regenerated document outputs; it requires a
new exact-object review tag before submission.

## Technically complete

- [x] English manuscript and editable-equation DOCX.
- [x] Chinese technical companion and editable-equation DOCX.
- [x] Primary-source citation audit for every used key.
- [x] Claim/evidence ledger with closed empirical claims.
- [x] Full-page visual, package-integrity, equation, and accessibility QA.
- [x] Immutable public review tag and remote file-hash verification.
- [x] ZCode GLM-5.3 Max review: P0 = 0, P1 = 0.
- [x] ChatGPT Pro successor review: PASS, P0 = 0, P1 = 0, external
  circulation ready.

## 2026-08-31 terminal-outcome successor

- [x] Exact provider state, zero-artifact boundary, and frozen one-shot
  disposition independently checked by ChatGPT Pro and ZCode GLM-5.3 Max.
- [x] Additive terminal-NO-GO record and English/Chinese source updates drafted
  without changing preregistration, study plan, anchor, behavior registry, or
  claim ledgers.
- [x] Rebuild both DOCX files and verify editable OMML equations.
- [x] Render and inspect every English and Chinese page after the rebuild.
- [ ] Obtain same-packet Pro/ZCode review with no unresolved manuscript P0/P1
  on the exact successor object.
- [ ] Close exact-head CI and create a new immutable external-review tag.

## 2026-08-31 current-source functional addendum

- [x] Freeze and independently review the current-source E4 conformance
  preregistration with no unresolved Pro/ZCode P0/P1.
- [x] Create the one-time lightweight source tag and dispatch exactly one
  current-source E4 run.
- [x] Audit the raw provider ZIP, exact 19-file set, checksums, JSON pointers,
  complete workflow inventory, and detached-source provenance.
- [x] Record the bounded 35/35 contract result and one-fixture OpenFHE oracle
  match in the Markdown manuscript and claim ledger.
- [ ] Obtain same-packet Pro/ZCode review of the raw-result audit and exact
  manuscript diff with no unresolved P0/P1.
- [x] Rebuild the editable-equation DOCX/PDF and complete page-by-page visual,
  equation, package, and accessibility QA. The accepted render has 26 English
  Letter pages and 24 Chinese A4 pages; both DOCX packages pass ZIP integrity,
  retain editable OMML, and have blank creator/last-modifier fields. The
  accessibility audit reports zero high or medium findings in either file; its
  only English findings are 26 low-severity raw-URL labels in the bibliography.
- [ ] Merge and tag the exact accepted result/manuscript packet.

## Human facts required before submission

Do not infer these from Git history, account names, email addresses, or prior
chat messages.

- [ ] Final author names in publication order.
- [ ] ORCID identifiers, if available.
- [ ] Affiliations and postal addresses.
- [ ] Corresponding-author name and submission email.
- [ ] Funding statement, including grant numbers, or an explicit
  `No external funding` confirmation.
- [ ] Competing-interest statement, including an explicit `None declared`
  confirmation when applicable.
- [ ] CRediT roles for every human author.
- [ ] Human confirmation of the generative-AI disclosure.
- [ ] Acknowledgements, if any.
- [ ] Software license selected by the rights holder.
- [ ] Final venue and article type.

## Recommended manuscript title

> Version-Bound Maintenance for Mutable Homomorphic Sparse Matrix--Vector
> Multiplication: A Fail-Closed Evaluation Boundary

The title deliberately foregrounds the actual contribution and does not imply
that a comparative performance campaign completed.

## Proposed data and code availability statement

The following text is accurate for the current review packet. Replace the
repository tag with an archival DOI only after an archive has successfully
minted one.

> Source code, frozen protocol definitions, verification tests, the
> claim--evidence ledger, the primary-source citation audit, and the exact
> external-review manuscript packet will be publicly available at the new
> immutable successor tag recorded before submission in
> <https://github.com/leemaple/dynamic-cssc-spmv>. The experiment-source and
> evidence-freeze snapshots for the primary lineage are Git commits
> `ee58627bb5752c6ac1ee2c5132c6574f9cb66552` and
> `c7ff6820d9323f1850c1c5c57fd9070db88db120`. Its sole qualification selected
> the stop route before formal dispatch; its transient q1 handoff was designated
> non-evidence. A separately preregistered follow-up used S1
> `f8d89d6f98f289dc2e0c3414f7b4ed59b5d30f52` and direct-child data-only S2
> `e1e488f177dc8a469c6132a29537b041fbf1430b`. Its sole qualification run
> `33348855548` was cancelled during hosted-runner setup before repository
> checkout or seed admission and produced zero artifacts. Consequently no
> admitted synthetic, ordered-event, native OpenFHE, terminal, aggregate, or
> analysis artifact exists. A separate current-source deterministic conformance
> replication at tag `current-source-e4-conformance-20260831-v1` passed in run
> `33386130654`; its one-fixture functional artifact is `9755741401`, raw digest
> `sha256:5978b7d9f75048939c9761243e224abb588ed82c2abc64e051523a7a598a1383`.
> It is not a performance artifact and does not reopen either stopped lineage.
> The public SNAP source object was not acquired into the formal lineage and is
> not redistributed by this paper.

## Proposed generative-AI disclosure

This wording is a factual draft, not a substitute for the selected publisher's
policy or human approval.

> Generative-AI systems assisted literature discovery, implementation and test
> generation, adversarial review, and manuscript drafting. The human authors
> independently reviewed the cited sources, code, evidence records, and final
> text and accept full responsibility for the work. No AI system is listed as
> an author.

Before submission, compare this wording against the selected venue's current
author policy and move it to the location that policy requires.

## CRediT worksheet

For each human author, mark only roles they actually performed:

| Role | Author name(s) |
|---|---|
| Conceptualization | |
| Methodology | |
| Software | |
| Validation | |
| Formal analysis | |
| Investigation | |
| Data curation | |
| Writing -- original draft | |
| Writing -- review and editing | |
| Visualization | |
| Supervision | |
| Project administration | |
| Funding acquisition | |

## Release sequence

1. Select the venue and article type from the current official-source venue
   review.
2. Supply the human metadata above.
3. Choose and add the top-level software license; do not treat public GitHub
   visibility as permission to reuse the source.
4. Create the venue-formatted submission branch from the immutable review tag.
5. Replace manuscript placeholders with verified author facts and the venue's
   required declarations.
6. Rebuild and inspect the venue-formatted PDF/DOCX/LaTeX package.
7. Run one final claim, citation, and evidence-boundary review on the exact
   submission bytes.
8. Tag the accepted submission packet.
9. Create the public GitHub release and, if selected, archive that exact tag in
   Zenodo or another approved repository; record the minted DOI only after it
   resolves.
10. Update the manuscript availability statement and `CITATION.cff` with the
    verified DOI and human author metadata.

## Submission stop conditions

Do not submit if any of the following is true:

- author order, affiliation, funding, or competing interests are still
  placeholders;
- the selected venue requires an empirical result that this Route C paper does
  not have;
- the manuscript describes q1/q2 qualification fragments as performance data;
- the manuscript treats follow-up runner setup, prerequisite controls, or the
  unknown watcher-admission subfailure as scientific or performance evidence;
- the successor terminal-NO-GO record, rebuilt DOCX files, exact review packet,
  CI, and immutable review tag have not all closed;
- a moving branch is cited in place of the immutable packet;
- a DOI, license, or artifact is claimed before it exists;
- citation keys remain unresolved or a newly public SparseE record has not been
  rechecked;
- the current-source E4 raw audit, bounded manuscript wording, exact-packet
  review, rebuilt DOCX/PDF, or immutable result tag has not closed;
- the final venue-formatted files have not received page-by-page visual QA.
