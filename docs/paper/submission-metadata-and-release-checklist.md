# Route C submission metadata and release checklist

Status date: 2026-08-30

This checklist separates technical work that is already complete from
author-owned facts that must not be guessed by an AI system. It applies to the
Route C methods/evidence-boundary paper bound by
`route-c-external-review-v1`, exact commit
`f4fe461ace07bceaf674a9cad61f98bd74f67531`.

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
> external-review manuscript packet are publicly available at the immutable Git
> tag `route-c-external-review-v1` in
> <https://github.com/leemaple/dynamic-cssc-spmv>. The experiment-source and
> evidence-freeze snapshots are Git commits
> `ee58627bb5752c6ac1ee2c5132c6574f9cb66552` and
> `c7ff6820d9323f1850c1c5c57fd9070db88db120`, respectively. The sole
> preregistered qualification selected the stop route before formal dispatch;
> consequently no admitted synthetic, ordered-event, native OpenFHE, terminal,
> aggregate, or analysis artifact exists. Its transient q1 handoff was
> designated non-evidence and is not distributed as a paper result. The public
> SNAP source object was not acquired into the formal lineage and is not
> redistributed by this paper.

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
- a moving branch is cited in place of the immutable packet;
- a DOI, license, or artifact is claimed before it exists;
- citation keys remain unresolved or a newly public SparseE record has not been
  rechecked;
- the final venue-formatted files have not received page-by-page visual QA.
