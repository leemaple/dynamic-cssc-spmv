# CiC submission metadata and release checklist

Status date: 2026-09-01 (Asia/Shanghai)
Technical manuscript state: **complete and anonymously frozen**
Portal state: **Issue 4 submission date 2026-10-26; portal not yet open**

This checklist separates completed technical work from author-owned facts that
must not be inferred by an AI system.

## Exact frozen submission object

- reviewed source commit:
  `78444ee1d8011c3a9268fd99e920e557ca92c2d4`
- reviewed tree: `a953b27148e7774d0c725f504b92584a8fa141de`
- repository merge commit:
  `3dfdaff617bb1a118ba68d3ac58cf3ee2e72e02b`
- PDF SHA-256:
  `c3a8c6d4e85323587c8336886367ca0527f1f9b211d79047b012851e9a4e9112`
- source archive SHA-256:
  `a39f9d1f28c9e05eced91d29b706ddfdf3860d02bc4f23487cc24b352b2a2d8c`
- final independent reviews:
  - Fable 5 max: `PASS — P0=0 / P1=0 / P2=0`
  - ChatGPT Pro 5.6 Sol Ultra: `PASS — P0=0 / P1=0 / P2=0`

## Technically complete

- [x] Sole preregistered 54-cell validation-scaling study completed.
- [x] Three producer jobs, three independent replay jobs, one aggregate job,
  and seven registered artifacts completed in the sole attempt.
- [x] Independent post-terminal package rehash, cell reinspection, and
  byte-identical aggregate reconstruction completed.
- [x] Bounded admitted result integrated without reopening the stopped
  comparative/native performance lineages.
- [x] Anonymous English CiC source uses
  `\documentclass[version=submission]{iacrcc}`.
- [x] Title, short abstract, and keywords present.
- [x] Nineteen non-bibliography pages, within the regular-paper limit.
- [x] Prominent generative-AI disclosure plus detailed working disclosure.
- [x] Two clean deterministic builds are byte-identical.
- [x] All 21 pages visually inspected.
- [x] Ten package checksums, citation resolution, anonymity, and PDF metadata
  checks pass.
- [x] Exact reviewed source and PDF preserved locally and in GitHub history.
- [x] PR #55 merged the exact reviewed manuscript; post-merge main CI
  `33488665458` completed successfully with `2667 passed, 2 skipped`, and its
  sole R0 artifact is bound to the merge SHA.

## Human facts required

Do not infer these from Git history, account names, email addresses, or earlier
chat messages. They remain outside the anonymous PDF until the venue requires
private portal entry or the paper is accepted/unblinded.

- [ ] Final human author names and publication order.
- [ ] ORCID identifiers, if used.
- [ ] Affiliations and postal addresses.
- [ ] Corresponding-author name and email.
- [ ] Complete conflict-of-interest declarations for every author.
- [ ] Funding statement and verified grant identifiers, or a human-confirmed
  no-external-funding statement.
- [ ] CRediT roles for every author.
- [ ] Human acceptance of the generative-AI disclosure.
- [ ] Acknowledgements, if any.
- [ ] Software/data license and public-artifact availability decision by the
  rights holder.

## Live venue gate

The official CiC CFP and FAQ were checked on 2026-09-01. They require an
English, anonymous PDF using `iacrcc` submission mode; regular papers may use at
most 20 pages excluding bibliography; generated content must be disclosed; and
conflict information must be correct. The manuscript meets the technical
requirements.

The official homepage lists Volume 3 Issue 4 submission on 2026-10-26. The live
CFP/submit link still targets Volume 3 Issue 3, whose 2026-07-27 deadline has
passed and which is now in rebuttal. The Issue 4 exact cutoff and portal are not
yet public. Therefore:

- [ ] Monitor for the official Issue 4 CFP/portal before 2026-10-26.
- [ ] Recheck deadline, portal URL, `iacrcc` version, page rule, AI policy,
  conflict policy, and supplementary-material rules on that day.
- [ ] Enter verified author/contact/conflict metadata privately.
- [ ] Choose the artifact/code-availability response consistent with the
  rights-holder decision.
- [ ] Upload the exact frozen PDF, unless a verified policy change requires a
  descendant and a new build/review cycle.

## Proposed availability statement

Human authors must approve the final form and remove any statement not
supported by the actual release decision:

> Source code, the frozen validation-scaling protocol and implementation,
> verification tests, the anonymous manuscript source, and the admitted
> evidence audit are preserved in the project Git history. The preregistered
> validation-scaling study ran exactly once and its independently reconstructed
> aggregate is reported under the manuscript's bounded claim rules. The two
> earlier comparative/native performance lineages stopped at their frozen
> gates and are not reported as successful experiments. Public artifact and
> archival-DOI availability will follow the rights-holder release decision.

## Submission stop conditions

Do not submit if any of the following is true:

- the Issue 4 portal is not open or its exact cutoff is unconfirmed;
- private author/contact/conflict information is missing or unverified;
- a license, DOI, or public artifact is claimed before it exists;
- the PDF/source hash differs from the frozen object without a documented
  descendant build and review;
- the manuscript overstates the admitted validation-scaling result or rescues a
  stopped performance lineage; or
- a live venue policy change has not been reconciled.
