# ChatGPT Pro Route C manuscript review — 2026-08-30

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

The review was performed in the project-scoped ChatGPT Pro conversation through
Ego Lite. Five exact files were attached: the English DOCX, authoritative
Markdown, bibliography, claim ledger, and citation-audit note. The review was
read-only and covered the mathematical propositions, threat/role model,
evidence boundary, citations, provenance, and every rendered DOCX page.

## Verdict

**AMEND. P0 = 0, P1 = 3.**

The reviewer found the Route C scientific core defensible. P1--P4 were
consistently limited to conditional functional claims, the claim ledger closed
the unavailable empirical Route A claims, and the evidence-outcome section did
not promote q1/q2, CI, PRE-S1, or smoke execution into performance evidence.
There was no mathematical contradiction, unsupported formal-security theorem,
released comparative result, or attempt to turn the stopped qualification into
empirical evidence.

## P0 findings

None.

## P1 findings

### P1-1 — Figure 1 contradicted the frozen role and authorization model

The prose correctly said that Client B owns the query and secret key, but Figure
1 labelled Client A as owning “publication and query” and placed “RowMap · plan ·
mask plaintexts” in Client B's metadata area. Exact S1 instead assigns the
matrix, CSSC metadata, RowMaps, ColumnIndex metadata, complete OutputPlan, and
mask sampling/encryption to Client A. Client B owns the query and key set,
receives the versioned ColumnIndex and complete plan, gathers/encrypts the query,
and never receives individual mask plaintexts. Both clients may read the
complete plan; it is private from the Cloud.

Minimal correction: make that ownership and data flow explicit in Section 3,
redraw Figure 1, and regenerate the DOCX.

### P1-2 — Unexecuted formal protocol was partly narrated as completed work

Sections 6.4--6.5 used realized formulations including “three recorded
producers,” “We report,” “directly measure,” and “Native cases instead report,”
although Section 7 correctly stated that no formal case ran and no reportable
strategy-cost or native result exists. The abstract contained the same milder
ambiguity.

Minimal correction: introduce Section 6 as the frozen counterfactual protocol
and convert measurement/reporting verbs to “was specified to” or “would have.”
No methodology, source, or evidence lineage needs to change.

### P1-3 — Attached bytes were hash-bound but the commit was not independently reachable

The supplied Markdown, DOCX, and bibliography matched the declared SHA-256
values, but the connected GitHub repository exposed no ref containing commit
`f3d26d9…`. The reviewer could not independently bind the attached bytes,
figures, ledger, and audit to the claimed commit/tree.

Minimal correction: push an immutable ref containing the exact review lineage,
preferably the named branch plus a review tag, then independently verify its
parent, tree, file hashes, and packet assets. No experiment or workflow rerun is
required.

## P2 findings

1. Tighten proposition notation: bind a canonical logical-state identity rather
   than placing an unexplained raw matrix in P1's acceptance tuple; define P2's
   component matrix as physical-output-row by global-logical-column; define P4
   segment entries as post-multiplication lane values.
2. Replace two unsupported performance-sounding motivation phrases: “can
   dominate update cost” and “can reverse the apparent ranking.”
3. Citation remediation was closed, but SparseE remained date-sensitive. An
   official BUAA institutional summary was public even though no public full
   paper, DOI, or software repository had been located.
4. Add standalone provenance or designate the claim ledger as a version-bound
   supplement; improve the long-digest paragraph's typography. Funding,
   competing-interest, CRediT, repository-release, and archival-DOI placeholders
   block submission but not expert draft review.

The DOCX otherwise had no submission-blocking layout defect: the reviewer found
no clipping and found the equations, tables, captions, and Figure 2 readable.

## Readiness estimate from the reviewer

- External-reviewable: two to three working days after the three P1 corrections,
  DOCX regeneration/inspection, and ref/hash verification.
- Submission-ready without a new positive experiment lineage: three to five
  weeks, including venue adaptation, human declarations, release/DOI, packaging,
  copy-editing, and a final adversarial pass.

## Disposition

P1-1 and P1-2, plus the four P2 groups, are addressed in the successor
manuscript revision. P1-3 is closed only when the regenerated packet is committed,
pushed on the named branch, tagged, and independently reread from the remote ref.
