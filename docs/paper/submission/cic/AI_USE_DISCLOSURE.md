# Working generative-AI disclosure

Status: detailed anonymous-review draft; human confirmation required before
submission.

## Systems used

- OpenAI Codex desktop agent, described by the service as GPT-5-based; no
  immutable model snapshot identifier was exposed to the project.
- ChatGPT Pro in a project-scoped conversation using the strongest available
  Pro reasoning mode; no immutable model snapshot identifier was exposed.
- ZCode CLI using provider model `bigmodel/GLM-5.3` with `Max` reasoning.
- Claude Code 2.1.239 using provider model `claude-fable-5` with `effort=max`
  for bounded, read-only escalation reviews.

The systems were not treated as authors, scientific authorities, evidence
producers, or substitutes for the preregistered execution gates.

## Material uses

1. Literature discovery and bibliography triage. Candidate papers and metadata
   were proposed by AI systems. Every citation used in the manuscript was then
   checked against a primary paper, official proceedings record, DOI record, or
   official project page. AI summaries were not accepted as citation evidence.
2. Implementation and test assistance. AI systems drafted and reviewed source,
   tests, workflow contracts, and validators. Exact-head CI, pinned OpenFHE
   smokes, deterministic replay checks, and repository evidence records—not
   model assertions—were used to decide technical gates.
3. Adversarial review. ChatGPT Pro, ZCode, Fable 5, and independent Codex review
   passes were asked to identify claim/evidence mismatches, missing fail-closed
   behavior, and source-line contradictions. Their findings were treated as
   review comments and independently resolved against code and records.
4. Manuscript drafting and editing. AI systems materially assisted the first
   drafts, restructuring, English and Chinese editing, LaTeX conversion,
   diagrams, tables, and formatting. The functional propositions and evidence
   boundary were checked against the frozen implementation and provenance
   records; no AI output was itself used as an experimental result. The same
   process was used to add the separately stopped follow-up chronology, the
   current-source E4 conformance addendum, and the admitted validation-scaling
   study while preserving their distinct claim boundaries.
5. Venue packaging and quality assurance. AI systems assisted conversion to the
   anonymous CiC class, identity-leakage scans, citation-key reconciliation,
   deterministic rebuild checks, PDF metadata inspection, and page-by-page
   visual review. These checks establish package consistency only; they do not
   predict acceptance or create scientific authority.

## Operative prompt templates

The project used iterative conversations rather than one one-shot generation
prompt. The following are the operative prompt templates; each review instance
also supplied an exact file, commit, digest, or evidence packet.

> Solve the blockers in the dynamic encrypted sparse matrix--vector
> multiplication project, complete a reproducible experiment and evidence
> chain, and use the resulting evidence to prepare a submission-ready paper.

> Perform a read-only specification and standards review of the exact attached
> candidate. Return P0, P1, and P2 findings with file-and-line evidence. Do not
> treat tests, CI, or intermediate artifacts as publication evidence unless the
> frozen admission contract authorizes them.

> Review the exact manuscript and claim--evidence packet. Check every claimed
> contribution, proposition, citation, experiment statement, identifier, and
> limitation against the frozen evidence. Reject performance or security claims
> not supported by an admitted artifact.

> Rewrite the paper around the verified method and evidence boundary after the
> preregistered qualification stop. Preserve the planned experiment only as
> counterfactual methodology, state that no formal campaign ran, and do not
> convert partial qualification execution into a result.

> Integrate the separately preregistered follow-up stop and the admitted
> current-source E4 conformance result. State the exact positive functional
> observation and retain every exclusion on admission, security, deployment,
> performance, speedup, and general correctness.

> Integrate the separately preregistered validation-scaling result only after
> the sole tagged attempt and independent aggregate rebuild pass. Report the
> complete 54-cell semantic/compile closure and descriptive lifecycle fits, but
> prohibit strategy ranking, speedup, native/deployment performance,
> asymptotic inference, general correctness, and security claims.

> Convert the reviewed manuscript to the venue template, keep author fields
> anonymous, preserve mathematical notation, check unresolved citations and
> identity leakage, render every page, and correct all visible layout defects.

Post-generation work included source-level fact checking, primary-source
citation verification, exact-identifier reconciliation, local and Linux CI,
real OpenFHE smoke execution, independent replay/guard testing, external-model
counter-review, manual claim narrowing, and full-page visual QA. Substantive AI
suggestions were rejected whenever they conflicted with the frozen protocol or
available evidence.

## Author confirmation required

Before submission, the human authors must confirm that this disclosure fairly
describes the tools and their material use, accept responsibility for every
claim and citation, and decide whether the venue requires this document as an
appendix, supplementary file, or expanded disclosure in the paper. Exact raw
conversation logs contain account and repository identifiers and are therefore
not included in the anonymous packet; they should be retained privately for an
editorial query.
