# Publication-Readiness Review — 2026-08-27

## Scope and evidence boundary

This is an advisory review note, not experimental evidence or publication
authority. Both external reviewers received the same bounded facts and were
instructed to remain read-only.

- Production `main` / Terminal Registration Freeze S2:
  `f158aa7697b8b47a7704c4a4a2028bf6c7c080c4`
- Experiment source / S2 parent:
  `febedea78c88ed779171cedc5dab4be097061a1f`
- Experiment-source tree:
  `c7351ccc4c85ddc32c04c840673ea9972621c43a`
- S2 CI run `33039600108`: 2095 passed, 2 skipped
- Registration run `33037473603`: success; six payloads plus
  `SHA256SUMS` independently verified; exact source/tree/run binding; all
  authority flags false
- Current Day1A run `33040816357`: non-admissible, single-shard diagnostic;
  plan/tests/Ruff passed; no result was available when the reviews were issued
- No accepted formal Day1A, Day2, real-corpus Day1B, mixed-circuit, or R4
  empirical result was available

## Independent verdicts

### ChatGPT Pro

- Verdict: `AMEND`
- Engineering pipeline: 88–94%
- Admissible evidence: 5–12%; core accepted empirical results remain near zero
- Submission-ready manuscript: 38–46%
- Best: 2026-10-19 through 2026-11-06
- Likely: 2026-11-16 through 2026-12-18
- Downside: 2027-01-18 through 2027-03-31, or the present headline scope may
  require a preregistered fallback

### ZCode — GLM-5.3 Max

- Verdict: `AMEND`
- Engineering pipeline: 85–90%
- Admissible evidence: about 5%; zero of the required empirical result families
  are complete
- Methods-first manuscript scaffold: 60–65%; results, figures, declarations,
  venue formatting, and archival identifiers remain open
- Best: mid-October through early November 2026
- Likely: late November 2026 through January 2027
- Downside: Q2 2027 if data-host, Day1B feasibility, lineage-amendment, or
  fallback work intervenes

## Reconciled assessment

The reviewers agree that the engineering and protocol surface is close to
complete, while the paper is not close to submission. The apparent manuscript
percentage difference is definitional: the methods scaffold is roughly 60–65%
complete, but the artifact-backed submission package is only roughly 38–46%
ready because the empirical sections cannot yet be populated.

A conservative joint schedule for a submission-ready manuscript is:

- Best: 2026-10-19 through 2026-11-06
- Likely: late November through December 2026, with January 2027 retained as
  schedule margin
- Downside: Q1–Q2 2027, or an explicit preregistered fallback if the current
  Day1B/R4 scope is infeasible

Peer-review acceptance and formal publication are outside the engineering
schedule and may add many months after submission.

## Immediate critical path

1. Let diagnostic run `33040816357` finish and accept it only as a smoke gate
   if replay, guard, provenance, and runtime limits all pass.
2. From the unchanged anchored `main`, dispatch and admit the formal 21-shard
   Day1A campaign, then complete the data-only anchor steps needed for Day2.
3. In parallel, close real-corpus acquisition/data-host feasibility and the
   explicit Day1B production adapter HOLD set; define the preregistered fallback
   decision point before waiting indefinitely on infrastructure.

