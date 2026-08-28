# Manuscript evidence-boundary review — 2026-08-28

## Scope

This is an advisory wording review of the Abstract, Section 5, and Section 7.1 of
`docs/paper/manuscript-draft.md`. The reviewed input had SHA-256
`85cbddf2863956cba1fd54bc0c4b15d988fa3d68c81a2ac459c55154f8b92ff4`.
The reviewers were asked only whether the text confuses historical witnesses,
engineering CI, descriptive registration, PRE-S1, or a NON-ADMISSIBLE diagnostic
with formal paper evidence. They were denied implementation, workflow, artifact,
held-out, and publication authority.

## Verdicts

### ZCode

ZCode GLM-5.3 Max independently rehashed the file and returned **PASS**, with zero
P0 and zero P1. It found the run IDs, commit identities, counts, time boundary, and
authority statements mutually consistent. Its two P2 wording suggestions were to
replace the time-sensitive Abstract phrase `is still running` with a permanent
authorization boundary, and to call PRE-S1 a `run` rather than a `gate`.

### ChatGPT Pro

ChatGPT Pro reviewed the same file and digest in the existing paper Project through
the signed-in Ego Lite session. It returned **PASS**, with zero P0 and zero P1. It
confirmed that the manuscript does not treat the historical fixture, Linux CI,
descriptive registration, PRE-S1 real-runner smoke, or the in-progress diagnostic as
an empirical result. Its P2 suggestions were to describe the evaluation as a protocol,
call the issuer implementation `commit-bound` rather than `frozen`, and label external
review verdicts as advisory.

## Disposition

All wording suggestions were accepted without changing the claim scope:

- the Abstract now uses a permanent one-run NON-ADMISSIBLE authorization boundary;
- `PRE-S1 run` replaces the potentially stronger `PRE-S1 gate` wording;
- the evaluation protocol keeps evidence roles separate;
- the issuer implementation is described as commit-bound; and
- external review verdicts are explicitly advisory and are not named as paper
  evidence.

The amended manuscript SHA-256 is
`3614b5ff5db60698bad8408e753136d72a1087d7be838f24f9886c36950b8e17`.
Pandoc citation processing and `git diff --check` both pass. Neither reviewer verdict
authorizes an experiment, artifact, result, or claim.
