# Paper Evidence Collaboration

Apply this policy at every material publication gate: architecture or protocol
freeze, behavior-changing implementation, pull-request merge, evidence freeze,
experiment dispatch, result interpretation, and submission-draft review.

1. Establish the repository facts first: exact commit and tree, bounded diff,
   test or workflow run IDs, artifact IDs and digests, and the claim being gated.
2. Send the same bounded review packet to every configured high-reasoning
   reviewer that is currently available. Prefer ChatGPT Pro and ZCode at their
   strongest configured modes; ZCode is currently expected to use GLM-5.3 Max.
3. Ask for a gate verdict (`PASS` or `AMEND`) and explicit P0/P1/P2 findings.
   Reconcile disagreements against repository source, tests, workflow logs, and
   primary artifacts. A gate is closed only when local checks pass and no P0 or
   P1 remains unresolved.
4. Record material verdicts or reviewer unavailability in the relevant PR or
   evidence note. If a reviewer is unavailable or quota-limited, continue with
   the available reviewer plus local verification and retry the missing reviewer
   at the next gate; availability alone must not stall safe work.

For ChatGPT Pro channel selection and reviewer handling, and whenever a
high-consequence question remains unresolved after local evidence review and the
available ChatGPT Pro/ZCode reviews do not converge, apply the
[`external-expert-escalation`](.agents/skills/external-expert-escalation/SKILL.md)
project skill. It prefers the signed-in Ego Lite session for ChatGPT Pro; Fable 5
is an escalation reviewer, not a routine extra vote.

External model output is advisory review, never source authority, experimental
evidence, or permission to weaken a fail-closed gate. Reviewers are read-only by
default; implementation work belongs on an isolated branch with its own tests.

Keep exact-SHA evidence stable: while a workflow is witnessing a commit, place
unrelated edits on a separate worktree and do not move the witnessed branch.
Run heavy tests and experiments on GitHub-hosted runners. Keep local probes
small and low-priority. Report schedule estimates as ranges with stated
dependencies, separating engineering completion, evidence completion, and a
submission-ready manuscript.
