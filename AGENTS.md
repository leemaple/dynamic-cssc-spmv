# Paper Evidence Collaboration

Apply this policy at every material publication gate: architecture or protocol
freeze, behavior-changing implementation, pull-request merge, evidence freeze,
experiment dispatch, result interpretation, and submission-draft review.

1. Establish the repository facts first: exact commit and tree, bounded diff,
   test or workflow run IDs, artifact IDs and digests, and the claim being gated.
2. Send the same bounded review packet to the available high-reasoning review
   channels. Prefer ChatGPT Pro plus ZCode/GLM-5.3 Max; when ZCode is unavailable
   or quota-limited, Fable 5/max immediately takes that review slot.
3. Ask for a gate verdict (`PASS` or `AMEND`) and explicit P0/P1/P2 findings.
   Reconcile disagreements against repository source, tests, workflow logs, and
   primary artifacts. A gate is closed only when local checks pass and no P0 or
   P1 remains unresolved.
4. Record material verdicts or reviewer unavailability in the relevant PR or
   evidence note. Availability never stalls safe work. A Fable-closed ZCode
   slot is not retried at the same gate; a later call requires a materially new
   gate or an explicit user request.

For ChatGPT Pro channel selection, shared ZCode quota handling, reviewer
handling, and whenever a high-consequence question remains unresolved after
local evidence review and the available ChatGPT Pro/ZCode reviews do not
converge, apply the
[`external-expert-escalation`](.agents/skills/external-expert-escalation/SKILL.md)
project skill. It prefers the signed-in Ego Lite session for ChatGPT Pro; Fable
5/max is the direct substitute for an unavailable ZCode channel and remains the
escalation reviewer for unresolved high-consequence disagreements. It is not a
routine third vote.

External model output is advisory review, never source authority, experimental
evidence, or permission to weaken a fail-closed gate. Reviewers are read-only by
default; implementation work belongs on an isolated branch with its own tests.

Keep exact-SHA evidence stable: while a workflow is witnessing a commit, place
unrelated edits on a separate worktree and do not move the witnessed branch.
Run heavy tests and experiments on GitHub-hosted runners. Keep local probes
small and low-priority. Report schedule estimates as ranges with stated
dependencies, separating engineering completion, evidence completion, and a
submission-ready manuscript.
