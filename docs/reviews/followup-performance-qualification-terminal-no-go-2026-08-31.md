# Follow-up performance qualification terminal NO-GO — 2026-08-31

## Authority and scope

This is an additive outcome record for the separately preregistered follow-up
performance study. It records a terminal control-plane failure and the resulting
one-shot disposition. It grants no qualification, formal-execution, analysis,
artifact-installation, or publication-result authority.

The frozen preregistration, study plan, behavior registry, registration anchor,
and claim ledgers are historical inputs to this record and are not amended by
it. In particular, this outcome does not create a post-hoc exception for an
infrastructure failure and does not authorize a second qualification.

## Frozen identities

- Experiment-source S1:
  `f8d89d6f98f289dc2e0c3414f7b4ed59b5d30f52`
- Data-only S2:
  `e1e488f177dc8a469c6132a29537b041fbf1430b`
- S2 tree:
  `f14d25967a0e069c9a09ce926e10ee0378bfe9f6`
- S1-to-S2 compatibility receipt:
  `c163974a0c3d382f0a5e47fc998da8ff42a879c08b6e70e678b9a37f4ed87e24`
- Independent-disposition packet SHA-256:
  `2201aafe9a604c1fd4795c64f67b56bf9099567c4e64c9b0b86742b099ff6ea9`

S2 is the sole direct child of S1. Its only change is the mode-`100644`
registration-anchor object at
`config/followup-performance-registration-anchors.json`.

## Fresh prerequisite controls

All five exact-S2, attempt-1, authority-false controls completed successfully
before the qualification controller was invoked.

| Control | Run | Exact terminal observation |
|---|---:|---|
| Exact-head Linux CI | `33347586537` | Success; 2,653 tests passed, two expected runner-dependent skips, Ruff and `git diff --check` passed |
| PRE-S1 | `33347586567` | Success; pinned OpenFHE 1.5.1 runner, ordinary/strong smokes, 98 sentinel tests, and Ruff passed |
| Descriptive registration | `33347586568` | Success; 32 tests, Ruff, deterministic archive production, and independent byte reinspection passed |
| Source anchor | `33347586620` | Success; direct-child and compatibility checks, including 16 focused tests, passed |
| Independent review | `33347586569` | Success; repository review gate reported `PASS — P0=0, P1=0` and 99 focused tests plus Ruff passed |

Before the controller call, both qualification and formal workflow inventories
were empty and the qualification claim tag was absent. These prerequisite facts
do not themselves authorize or constitute a qualification result.

## Sole production action and provider outcome

The production controller was invoked once. It consumed the nonserialized
capability, created the qualification claim tag, and dispatched exactly one
provider run:

- run: `33348855548`
- identity: `workflow_dispatch / main /
  e1e488f177dc8a469c6132a29537b041fbf1430b / attempt 1`
- created: `2026-08-31T01:51:37Z`
- terminal: `completed/cancelled`, updated `2026-08-31T01:51:46Z`
- controller exit: `2`
- controller message:
  `follow-up controller failed closed: qualification watcher could not be armed before seed admission`

The provider exposed six cancelled jobs. Only the first job entered GitHub's
internal `Set up job` step, from `01:51:41Z` to `01:51:42Z`, and that step ended
cancelled. The remaining five jobs had zero steps.

No repository checkout, identity check, seed normalization, registered-seed
computation, q1 producer, independent replay, guard, native case, q5 combined
guard, or q6 post-run stage executed. The artifact API returned
`total_count=0`; the new local evidence root was empty.

The claim ref
`refs/tags/dynamic-cssc-followup-performance-qualification-authority-v1`
exists and still targets exact S2. The watch-binding candidate was therefore
not installed. No formal, campaign, terminal, aggregate, or analysis ref exists.

## Frozen one-shot disposition

The provider run and consumed capability constitute the sole qualification
attempt even though seed admission and repository execution did not begin. The
frozen definition attaches the attempt to the sole authorized dispatch, not to
the first measured cell. It contains no rollback or refund transition after a
provider run has been created.

The terminal `cancelled` conclusion is a qualification non-success. Under the
frozen preregistration and claim ledger, it has these consequences:

1. the follow-up result is **TERMINAL-NO-GO**;
2. no direct rerun or second qualification run is permitted;
3. repairing the watcher/CAS seam and replacing S1/S2 would still be an
   impermissible outcome-informed second attempt;
4. deleting, moving, or renaming the claim ref or workflow cannot restore the
   consumed attempt;
5. no formal-dispatch capability exists, so acquisition and all formal units
   remain forbidden; and
6. a third study with the same estimand and resource thresholds cannot be used
   to support this paper.

This is an operational stopping decision, not a finding that any maintenance
strategy is slow, incorrect, insecure, or infeasible.

## Independent disposition reviews

The same 132-line, 6,197-byte packet was independently reviewed by ChatGPT Pro
and ZCode GLM-5.3 Max in read-only mode.

- ChatGPT Pro: `TERMINAL-NO-GO — P0=0, P1=0, P2=0` for new findings in the
  disposition review. It independently verified the packet hash, provider run,
  six-job inventory, zero artifacts, claim ref, frozen one-shot language, and
  the prohibition on a repaired-lineage continuation.
- ZCode GLM-5.3 Max: `TERMINAL-NO-GO — P0=0, P1=1, P2=0`. Its P1 identifies the
  watcher-arm controller defect as a future engineering defect; it explicitly
  states that the defect cannot reopen this study.

The severity counts use different scopes, but the controlling disposition is
the same: the sole attempt is exhausted, formal execution is forbidden, and
only factual failure reporting plus read-only diagnosis remain permissible.

## Root-cause boundary

The exact failing substep is **not established**. The public error collapses a
block containing the initial live read, watcher construction, binding
construction, message-commit creation, compare-and-swap ref update, and
run-admission construction. The nested exception was chained in process but was
not printed or persisted, and the evidence root is empty.

The unchanged tag proves that the binding was not installed; it does not prove
whether the GraphQL CAS was attempted. A generic claim that GitHub forbids a
fast-forward update to an existing tag is not supported by the documented
GraphQL `updateRefs` semantics, and the repository currently has no rulesets.
Plausible residual causes include message-commit creation, a transient or
permission-related GraphQL failure, or the initial early live-read/watcher
construction. Existing read-only evidence cannot distinguish them.

A future, independently preregistered project should persist the full exception
cause chain, exercise message-commit and compare-and-swap behavior in an
authority-false provider drill, and consider a dedicated mutable ref namespace.
Those recommendations are prospective only and cannot repair or continue this
study.

## Paper claim mapping

The paper may report all of the following factual statements:

- five fresh exact-S2 authority-false controls passed;
- one exact qualification run was dispatched and cancelled during hosted-runner
  setup after the external controller failed to establish the watcher-admission
  binding;
- no repository checkout, registered seed, scientific stage, or artifact
  occurred;
- the frozen one-shot rule therefore closed the follow-up as terminal NO-GO;
  and
- no formal execution followed.

The paper must not report a qualification GO, performance estimate, strategy
comparison, 45/55-minute timeout result, algorithmic infeasibility, cryptographic
failure, or precise watcher/CAS root cause. CI, sentinel smokes, setup duration,
and reviewer agreement remain engineering observations, not empirical strategy
evidence.

The scientifically honest submission route is the existing Route C
methods/evidence-boundary manuscript, updated to disclose this chronology and
the continuing absence of performance results.
