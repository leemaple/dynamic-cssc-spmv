# Follow-up qualification watch-arm failure — exact disposition review packet

Review date: 2026-08-31 (Asia/Shanghai)

Repository: `leemaple/dynamic-cssc-spmv`

This is a read-only disposition request. Do not edit code, mutate refs, dispatch,
rerun, cancel, download artifacts, or use any registered seed.

## Frozen identities

- Experiment-source S1: `f8d89d6f98f289dc2e0c3414f7b4ed59b5d30f52`
- Data-only S2: `e1e488f177dc8a469c6132a29537b041fbf1430b`
- S1-to-S2 compatibility receipt:
  `c163974a0c3d382f0a5e47fc998da8ff42a879c08b6e70e678b9a37f4ed87e24`
- S2 tree: `f14d25967a0e069c9a09ce926e10ee0378bfe9f6`
- S2 is the sole direct child of S1 and changes only
  `config/followup-performance-registration-anchors.json` at mode `100644`.

## Fresh prerequisite controls

All five exact-S2, attempt-1, workflow-dispatch controls completed successfully
before qualification dispatch:

1. exact-head Linux CI `33347586537` — 2653 passed, 2 expected runner-dependent
   skips, Ruff and `git diff --check` passed, one authority-false artifact;
2. PRE-S1 `33347586567` — pinned OpenFHE 1.5.1 and exact runner built,
   ordinary/strong smokes passed, 98 sentinel tests and Ruff passed, one
   authority-false artifact;
3. descriptive registration `33347586568` — 32 tests and Ruff passed,
   deterministic archive and independent byte reinspection passed, one
   authority-false artifact;
4. source anchor `33347586620` — direct-child/compatibility checks and 16 tests
   passed, one authority-false artifact;
5. independent review `33347586569` — exact review verdict `PASS — P0=0, P1=0`,
   99 tests and Ruff passed, one authority-false artifact.

Before controller execution, the exact-S2 qualification and formal workflow
inventories were both empty and the qualification authority tag was absent.

## Exact controller action and terminal observation

The production command `scripts/control_followup_performance.py
execute-qualification` was invoked once with the five run IDs above, exact
S1/S2/receipt, and a new absolute evidence root. Its authorization phase
completed far enough to consume the nonserialized capability, create the
qualification claim tag, and dispatch exactly one provider run:

- qualification run: `33348855548`
- event/branch/head/attempt:
  `workflow_dispatch / main / e1e488f177dc8a469c6132a29537b041fbf1430b / 1`
- created: `2026-08-31T01:51:37Z`
- terminal: `completed/cancelled`, updated `2026-08-31T01:51:46Z`
- controller exit: 2
- controller message:
  `follow-up controller failed closed: qualification watcher could not be armed before seed admission`

The controller itself submitted the cancellation from the exception handler
covering `start_qualification_watch`, binding construction, binding CAS, and
run-admission construction.

## What executed and what did not

- The first job, `qualification-simulator-producer`, ran only GitHub's internal
  `Set up job` step from about `01:51:41Z` to `01:51:42Z`; setup ended with
  `The operation was canceled.`
- No repository checkout step ran.
- No identity check, seed normalization, registered-seed computation, q1
  producer, replay, guard, native case, q5, or q6 step ran.
- The other five jobs had zero steps and were cancelled.
- Artifact API: `total_count=0`.
- The local evidence root exists but is empty.
- A fresh production `read_live_qualification(33348855548)` succeeds after the
  cancellation and returns the exact six terminal-cancelled jobs.

## Provider ref state

The newly created claim tag now exists:

`refs/tags/dynamic-cssc-followup-performance-qualification-authority-v1`

It still targets exact S2
`e1e488f177dc8a469c6132a29537b041fbf1430b`. Therefore the watch-binding
candidate was not installed by the compare-and-swap. No formal progress,
terminal, analysis, or campaign ref exists.

This ref state narrows the likely failure to either the immediate initial live
read / watch construction or the subsequent message-commit / GraphQL
`updateRefs` CAS. The public controller intentionally hides the nested exception,
so this packet does not assert which substep failed.

## Frozen normative text

`docs/paper/followup-performance-preregistration.md:154-171` states:

- exactly one follow-up qualification attempt;
- any timeout, correctness failure, provider failure outside the frozen handling
  rule, identity mismatch, missing/extra artifact, guard failure, or deadline
  miss produces terminal follow-up NO-GO;
- the qualification cannot be rerun;
- failure authorizes neither a threshold change nor a second seed.

Lines 181-202 further state that atomic capability consumption authorizes only
the sole exact qualification and that qualification non-success reaches terminal
follow-up NO-GO without a formal capability.

`src/dynamic_cssc/followup_performance_qualification_execution.py:103-191`
defines the sole `claim -> dispatch -> watch -> CAS -> terminal` sequence. After
dispatch, any failure while arming/installing the watcher cancels the run and
raises the exact error observed here.

## Questions requiring an independent binding verdict

Return `TERMINAL-NO-GO` or `AMENDABLE-PRE-ADMISSION-FAILURE`, with P0/P1/P2
counts and exact reasoning.

1. Under the frozen wording, does creation of provider run `33348855548` plus
   consumption of the capability constitute the sole qualification attempt even
   though no checkout or registered-seed step began?
2. Is any second qualification dispatch forbidden for this follow-up study?
3. Would a replacement S1/S2 that repairs the watch/CAS path and then dispatches
   a fresh qualification be an impermissible post-outcome second attempt, or can
   it be justified as a pre-admission infrastructure amendment? Point to the
   exact frozen text that controls the answer.
4. What read-only checks can determine whether initial watch construction or the
   GraphQL tag CAS failed without mutating the provider?
5. If this follow-up is terminal NO-GO, what scientifically honest paper route
   remains, and which empirical claims must stay absent?

Do not optimize for continuing the experiment. Optimize for the strictest
defensible publication-integrity interpretation. Separate observed facts from
inference.
