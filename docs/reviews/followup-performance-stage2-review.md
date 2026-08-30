# Follow-up performance Stage-2 implementation review

Review object: the next exact candidate is pending.  Historical Stage-2 review
object `f920f87c8342673a8e129a886f70d80b585502a9` had sole parent
`5421cecda19be559ba1c25297dd66c2634489c39`.

Verdict: HOLD — independent implementation review has not yet closed.

External gate history:

- ZCode, GLM-5.3 strongest mode, reviewed exact `f920f87...` and returned
  **AMEND**.  It independently found the formal launch-name mismatch and
  confirmed that retry and the 12-hour ledger were not implemented.
- ChatGPT Pro, Pro reasoning in the signed-in Ego Lite project, reviewed exact
  `5421cec...f920f87` and returned **AMEND: P0=1, P1=3, P2=1**.  It confirmed
  the provider-global one-shot defect, retry/budget defect, Behavior Set
  closure defect, and FU-E4 mapping defect.  It additionally found that formal
  dispatch and watch were separable operations, so active stop-loss was not an
  execution invariant.

Both reviews were advisory and read-only.  No workflow was dispatched and no
registered seed was executed.

The candidate must not be used for qualification or formal dispatch until this
file records zero unresolved P0/P1 findings, both named external reviews have
rechecked the exact final candidate, exact-head Linux CI and PRE-S1 validation
are successful, and the sole data-only S2 child has been produced and verified.

Current implementation notes:

- the formal matrix contains seventeen units in strict producer/replay pairs;
- a live controller enforces each combined unit reservation and cancels the
  exact formal run at the frozen boundary;
- terminal admission and raw aggregation remain separate from isolated S3
  descriptive analysis; and
- no registered qualification or formal seed has been executed during tests.

## Disposition after historical review

Commit `1408e57` is an implementation checkpoint, not a gate candidate.  It:

- adds fixed provider-side qualification and formal claim refs, then performs
  one exact `beforeOid`/`afterOid`, `force:false` provider CAS in the run before
  any registered seed or formal unit;
- independently reinspects the resulting binding commit and exact unchanged-S2
  tree;
- fixes the launch name and adds exact workflow regression coverage;
- closes the transitive native Behavior Set inventory; and
- adds the FU-E4 claim-to-artifact mapping.

The checkpoint passed all 77 follow-up tests, YAML parsing, Ruff, and
`git diff --check`.  It does **not** close this gate: the one permitted
provider-classified whole-unit replacement, unified 12-hour ledger, and
mandatory dispatch-plus-watch campaign transaction remain under implementation.
The next material review must bind an exact later commit and recheck every
historical P0/P1; no finding is inherited as closed merely from this note.

## Successor candidate prepared for exact review

The currently prepared successor is still uncommitted and therefore cannot be
the review object yet.  Its bounded implementation scope is:

- replace the duplicated 34-job formal workflow with one exact two-job unit
  workflow and a strictly serial external controller over the frozen 17-unit
  matrix;
- reserve, dispatch, bind the provider-returned run ID, start the mandatory
  watcher, install the watch-armed CAS state, and only then allow the in-run
  admission gate to cross the registered-seed boundary;
- carry the producer job's provider `startedAt` deadline through the guard job,
  with both an external stop-loss and in-run provider-`Date` checkpoints before
  expensive stages and before/after artifact upload;
- implement the sole eligible whole-unit replacement, segment reservations,
  retry reserve, 12-hour campaign ledger, terminal 30-minute segment, and
  fail-closed terminal/aggregate/isolated-S3-analysis transitions;
- bind every selected provider run, artifact ID/name/digest, acquisition
  dependency, watcher receipt, terminal object, and analysis object into the
  independent evidence installers; and
- close all five follow-up Behavior Sets transitively.  A mechanical Route A
  Behavior-Set inventory repair is included only to restore the inherited
  exact-head CI gate; it changes no scientific payload or registered value.

The GitHub REST API `2026-03-10` contract was independently checked against the
official workflow-dispatch endpoint: a successful dispatch returns status 200
with the exact `workflow_run_id` and run URL used by the controller.  The
watcher additionally uses the later of the run/jobs provider timestamps and
submits at most one cancellation request at an assignment or shared-deadline
gate.

Local pre-candidate evidence currently consists of 157 follow-up tests and six
targeted inherited Route A Behavior-Set closure tests, all passing under a
low-priority single pytest process; changed Python files pass Ruff, the changed
workflow/action YAML parses, and `git diff --check` passes.  The complete Linux
suite remains intentionally deferred to exact-head GitHub CI.  None of these
checks used a registered qualification or formal seed, and no workflow was
dispatched.

This section records implementation facts only.  The verdict remains **HOLD**
until the exact committed successor is reviewed from the same bounded packet by
ChatGPT Pro and ZCode, every resulting P0/P1 is closed, and the exact-head
provider gates named above succeed.
