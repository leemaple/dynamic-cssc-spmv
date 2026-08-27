# Day 1A critical-path static audit (2026-08-28)

## Scope and authority

This note is a read-only performance diagnosis. It is not experimental evidence and
does not authorize a formal Day 1A dispatch.

- Pre-anchor experiment source: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`.
- Disposable data-only S2: `bf25f10fff30ce294656d6ecef80a2658d3b4f63`.
- Current NON-ADMISSIBLE diagnostic: run `33099397289`, seed `20260821`, exactly one
  `mixed-insert-delete-modify` / `1s` shard.
- Frozen operational gate: elapsed time from producer-job `startedAt` through the
  replay job's completed receipt guard, including artifact handoff, must be at most
  **300.00 minutes**. The per-job 355-minute timeout is only a hard stop and cannot be
  substituted for this gate.
- Current producer `startedAt`: `2026-08-27T17:38:59Z`; active stop-loss deadline:
  `2026-08-27T22:38:59Z`. If the guard has not completed by that instant, the run is
  NO-GO and must be cancelled rather than left to the 355-minute job timeout.

The disposable S2 must remain immutable. The diagnostic must not upload aggregate or
formal shard evidence, and this ancestry can never become a formal Day 1A source.

### Machine-enforcement status

At the reviewed source, the workflow and its contract tests machine-enforce only a
355-minute timeout on the producer job and a separate 355-minute timeout on the replay
job. They do **not** encode the cross-job 300.00-minute critical-path gate. That gate is
currently an external pre-dispatch operational decision recorded in this audit and
enforced for run `33099397289` by exact-run monitoring and cancellation.

This distinction is material: two individually non-timeout jobs do not prove the
300-minute condition. Before a fresh formal S1 is frozen, the project must record a
reviewed launch-gate disposition that binds the exact diagnostic run/head, producer
`startedAt`, replay-guard `completedAt`, and the unrelaxed threshold. It must either
machine-validate that closed observation or explicitly retain it as an independently
verified operational prerequisite. The current diagnostic may not be promoted into
publication evidence, and this finding is not permission to add a general evidence
schema or weaken the threshold.

## Established observations

The previous diagnostic run `33040816357` ended by job timeout, not a Python exception:

- producer: 273.90 minutes, success;
- old independent replay: 81.08 minutes before cancellation;
- total shard job: 355.25 minutes;
- replay receipt, guard, upload, and aggregate: absent or skipped.

That run therefore failed the 300-minute operational gate. It did not contain enough
logging to attribute time to individual rho cells.

A later reference run, `33075408647` at source `bb83d4e42209e24df0c71df3eea5df7cbff7e1d5`,
also failed the gate before replay:

- producer job: `13:10:57Z` to `18:22:36Z`, or 311 minutes 39 seconds;
- core producer step: 311 minutes 21 seconds;
- replay was cancelled after 9 minutes 30 seconds because the critical path was already
  unrecoverably over 300 minutes;
- guard, shard upload, and aggregate evidence were skipped or cancelled.

This is direct runtime evidence for the older source, not a substitute for the current
exact-head observation. Between `bb83d4e` and `50d8ade`, the simulator changed to avoid
building a strong execution bundle for zero-query windows, among other accounting
refactors. The current run must therefore continue only until its independently frozen
deadline.

## Static cost facts in the current source

The publication plan fixes 4,096 rows, 8 initial nonzeros per row, 6,000 accepted
updates, 14 fixed candidates, and nine query/update ratios. `run_suite` performs full
simulation for rho in `{0.01, 0.03, 0.1, 0.3, 1}` and exactly rescales query-linear
metrics from rho=1 for `{3, 10, 30, 100}`.

The following are direct source facts:

1. `generate_event_stream(...)` is currently inside the nine-rho loop even though its
   arguments and seed are unchanged between rho cells. The same base stream is thus
   regenerated nine times.
2. For `mixed-insert-delete-modify`, `_existing_in_row(...)` linearly scans the whole
   logical dictionary for every accepted update. The initial dictionary has 32,768
   entries, so stream generation alone performs a large repeated Python scan.
3. Every fully simulated ordinary candidate and publication window calls
   `_validated_candidate`, which starts with `dict(state.logical)`. State construction
   then normally performs another `dict(candidate)` copy.
4. The strong reference has the same two-copy pattern through
   `_validated_strong_candidate` and `StrongStrategyState(logical=dict(candidate), ...)`.
5. The five full rho cells contain at least 8,640 query boundaries in total
   (`60 + 180 + 600 + 1,800 + 6,000`), before any extra microbatch/freshness boundary.
   Across 14 candidates this implies at least 120,960 state transitions. This is a
   lower-bound count, not measured wall time.
6. The v3 independent replay reduces full replay from nine rho cells to five and
   validates four exact rescalings. It still invokes the same full causal evaluator for
   those five cells; it does not remove the producer's five full evaluations.
7. After every ordinary multi-target window, `simulate_targets_causal` compares the
   logical dictionary of each of the other 12 targets with the first target. Because
   equal Python dictionaries are distinct objects, these are 12 additional deep
   equality walks per window. The same pattern exists in the non-causal multi-target
   simulator.

## Diagnosis, explicitly marked as inference

The dominant cost is likely a combination of repeated whole-stream construction and
whole-logical-state copying. At the initial 32,768-entry size, 120,960 transitions
correspond to roughly 4 billion dictionary-entry insertions for one full copy per
transition, or roughly 8 billion for the current two-copy pattern. The 12 cross-target
deep-equality checks add another order-of-magnitude-comparable set of dictionary walks.
Matrix size changes during the mixed workload, so these are order-of-magnitude
estimates, not measurements.

The source therefore does **not** justify treating the replay-only `9 -> 5` change as
sufficient. With a 273.90-minute historical producer, the frozen gate leaves only
26.10 minutes for artifact handoff, replay, and guard. The present split-job workflow
must be judged by its actual end-to-end critical path.

A local, non-authorizing attempt to count windows was stopped after approximately
18 seconds when even stream/window generation occupied one CPU core continuously. No
number from that aborted probe is used as evidence. Further profiling belongs on a
GitHub-hosted runner.

## Bounded contingency if the current diagnostic is NO-GO

Only one root-cause performance branch is justified before reconsidering the paper
shape. Its allowed scope is:

1. Hoist deterministic base-stream generation outside the rho loop and prove byte-for-
   byte/event-for-event equivalence for every rho consumer.
2. Remove only the redundant second logical-dictionary copy where ownership is proven:
   the freshly minted candidate may become the new state's private logical dictionary.
   Preserve one copy, all validation, and state isolation. Cover every strategy and the
   strong path with mutation-isolation and causal-equivalence tests.
3. Replace the 12 per-window cross-target deep-equality walks only if an explicit
   inductive invariant is tested: all targets start from the same logical map, the
   shared generic validator applies the same causally closed window, and every physical
   strategy transition leaves the validator-owned logical result unchanged. Include a
   fault-injection test proving that an intentionally divergent transition still fails
   closed; otherwise retain the existing comparisons.
4. Add non-authorizing per-phase/per-rho timings to a disposable GitHub diagnostic so
   producer, replay, stream construction, and state transition costs are separately
   visible. Timing output must not enter publication artifacts.

Do not introduce a second simulator, a new receipt/schema hierarchy, a new experiment
plan, a reduced publication matrix, or a weakened runtime gate. A shared immutable or
copy-on-write logical state would be a larger architectural change and is out of this
first bounded fix.

After exact-head Linux CI, run one short GitHub-hosted diagnostic. If the frozen
end-to-end gate still fails, stop full-system infrastructure expansion and decide
explicitly between a method/system paper with a narrowed empirical claim and a
negative-result/performance-bound paper. Do not dispatch the formal 21-shard matrix.

## Advisory review disposition

ChatGPT Pro returned `AMEND` on this bounded packet. Its advisory findings were checked
against source and incorporated as follows:

- the 8,640 query-boundary count and 120,960 conservative candidate-transition count
  have no identified arithmetic error;
- the roughly 4-billion/8-billion copy figures remain order-of-magnitude estimates,
  never measurements or strict lower bounds;
- the current run has an active 300-minute cancellation point rather than an open-ended
  wait for the workflow timeout;
- base-stream hoisting and second-copy removal are permitted only with event/trace and
  state-ownership equivalence tests;
- the 12 cross-target deep-equality walks are part of the same repeated-whole-logical-
  dictionary root cause, not permission for a second optimization round. They may be
  replaced only if fault injection proves that a divergent transition still fails
  closed; otherwise the comparisons stay;
- timing remains NON-ADMISSIBLE diagnostic output and must not expand a publication
  receipt or artifact schema.

ZCode was unavailable/quota-limited at this gate and no verdict is attributed to it.
External review is advisory and supplies neither source authority nor experimental
evidence.
