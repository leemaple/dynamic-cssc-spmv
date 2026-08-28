# Day 1A critical-path static audit (2026-08-28)

## Scope and authority

This note is a read-only performance diagnosis. It is not experimental evidence and
does not authorize a formal Day 1A dispatch.

- Pre-anchor experiment source: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`.
- Disposable data-only S2: `bf25f10fff30ce294656d6ecef80a2658d3b4f63`.
- Terminal NON-ADMISSIBLE diagnostic: run `33099397289`, seed `20260821`, exactly
  one `mixed-insert-delete-modify` / `1s` shard, completed `cancelled` after the
  frozen stop-loss was reached.
- Frozen operational gate: elapsed time from producer-job `startedAt` through the
  replay job's completed receipt guard, including artifact handoff, must be at most
  **300.00 minutes**. The per-job 355-minute timeout is only a hard stop and cannot be
  substituted for this gate.
- Producer `startedAt`: `2026-08-27T17:38:59Z`; stop-loss deadline:
  `2026-08-27T22:38:59Z`. At that instant the replay calculation was still running
  and the guard was pending. The exact run was therefore declared **NO-GO** and only
  that run was cancelled.

The disposable S2 must remain immutable. The diagnostic must not upload aggregate or
formal shard evidence, and this ancestry can never become a formal Day 1A source.

### Machine-enforcement status

At the reviewed source, the workflow and its contract tests machine-enforce only a
355-minute timeout on the producer job and a separate 355-minute timeout on the replay
job. They do **not** encode the cross-job 300.00-minute critical-path gate. That gate is
an external pre-dispatch operational decision recorded in this audit. It was enforced
for run `33099397289` by exact-run monitoring and cancellation at the frozen deadline.

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
refactors.

The exact-S2 diagnostic run `33099397289` then closed the remaining observation:

- producer job: `17:38:59Z` to `22:23:59Z`, exactly 285 minutes;
- nine-rho producer step: 284 minutes 44 seconds, success;
- non-evidence pre-replay handoff: success;
- replay job began at `22:24:01Z`; its download and exact-tree rejection succeeded;
- replay calculation ran from `22:24:22Z` until cancellation was observed at
  `22:39:23Z`;
- at the exact `22:38:59Z` deadline, replay was still running and the receipt guard had
  not started.

The run therefore failed the unrelaxed 300-minute critical-path gate. No replay receipt
was produced, receipt-v2/validator-v4 and the `5 full + 4 exact-rescaled` replay counts
were not verified, the guard was skipped, and no formal shard or aggregate evidence was
created. The sole Artifact was the one-day, explicitly non-evidence pre-replay transport
payload: Artifact `9666934132`, provider digest
`sha256:4f6820482dfb233936d3248c0f3cbd0f5f854a45875569b40c6d434efa7a3f01`.

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

## Authorized bounded fix after the diagnostic NO-GO

Only one root-cause performance branch is justified before reconsidering the paper
shape. Its allowed scope is:

1. Hoist deterministic base-stream generation outside the rho loop and prove byte-for-
   byte/event-for-event equivalence for every rho consumer.
2. Remove only the redundant second logical-dictionary copy where ownership is proven:
   the freshly minted candidate may become the new state's private logical dictionary.
   Preserve one copy, all validation, and state isolation. Cover every strategy and the
   strong path with mutation-isolation and causal-equivalence tests.
3. The attempted identity-only replacement for the 12 per-window cross-target
   deep-equality walks was rejected before commit: it caught replacement with a
   different mapping but did not catch an in-place mutation of the validator-owned
   mapping. The original cross-target comparisons therefore remain. A stronger
   in-place-divergence fault injection now proves that the retained check fails closed.
4. Add non-authorizing per-phase/per-rho timings to a disposable GitHub diagnostic so
   producer, replay, stream construction, and state transition costs are separately
   visible. Timing output must not enter publication artifacts.

Do not introduce a second simulator, a new receipt/schema hierarchy, a new experiment
plan, a reduced publication matrix, or a weakened runtime gate. A shared immutable or
copy-on-write logical state would be a larger architectural change and is out of this
first bounded fix.

After exact-head Linux CI, run one and only one same-input GitHub-hosted diagnostic. If
the frozen end-to-end gate still fails, stop full-system infrastructure expansion and
decide explicitly between a method/system paper with a narrowed empirical claim and a
negative-result/performance-bound paper. Do not dispatch the formal 21-shard matrix.

## Frozen bounded-fix implementation

The single authorized implementation is frozen at:

- branch: `codex/day1a-stream-hoist-clean`;
- commit: `efdd9af894842a219080f93c8d36fb09ee93b161`;
- tree: `1c27b664227b859f43af2fb6cab3807534dd9dc9`;
- sole parent: the exact no-anchor source
  `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`;
- binary diff SHA-256:
  `a6d6464a8edb5a274a47abe41b036424f0493a15e5b661c6bd94f8a69237b44e`;
- scope: 14 files, 614 insertions and 60 deletions.

The disposable diagnostic S2 `bf25f10fff30ce294656d6ecef80a2658d3b4f63`
is not an ancestor of this commit. The registration-anchor set is still exactly empty.
The commit hoists one frozen base stream per shard, removes the redundant second
logical-state copy while retaining validator ownership and predecessor isolation,
retains the cross-target deep comparison, adds an in-place-divergence fault injection,
and upgrades the Day 1 behavior set to v4.

Diagnostic timing is opt-in and stderr-only. Every record has the exact pipeline phase,
workload, freshness, and rho identity. Full cells separately expose ordinary state
transitions, strong state transitions, and result assembly; replay additionally
separates window construction, trace validation, exact rescaling, and artifact
validation. Tests bind five full replay cells and four exact-rescaled cells. No timing
record enters an artifact, receipt, checksum, registration schema, or authority field.

The exact local targeted gate reported 29 passing tests, with Ruff, YAML parsing, and
`git diff --check` also passing. Exact-head push CI run `33125107658` then completed
successfully at `2026-08-27T23:36:36Z`: P-1 and syntax passed, the Linux suite reported
2,147 passed and two expected skips for the unbuilt real OpenFHE runner, the predicted
smoke passed, and R0 Artifact `9668701772` was uploaded with provider digest
`sha256:3f35ee46222e901e50974a9370faf27d4845bc44c44ee052d1addebd74736a8b`.
This is engineering evidence, not publication evidence. Only after that exact-head CI
success was descriptive registration run `33126982746` dispatched; no diagnostic has
been dispatched.

## Advisory review disposition

The original `7f3cd61` review object is obsolete. A local specification review first
returned `AMEND` because the timing did not separate transition phases. That finding
was incorporated into the amended commit `efdd9af`, after which the same exact-source
review returned `PASS` with zero P0, P1, or P2 findings.

The independent standards review of `efdd9af` returned `PASS` with zero P0/P1. It
recorded two non-blocking P2 observations for a later refactor: the four-string timing
identity could become a small frozen value type, and the ordinary/strong candidate
validators still duplicate a logical-update core. Neither is permitted to expand this
one bounded performance fix.

ZCode GLM-5.3 Max independently reconstructed the exact commit, tree, binary-diff
digest, clean lineage, and empty anchor set and returned `PASS` with zero P0/P1. Its
non-blocking notes concerned the exact selected-test accounting and local optional
dependencies. Its prose accidentally placed the re-diagnostic before CI; that ordering
is rejected. The repository order remains CI, descriptive registration and independent
review, disposable S2, then one non-admissible diagnostic.

ChatGPT Pro found no design P0/P1 but initially returned `AMEND` solely because the
commit had not yet been pushed and therefore was not independently retrievable. After
the exact object was pushed, it independently verified the remote branch, commit, tree,
parent, empty anchor set, bounded file scope, ownership invariants, retained deep guard,
timing isolation, and Behavior Set v4. Its final exact-object verdict is `PASS` with zero
P0/P1. It also restated that Linux CI must complete successfully before registration or
diagnostic dispatch.

Earlier Pro findings were checked against source and incorporated as follows:

- the 8,640 query-boundary count and 120,960 conservative candidate-transition count
  have no identified arithmetic error;
- the roughly 4-billion/8-billion copy figures remain order-of-magnitude estimates,
  never measurements or strict lower bounds;
- the current run has an active 300-minute cancellation point rather than an open-ended
  wait for the workflow timeout;
- base-stream hoisting and second-copy removal are permitted only with event/trace and
  state-ownership equivalence tests;
- the 12 cross-target deep-equality walks are part of the same repeated-whole-logical-
  dictionary root cause, not permission for a second optimization round. The proposed
  replacement did not close the in-place-mutation fault, so the comparisons stay;
- timing remains NON-ADMISSIBLE diagnostic output and must not expand a publication
  receipt or artifact schema.

External review is advisory and supplies neither source authority nor experimental
evidence.
