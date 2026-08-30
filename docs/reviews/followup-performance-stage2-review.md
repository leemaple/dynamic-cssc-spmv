# Follow-up performance Stage-2 implementation review

> **Current gate:** qualification and formal execution remain forbidden.  A
> replacement S1 may enter a merge-only pull request only after its exact final
> commit has zero unresolved P0/P1 findings from both configured external
> reviewers and terminal-success exact-head Linux CI.  The merge must preserve
> the reviewed tree and canonical empty registration-anchor object.  This
> review record is authority-false and does not itself assert that a future
> candidate has met those conditions.

## Review lineage

The historical candidate `f920f87c8342673a8e129a886f70d80b585502a9`
received AMEND findings from both configured reviewers.  ChatGPT Pro reported
P0=1/P1=3/P2=1; ZCode independently confirmed the launch-name, retry, budget,
and serial-watch defects.  Checkpoint `1408e5730c077c87957674d9098706510f69a962`
closed part of that set but was never treated as a dispatch gate.

The first complete successor reviewed from the common packet was:

- commit `b085e26ed20436f7d42c461d8decebdc14b7d37e`;
- tree `b92f0f8084430a62ae0d4c296473ceb218cfad5e`;
- sole parent `1408e5730c077c87957674d9098706510f69a962`;
- binary diff SHA-256
  `8f0d45d880d0bbc4b328265adaf7403575d9e513b158aa3a996fc79d05f84f9c`;
  and
- packet `stage2-review-packet-b085e26.md`, SHA-256
  `fd07537f05206de7ad7861295620c9e6f2d7b3d3af5c42ff41bfdeab2264bc7d`.

The packet called the machine plan
`config/followup-performance-plan.json`; the repository-owned file is actually
`config/followup-performance-study.json`.  ZCode detected the packet typo,
reviewed the real frozen file, and classified it as a packet discrepancy rather
than a candidate defect.  The packet hash is retained unchanged so the review
record remains reproducible.

## Exact `b085e26` results

ZCode ran GLM-5.3 in Max reasoning and Full access mode, read-only, against the
exact public commit.  Its verdict was **PASS, P0=0, P1=0, P2=4**.  It
independently re-proved closure of:

1. provider-global one-shot creation and every later `beforeOid`/`afterOid`,
   `force:false` compare-and-swap;
2. the reserve -> dispatch -> bind -> watch-arm transaction and the in-run
   exact-`GITHUB_RUN_ID` admission barrier;
3. exact unit-workflow dispatch and repeated run-identity checks;
4. the one permitted replacement, segment reservations, retry reserve, and
   unified 12-hour ledger;
5. transitive follow-up Behavior Sets without hidden scientific-payload drift;
   and
6. the exact 17-unit FU-E4 claim-to-artifact relation and bounded descriptive,
   non-superiority wording.

ZCode's four P2 findings were evidence-pipeline hygiene and negative-test debt,
not authority or evidence-integrity failures:

- historical one-run formal helpers still name the deleted 34-job workflow,
  although the production command reaches only the new serial controller;
- the production provider classifier deliberately mints a replacement only for
  the unambiguous `startup_failure` signal and treats every other provider
  failure as terminal NO-GO;
- Behavior-Set closure started from registry roots rather than sweeping the
  repository for orphan follow-up behavior files; and
- several load-bearing negative paths lacked direct regression tests.

Exact-head GitHub Actions run
[`33303067475`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33303067475)
then completed successfully on the same branch/head/event identity.  It
recorded:

- P-1 manifest and Python syntax gates: success;
- unit tests: **2,586 passed, 2 skipped** in 1,763.17 seconds;
- the only skips: the two real-OpenFHE-runner tests whose binary is not built in
  ordinary CI;
- predicted-only smoke, R0 bundle creation, and upload: success; and
- artifact ID `9729951938`, name
  `r0-freeze-b085e26ed20436f7d42c461d8decebdc14b7d37e`, 479 files,
  8,878,911 bytes, provider digest
  `sha256:cfb37a178752f270c1bc9c49d6b201a8bb671a1b59a9faa43d7dae2f70072bfb`,
  expiring 2026-09-29.

That CI run was a control witness only.  It parsed no registered follow-up seed
through a generator and produced no publication experiment artifact.

## P2 closure successor after the first exact review

The successor delta is deliberately limited to evidence-pipeline
hardening.  It makes no scientific-plan, seed, workload, rho, matrix, runner,
dependency, cache, timing, estimand, or claim-threshold change.

- The unused `followup-provider-authority` composite action is deleted.  The
  repository-owned GitHub adapter no longer exposes the old one-run
  `open_formal_campaign` method.  Historical observation/stop-loss helpers
  remain for old record interpretation, but no production adapter can dispatch
  through them; the only live `execute-formal` path opens the serial campaign
  provider.
- Conservative classifier under-recognition is accepted intentionally.  Only
  explicit `startup_failure` is replacement-eligible; an ordinary provider
  `failure` remains terminal `scientific-or-guard-failure`.  This can reduce
  availability but cannot admit a second attempt after an ambiguous scientific
  failure.
- A repository sweep now fails if any follow-up-owned workflow, composite
  action, Python module, or controller/verifier script is absent from every
  follow-up Behavior Set.
- Direct negative regressions now cover a lost provider CAS, unclassified
  provider failure, expired/wrong-run artifacts, 16- and 18-directory terminal
  inputs, a 16-record FU-E4 ledger, cancellation-lag charging, insufficient
  replacement reserve, and the qualification/formal-unit/terminal admission
  script I/O seams.

The affected local gate is **68 passed** in 26.07 seconds under a low-priority
single process.  Every changed Python file also passes Ruff, and the Git diff
check passes.  These checks use only disjoint sentinel identities.  The delta
still requires one exact commit, exact-head CI, and the same configured
reviewers before it can replace `b085e26` as the final Stage-2 gate object.

## Exact `67e7708` review and the authority/cancellation successor

The P2-closure candidate subsequently frozen for common review was:

- commit `67e77086e708ea4de31e4827364f5f0107209bdc`;
- tree `45bb9278c3ae67a4c4f7eeaf4c8acc46bb1f7d23`;
- sole parent `b085e26ed20436f7d42c461d8decebdc14b7d37e`;
- binary diff SHA-256
  `13ee175c8f529a0444e1dbc05c6c2d0679f11fafdb40524a1b3c81f093e45431`;
  and
- unchanged external packet SHA-256
  `759f65bb74e2d207358a29d39398489bc5e6885a31fc12ddf3f6a822cae55d1f`.

ZCode GLM-5.3 Max returned **PASS, P0=0, P1=0, P2=3**.  Its nonblocking
findings were the retained legacy positive-authority exports, a repository
sweep that could be broadened beyond the registered follow-up filename
patterns, and one test that reached the child classifier through a private
helper rather than its public inspector.

ChatGPT Pro independently returned **AMEND, P0=1, P1=1, P2=1**.  The P2 was
the already-corrected external packet filename.  Its two blocking findings
were stricter and are adopted as the controlling interpretation:

1. the public controller module still exported two authority-consuming legacy
   operations and their dispatcher protocols, so a caller-supplied dispatcher
   could consume an in-process capability without first winning the durable
   provider-global claim; and
2. the formal watcher and final timing ledger did not retain the frozen
   threshold, controller detection/request/API-ack/decision clocks, exact
   provider terminal update/conclusion, or the two same-clock lag values.

Exact-head CI run
[`33305210194`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33305210194)
completed successfully on `67e7708`: P-1 and syntax passed; unit tests recorded
**2,600 passed, 2 skipped** in 1,701.80 seconds; predicted-only smoke and R0
packaging passed.  Artifact `9730595652`,
`r0-freeze-67e77086e708ea4de31e4827364f5f0107209bdc`, is 8,885,131 bytes with
provider digest
`sha256:7ee94001206ee5995cf193a6bc5da7e169e0dbbb83e4654909f6c05869fede7e`.
That historical green run cannot close Pro's P0/P1 and grants no dispatch
authority.

The present successor closes the stricter findings without changing a seed,
matrix, workload, estimator, threshold, or claim rule:

- it deletes the four legacy positive-authority names from the controller and
  deletes the unused legacy qualification claim/dispatch methods from the CLI
  adapter; the only qualification path now consumes its capability inside the
  provider-global claim -> dispatch -> watch -> CAS execution module;
- the formal watcher receipt is version 3 and retains all nine frozen
  cancellation fields, with provider and controller clocks kept in separate
  domains and only same-controller-clock elapsed values derived;
- one deep canonical receipt inspector now closes exact field sets, authority
  flags, provider-document hashes, terminal update/conclusion, cancellation
  order/arithmetic, guarded artifact identity, and the terminal campaign-state
  receipt hash before any commit or timing admission;
- cancellation requested at a frozen threshold remains NO-GO even if the
  provider later reports a successful run conclusion or a startup-failure
  label that would have been replacement-eligible before controller
  cancellation; and
- regressions now include two controller instances competing for the one
  provider claim, exact-provider-byte substitution, rehashed authority and
  cancellation-ledger tampering, and single charging of failed/replacement
  runner seconds.

The affected follow-up suite is **155 passed** in 81.28 seconds under one
low-priority process.  Ruff, Git diff checking, Behavior-Set import closure,
the orphan-path sweep, and sorted/unique role inventories pass.  Because these
changes alter authority and evidence interpretation, the analyzer,
control-registration, and formal follow-up Behavior Sets advance from v2 to
v3.  This remains a local engineering witness only: after it is frozen as one
exact commit, exact-head Linux CI and zero-P0/P1 verdicts from both configured
reviewers are still mandatory.

## Exact `bc6a0df` review and pending P1 closure

The next common-review object was:

- commit `bc6a0df4c39613c89ad7b0a9675d62d30966c484`;
- tree `0ecf10c3435f919a2028f33d16d974fdd9a37ae7`;
- sole parent `67e77086e708ea4de31e4827364f5f0107209bdc`;
- binary diff SHA-256
  `a2ebb100939c66a6a0149001418a2d961e2bbbb324f0c847b88b2ca7b64051d7`;
  and
- common packet SHA-256
  `6337fe443a070fc8719a7b300d2a3a3475cf98048596617374e01207fbcffa03`.

Exact-head CI run
[`33307462481`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33307462481)
completed successfully: P-1 and syntax passed, **2,606 tests passed** and the
only two skips were the expected unbuilt-real-OpenFHE-runner tests, predicted
smoke and R0 packaging passed, and artifact `9731267918` had provider digest
`sha256:cc34fd0add79b1700f24c6520a33aaa0f8777f238508bb30e8d832f28c56b623`.
This remained a control witness and granted no experimental authority.

ZCode GLM-5.3 Max returned **PASS, P0=0, P1=0, P2=3**.  ChatGPT Pro reviewed
the identical packet and independently returned **AMEND, P0=0, P1=2, P2=1**.
Repository-level reproduction resolved the disagreement in Pro's stricter
direction:

1. a fully rehashed `provider-failure` watcher receipt could also carry a
   cancellation ledger, reach `unit-provider-failed`, and authorize attempt 2;
2. `cancel_formal_unit` could observe an already-terminal run in its preflight,
   send no cancel POST, and still let the outer watcher record request and API
   acknowledgement times; and
3. a cancellation threshold later than the provider terminal `updated_at`
   remained canonically admissible.

Four minimized regressions reproduced those exact paths twice on unmodified
production code: **4 failed in 1.37 seconds** and **4 failed in 1.38 seconds**.
The pending successor then closes the outcome matrix at the canonical receipt,
controller, and pre-replacement-dispatch layers; requires success and
provider-failure receipts to carry no cancellation, budget exhaustion to carry
one cancellation, and scientific/guard NO-GO to carry none; enforces
`threshold_utc <= provider_terminal_updated_utc`; replaces the ambiguous
cancel callback with a typed confirmation of one exact HTTP 202 POST; and adds
the missing symmetric two-controller formal-ref race regression.  The analyzer,
control-registration, and formal Behavior Sets therefore advance from v3 to
v4.  These are evidence-control changes only: no seed, workload, matrix,
estimator, threshold, claim rule, or scientific payload changes.

The GitHub REST contract for
[cancelling a workflow run](https://docs.github.com/en/rest/actions/workflow-runs#cancel-a-workflow-run)
lists `202 Accepted` and `409 Conflict`.  The successor mints the typed
submission only from the exact `202` response; a `409`, transport error, stale
provider clock, or malformed return fails closed and cannot populate the
cancellation acknowledgement ledger.

After the production fix, the original minimized loop closed at **4 passed in
1.22 seconds**.  The expanded regression set, including the explicit outcome
matrix, defensive pre-replacement reinspection, `202`/`409` cancel responses,
and the formal-ref race, passed **49 tests in 9.71 seconds**.  The complete
follow-up control/evidence/CLI/workflow-contract suite then passed **186 tests
in 84.68 seconds** under one low-priority process.  Ruff, JSON parsing, Behavior
Set import/orphan closure, and `git diff --check` also passed.  These remain
local engineering evidence until the exact successor and CI closure recorded
below.

## Exact `37d5e5a` P1 closure

The exact implementation closure object was:

- commit `37d5e5a0b56e17ff5c6bade87e9bfeb018a6f3fd`;
- tree `ab436bef8c12b01dc101b6bbd21adf84ea181d82`;
- sole parent `bc6a0df4c39613c89ad7b0a9675d62d30966c484`;
- parent-to-candidate binary diff SHA-256
  `38fb26ad393475236c13bcdc5a276c2c4a3f26d069d51e5d78f38ddcf9a3a857`;
  and
- common review packet SHA-256
  `e8481a3e0cef90d735c1692f6240208f159628f7f2eab368b58f20aeaee2f4a9`.

ChatGPT Pro returned **PASS, P0=0, P1=0, P2=0**.  It independently closed
the four-way decision/cancellation matrix at the canonical receipt,
controller, replacement-dispatch, and timing boundaries; verified that only
one exact cancel `POST` receiving `202 Accepted` can mint the typed submission;
confirmed that `409`, wrong-run, malformed-return, transport, and provider-clock
regression paths fail before a cancellation acknowledgement; and accepted the
new symmetric fixed-ref race regression.  It also freshly read exact-head CI
run `33310810906` in terminal success rather than inheriting the packet's
earlier in-progress observation.

ZCode GLM-5.3 Max independently returned **PASS, P0=0, P1=0, P2=3**.  It
recomputed the packet and Git identities, passed 49 focused regressions, 12
Behavior-Set closure tests, and an expanded 188-test follow-up selection.  Its
nonblocking P2 findings were: the live cancel-202 provider `Date` is validated
but not persisted for later forensic replay; the completed-campaign timing
schema now retains a structurally unreachable cancellation-ledger array and a
conservative cancel-then-success asymmetry; and the exact 186-test selection
command should be retained with the witness count.  The first two can reduce
forensic detail or keep a conservative dead field but cannot authorize a
replacement or fabricate an acknowledgement.  The third is closed here by
recording the exact command:

```text
nice -n 15 .venv/bin/pytest -q tests/test_followup_performance_*.py tests/test_control_followup_performance.py tests/test_prepare_followup_performance_analysis_inputs.py tests/test_run_followup_performance_*.py tests/test_verify_followup_analysis_run_admission.py
```

Exact-head push CI run
[`33310810906`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33310810906)
completed successfully on the same commit, branch, and push event.  P-1 and
syntax passed; unit tests recorded **2,615 passed, 2 skipped** in 1,347.55
seconds; the two skips are the ordinary/strong parametrizations that require
the real OpenFHE runner absent from ordinary CI; predicted-only smoke, R0
creation, and upload all succeeded.  The sole artifact is ID `9732208497`,
`r0-freeze-37d5e5a0b56e17ff5c6bade87e9bfeb018a6f3fd`, 8,908,119 bytes,
provider digest
`sha256:441320056ea182f68434168eca0cc944911e85cd656f7e70d4dc3d367405fa82`,
expiring 2026-09-29.  It is a control witness, not experiment evidence.

Verdict: PASS — P0=0, P1=0.
External gate: ChatGPT Pro PASS; ZCode strongest-mode PASS.

The successor that records this closure may alter only this Markdown file.  It
must preserve the exact implementation tree outside this path, pass exact-head
CI, and receive a short exact-object fidelity review before it can become S1.
Neither this verdict nor that mechanical successor mints qualification,
formal, analysis, or publication authority.

## Post-merge S1/S2 closure defect and exact `ad7ce05` / `7c52925` repair

PR #43 merged the reviewed Stage-2 tree as commit
`d73668f7f10f4305898308a24f04f3c3b60583a7`.  Before any workflow or seed
dispatch, a dry-run construction of its deterministic data-only S2 exposed a
real fail-closed incompatibility.  The local direct child
`b190509ed78c9b8262597029e459e723355c308d` changed only
`config/followup-performance-registration-anchors.json`, but the production
verifier rejected it with:

```text
follow-up control-registration Behavior Set changed across S1/S2
```

That child was never pushed, and no control, qualification, formal, analysis,
registered-seed, or publication workflow was dispatched from it.  It minted no
capability and produced no experiment evidence.

The exact inventory comparison identified one cause: the data-only anchor was
also listed as a `control-registration` behavior path.  S1 correctly required
that anchor to be empty, while S2 correctly required the deterministic nonempty
builder output, so the behavior projection made every legitimate S2
self-incompatible.  All other role entries were byte-equal.  Removing only the
anchor entry made the two behavior projections equal; the dedicated lineage
rules still require an exact direct child, one changed path, an empty S1 anchor,
and S2 bytes equal to the exact-S1 deterministic builder output.

The reviewed repair candidate is:

- commit `ad7ce058ad1126b45119896513e4bdedce484805`;
- tree `ddfde3984c58e3f25cb9c5a3473ea00dffd5a5ee`;
- sole parent `d73668f7f10f4305898308a24f04f3c3b60583a7`;
- parent-to-candidate binary diff SHA-256
  `139e942c34934b95bf975fcfe2cb24d5798926df2ba94808df3d39b81e995011`;
  and
- common review packet SHA-256
  `8554003b1711562e143c62baa64650d8924ac5c6d3c456cdb67128169bd915ea`.

The delta contains exactly two paths, 55 additions, and 2 deletions.  It
removes the data anchor from the only role that listed it, advances only the
affected control-registration Behavior Set from v4 to v5, and adds two
regressions: a direct all-role exclusion invariant and a production-registry
S1/S2 round trip using the real builder and verifier.  No source verifier,
workflow, controller, seed, workload, rho, matrix, estimator, threshold,
dependency, artifact schema, scientific payload, or claim rule changes.

Local red/green evidence records the invariant failing before the registry fix
and the production-registry round trip reproducing the same production error.
After the fix, the invariant passed in 0.02 seconds, the production round trip
passed in 45.74 seconds, the complete lineage file passed 14 tests in 65.37
seconds, the bounded contract/lineage/workflow selection passed 41 tests in
66.46 seconds, and the expanded follow-up selection passed 190 tests with
2,429 deselected in 138.11 seconds.  Ruff and `git diff --check` passed.

ZCode GLM-5.3 Max independently returned **PASS, P0=0, P1=0, P2=0**.  It
recomputed every packet and Git identity, reproduced the exact failure against
the real unpushed `b190509` child, proved that the per-role difference was only
the anchor entry, reran the candidate lineage suite at 14 passed, and accepted
all five review axes.  It concluded that excluding the data record from
executable behavior hides no behavior because the unchanged dedicated anchor
checks bind the exact bytes and all five role inventory hashes.

ChatGPT Pro independently agreed with the data/behavior separation, regression
fidelity, scoped v5 bump, scientific boundary, and authority boundary, but
returned **AMEND, P0=0, P1=1, P2=0**.  Its blocking counterexample kept exact
deterministic anchor bytes while changing the anchor Git mode from `100644` to
`100755`.  `_read_blob()` admits both modes, while the dedicated anchor path at
`ad7ce05` inspected only `.content`; after exclusion from all Behavior Sets,
no remaining check rejected the executable-mode S2.  Pro correctly classified
this as a lineage P1 rather than scientific or authority misgrant.

Exact-head push CI run
[`33315414172`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33315414172):
completed successfully on exact `ad7ce05`.  P-1 and syntax passed; unit tests
recorded **2,617 passed, 2 skipped in 1,740.59 seconds**; predicted smoke and
R0 packaging passed.  The sole artifact is ID `9733673397`,
`r0-freeze-ad7ce058ad1126b45119896513e4bdedce484805`, 8,911,726 bytes,
provider digest
`sha256:231a8a825d3af0f3ec66ec48f18275ef7f919c4ff848ef0169383b8ac342eb82`,
expiring 2026-09-29.  This historical green run cannot close Pro's P1 or
transfer to a changed successor.

The exact P1-closure candidate is:

- commit `7c52925182603889d78425ae57ab145665bb6d70`;
- tree `e97dec8598d9cdb638db3a91736556da1dc9037b`;
- sole parent `ad7ce058ad1126b45119896513e4bdedce484805`;
- parent-to-candidate binary diff SHA-256
  `4615d9c569aefde7fa846de4200d62439da670cb3da4a17dcefb081afcc5d956`;
  and
- common review packet SHA-256
  `67435bf465399651fa69b30eaed6f9915ed81f15c6718c095d2290cac4297629`.

The three-path delta requires both exact S1 and exact S2 anchors to be ordinary
`100644` blobs before their existing byte checks, adds isolated `100755` S1 and
S2 negative regressions, and advances all five roles importing the changed
lineage verifier: acquisition v2 to v3, analyzer v4 to v5,
control-registration v5 to v6, formal v4 to v5, and qualification v2 to v3.
The fixed mode is a source invariant, so the closed receipt schema remains
unchanged.

Before the source fix the two exact mode regressions returned **2 failed** in
6.38 seconds because neither raised.  After the fix they returned **2 passed**
in 4.23 seconds, and again **2 passed** in 4.06 seconds after adding an explicit
assertion that the S1-mode case's S2 is regular.  The complete lineage file
passed 16 tests in 71.83 seconds; the contract/lineage/workflow selection passed
43 tests in 72.64 seconds; Ruff, JSON parsing, debug cleanup, and
`git diff --check` passed.

Exact `7c52925` ChatGPT Pro verdict:
**PASS, P0=0, P1=0, P2=0**.  It recomputed the 160-line, 7,182-byte
packet and every exact Git identity, closed its own prior P1 on both S1 and S2,
and verified that the two real-Git regressions isolate the two sides.  Its
counterexample analysis confirmed that executable anchors, mixed executable
and regular anchors, mode-only empty S2, and non-blob entries all reject before
a compatibility receipt can be produced.  It also accepted the five exact
role-version advances, the unchanged receipt schema, the retained parent/path/
content/inventory/builder checks, and the unchanged scientific and authority
boundary.
Exact `7c52925` ZCode GLM-5.3 Max verdict:
**PASS, P0=0, P1=0, P2=0**.  It independently recomputed the packet,
candidate, tree, parent, binary-diff, changed-blob, remote-ref, and historical
CI/artifact identities.  Its editable environment initially resolved the
parent implementation and therefore independently reproduced the expected red
counterexample (2 failed, 14 deselected); forcing the exact candidate source
then produced 16 passed in 88.15 seconds.  It confirmed that the two checks are
at the only anchor-admission seam, both registration archive paths and S3
analysis transit that seam, all and only the five importing roles advance, and
the closed receipt grammar need not change because the only admitted mode is
now fixed to `100644`.
Exact-head push CI run
[`33316814482`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33316814482):
completed successfully on exact head `7c52925`.  P-1 and syntax passed; unit
tests recorded **2,619 passed, 2 skipped in 1,759.54 seconds**.  Both skips are
the ordinary/strong parametrizations requiring the real OpenFHE query runner
that ordinary CI deliberately does not build.  Predicted-only smoke, R0 bundle
creation, and upload all passed.  The run exposed exactly one artifact: ID
`9734091071`,
`r0-freeze-7c52925182603889d78425ae57ab145665bb6d70`, 480 files,
8,912,242 bytes, provider digest
`sha256:05eef26f1e7a7fbfa80f927bbcf9dd95b8f6405c317932e57ace13ca7c1b9f26`,
expiring 2026-09-29.  Review and CI remain authority-false controls.  This
review-record-only successor must receive its own exact-head CI and short
fidelity review before it may enter a PR as the replacement S1 tree.

## Dispatch boundary

The final Stage-2 candidate must not be used for qualification or formal
dispatch until this file records:

1. zero unresolved P0/P1 findings from both ChatGPT Pro and ZCode on the exact
   final commit;
2. successful exact-head Linux CI and PRE-S1 validation;
3. a successful descriptive registration archive and independently verified
   data-only direct-child S2 anchor; and
4. a fresh external-controller reread of all exact identities and artifacts.

Only that fresh reread may mint the one nonserialized qualification capability.
Qualification q1--q6 must then close within both frozen deadlines.  A factual
qualification GO permits a separate fresh reread and, only if it passes, one
nonserialized formal capability for the strictly serial 17-unit campaign.
Every non-success remains fail-closed.  CI, registration, review, and this note
mint no publication authority.

## Post-S2 registration failure and replacement boundary

The first five-control attempt against historical S1
`7b3a8fbf79794ea07d6002e19b6d267552fa841d` and its data-only child S2
`974d35672d25a1eac331fd5601b4b0f8f9585f03` exposed a deterministic control
workflow defect before qualification or formal execution began.  Descriptive
registration run
[`33321883812`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33321883812)
failed in `Verify lineage and the registration producer contract` with
`ModuleNotFoundError: No module named 'dynamic_cssc'`.  Checkout, exact
identity validation, CPython setup, and the hash-locked dependency install had
all succeeded.  The run produced zero artifacts; all producer, independent
reinspection, and upload steps were skipped.

The cause is local to
`.github/workflows/followup-performance-registration.yml`: its isolated virtual
environment installs the frozen third-party requirements but the job did not
bind repository imports to the exact checked-out `src/` tree.  This is a
deterministic workflow defect, not a provider transient, scientific result, or
authorization event.  The failed run must not be rerun.  Historical controls
against S1/S2 above cannot transfer to a behavior-changing repair.

The replacement source candidate therefore adds one job-wide absolute
`PYTHONPATH` binding to the checked-out repository, adds a focused regression
that first failed against the historical workflow and then passed with the
binding, advances only the affected control-registration Behavior Set from v6
to v7, and restores the registration-anchor file to its canonical empty S1
form.  Qualification, formal execution, analysis, and registered-seed values
remain untouched.  A new reviewed S1, a new deterministic direct-child
data-only S2, and all five fresh authority-false controls are required before
the existing dispatch boundary can be reconsidered.

## Post-replacement dedicated-CI static-gate failure

The replacement lineage then closed its generic push CI and four dedicated
authority-false controls, but the first dedicated exact-head Linux CI run
[`33327887418`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33327887418)
failed before emitting its control receipt.  The run was bound to replacement
S1 `ecdc1e248e1d54d473510ab9c61a40af81777c79`, data-only S2
`b3541edf5519fd64debb56ec697f7c6dd879418d`, and compatibility receipt
`ce45f1a9a50fa42a7e430ec54e8280371ca7f81b14e6fd1579b61c15f89a93d7`.
Its identity, detached-S1 checkout, S1/S2 compatibility, compilation, and full
test suite all succeeded; the suite reported **2620 passed, 2 expected
runner-dependent skips in 1702.98 seconds**.

The subsequent Ruff command failed on exactly eight static findings in
`scripts/build_route_c_paper_docx.py`: one import-layout finding, six line-length
findings, and one nested-condition simplification.  Bash fail-fast therefore
did not execute the following `git diff --check`.  Receipt packaging and upload
were skipped, and the provider artifact API returned zero artifacts.  No
qualification tag, qualification run, formal capability, or experimental
artifact was created.

This is a deterministic source-tree hygiene defect exposed by the dedicated
control, not a provider transient or scientific outcome.  The failed run must
not be rerun or used as one of the five controls.  The narrow repair changes
only Python layout: it organizes the import boundary, wraps signatures, tuples,
and literal strings without changing their values, and combines two equivalent
nested conditions.  It does not change a workflow, scientific plan, seed,
artifact schema, claim, Behavior Set registry membership, or Behavior Set
schema.  This review note is itself an existing control-registration member, so
its exact-byte inventory digest changes and must be regenerated in the fresh S2
anchor.  The repair therefore changes the exact S1 tree and requires a new
reviewed replacement S1, a new deterministic direct-child data-only S2, and
five fresh authority-false controls before the external controller may
reconsider qualification dispatch.

## First static-repair candidate topology amendment

The first static-repair candidate
`38a806529f9fecd6058e0886f2d826d8717f9d58` was created from replacement S1
`ecdc1e248e1d54d473510ab9c61a40af81777c79`.  Its two-path repair was locally
Ruff-clean and behavior-preserving, and ZCode's GLM-5.3 Max review returned
`PASS, P0=0, P1=0, P2=0` for the source repair.  ChatGPT Pro independently
accepted the source and evidence-note semantics but returned `AMEND, P1=1` for
the proposed integration topology.

Remote `main` already pointed to historical data-only S2
`b3541edf5519fd64debb56ec697f7c6dd879418d`.  The candidate diverged from that
S2 at merge base `ecdc1e248e1d54d473510ab9c61a40af81777c79` and did not change
the registration-anchor path relative to the merge base.  An ordinary merge
would therefore retain the populated S2 anchor rather than restore canonical
empty S1 bytes.  Force-moving `main` back to the candidate would instead remove
the historical S2 from the forward lineage.  Neither result is admissible.
Pull request #46 was closed without merge, and its branch remains as the exact
reviewed-but-amended object.

The successor must descend from exact current `main` S2, carry the same narrow
source repair and factual record, and explicitly reset
`config/followup-performance-registration-anchors.json` to the canonical empty
`100644` S1 object.  Its parent, three-path diff, tree, empty-anchor object, and
prospective merge tree require fresh exact-object review and CI.  Only the
eventual merge commit may become the next replacement S1; all anchors,
inventories, receipts, controls, and run IDs from the `b3541edf...` cycle remain
non-transferable.

## Corrected static-repair successor and material review closure

The corrected material candidate is
`23c53a4bc39cfeeadc84024db2e59f7b37344b01`, with tree
`f5d772778019133044b2c0318daffdf327db3755` and sole parent exact current
`main` S2 `b3541edf5519fd64debb56ec697f7c6dd879418d`.  Its binary diff SHA-256 is
`5f8086b555853c63f6399e9bdb9fc5e75a528ca5995cc7ed5d1e6794a5c9b509`,
and it modifies exactly three paths: the route-C DOCX builder, this review
record, and the registration-anchor set.  The anchor is restored as mode
`100644`, blob `7ce8f9944629317901269249585f9b2860593f91`, with canonical bytes
`{"anchors":[],"schema_version":"dynamic-cssc-followup-performance-registration-anchor-set-v1"}\n`.
An independent prospective merge-tree computation against exact parent
`b3541edf...` yields the candidate tree `f5d77277...`, so a merge commit can
preserve both the reviewed repair and the empty S1 anchor without rewriting
history.

ZCode GLM-5.3 in Max reasoning and Full access mode returned
**PASS, P0=0, P1=0, P2=0** on the exact material object.  It independently
verified the commit, tree, parent, binary diff, three-path scope, anchor mode,
blob and bytes, prospective merge tree, behavior-preserving source repair, and
the expected control-registration inventory-digest change without a schema
advance.  ChatGPT Pro independently returned **PASS, P0=0, P1=0, P2=1**.  It
closed the prior integration-topology P1 and accepted the exact source, anchor,
tree, inventory, and authority boundaries.  Its only P2 was that the prior top
banner still described the historical `7c52925` gate.  This review-record-only
successor replaces that stale status claim with the time-stable, authority-
false gate above; it changes no implementation or registration-anchor bytes.

Exact-head push CI run
[`33330315004`](https://github.com/leemaple/dynamic-cssc-spmv/actions/runs/33330315004)
completed successfully on branch `codex/followup-static-gate-s1-v2`, exact
head `23c53a4bc39cfeeadc84024db2e59f7b37344b01`, attempt 1.  P-1, syntax,
unit tests, predicted-only smoke, R0 bundle creation, upload, and all cleanup
steps succeeded.  The suite recorded **2620 passed, 2 skipped in 1683.94
seconds**; the only skips were the two parametrizations requiring the real
OpenFHE query runner that ordinary CI deliberately does not build.  The sole
R0 artifact is ID `9737808767`, name
`r0-freeze-23c53a4bc39cfeeadc84024db2e59f7b37344b01`, 480 files,
8,922,465 bytes, provider digest
`sha256:1ff63ff4e9c08f496c58b3dcdf80c0eddbf6b3374db69bfafb7886826ffcfec1`.
It is bound by the provider API to the same run, branch, and head.  This CI and
both reviews are control evidence only and grant no qualification, formal, or
publication authority.
