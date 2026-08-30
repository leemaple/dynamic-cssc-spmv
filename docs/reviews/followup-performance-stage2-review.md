# Follow-up performance Stage-2 implementation review

> **Current gate:** HOLD.  The first exact successor candidate passed ZCode and
> exact-head Linux CI with no P0/P1 finding, but ChatGPT Pro is still reviewing
> that exact object.  The committed P2 closure successor below is not yet
> exact-head reviewed.  No qualification or formal seed is authorized by this
> document.

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
