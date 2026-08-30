# Exact review packet: post-failure follow-up Stage-1 preregistration

## Review mode

Read-only. Do not edit files, dispatch workflows, reinterpret predecessor
artifacts, or authorize an experiment. Review the four attached candidate files
as one bounded Stage-1 gate.

Return exactly:

1. `PASS`, `AMEND`, or `FAIL`;
2. P0/P1/P2 counts and each concrete finding with file/field or line evidence;
3. explicit assumptions;
4. the cheapest falsifying checks; and
5. a separation of system/scientific-design defects from evidence-pipeline or
   wording defects.

## Exact candidate

- Repository: `leemaple/dynamic-cssc-spmv`.
- Worktree branch: `codex/followup-study-prereg`.
- Exact base commit: `4f328afc079b328c31f2e0790cb65cdf96fcc1d7`.
- Exact base tree: `ab48bd66a2a8ae99da17c6cd960b71fffffb71bc`.
- Bounded change: four new, non-authorizing documentation/JSON files only;
  576 lines total; no source, test, schema, or workflow edit.
- Sorted four-file hash-manifest SHA-256:
  `594eb7a60640d44eb1210a106c042a4b1840081266ef5ee3b84cbb4db04f4abe`.

Candidate files and SHA-256:

- `config/followup-performance-study.json`:
  `175af73d320f854296e62016c34a675e6ea214cc363de866c0383889abe11d77`;
- `docs/paper/followup-performance-preregistration.md`:
  `8ea23f19296ba770b0bf66f6af3dc3d863d37aaca19e5b4bb62505cd626ce3da`;
- `docs/paper/followup-performance-claim-ledger.md`:
  `ac405b6130147831a797eba89b449b5d778af7698606ecd454f2fbe29b5b4e36`;
- `docs/research/followup-performance-novelty-inheritance-review-2026-08-30.md`:
  `b4adb13d8cc5c2f639d4469baa69333b898f194ae522391e2aad8f4a9ae4d4e3`.

## Single decision being gated

Is this a scientifically and evidentially valid **pre-implementation Stage-1
preregistration for one separate post-failure follow-up study**, with enough
frozen detail to proceed to bounded Stage-2 namespace/runner implementation,
while permanently preventing the old failed qualification or outcome-informed
diagnostics from becoming performance evidence?

In particular, decide whether the packet adequately closes:

- optional stopping, rerun, seed replacement, and threshold-relaxation paths;
- outcome reuse, before/after speedup, pooling, and confirmatory-lineage claims;
- scientific-contract drift under the compact base-plan-plus-five-replacements
  representation;
- evidence namespace collision with the predecessor;
- novelty expansion caused by the engineering repair; and
- post-Stage-1 performance optimization or estimand changes.

Do not judge whether future experiments will pass. Judge whether the proposed
follow-up can become auditable if the later Stage-2 implementation and formal
evidence gates are separately reviewed and pass.

## Direct observations

### Closed predecessor

- Sole Route A qualification: run `33261434612`, event `workflow_dispatch`,
  head `c7ff6820d9323f1850c1c5c57fd9070db88db120`, attempt 1,
  `completed/cancelled`.
- q1 job `99123955873`: `15:52:45Z--16:34:30Z`, success.
- Frozen q1-through-q5 deadline: `2026-08-29T16:37:45Z`.
- q2 job `99128929460`: `16:34:33Z--16:38:02Z`, cancelled; its replay step
  never completed successfully.
- q3--q6 exist in the provider API only as zero-step cancelled job nodes after
  cancellation. No q3--q6 computation or guard ran.
- Exactly one provider artifact: ID `9717884587`, name
  `q1-simulator-pre-replay-handoff`, 621,877,534 bytes, digest
  `sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`,
  one-day retention, permanently `NON-EVIDENCE`.
- No qualification capability was minted; acquisition and the 16 formal shards
  were never dispatched. The predecessor forbids a rerun.

### Outcome-informed repair

- Diagnosis note at merged main SHA-256:
  `405024f027c493a91eb38046874aedc8cb6cd06f6fdc5bb2d87f067b0288ff24`.
- Implementation commit: `e204bb90fcfce0b2e9f3082fc2849c2de41e3b4b`.
- Hardening successor: `5b5d1468bfe3cac324819747388a2c897101f2bb`;
  tree `ab48bd66a2a8ae99da17c6cd960b71fffffb71bc`.
- Exact implementation-to-hardening diff SHA-256:
  `f8294786bc9703a3046f462ccb50d738f429f72cd3c64e4c56016177102c1204`.
- Both ChatGPT Pro and ZCode GLM-5.3 Max independently returned `PASS` with
  P0/P1/P2 = `0/0/0` on that successor.
- Push CI `33275856741` and PR CI `33276206350` both completed success on exact
  head `5b5d146...`; each reported 2,416 passed and two expected real-runner
  skips. Push R0 artifact ID `9721794912`, digest
  `sha256:7ed976ec525d4d353d9b906f06833b2ec55fe41eef35e9a8a71086946f683598`.
- PR #42 merged as `4f328afc079b328c31f2e0790cb65cdf96fcc1d7`.
- Main push CI `33277015441` on the merge commit was still in progress at this
  packet's observation point; it must not be credited as success here.

### Candidate contract

- Exact predecessor plan SHA-256:
  `ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c`.
- The candidate permits exactly five scientific value replacements, all fresh
  seeds: qualification `20260901`; formal synthetic
  `20260902,20260903,20260904`; native/plaintext snapshot `20260902`; query
  vector `2026090202`.
- Those integers do not occur elsewhere in the base tree; no generator or
  evaluator supporting the new namespace exists yet.
- Applying exactly those five replacements and the stated canonical JSON
  serialization gives materialized scientific-contract SHA-256
  `0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e`.
- The candidate keeps the old 45-minute q1--q5 threshold, 55-minute q1--q6
  threshold, matrix, rho set, serial 12-hour formal budget, strategies, roles,
  analysis boundary, and one-shot/no-rerun rule.
- All empirical follow-up claims are `HOLD`; only implementation provenance is
  marked releaseable. Qualification artifacts remain non-evidence.
- After Stage 1, query-lifecycle optimization, strategy changes, seed changes,
  matrix/rho changes, budget relaxation, and claim expansion are forbidden.
- The four-condition novelty vector is unchanged; bounded combination-search
  `PASS` is inherited, while every first/only/global/security claim remains
  `HOLD`.

## Inferences to challenge

1. A fresh, explicitly outcome-informed follow-up with a new one-shot
   qualification is methodologically distinct from rerunning the closed study.
2. The base-plan hash plus exactly five canonical replacements freezes the
   scientific contract as strongly as copying the full plan, while the later
   exact Stage-2 source/evidence namespace can be reviewed without changing the
   estimand.
3. Because no performance result, superiority claim, or before/after contrast is
   registered, using the old failure only to choose a shared-validation repair
   does not contaminate the descriptive results of fresh formal seeds, provided
   the chronology is disclosed.
4. The implementation repair changes neither C1--C4 nor the bounded prior-art
   collision question, so a new global literature search is not required before
   Stage 2; the explicit reopen rule still applies.

## Frozen non-negotiable boundaries

- The old qualification stays terminal NO-GO and is never rerun, completed,
  pooled, rescaled, or reinterpreted.
- Old partial timings and local post-repair diagnostics never enter tables,
  estimators, speedup statements, or formal evidence.
- The follow-up gets one qualification attempt and no replacement qualification
  seed or threshold relaxation.
- No formal dispatch occurs until a new exact Stage-1/Stage-2 chain, closed
  Behavior Sets, Linux CI, registration, terminal data-only anchor, and external
  live-controller check all pass.
- No paper performance sentence is released without fresh independent replay,
  guards, terminal admission, and isolated analysis of the new formal artifacts.
- No external reviewer verdict itself authorizes execution or supports a paper
  result.

## Cheapest checks already performed

- all four candidate files are readable; JSON parses; `git diff --check` passes;
- all recorded predecessor file hashes reproduce on the exact base tree;
- the materialized scientific-contract digest independently reproduces;
- repository scan finds none of the fresh seed values outside the four candidate
  documents; and
- no test or workflow was run for this documentation-only Stage-1 candidate.

If the packet is insufficient, identify the exact missing frozen field or byte
domain and why later Stage-2 review cannot safely close it. Do not solve a
scientific defect by weakening a threshold or by treating non-evidence as data.
