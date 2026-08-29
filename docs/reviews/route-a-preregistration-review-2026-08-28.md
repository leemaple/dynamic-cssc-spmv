# Route A preregistration material-gate review

Date: 2026-08-28
Scope: paper claim, fixed experiment plan, and pre-implementation novelty gate
Authority: advisory review record only; it does not authorize execution

## 1. Reviewed drafts

Initial preregistration draft:

- path: `docs/paper/publication-preregistration-route-a.md`
- SHA-256: `a2656a5cc627f2ea790b588f2798626f92bde16a7376e6a325cc30168e40c07e`
- lines: 440

First final-gate candidate (superseded by the closed candidate below):

- preregistration SHA-256:
  `db328b934899edcac3f8701396533f18197d65807f395b1f7334e8da5ee969fe`
- preregistration lines: 762
- machine plan: `config/route-a-publication-plan.json`
- machine-plan SHA-256:
  `6c95f00ef3d6984a91803e142f343912f437956269b9b0be94d7b9d31d71ed9a`
- machine-plan lines: 257
- novelty review:
  `docs/research/route-a-complete-combination-novelty-review-2026-08-28.md`
- novelty-review SHA-256:
  `e8b5dc2674cacd71b92e61e2f9ac1bb4e9c8b6b99a25e65367b2087061fb36f3`

Closed local-audit candidate for the final advisory round:

- machine plan: `config/route-a-publication-plan.json`
- machine-plan SHA-256:
  `b9106cfa96489d9e40ee39fc55a4e1244498aaaa1e3f6d66185ff15d2e58f9d2`
- machine-plan lines: 905
- preregistration SHA-256:
  `03fd3576f968eabb3bbad3e2d4698440b1194a9fbb7f4ef09016a2d4fb9c998c`
- preregistration lines: 1198
- novelty-review SHA-256:
  `e01c37d83d3e4c28299879f1f99dbf0cd1c552197dc24c08d532e0bd6c05f3c3`
- novelty-review lines: 263
- claim-ledger SHA-256:
  `5189f5f63e3a3ff328943d8d7229bab32a66d3c451529e38dbe7958551f50f5f`
- claim-ledger lines: 129

These are retained-file byte hashes, not a claim of Git commit identity. The
local design/specification and resource audits both report P0=0 and P1=0 on
this candidate. External final-round review remains required before the
material gate can close.

## 2. First advisory round

### 2.1 ChatGPT Pro

Verdict: **AMEND; no P0**.

Blocking findings were:

1. move the primary-source novelty decision before runner implementation;
2. turn P1--P4 into precise functional propositions, reconcile the exact F1-M
   ledger scope, correct the Cloud/Client leader roles, and replace unsupported
   atomicity wording;
3. freeze total strategy behavior and a matched end-to-end accounting boundary;
4. make `rho=10` projection mandatory-or-fail and separate measured, counted,
   projected, and unavailable quantities;
5. close every SNAP mapping/window/logical-time ambiguity;
6. bind exact strategy/scale/seed/rho/version/query snapshots for OpenFHE;
7. freeze artifact counts, runner-hour accounting, retry classification, and
   prohibit a correctness repair after formal dispatch; and
8. plan for three to four weeks, not two.

### 2.2 ZCode GLM-5.3 Max

Verdict: **AMEND**.

Its P0 findings were:

1. record the 45/60-minute and 12-hour gate rationale and explicitly disclose
   whether any hidden M-scale timing had been observed;
2. bind the OpenFHE critical-path unit and provide a segmented runner-hour
   budget; and
3. restrict P1's quantifier to the enumerated registered admission fields and
   make P4's 127/128/129 construction explicit.

Its P1 findings additionally required no two-point scaling/extrapolation claim,
a small plaintext context measurement, strategy-symmetric `rho=10` treatment,
complete T2 semantics, an explicit non-exhaustive comparator-panel boundary,
and a reuse-contingent schedule. Its P2 measurement/reporting items were also
accepted where they removed ambiguity without expanding the claim.

The two reviewers converged on Route A and the same amendment direction, so the
Fable 5 escalation rule was not triggered.

## 3. Disposition in the final-gate candidate

The candidate now:

- places a bounded, commit-bound primary-source novelty matrix before runner
  implementation and retains all first/only/global novelty claims on HOLD;
- changes the contribution from `atomically binds` to `jointly binds`;
- defines the roles/leakage/malformed-input model and precise P1--P4, including
  the exact five-field F1-M reservation key and prepared-batch scope;
- freezes complete behavior for exactly three non-exhaustive strategies and one
  matched cost boundary;
- excludes static CSSC and the retired catalog from optional result inclusion;
- freezes S/M, seeds, scheduling, query-vector derivation, coefficient/modulus,
  strategy policies, and the exact machine-plan bytes;
- makes `rho=10` an all-strategy exact projection or Route C, never an optional
  direct run, and forbids projected wall time/RSS/scratch;
- defines the one-source evidence as ordered events under synthetic logical
  time and closes parser, prefix, partition, mapping, reserved-ID, T1/T2,
  expiry/admission, and query-order rules;
- expands OpenFHE to the exact three-strategy by two-scale six-case matrix,
  each case being one warm-up plus three technical repetitions inside one
  producer/replay/guard shard;
- freezes one guarded acquisition/transform artifact, 16 shard artifacts, one
  aggregate, and one analysis bundle;
- declares no prior Route A M-scale timing, derives the 45-minute gate only from
  the retired diagnostic as an administrative projection, and leaves the old
  300-minute failure untouched;
- defines the 12-hour sum, segmented budget, mechanical provider retry, peak RSS
  and scratch measurements; and
- forbids correctness repair, source mutation, or a second qualification after
  any qualification failure; that lineage selects Route C.

## 4. Independent novelty gate

The bounded primary-source collision search is **PASS** only for the complete
four-condition combination. Component novelty, `first`, `only`, global novelty,
patent novelty, and formal security remain **HOLD**. SparseE full-text release or
a change to the four-condition claim vector reopens the gate.

## 5. Final advisory round

The first exact-file candidate in Section 1 received:

- ChatGPT Pro: **AMEND; P0=0, P1=7, P2=1**. The seven blockers were
  cross-attempt retry identity, non-executed `rho=10` correctness/bindings,
  SNAP initial state, synthetic/SNAP serialized-byte authority, query-vector
  attempt/domain exactness, Stage-1/Stage-2 schedule ordering, and the need for
  definition-level proofs behind universal P1--P4 wording.
- ZCode GLM-5.3 Max: **PASS; P0=0, P1=0, P2=3**. Its nonblocking requests were
  to name the live controller and provider fields, record all four hashes in the
  Stage-1 commit/manifest, and show the `6 × (1+3+3)=42` native-evaluation
  derivation.
- Local exact-file design/specification and resource audits: **PASS; P0=0,
  P1=0** on the pre-amendment candidate.

These judgments are not treated as a substantive conflict: Pro identified
additional implementation ambiguity that ZCode had not rejected. All seven Pro
P1 items and all three ZCode P2 items were accepted for the amended candidate.
Fable 5 therefore remains untriggered unless the exact-diff rechecks diverge.

### 5.1 Amended exact-file candidate

- machine plan SHA-256:
  `b7264c3f67326fdfd31c9acb2ddfa15182e01ddc5c63938237661e24a474dfcf`
- machine-plan lines: 1076
- preregistration SHA-256:
  `5e6d42b8f5159181ec82f4b6663acabf21fd457d6a444dac8b714fc5c30de2c3`
- preregistration lines: 1358
- novelty-review SHA-256:
  `f2cafb0cae77b40470114b09c2c8beed7b98c192d208f74c24fed7f88e393f69`
- novelty-review lines: 268
- claim-ledger SHA-256:
  `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`
- claim-ledger lines: 129

The amendment:

1. adds `unit_attempt_ordinal` to unit, acquisition, lane, query, artifact, and
   admission lineage, gives the replacement fresh identities, binds any
   previously completed source observation, and makes failed-attempt objects
   permanently non-admissible;
2. gives the object-free `rho=10` target a closed non-executed correctness object
   and source-only/null query bindings rather than copying `rho=1` authority;
3. freezes the SNAP suffix start as an all-zero matrix with empty T1/T2 maps and
   FIFO;
4. freezes exact emitted metadata bytes, per-category S1 type-derived maximum
   cryptographic-byte formulas, separate one-time keys, and native-measured
   OpenFHE bytes;
5. freezes query-vector attempt zero, domain schema/literal `kind` values, and
   raw-object digest equality;
6. commits Stage 1 before implementation and prohibits any transform/plan/schema
   edit after Stage 2 or acquisition; and
7. adds written definition-level P1--P4 proofs and exact-S1 source-conformance as
   necessary evidence.

It also names `route-a-live-dispatch-controller-v1` and its exact API fields and
records the 42-evaluation derivation. JSON parsing, duplicate-key rejection,
Pandoc parsing, embedded hash checks, and `git diff --check` pass locally.

ChatGPT Pro exact-diff recheck: **PASS; P0=0, P1=0, P2=0**.
ZCode GLM-5.3 Max exact-diff recheck: quota-unavailable before the Stage-1
commit; its prior exact-file review was advisory input, not a substitute for the
missing recheck.
Local amended exact-file design/specification and resource audits: **PASS;
P0=0, P1=0, P2=0**.

The exact four-file packet was committed as
`0cbe443cf5b9c0fd6f310c804190de57497bbb7a`. That commit authorized bounded
runner implementation only. SNAP download, qualification, formal execution,
and empirical claims remained forbidden.

### 5.2 Pre-implementation scheduling clarification

The first scheduler implementation reading exposed one remaining semantic
question before any implementation commit: whether the payload-free logical
tick advanced time or closed a microbatch, and whether a scheduled query batch
shared the current Publication Window with pending SET transitions. ChatGPT Pro
ruled **AMEND** on that question, so implementation paused and the Stage-1
clarification path was used.

The first clarification packet had these exact identities:

- plan: `cd95b9e5315cea589818e4062974de97f3e2c980f6088d60786f856af310a279`,
  1082 lines;
- preregistration:
  `3a41c2dfecd0799b7514287819c2695e59deb8f171ef61a3f2c351d83032ba8e`,
  1373 lines;
- novelty review:
  `ede0566594e42e421e37d18ddd52ff86edf09b03292c3fc526d68aede1f9c8d6`,
  277 lines; and
- unchanged claim ledger:
  `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`,
  129 lines.

ChatGPT Pro returned **PASS; P0=0, P1=0, P2=0** on that packet. ZCode GLM-5.3
Max returned **AMEND; P0=0, P1=1, P2=2** because the machine plan's
`query_window_closure` allowed a query-only reading whenever the current group
emitted no SET, while the prose correctly also required that no earlier SET
remain pending. The finding included a reachable no-op-group counterexample and
was accepted.

The final corrected packet is:

- plan: `7c59f10aa2ece721270d19303260531ed57777be8473ab3f63cd328925189fbf`,
  1082 lines;
- preregistration:
  `690f8405dba39a491977fe6c444e93c5c7665af56bd7b695ce615b5f05d3ca4a`,
  1373 lines;
- novelty review:
  `3ca8e71fd0f5fdd7bbf658e3f9630659f07d58ae4f513b18b5a1a7b670a047b6`,
  277 lines; and
- unchanged claim ledger:
  `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`,
  129 lines.

The authoritative diff from `0cbe443` is plan `+6/-0`, preregistration
`+18/-3`, novelty review `+9/-2`, and no claim-ledger change. `jq`, exact hashes
and line counts, and `git diff --check` passed locally. On this corrected packet:

- ChatGPT Pro: **PASS; P0=0, P1=0, P2=0**;
- ZCode GLM-5.3 Max: **PASS; P0=0, P1=0, P2=1**; its sole P2 requested that
  all four hashes be recorded in the Stage-1 commit message; and
- local disposition: the P1 was closed by the exact machine-plan conjunct, no
  contribution/C1--C4/threat/evidence/cost/authority drift occurred, and the
  bounded novelty PASS therefore inherited without reopening the search.

Commit `da2bb35` records all four hashes, the exact diff, and both final
verdicts. Fable 5 was not triggered because the initial reviewer difference was
resolved by a concrete, accepted minimum edit rather than remaining an
unresolved P0/P1 disagreement. This commit authorizes bounded runner
implementation only; source acquisition, qualification, formal execution, and
empirical or publication-claim release remain forbidden until Stage 2 and the
registered downstream gates close.

### 5.3 Strategy-input reduction clarification

The first exact Stage-2 implementation review exposed one scientific and cost-
accounting ambiguity before any implementation commit: whether multiple SETs
to one coordinate inside a single closed Publication Window are charged and
applied sequentially, or are reduced to one common first-before-to-final-after
net update before the three strategies run. The implementation used the latter
reading, but Stage 1 had not frozen it. The same review also found three
separate code blockers: zero-query net-zero windows compiled query plans, the
exported adapter did not validate the complete window/reference contract, and
the one-use qualification capability had no claim-time expiry or abandonment
path. ZCode additionally found that qualification seed `20260821` was rejected
by both registered synthetic-seed validators.

Only the strategy-input ambiguity required a Stage-1 document amendment. The
exact amended four-file packet is:

- machine plan SHA-256:
  `c391119d36ea882919cf787167baa9c80f346d2860fce9e3b8f98421a034fbfb`;
  1103 lines;
- preregistration SHA-256:
  `caea6c5a15baf3b1ee8f988a82b1271ce82eadb7ba8cd87d51dc0970fab6baa0`;
  1438 lines;
- novelty-review SHA-256:
  `62028624787d4f900bb4b833c30f6e2a28c850a0b7c74588ebeca4534afc048e`;
  293 lines; and
- unchanged claim-ledger SHA-256:
  `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`;
  129 lines.

The amendment freezes a single strategy-independent reduction inside one
closed Publication Window: every canonical SET reference remains retained;
same-coordinate continuity is mandatory; the first `before` and final `after`
form one coordinate-sorted `NetUpdate`; endpoint-equal coordinates are omitted
only from the physical update list; and `accepted_set_transition_count` and
`net_update_count` remain separate. SET-reference presence, not a nonempty net-
update list, defines an update-bearing window and advances exactly one version.
For a SET-bearing net-zero window, periodic repack fully republishes, while
padding reuse and the strong segmented strategy replace no value/base/segment
ciphertext but do publish and charge the exact version/plan metadata. No path
may charge omitted ciphertext work or omit required binding metadata, and
`query_count=0` compiles no query plan. Existing resource gates and evidence
authority remain unchanged.

The authoritative Git `--numstat` diff from `e892ce26` is plan `+11/-0`,
preregistration `+28/-1`, novelty review `+11/-2`, and no claim-ledger change.
Exact retained-
file hashes and line counts, JSON parsing, and `git diff --check` passed locally.
The independent exact-packet rechecks returned:

- ChatGPT Pro through the existing Ego Lite paper Project: **PASS; P0=0,
  P1=0, P2=0**. It found no contradiction, cost drift, or authority drift and
  confirmed that C1--C4 and the bounded novelty PASS inherit without a new
  search.
- ZCode GLM-5.3 Max in the existing `dynamic-cssc-spmv` paper task: **PASS;
  document P0=0, P1=0, P2=1**. Its sole document P2 is satisfied by recording
  all four independently computed hashes above in this review and the commit
  message. It likewise confirmed that the prior net-reduction P1 is closed and
  that the document packet may precede the code fixes.

The first review prompts misstated the preregistration and novelty `numstat`
addition counts while supplying the correct exact files, hashes, and line
counts. After the local Git correction to `+28/-1` and `+11/-2`, respectively,
both reviewers explicitly confirmed that their verdicts, novelty inheritance,
and commit decisions were unaffected.

No substantive P0/P1 disagreement remains, so Fable 5 is not triggered. This
amendment authorizes only the bounded code correction and review cycle. Source
acquisition, qualification, formal execution, evidence installation, claim
release, and any replayable authority remain forbidden until the registered
Stage-2 and downstream gates close.

### 5.4 Qualification stop-loss and provider-transport amendment

The exact `02a88bf5e729954b4c80c111f578be043a036bb9` material-gate review exposed a
real four-key q5 vocabulary defect and missing stop-loss branch evidence. The
first successor, `e8d4783db179bc01bf059ddcac22a8b22b41051e`, closed that bounded
packet. ZCode GLM-5.3 Max returned **PASS; P0=0, P1=0, P2=6**, and Fable 5
returned **PASS; P0=0, P1=0, P2=0** for the five claimed closures. A broader
ChatGPT Pro review nevertheless returned **BLOCK; P0=1, P1=3, P2=3**: API and
cancel redirects were not separated from artifact redirects, q5 could be
accepted after an earlier prefix failure, and the cancellation record used a
workflow-run `completedAt` field that GitHub does not provide. Exact-head CI
`33243560733`, PRE-S1 `33243567501`, and PR CI `33243579066` were therefore
cancelled as non-authorizing invalid-candidate diagnostics.

This narrow amendment rejects every metadata GET and cancellation POST
redirect, permits only a three-hop tokenless HTTPS q6-artifact redirect, requires
all q1--q5 jobs to be completed and successful before q5 acceptance, and
separates controller-clock timestamps from provider `run.updated_at` and final
conclusion. It neither changes the scientific contribution/C1--C4 vector nor
the threat model, matrix, cost thresholds, evidence authority, or permanent
non-claims. The bounded novelty review is therefore rebound without a broad
search to this exact Stage-1 document packet:

- machine plan SHA-256:
  `b5d561bb5579976e4a9b5cc976ecaf2a6b7bbc9318ef43689f870522e68c8f0a`;
  1170 lines;
- preregistration SHA-256:
  `bdc4ae8e231cdb45b07be543f29cdb02cd330315c4b85364625b4231f8400d62`;
  1503 lines;
- novelty-review SHA-256:
  `6af839029bbec127f4b5ad6e8c48877d614c45e16924245a9b079c5f08a58fe0`;
  316 lines; and
- unchanged claim-ledger SHA-256:
  `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`;
  129 lines.

The registered role versions advance to acquisition v4, analyzer v4,
control-registration v5, formal v5, and qualification v7 because every role
contains the amended Stage-1 documents and source-conformance record. Local
evidence before the successor commit is 45 focused controller/stop-loss tests
passing, 105 broader controller/lineage/CLI/workflow tests passing, Ruff,
`compileall`, JSON parsing, exact hash-chain checks, and `git diff --check` all
passing. These are implementation evidence only. A new exact successor still
requires independent Pro/ZCode/Fable review plus its own CI and PRE-S1; nothing
in this section authorizes qualification, source acquisition, formal execution,
artifact installation, empirical claims, or submission.

### 5.5 Runtime-plan parity and provider-clock amendment

The unpushed `8b278e94cdf55fef126d3d8b09551b0fc1eb5477` successor was reviewed as one
exact attachment by all three external reviewers. ZCode GLM-5.3 Max returned
**PASS; P0=0, P1=0, P2=3**, but missed an executable stale plan digest. Fable 5
returned **AMEND; P0=0, P1=1, P2=3** and demonstrated that the mismatch caused
23 failures plus 26 errors across the affected focused files. ChatGPT Pro
returned **AMEND; P0=0, P1=3, P2=3**. Its three blocking findings were: the
same stale `ROUTE_A_MACHINE_PLAN_SHA256`; a provider-derived q1 deadline being
compared with and subtracted from the controller clock despite the frozen
no-cross-clock rule; and a post-cancel provider observation being checked
against a controller timestamp captured before the HTTP reads finished. The
candidate was never pushed and no workflow was dispatched from it.

The amended successor closes the three findings without widening the scientific
experiment. Both runtime plan constants now equal the retained plan bytes, and a
single regression requires equality among the file digest, controller constant,
and result-contract constant. Live stop-loss schema v3 obtains provider-clock
“now” only from mandatory HTTPS `Date` response headers on the sequential run
and jobs metadata reads. It compares provider q1 time only with that provider
clock, maps at most a same-provider-clock remaining duration onto a local
fail-safe deadline after a bound read failure, emits no cross-clock detection
lag, and retains the raw provider threshold and controller detection values
separately. Cancellation failure and terminal-read decisions now use local
timestamps captured after the corresponding I/O; a read completing outside the
ten-minute window is charged and fails closed. Tests cover provider clock
offsets of -31, -5, 0, +5, and +31 seconds, delayed successful terminal reads,
post-deadline terminal reads, failed cancellation I/O, missing/nonmonotone
provider `Date` headers, stale dates that cannot extend the local fail-safe,
and exactly-once cancellation.

The amended Stage-1 packet is:

- machine plan SHA-256:
  `ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c`;
  1171 lines;
- preregistration SHA-256:
  `6b53a73c6973a4be53d195f5d9407e7e023ae3a5617bce57b4a40a7033a32f79`;
  1518 lines;
- novelty-review SHA-256:
  `6030bec34d194aeaa59b813b06c34c9f5a901ef0e1fa8bafadf1b1079a080ba5`;
  319 lines; and
- unchanged claim-ledger SHA-256:
  `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`;
  129 lines.

All five registered roles advance exactly once relative to `8b278e9`:
acquisition v5, analyzer v5, control-registration v6, formal v6, and
qualification v8. Local lightweight evidence is 132 distinct controller,
stop-loss, GitHub-provider, plan-parity, lineage, CLI, and workflow checks
passing, with Ruff, `compileall`, JSON parsing, Stage-1 hash-chain equality, and
`git diff --check` also passing. These checks are non-authorizing. The new exact
commit still requires the same-packet Pro/ZCode/Fable terminal review,
exact-head CI, and PRE-S1 before any qualification dispatch.

### 5.6 Earliest-only fail-safe wait amendment

ChatGPT Pro's terminal review of exact unpushed commit
`3e0ac9335f9d020d0465fb605a76599e0f9b4db7` returned **AMEND; P0=0,
P1=1, P2=3**. It independently closed all three findings from Section 5.5,
then found one narrower control-plane defect: after a later successful but stale
provider read, the watcher checked the already-frozen local fail-safe deadline
but computed its next sleep only from the provider-clock remainder. With a
15-second polling interval, a five-second local remainder and a twenty-second
stale provider remainder could therefore sleep ten seconds beyond the immutable
local boundary. This could delay Route C enforcement, although the terminal
provider-timestamp check still prevented a false GO.

The successor adds a deterministic red regression for that exact ordering. The
unfixed implementation requests cancellation at `00:45:10` instead of the
frozen `00:45:00` boundary. The production wait now takes the minimum of the
poll interval, provider-threshold remainder, and local-fail-safe remainder.
Both subtractions stay within one clock domain: provider minus provider and
controller minus controller. The new regression and the prior stale-Date
regression pass; Pro's four requested controller files pass **96 tests**, the
broader controller/GitHub/results/CLI/workflow/postrun set passes **112 tests**,
and the independent lineage file passes **27 tests**, for **139 distinct
lightweight tests** in the recorded local packet. Ruff passes on both changed
Python files. No OpenFHE, S/M-scale, source acquisition, qualification workflow,
formal unit, artifact installation, or authority-producing action ran.

The scientific contribution, C1--C4 vector, threat model, matrix, seed/order,
45/55/60-minute and 12-hour gates, Stage-1 document bytes and hashes, role
schemas, and all authority-false boundaries are unchanged. The exact successor
still requires narrow same-commit external review, exact-head CI, and PRE-S1;
this amendment itself authorizes no publication execution.
