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
