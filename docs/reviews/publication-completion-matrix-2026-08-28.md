# Publication completion matrix (2026-08-28)

## Scope and cutoff

- Audit cutoff: `2026-08-28T03:11:26+08:00`.
- Audit type: repository-local completion review; not experimental evidence.
- Current pre-anchor publication source: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`.
- Disposable diagnostic-only S2: `bf25f10fff30ce294656d6ecef80a2658d3b4f63`.
- Active NON-ADMISSIBLE diagnostic: GitHub Actions run `33099397289`, seed
  `20260821`, one `mixed-insert-delete-modify` / `1s` shard.
- Frozen diagnostic deadline: producer job `startedAt`
  `2026-08-27T17:38:59Z` through completed replay receipt guard must be at most
  300.00 minutes, so the stop-loss instant is `2026-08-27T22:38:59Z`
  (`2026-08-28 06:38:59` Asia/Shanghai).
- Historical implementation issues #8 and #11 were closed at
  `2026-08-27T19:21Z` after mapping their requirements to exact-source CI,
  tests, and descriptive registration. Their closure comments explicitly keep
  formal Day 1A, calibration, Day 1B/TRACE, R4, performance, complete-cost, and
  security claims on `HOLD`; issue state is not evidence authority.

This matrix keeps the requested end state intact: reproducible formal
experiments and evidence, followed by a submission-ready manuscript. A green
unit test, descriptive registration archive, non-authorizing diagnostic, or
methods draft cannot substitute for a missing formal artifact.

## Requirement-by-requirement status

| Required deliverable | Evidence that would prove completion | Current authoritative evidence | Status at cutoff | Remaining work |
|---|---|---|---|---|
| Frozen method, candidate roles, and decision rules | Exact pre-anchor S1 Behavior Sets, clean CI, reviewed registration archive, immutable terminal S2 | Registration run `33094281493` at `50d8ade` succeeded; S2 CI `33096552659` at `bf25f10` passed 2128 tests with 2 expected OpenFHE skips | **PARTIAL / diagnostic lineage only** | Current S2 is disposable and cannot become the formal publication lineage. Any behavior fix requires fresh S1 registration and terminal S2. |
| Day 1A operational feasibility | Exact-input producer→artifact handoff→independent replay→guard in at most 300.00 minutes | Historical runs `33040816357` and `33075408647` failed the gate; current exact-S2 run `33099397289` is still in producer; workflow tests currently encode only separate 355-minute job timeouts | **IN PROGRESS** | Enforce stop-loss. If NO-GO, apply exactly one bounded root-cause fix and one same-input re-diagnostic. Before fresh formal S1, record the reviewed machine/external enforcement disposition so two 355-minute jobs cannot be mistaken for a 300-minute critical-path PASS. |
| Formal Day 1A causal count evidence | 21/21 producer and replay shards, zero timeout/cancel, every final guard success, 21 final shard artifacts plus one aggregate, exact anchor/plan/manifest binding | No formal Day 1A run or accepted aggregate exists | **HOLD / missing** | Requires operational GO, fresh final lineage, then formal dispatch and independent artifact admission. |
| Day 2 measured calibration and key plan | Day1A-authorized exact rotation plan, frozen profile binding, pinned OpenFHE runner, 3 archived warm-up blocks plus 14 complete raw measurement blocks, post-run anchor | One historical 11-block probe is permanently non-R3; no admissible profile/plan binding or 14-block archive exists | **HOLD / missing** | Install selected formal Day1A receipt, then data-only profile binding, execute and anchor the complete Day 2 archive. |
| Real-source acquisition authority | Exact official URLs, response contracts, bytes and hashes, source-set identity, isolated downloader/runtime receipt, atomic installed bundle | Source register, code, contracts, and resource pilot infrastructure exist; repository-owned production acquisition bundle is absent | **HOLD / missing bytes and authority** | Acquire the three fixed sources under the frozen transport contract and install the validated bundle. |
| TRACE and 30 paired real-source units | Admitted acquisition consumer, deterministic T1/T2 transforms, 5 partitions per source, 30 manifests, exact event/query programs, TRACE post-run anchor | Transform/protocol code exists; no admitted source bundle, 30-unit production manifest set, or TRACE anchor exists | **HOLD / missing** | Must follow acquisition; no synthetic substitute may authorize the primary verdict. |
| Day 1B production admission | Repository-owned adapter, production issuer consuming registry plus composed runtime receipt, exact plan preimage, runner identity, typed exception HOLD, Linux ordinary/strong proof | Existing code remains correctly fail-closed; `day1b-production-admission-contract-review-2026-08-28.md` identifies three P1 gaps | **AMEND / not runnable** | Implement the single existing adapter seam without a second protocol/schema hierarchy; bump Day 1B Behavior Set and pass exact-head Linux CI. |
| Formal Day 1B empirical evidence | Complete 30-unit campaign, all 14/13/1 roles, byte-complete protocol accounting, admitted Day 2 projection, paired held-out outputs and replay receipts | No production Day 1B unit or campaign artifact exists | **HOLD / missing** | Depends on acquisition/TRACE, Day 2, production admission, and final lineage. |
| Mixed-circuit and R4 correctness/performance | Pinned worst-profile decrypt/noise evidence plus end-to-end raw wall clock, RSS, serialized bytes, correctness and provenance | One old fixture proves only a narrow base-plus-delta query path | **HOLD / missing** | Execute after the same admitted identities are available; a unit microbenchmark cannot substitute. |
| Analysis, figures, and empirical claims | Detached S3 runtime admission, exact compatibility receipt, admitted inputs, generated figures/tables, claim-ledger links | Analysis and claim-gating code/framework exist; all empirical ledger entries E1--E6 remain `HOLD` | **HOLD / no result figures** | Run only on admitted evidence. Populate results without held-out retuning or threshold changes. |
| Related Work and novelty boundary | Primary-source bibliography, all cited keys resolve, claims narrower than prior art | Primary-source audit completed; CipherSkip, SparseE, D'Agata, d-DSE, and CKKS-Auth Tree added; 30 manuscript keys match 30 BibTeX entries; Pandoc citeproc passes | **METHODS COMPLETE, reviewer check pending** | ChatGPT Pro packet is prepared but not sent without the required action-time confirmation; ZCode is quota-unavailable. No `first` claim is authorized. |
| Detailed paper idea and editable Word | Current Markdown, native Word equations, rendered page-by-page visual QA | Detailed Chinese MD exists; old DOCX has exactly 182 Markdown math nodes mapped to 182 native OMML nodes and passed structural/a11y review | **PARTIAL** | Update status/results after the diagnostic and evidence stages, rebuild once, then render and inspect every page. |
| Submission-ready manuscript package | Final abstract/results/figures/limitations, venue formatting, author/funding/COI/CRediT statements, code/data availability and archival identifiers | Methods-first draft exists; result sections and human declarations remain explicit placeholders | **HOLD / missing** | Requires admitted results plus human-supplied declarations and final venue/release/DOI work. |

## Current critical path

```text
Day1A operational gate
  ├─ GO ───────────────→ fresh final S1/S2 → formal Day1A → Day2
  └─ NO-GO → one bounded fix → one same-input diagnostic
                                   ├─ GO → fresh final S1/S2 → formal Day1A → Day2
                                   └─ NO-GO → stop expansion and freeze a narrower paper form

acquisition → TRACE ───────────────────────────────┐
Day1B admission contract ──────────────────────────┼→ formal Day1B → R4 → S3 analysis
formal Day1A → Day2/profile ───────────────────────┘

admitted analysis → results/figures → final MD/DOCX → submission package
```

The first three feeder branches may progress independently only while they do
not open held-out outcomes or mutate the active evidence lineage. Formal Day 1B
cannot start until all three converge.

## Schedule interpretation

The 2026-08-27 external reviews estimated a likely submission-ready window in
late November through December 2026, with January 2027 as margin. Current facts
do not justify moving that date earlier: the methods and governance surface is
advanced, but none of the four empirical result families (formal Day 1A, Day 2,
formal Day 1B, mixed-circuit/R4) is complete.

Three conditional schedules are defensible:

1. **Current diagnostic GO:** retain the late-November--December 2026 working
   range, conditional on data acquisition and Day 1B admission proceeding in
   parallel without a lineage amendment.
2. **One bounded performance fix succeeds:** add approximately one to three
   engineering weeks before the same evidence campaign. This is a planning
   range, not a promise.
3. **The same-input re-diagnostic also fails:** do not schedule the current full
   headline. Freeze a method/boundary or negative performance result, rewrite
   the preregistered empirical scope before any new held-out access, and produce
   a separate schedule for that paper form.

Peer-review acceptance and publication occur after submission and are outside
all engineering estimates.

## Next irreversible decisions

1. At the exact 300-minute boundary, either accept the completed guard as an
   operational GO or cancel only run `33099397289` and record NO-GO.
2. After a NO-GO, permit only the already reviewed four-part performance fix;
   no second optimization framework or reduced experiment plan is authorized.
3. After a GO, establish one fresh formal lineage. The disposable S2 and every
   diagnostic artifact remain permanently non-admissible.
4. Do not turn manuscript completeness, review approval, or green CI into
   authority for any missing empirical claim.
