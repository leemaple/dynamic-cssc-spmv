# ZCode Paper-Claim Audit — dynamic-cssc-spmv @ e2b411e

Date: 2026-08-22. Branch: `zcode/paper-claim-audit`, base commit `e2b411edcb0acc7fd000a3b5b0e999ae9f485935`.
Read-only audit by four parallel Explore subagents (protocol/security, algorithms/state, gates/evidence, narrative/attribution) plus main-agent adversarial synthesis. No experiments, benchmarks, tests, or Day1/Day2/R4 runs were executed. This is the only file added.

**Verdict in one line:** the repository's specification, labeling discipline, and exact-layout machinery are unusually honest and strong, but **no paper-ready empirical claim exists yet** — all committed evidence covers only freeze (R0) and BFV rotation semantics (P0a), both attached to an *earlier* commit `eb15adf` and hosted off-repo; every performance number producible today is a normalized proxy; and the recently declared causal per-strategy snapshot model (ADR 0006) is documentation-only. Overall recommendation: **HOLD on any empirical/submission claim; GO on protocol/cost-model design-writing.**

---

## 1. Contribution candidates with exact local evidence paths

| # | Candidate contribution | Local evidence (paths) | Status |
|---|---|---|---|
| C1 | Exact CSSC publication layout builder with global ColumnIndex lanes, capacity-sorted RowMap, column-major rectangle carving, and Physical Lane classification | `src/dynamic_cssc/cssc.py:11-13,168-307`; in-repo test coverage in `tests/` (CSSC exactness); exercised by `src/dynamic_cssc/preflight.py:36-140` (commit `35463f5`) | Builder implemented with in-repo test coverage (not a recorded passing HEAD CI run). Caveat: `LaneKind` *declares* five lane kinds including `tombstone` (`cssc.py:11-13`), but `publish_component` only ever emits `actual`, `natural-padding`, `reserved`, and `tail` (`cssc.py:236,247,254,263`); tombstone lanes exist only in the simulator's abstract counters. Preflight logic checks one fixed 257×521 layout (in-repo, deterministic) |
| C2 | OutputPlan / Output Shares / Contributor Multiplicity reconstruction model, incl. implicit-zero coordinates and public OutputPlan Digest | `src/dynamic_cssc/cssc.py:310-366`; `src/dynamic_cssc/output_plan.py:20-31,108-182` (digest at 160-170, implicit zeros at 153, commit `e2b411e`); in-repo test coverage in `tests/test_output_plan.py` | Implemented with in-repo test coverage (plaintext domain only; not a recorded passing HEAD run) |
| C3 | Overlap-only one-time zero-sum blinding (F1-M) bound to the OutputPlan digest, with persistent atomic mask-binding ledger | `src/dynamic_cssc/output_plan.py:185-255` (zero-sum completion at 238); `src/dynamic_cssc/mask_ledger.py:27-28,59-90`; ADRs `docs/decisions/0003*`, `0005*`; spec `docs/protocol-patch-v2.1b.md` | Mask generator + ledger implemented in the **plaintext domain**; no encrypted transport/cloud addition/decryption anywhere (that is R4) |
| C4 | Predicted-vs-measured evidence discipline: fail-closed manifest, evidence-scope labels, preflight gate, provenance rules, checksummed/provenance-tagged review bundles | `src/dynamic_cssc/manifest.py` (policy checks, predicted/measured separation 690-701); `src/dynamic_cssc/cli.py:73-75`; `src/dynamic_cssc/report.py:39`; `scripts/package_review_bundle.py`; `.github/workflows/*` | Implemented; the *methodological* contribution is real even if crypto results are pending |
| C5 | Dynamic maintenance layer itself: Publication Window semantics, base/delta/overflow components, version-bound plans — extension beyond static CSSC (source paper explicitly defers this to future work) | `src/dynamic_cssc/events.py:57-177`; `src/dynamic_cssc/simulator.py`; design `docs/task-v2.1-original.md:82-88`; `docs/research/cssc-query-reorganization.md:32,143,161` | Designed + simulated with a **static-layout proxy**; per-strategy persistent snapshots not yet coded (ADR `docs/decisions/0006*` is text-only) |
| C6 | Cost-model / strategy-representation paper (fallback): 6 reference strategies + Tuned Fixed Policy + Best Fixed Offline Oracle with causal tuning/held-out split | `src/dynamic_cssc/simulator.py:230-420` (oracle 409-418); `config/experiment_plan.json` (10/30/60 split); `docs/task-v2.1-original.md:101-105` | The six reference strategies and the Best Fixed Offline Oracle are implemented in `simulator.py` (oracle hygiene verified in code). Tuned Fixed Policy is **documentation-only** (ADR `docs/decisions/0006*`), and the causal warm-up/tuning/held-out state transition across persistent snapshots is **not implemented** — the current simulator uses a static-layout proxy. **No committed Day-1 results** |

Explicitly **not** claimable as ours: CSSC layout/chunking/ColumnIndex/RowMap/query-reorganization/aggregation, and the six reference strategies (PaddingReuse, ReservedSlack, Mini-CSSC-Delta, Packed-COO/HYB-Delta, Strict-LocalRepack, PeriodicRepack) — all labeled reference (`docs/task-v2.1-original.md:74-79`; `docs/architecture.md:49`).

## 2. Claim / Evidence / Counterevidence / Strength / HOLD-condition matrix

| Claim (as a paper might state it) | Supporting evidence | Counterevidence / gaps | Strength | HOLD condition |
|---|---|---|---|---|
| "BFV packed-slot rotation semantics validated on pinned OpenFHE 1.5.1" | `docs/review-checkpoints.md:19-27` (PASS, run 32514435923, 27 rotations, ZIP SHA-256, release `r1-p0a-v21b-20260822`) | Raw artifacts off-repo (private release); scope is `p0a-layout-semantics-only`; predates the 5 later commits (eb15adf..e2b411e) | Moderate (externally verifiable only via release) | Cite only with scope qualifier; never extend to mixed circuits |
| "Protocol freeze + manifest validation (R0)" | `docs/review-checkpoints.md:9-16`; `config/params_manifest.json`; 105 tests claimed at `eb15adf` | Same off-repo caveat; smoke run is prediction-only | Moderate | Same |
| "Exact dynamic CSSC layout reconstruction is correct" | `src/dynamic_cssc/preflight.py` logic with in-repo test coverage (`tests/test_day1_preflight.py`; deterministic 257×521) | Not yet executed as a CI-recorded gate artifact; only in-repo test coverage, not a recorded passing HEAD run; `tombstone` lane kind declared but never emitted by `publish_component` | Moderate (code-verifiable) | Run Day-1 preflight gate to convert to recorded evidence |
| "Our maintenance strategy beats baselines on cost" | None committed | `results/` contains only `results/README.md`; simulator uses stale initial layout (see §3) | **None** | Full Day-1 suite with persistent snapshots + held-out split |
| "F1-M blinding prevents output-component leakage" | Plaintext mask generator + ledger + simulator accounting (`output_plan.py`, `mask_ledger.py`, `simulator.py:202-208`) | No encrypted protocol execution; Client B still learns the full RowMap-sensitive OutputPlan (authorized by ACL, but must not be overstated); ledger crash semantics are an operational premise (`docs/protocol-patch-v2.1b.md:63-66`) | Design-level only | R4 prototype + leakage-mode demonstration |
| "Day-2 microbenchmarks predict end-to-end cost" | Day-2 infra + evidence contract exist (`.github/workflows/day2-microbench.yml`, `tests/test_day2_evidence_contract.py`) | Not run; mixed-circuit parameterization explicitly unfrozen (`config/params_manifest.json`: `formal_parameter_claim_allowed: false`; `docs/protocol-patch-v2.1b.md:91-93`) | **None (forbidden)** | Mixed-circuit decryption-correctness gate |
| "Noise-budget safety for the pipeline" | Manifest integer bound 2B<t (28672·2<65537) | Bound is compliance-only: nnz/value bounds asserted at validation time, not runtime-checked in `simulator.py` (`src/dynamic_cssc/manifest.py:386`; `docs/protocol-patch-v2.1b.md:74-84`) | Weak | Runtime bound enforcement or per-version check |
| "Independent reconstruction/reimplementation of CSSC" | `docs/research/cssc-query-reorganization.md` (pseudocode-derived, checksummed PDF/TeX) | No author code comparison possible — must never claim "author-implementation reproduction" (`:166`) | Moderate if phrased as independent reconstruction | Keep wording exact |

## 3. What is only a predicted proxy (never present as measured)

- All strategy costs: `StrategyMetrics.predicted_time()` with `UnitCosts` normalized proxies (mult=24, rotate=6, add=1) — `src/dynamic_cssc/metrics.py:8-21`, label `normalized-proxy-not-measured`.
- Rotation counts: `aggregation_rotations_proxy = ⌊log₂w⌋ + popcount(w) − 1` heuristic — `src/dynamic_cssc/cssc.py:41-45`. Never cite as exact CSSC aggregation cost.
- Unit costs: `config/unit_costs.example.json` is all zeros, `predicted-placeholder` / `placeholder-not-measured`.
- Smoke CLI output: `predicted-proxy-not-measured`, `gate_eligible: False`, `state_model: "static-initial-layout-proxy"` — `src/dynamic_cssc/cli.py:73-75`, `scripts/run_day1_suite.py:104,154`.
- The *only* measured things on disk-adjacent evidence: P0a rotation-permutation semantics and (future) `cpp/rotation_probe.cpp` / `cpp/microbench.cpp` outputs.

**Simulator is not yet causal** (adversarial finding, most dangerous for C5/C6): `simulate()` builds one layout from the initial state and never advances it (`src/dynamic_cssc/simulator.py:389-392`); absorption counters are per-window and re-read stale padding (`:73`); `_touched_value_chunks` counts only `candidates[0]` per modification and applies a **global** absorption test per row (`:109-126`, bug at 118-121); tuning windows are dropped from reported metrics so warmup effects on state are invisible (`scripts/run_day1_suite.py:135,141`). ADR 0006 (persistent snapshots, TunedFixedPolicy, decode-and-verify) exists only as text. Cross-window reuse/overflow totals are therefore systematically biased and **must not** appear in a paper until the snapshot model is implemented.

## 4. Supported by R0/P0a vs requires Day1 / Day2 / R4

- **R0 + P0a already support (with qualifiers):** protocol freeze and role/leakage policy consistency; manifest validation; BFV slot-permutation semantics for the 27 probed rotations on pinned OpenFHE 1.5.1 (`1306d14f…`); honest predicted/measured separation as a design principle. Nothing else.
- **Requires Day 1 (R2):** any strategy comparison, layout cost claims, Span80 diagnostics, tuning-vs-held-out results, the fallback "cost-model paper" content.
- **Requires Day 2 / P0b (R3) + the mixed-circuit gate:** any measured timing, any cost-model calibration, any noise statement beyond isolated unit probes.
- **Requires R4 prototype:** end-to-end correctness, F1-M blinding as an executed protocol, memory/communication accounting, baseline comparisons, any security claim beyond the design argument.

## 5. Most dangerous attribution / reconstruction / evidence-mixing risks (2025/1935 & CSSC)

1. **The "2025/1935" identifier is a provenance trap.** The repo's own provenance doc states the local `2025-1935_Fully_Homomorphic_Encryption_for_Matrix_Arithmetic.pdf` (a Gentry–Lee FHE matrix-arithmetic paper) is **not** the CSSC source and was not used; CSSC is Gao et al., arXiv:2603.04742 / Information Sciences 739 (2026) 123180 (`docs/research/cssc-query-reorganization.md:5,17,21`). Yet the repository's parent directory is literally named "AI 从 20251935 开始写论文". Any draft, artifact path, or citation that inherits "2025/1935" risks citing the wrong paper or implying the contribution builds on Gentry–Lee. **Recommendation: never let the directory name or 1935 identifier reach the paper; cite only arXiv:2603.04742 + DOI.**
2. **CSSC leakage-model inconsistency must not be inherited.** The source paper is internally inconsistent on whether sparsity is public (§3.1 vs §3.3) (`cssc-query-reorganization.md:118-124`). Do not claim CSSC "already hides sparsity," and do not attribute Hidden-RowMap or role freezing (Client B as sole secret-key holder) to the source — both are this project's decisions (`:128,163`).
3. **Forbidden-claim list already in-repo** (`:157-166`) — respect all of it: no "author-code reproduction," no "one ciphertext per query" (it is one per value chunk), no slot-domain reduction of ColumnIndex, no citing Table 7 A→B bytes as global-ColumnIndex sync cost (920 B vs ≥497 KB), no dynamic/versioning attribution to CSSC, no arbitrary multi-component addition licensed by Algorithm 1's single `ct_res`.
4. **v2.1a vs v2.1b evidence collision.** `docs/review-checkpoints.md` was overwritten in commit `76b58a4`: superseded v2.1a PASS digests (release `r1-p0a-20260822`, SHA `3be48683…`/`08abe505…`) replaced by v2.1b (`r1-p0a-v21b-20260822`, `1c3a5f14…`/`8e818195…`). Near-identical release names + same-file overwrite make it easy to cite the wrong digest. Nothing mechanically separates v2.1a/v2.1b artifacts even though cross-mode pooling is forbidden.
5. **HEAD ≠ audited commit.** All PASS claims attach to `eb15adf`; HEAD `e2b411e` is 5 commits later with changed layouts/accounting/preflight. New artifacts at HEAD must not be described as covered by the `eb15adf` audit.
6. **Blinding-protocol version mixing.** Task v2.1 originally specified *server-side plaintext* blinding (`docs/task-v2.1-original.md:57-63`); v2.1a/ADR 0003 disabled it (cloud would need RowMaps) and moved mask generation to Client A, which encrypts the masks under Client B's public key so the Cloud can add them ciphertext-side; Client A does **not** send masks to Client B. A draft quoting the original task text would misdescribe the protocol.
7. **Review-bundle import path.** `review-bundle.yml` can merge arbitrary prior `source_run_id` artifacts into a pack; nothing enforces that imported runs share the commit/manifest version (`scripts/package_review_bundle.py`).

## 6. Minimum experiment & ablation set

Experiments (strictly ordered per `docs/task-v2.1-original.md:404`; all currently blocked or unrun):

1. **Day-1 preflight gate** (deterministic 257×521 exact-layout check) — code ready (`src/dynamic_cssc/preflight.py`), needs a recorded CI run to become citable evidence.
2. **Day-1 causal cost suite (R2)** at frozen seed 20260821: prerequisite is *implementing* ADR 0006 persistent per-strategy snapshots + TunedFixedPolicy + decode-and-verify, then warm-up/tuning/held-out 10/30/60 split, six reference strategies, Span80 diagnostics; synthetic status string must stay `synthetic-predicted-proxy-not-a-48h-gate-verdict`.
3. **Day-2 / P0b microbenchmarks (R3)**: only rotation keys Day-1 actually derives; per-profile (add-only / mult-only / rotation) medians + P95; model dir separate from measured dir.
4. **Mixed-circuit decryption-correctness gate** — precondition for any noise/parameter claim.
5. **R4 minimal OpenFHE prototype**: end-to-end correctness vectors, F1-M leakage-mode demonstration, memory/communication accounting, ≥1 strong baseline comparison.

Minimum ablations for the paper:

| Ablation | Question answered |
|---|---|
| A1: causal snapshots vs static-layout proxy | Does the (currently unimplemented) state model change strategy rankings? (internal validity) |
| A2: blinding on vs off (full cost accounting) | Marginal cost of F1-M component-leakage prevention (task `:70` mandates counting it) |
| A3: overlap-only masks vs naive all-lanes masks | Value of OutputPlan-driven mask scoping (ADR 0005) |
| A4: fixed `_touched_value_chunks` heuristic vs exact touched-chunk accounting | Sensitivity of strategy deltas to the crudest proxy |
| A5: measured vs proxy unit costs (post-Day-2) | Does ranking survive calibration? |
| A6: window-flush policy (query/freshness/microbatch/version) | Sensitivity of maintenance cost to Publication Window semantics |
| A7: seed variation on synthetic workloads | Robustness beyond the single frozen seed |

## 7. Ten strongest likely reviewer attacks and evidence plans

1. **"No measured results at all."** — Plan: complete Day-2/R4 before submission; until then the paper must be framed as design + cost-model + validated protocol freeze, with every number labeled predicted.
2. **"The simulator's state model is not causal; absorption/reuse is overcounted against a stale layout."** — Plan: implement ADR 0006 snapshots + decode-and-verify, run ablation A1, publish the static-vs-causal delta.
3. **"Zero-sum blinding is routine additive one-time-pad sharing; the 'missing true contribution' claim is inflated."** — Plan: claim only the *binding discipline* (OutputPlan-digest scope, persistent atomic ledger, overlap-only mask count) and quantify its cost (A2/A3); cite prior masking literature honestly.
4. **"Client B receives the full RowMap-sensitive OutputPlan — where is the privacy win?"** — Plan: state the ACL explicitly (Cloud sees only ciphertexts + digest), cite `config/params_manifest.json` leakage section; scope claims to output-*component* decomposition hiding, not output privacy.
5. **"Wrong paper cited / provenance confusion (2025-1935 vs arXiv:2603.04742)."** — Plan: single citation of record (arXiv:2603.04742 + DOI), remove the 1935 identifier from all paper-adjacent paths, keep `docs/research/cssc-query-reorganization.md` checksums in the artifact appendix.
6. **"The CSSC source is internally inconsistent on leakage; your comparison baseline is ill-defined."** — Plan: present the inconsistency explicitly and define the baseline under both readings (public vs hidden RowMap), citing `cssc-query-reorganization.md:118-124`.
7. **"Novelty: dynamic sparse structures (LSM, main/delta DBs, SELL-C-σ, HYB) already exist; only the encrypted setting is new."** — Plan: required related-work set per task `:114`; position contribution as *update-aware maintenance under a fixed HE layout and slot semantics*, not "first dynamic layout."
8. **"P0a PASS is over-extended to noise/performance claims."** — Plan: every P0a citation carries `p0a-layout-semantics-only`; mixed-circuit claims blocked by manifest until their gate passes.
9. **"Evidence is a private GitHub release; nothing is independently checkable."** — Plan: make the R0/R1 release public or attach ZIPs + SHA-256 as paper artifacts; record per-run commit/manifest binding inside bundles (already partly done via `PROVENANCE.json`).
10. **"Cherry-picking across seeds/versions/protocol patches."** — Plan: enforce single frozen seed 20260821 in workflow inputs (currently only a default), mechanically block cross-version artifact merging in `review-bundle.yml`, and run A7.

## 8. Conservative paper outline

Title direction: neutral per `docs/task-v2.1-original.md:20` — "Dynamic CSSC for Mutable Encrypted SpMV" (fallback: maintenance-strategy representation paper per `:105`).

1. Introduction — mutable encrypted SpMV problem; static CSSC defers updates (cite arXiv:2603.04742 future-work).
2. Background & Related Work — CSSC reconstruction (independent, from pseudocode; leakage-model inconsistency stated); BFV batching/rotations; dynamic sparse structures (LSM, main/delta, SELL-C-σ, HYB); encrypted-blinding prior art.
3. Model & Threat Model — roles, F1-M, semi-honest single-corruption no-collusion, leakage ACL (`docs/protocol-patch-v2.1b.md:8-10`).
4. Dynamic CSSC protocol — Publication Windows, Published Components, OutputPlan/Shares, Contributor Multiplicity, implicit zeros, digest.
5. F1-M overlap-only zero-sum blinding + mask-binding ledger; full cost accounting.
6. Exact publication layout & preflight (257×521 fail-closed check; P0a slot-semantics evidence).
7. Predicted cost model & maintenance strategies (explicitly labeled proxy; six reference strategies; Tuned Fixed Policy; oracle hygiene).
8. Evaluation — *only gates that have actually run by freeze time*; predicted vs measured strictly separated.
9. Limitations — no end-to-end prototype yet (if R4 pending), mixed-circuit parameters unfrozen, Client-B plan knowledge, compliance-only integer bounds.
10. Conclusion.

**Abstract skeleton (claims kept to what R0/P0a + code support):**

> Sparse matrix–vector multiplication under homomorphic encryption has efficient static layouts (CSSC, Gao et al., 2026), but ciphertext matrices are in practice mutable: updates arrive faster than re-encryption. We present a maintenance layer for CSSC-style encrypted SpMV over OpenFHE BFV that (i) organizes updates into causally closed Publication Windows and version-bound Published Components; (ii) reconstructs outputs through an OutputPlan with per-coordinate Contributor Multiplicity, switching between concatenation and masked modular summation; and (iii) specifies an output-component-leakage countermeasure — overlap-only one-time zero-sum masks bound atomically to a per-query, per-version, per-plan digest — implemented to date as a plaintext-domain mask generator and binding ledger, with encrypted execution deferred to a future prototype. We specify a frozen three-party semi-honest protocol with an explicit leakage ACL, validate BFV packed-slot rotation semantics on a pinned OpenFHE build, and define a fail-closed exact-layout preflight. A cost simulator over six reference maintenance strategies quantifies predicted trade-offs under clearly labeled static-layout normalized-proxy assumptions; measured unit-level microbenchmarks and end-to-end evaluation remain future work. Predicted and measured evidence are kept strictly disjoint, and review artifacts are checksummed and provenance-tagged.

## 9. GO / HOLD / KILL

**Facts** (verifiable in-repo): R0+P0a PASS recorded at `eb15adf`, evidence off-repo (`docs/review-checkpoints.md`); Day 1 HOLD per `README.md:11`; `results/` and `data/` contain no committed artifacts; unit costs exist in two forms — nonzero code defaults that are normalized proxies (`UnitCosts` in `src/dynamic_cssc/metrics.py:8-21`, e.g. mult=24, rotate=6, add=1) and an all-zero placeholder config (`config/unit_costs.example.json`, `predicted-placeholder`); ADR 0006 has no implementation; simulator state model is static (`simulator.py:389-392`); masks/ledger implemented in plaintext domain only; "2025-1935" PDF ≠ CSSC source.

**Inferences** (audit judgment): current strategy-ranking numbers would be biased by stale-layout accounting; the security story is design-sound but evidence-free; the strongest *current* paper is a protocol+cost-model+evidence-discipline paper, not an algorithm-results paper; the C5/C6 empirical claims hinge entirely on implementing snapshots and running Day 1.

**Recommendations:**
- **GO:** protocol/threat-model writing (§8 sections 1–6); abstract skeleton above; contribution claims C1–C4 phrased at design level; provenance cleanup (retire the 2025/1935 identifier from anything paper-facing); evidence-discipline narrative (C4).
- **HOLD:** any performance or strategy-ranking claim (needs Day 1 with implemented snapshots + A1); any measured-cost claim (needs Day 2 + mixed-circuit gate); any end-to-end correctness/security claim (needs R4); citing the `eb15adf` audit as covering HEAD; any "beats baselines" sentence; algorithm-paper framing until held-out Pareto evidence exists (task `:89,101-105`).
- **KILL (already killed / must stay killed):** original whole-block RM-aligned ELLPACK delta (README:8); claims on the forbidden list `cssc-query-reorganization.md:157-166` (author-code reproduction, one-ciphertext-per-query, slot-domain ColumnIndex, Table-7 sync cost, dynamic attribution to CSSC, server-side plaintext blinding per task v2.1, multi-component addition from Algorithm 1, "first dynamic layout"); formal mixed-workload parameterization before its gate; cross-mode / cross-version result pooling.

## 10. Verification note

This file was created with native Write and revised with native Edit. Scope verification and the commit are performed as a separate final git step; the resulting status and commit SHA are reported in the accompanying ZCode response.
