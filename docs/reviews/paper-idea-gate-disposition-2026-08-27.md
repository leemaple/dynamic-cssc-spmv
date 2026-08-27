# Paper Idea / Mathematical Consistency Gate — Review Disposition

- Date: 2026-08-27
- Scope: `docs/paper/paper-idea-detailed-zh.md`
- Frozen first-pass packet: `docs/reviews/paper-idea-gate-packet-2026-08-27.md`
- Mode: read-only external review; no reviewer edited files, ran tests, or dispatched workflows.

## Reviewers

- ChatGPT Pro, project chat `项目进展与论文距离`: first-pass verdict **AMEND**.
- ZCode, GLM-5.3 Max, task `Read-only publication-readiness review of S2 manuscript`: specification-gate verdict **PASS**, with two P1 tightening requests and three P2 clarifications.

These verdicts concern the Idea/mathematical specification only. They do not open the submission gate: no admissible empirical result exists yet.

## ChatGPT Pro findings and disposition

1. **F1-M role/message flow (P0): accepted and fixed.** The document now states that Client A and Client B may both read the complete plan while it remains private from Cloud. Client A derives logical zero-sum values from that plan, maps them into physical share vectors, encrypts them under Client B's public key, and sends only bound mask ciphertexts to Cloud. It also states the exact visible information and the absence of a simulation-based security proof.
2. **10/30/60 integer split (reported P0): already closed in the document; strengthened.** The first-pass packet omitted the existing floor formulas. The document already froze `[0,floor(N/10))`, `[floor(N/10),floor(4N/10))`, and `[floor(4N/10),N)`; it now also prints the exact `N=131072` boundaries `[0,13107)`, `[13107,52428)`, and `[52428,131072)`.
3. **Pareto/rho gate (reported P0): already closed in the document.** The document already lists all nine rho values, both Pareto coordinates, weak inequalities with at least one strict inequality, exact-zero failure, and adjacency examples.
4. **Fixed-segment rotation convention (P1): accepted and fixed.** The document now freezes lane numbering, positive-rotation indexing, leader positions, the per-round leader invariant, and why non-leader cross-segment intermediates are masked away.
5. **Bandwidth units (reported P1): already closed in the document.** The text immediately defines `b` in Mbps and the result in seconds.
6. **SHA-256 privacy boundary (P1): accepted and fixed.** The document now says the digest binds but does not hide, and discloses equality linkage and low-entropy dictionary risk.
7. **Causal estimand (P1): accepted and fixed.** The document now defines the paired finite-trace strategy-replacement estimand and rejects population/deployment causal extrapolation.
8. **Fourteen-block median/resampling (P1): accepted and fixed.** The document now defines the even median as the average of order statistics 7 and 8, rejects missing/extra/invalid blocks, and freezes shared-with-replacement ordinal resampling with full primitive recomputation.
9. **Overloaded `B` and dispersed binding fields (P2): accepted and fixed.** The integer magnitude bound is now `M_max`, and a field-scope list covers `v`, `q`, `d_v`, opaque routes, and the ledger key.

## ZCode findings and disposition

1. **4096-row-support premise (P1): implementation already enforces it; documentation strengthened.** `publication_traces.py` measures `peak_row_nonzeros` and marks overflow ineligible; `publication_schedule.py` replays and rejects any production bundle unless all eligibility gates pass; `strategy_state.py` rejects an over-cap candidate before publication. The document now names this fail-closed chain explicitly.
2. **`floor(log2 w)+popcount(w)-1` terminology (P1): packet wording fixed; document was already correct.** It is a rotation/add abstract-node count, not a power-of-two subblock count. The frozen packet now uses the correct name.
3. **Logical Gamma versus share-level beta (P2): fixed.** The document now explains that one share-level ledger binding carries a vector tuple containing multiple lane masks, while Gamma remains logical-coordinate scoped.
4. **Formal 14 blocks versus legacy 11 repetitions (P2): fixed.** The document labels the manifest's 11-repeat value as historical exploratory context and forbids mixing it with the formal three-warm-up plus fourteen-block Day 2 contract.
5. **Rejected-transition fate (P2): fixed.** A failed candidate/cell is recorded fail-closed; it is not silently dropped, deferred, or selectively retried.

## Second-pass question

Review the current document and this disposition. Return only:

1. `PASS`, if no remaining P0/P1 blocks the Idea/mathematical specification; or
2. `AMEND`, followed only by remaining P0/P1 with exact location, reason, and smallest correction.

Do not treat missing empirical results as an Idea-specification defect; separately confirm that the submission gate remains closed.

## Final second-pass verdicts

- **ChatGPT Pro: PASS.** Its final P0 required one explicit consistency correction: the complete plan is readable by both Client A and Client B and remains private only from Cloud. The document, frozen packet, and this disposition were corrected accordingly. Pro then returned `PASS` with no remaining P0/P1.
- **ZCode GLM-5.3 Max: PASS.** It re-read the current document and disposition, independently re-derived the segment leader invariant, checked all review closures, and returned `Remaining P0/P1: none.`
- **Submission gate: CLOSED.** Both reviewers separately confirmed that the specification PASS does not compensate for zero admissible empirical results.
