# ZCode Max publication audit — 2026-08-23

> **Superseded statistical disposition:** this file records a historical review
> snapshot. Its proposed sign-test, Holm, confidence-interval, and population-
> inference language was withdrawn after the deterministic-partition
> independence audit. The current authority is the finite-corpus rule in
> `docs/paper/publication-preregistration-draft.md`: 15-of-15 positive effects,
> median at least 15%, all-unit non-domination, and two adjacent prespecified rho
> grid points. Partition resampling is descriptive only.

## Review conditions

- Reviewer: ZCode, `GLM-5.3`, reasoning `Max`.
- Mode: read-only; no repository edits, commits, pushes, workflow dispatches, or
  long experiments.
- Live checkout reviewed: `dynamic-cssc-spmv` on local branch
  `codex/p0a-common-query-compiler` at `d48ff5688326f540549927887a0a41929bb4b477`,
  including the uncommitted manuscript and preregistration files.
- The reviewer was instructed to ignore earlier ZCode reports and form an
  independent novelty, claims, experimental-design, statistics, and
  reproducibility judgment.

## Independent verdict

**Submission: HOLD. Research program: GO.** The reviewer found the manuscript's
claim discipline sound: performance, security, complete-reference, and
end-to-end conclusions remain withheld behind named gates. The blockers are
missing implementation or evidence rather than claims that must be retracted.

The reviewer judged the narrow novelty position defensible for an engineering
paper: version-bound publication, a RowMap-sensitive reconstruction plan,
overlap-scoped F1-M integration, the witnessed fixed-segment path, and causal
fail-closed evaluation are presented as systems/protocol integration around
prior static CSSC and masking work, not as a new HE primitive or formal-security
result.

## Findings and disposition

| ID | Severity | Finding | Disposition after review |
|---|---:|---|---|
| A1 | P1 | The manuscript had no bibliography and named prior work without citations. | CLOSED IN WIP. The manuscript's 25 citation keys and the 25-entry primary-source bibliography are one-to-one, with no missing, duplicate, or orphan key. |
| A2 | P1 | Adjacent 2025–2026 work, including Rhombus and secure sparse matrix multiplication via MPC, was absent. | CLOSED IN WIP. The related-work matrix now includes these boundaries without widening the novelty claim. |
| A3 | P1 | Promised Lodia/Diagonal-Packing comparability was not yet an explicit table. | CLOSED IN WIP. Manuscript §2.1 now gives a non-equivalence table covering CSSC, Lodia, Diagonal Packing, Ferguson et al., Rhombus, Damie et al., and this work, with mutable-support and threat/cost-interface boundaries. |
| B1 | P0 | No executable fixed-corpus, adjacent-rho, or Pareto verdict module existed. | CLOSED IN WIP. The replacement module implements the finite-corpus rule and calibration-classification sensitivity; the earlier sign/multiplicity requirement is withdrawn. |
| B2 | P0 | No acquisition, T1/T2, mapping, partition, or eligibility pipeline existed for the three real datasets. | CLOSED AT IMPLEMENTATION LEVEL. The fail-closed transform, T1/T2, mapping, partition, query-vector, and eligibility code exists; real acquisition receipts and 30 derived traces remain HOLD. |
| B3 | P0 | The strong candidate is intentionally unregistered and the zero-argument catalog fails closed. | IN PROGRESS. Registration requires the composite correctness/accounting/report/policy anchor; the correctness receipt alone is not authority. |
| B4 | P1 | The confirmatory comparator and per-semantics selection estimand were not frozen. | CLOSED IN DRAFT. The preregistration now defines tuning selection per cell and compares its held-out alias with `periodic-repack/windows=1`; T1/T2 remain separate. |
| B5 | P1 | Day-2 calibration uncertainty did not enter the decision rule. | CLOSED IN WIP. Ten thousand shared whole-block resamples must preserve all-positive, threshold, all-unit non-domination, combined-gate, and adjacent-pair classifications on the same fixed 15 units. |
| B6 | P1 | Old partial Day-1 workflow assertions contradicted the new complete 14/13/1 report contract. | CLOSED IN WIP. Runner, separate replay, aggregation, and workflow now enforce the role-aware contract; no Day 1 artifact has been dispatched. |
| B7 | P1 | `c=128` lacked a Methods justification or sensitivity statement. | CLOSED IN DRAFT. It is a pre-outcome protocol identity justified by the seven-stage schedule, 32 segments per effective row, and the witnessed 127/128 boundary; no optimality/generalization claim is allowed. |
| B8 | P1 | The design risked treating 15 deterministic partitions as independent trials. | CLOSED IN WIP. No p-value, confidence interval, or population inference is emitted; the result is explicitly conditional on the fixed three-dataset corpus. |
| B9 | P1 | Dataset identities/checksums and several execution details remained `PENDING-FREEZE`. | PARTIAL. Byte conversion, framing, key-amortization policy, partition/calibration resampling seeds, failed-unit handling, and the no-smaller-tier stop rule are frozen. Object URLs, receipts, terms decisions, and hashes remain correctly pending acquisition. |
| E1 | P0 | The cited merged commit did not resolve in the stale local object store. | EVIDENCE AVAILABLE. GitHub's commit API independently verifies `fcb00e0d7f111f3ab5003c111b124df83ae11813`, signed, with parents `5bf0e51...` and `d48ff568...`, tree `afba18b...`. Local `git fetch` was blocked by the configured proxy and did not alter the worktree. |
| E2 | P0 | The cited current-source R0 artifact was not locally archived. | CLOSED. Run `32580113632` artifact `9477692484` is downloaded under ignored `artifacts/run-32580113632`; GitHub digest is `8eb299c760e429740f36b3ecb42b365e690d8f2e027925ae4eb9018a0991ec13`, inner ZIP sidecar/CRC and all 121 checksummed files pass, provenance binds exact `fcb00e0d...`, and JUnit contains 750 passing cases. |
| E3 | P0 | Manuscript/preregistration were uncommitted, so they could not authorize held-out execution. | OPEN BY DESIGN. The reviewed replacements must be committed before held-out execution. The unrelated user-owned untracked `uv.lock` is explicitly excluded and must not be staged, changed, or treated as publication authority. |

## Smallest defensible paper scope

For Journal of Cryptographic Engineering, the minimum closed loop is:

1. repository-admitted strong candidate and complete role-aware references;
2. causal real-stream evidence over all eligible preregistered paired units;
3. measured OpenFHE primitive and communication calibration using the exact key
   inventory;
4. a worst-profile mixed-circuit decryption/noise gate;
5. executable preregistered finite-corpus analysis with negative results preserved;
6. end-to-end R4 evidence, or an explicit component-evidence limitation; and
7. a committed claim ledger mapping each result and figure to source, run, and
   artifact digests.

If mixed-circuit or R4 evidence cannot close, the allowed downgrade is a
benchmark/methodology characterization paper. A design-only submission is not
authorized.
