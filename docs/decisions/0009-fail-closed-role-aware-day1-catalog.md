# ADR 0009: Admit Day 1 candidates through a fail-closed role catalog

- Status: Accepted for the Day 1 contract; composite registration anchor pending
- Date: 2026-08-23

Day 1 uses a repository-owned, zero-argument catalog rather than accepting candidate IDs,
receipts, capabilities, or completeness flags from callers. Once the pending
composite registration anchor is admitted, the frozen catalog emits 14 fixed
records: 13 Reference Candidates eligible for tuning and selection, including
`Packed-COO-Cloud-Segmented-Delta` at segment width 128, and one
`Packed-COO-Client-Lane-Delta` Ablation Candidate. The latter remains visible for diagnosis
but cannot be selected or used by the offline oracle.

This replaces the earlier partial-reference fallback recorded in ADRs 0006--0008. If the
strong correctness receipt, composite registration evidence, frozen policy, accounting
contract, or source identities do not match the repository anchor, catalog construction
fails before any experiment output is written. After admission, every cell must prove the
exact 14/13/1 role split, 13 tuning records, 16 total records including the two aliases,
and exact operation and rotation inventories before `complete_reference_set=true` may be
derived. A missing strong candidate is therefore an execution refusal, not a reportable
partial suite.

The role catalog establishes comparison completeness only. It does not make predicted
costs measured, authorize security or performance claims, or replace the Day 2 and R4
gates.
