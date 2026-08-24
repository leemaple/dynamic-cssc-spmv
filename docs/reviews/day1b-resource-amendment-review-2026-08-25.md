# Day1B resource-amendment outcome-blind review

- Review date: 2026-08-25
- Review state: `NON-AUTHORIZING-OUTCOME-BLIND-REVIEW`
- Schema-source Git SHA: `e4d5d63ddcc7cadf2d2efa870b9faf41ae573489`
- Schema-source DAY1B Behavior inventory SHA-256: `e23400d6c38245dec97928ff9766130be71c8e86365b06f440964ff97b2b23ec`
- Permanently non-admissible structure-pilot source Git SHA: `23a15f746af5ca62283bfd716b09adf05c64a346`
- Sealed structure-pilot report SHA-256: `aab05a91125e025407f2159f3f0d71d3e98066f556f18fb27813c5ddace3a731`
- Sealed structure-pilot checksum-file SHA-256: `3c3e111e91f84a8135f0b7c1554abdb35932d068a5b5d97cba0828fa9e302fd2`
- Independent project-context review: ChatGPT project `矩阵向量乘法论文`, thread `6a890380-a1d4-83ec-93d0-af36ce57fe03`, response `9f443e8f-c137-498b-be3c-0dec2f34260c`
- Review decision: `AMEND_NOW_ADMIN_LIMITS`

## Scope and interpretation

The review used only the structure pilot's closed aggregate health, coverage,
cardinality, and resource fields. It did not read or derive candidate outcomes,
timings, effects, rankings, Pareto facts, rho selections, held-out classifications,
or confirmatory verdicts. The pilot artifacts remain permanently non-admissible
and are not copied into this repository.

Every numeric value below is an outcome-independent execution-safety budget. It
is not a measured candidate resource result and may not be cited as empirical
evidence in the paper. The structure pilot informs only the decision to use a
single-worker, externally controlled scratch policy; its canonical-store
checkpoint and cumulative serialization volume are not treated as scratch or
output high-water measurements.

The amendment is deliberately non-authorizing. It does not supply a production
worker, host/build/runtime identity, Day1 registration anchor, TRACE post-run
anchor, Day2 profile, dispatch capability, evidence authority, or publication
claim.

## Frozen administrative budgets

| Limit | Value | Basis |
|---|---:|---|
| candidate wall clock | 3,600 s | administrative timeout |
| candidate resident memory | 16,000,000,000 B | administrative process ceiling |
| candidate controlled scratch | 32,000,000,000 B | administrative launcher-root ceiling |
| one serialized object | 67,108,864 B | administrative object ceiling |
| serialized-object receipt count | 5,000,000 | administrative materialization ceiling |
| serialized-object receipt spool | 2,000,000,000 B | administrative controller ceiling |
| serialized payload per cell | 4,000,000,000 B | administrative worker-stream ceiling |
| worker frames per cell | 10,000,000 | administrative worker-stream ceiling |
| controller registry/spool checkpoint | 2,000,000,000 B | administrative anonymous-scratch ceiling |
| installed output per 18-cell unit | 8,000,000,000 B | repository hard ceiling |
| cells per shard | 18 | preregistered protocol invariant |
| worker concurrency | 1 | preregistered protocol invariant and pilot policy |
| whole-shard infrastructure-preemption reruns | 1 | preregistered failure policy |
| shard wall clock | 172,800 s | administrative orchestration ceiling |
| campaign job wall clock | 2,592,000 s | administrative orchestration ceiling |
| shard cost | USD 50 maximum | administrative spend ceiling; no spend authorization |
| campaign job cost | USD 1,500 maximum | administrative spend ceiling; no spend authorization |

Candidate selective retries remain exactly zero. A candidate that exceeds an
applicable limit remains a recorded failed/infeasible/timeout outcome. Only an
independently classified infrastructure preemption may invalidate and rerun the
entire identical shard once.

## Review conclusion

The limits may be committed before the production adapter because they are
safety budgets, not measurements. Formal dispatch remains on `HOLD` until the
repository-owned weighted adapter, controlled-scratch observations, runtime and
profile bindings, clean S1, Terminal Registration Freeze, and TRACE authority
are separately installed and verified.
