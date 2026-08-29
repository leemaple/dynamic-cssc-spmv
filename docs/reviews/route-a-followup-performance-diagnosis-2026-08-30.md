# Route A follow-up performance diagnosis — 2026-08-30

## Status and evidence boundary

This note records a performance diagnosis and a candidate semantics-preserving
implementation change. It is **not** a publication result, registration anchor,
dispatch capability, or authority to reinterpret the closed Route A
qualification.

- Base commit: `1d5526579b9b681789e657452f769de92bb4b54f`
  (`origin/main` when the independent follow-up worktree was created).
- Working branch: `codex/followup-performance-study`.
- Bounded code-and-test diff SHA-256 before this note was added:
  `2eabf7afbe57c437efe1c08fc7aff92e7457db3905736be21fe125161d619596`.
- Closed qualification run: GitHub Actions run `33261434612`.
- Expiring q1 transport artifact: provider artifact `9717884587`, named
  `q1-simulator-pre-replay-handoff`, provider digest
  `sha256:51cb6800...`; it is permanently NON-EVIDENCE.
- A diagnostic copy of the exact q1 payload was retained outside the repository.
  Its suite archive SHA-256 is
  `59752a15cccbb3833146354806137f62d3744cf26bf69091eb9f6313f8477d26`.

The old one-shot gate remains final: q1 succeeded, q2 was cancelled when the
frozen 45-minute qualification deadline arrived, q3--q6 never ran, and the
formal campaign did not start. This branch must not rerun that qualification,
loosen its threshold, or substitute new bytes into its lineage. Any future
performance study requires a distinct preregistration, source anchor, and run
identity.

## Direct observations from the closed run

The provider clock and downloaded q1 receipt close the following facts:

- q1 owned child: 2,451.120 seconds (40.852 minutes), peak RSS 1,555,748 KiB;
- q1 suite archive: 621,872,930 bytes;
- final archive write: about 3.423 seconds;
- the slow path is nearly query-linear and is concentrated in result/lifecycle
  work rather than archive construction.

The exact q1 per-cell stage ledger reports:

| Strategy | rho | Result/lifecycle (s) | State transition (s) |
|---|---:|---:|---:|
| periodic repack | 0.01 | 5.421 | 1.944 |
| periodic repack | 0.1 | 59.206 | 10.393 |
| periodic repack | 1 | 593.117 | 95.419 |
| padding reuse | 0.01 | 4.769 | 2.013 |
| padding reuse | 0.1 | 55.382 | 10.279 |
| padding reuse | 1 | 584.945 | 75.081 |
| strong packed COO | 0.01 | 6.807 | 2.565 |
| strong packed COO | 0.1 | 70.453 | 8.517 |
| strong packed COO | 1 | 746.407 | 76.721 |

Across the three rho-1 cells, result/lifecycle work accounts for about
1,924 seconds while state transitions account for about 247 seconds. Upload and
archive creation therefore do not explain the failure.

## Reproducible feedback loop and hypotheses

A deterministic one-query probe counted compilation calls inside the real
`evaluate_route_a_synthetic_cell` path. Before the change it observed ten
`compile_query` calls for one ordinary query, and the initial red test failed all
three registered strategies:

- periodic repack: 50 compilations for 5 queries;
- padding reuse: 50 compilations for 5 queries;
- strong packed COO: 20 compilations for 5 queries;
- required bound: no more than two compilations per query.

The ranked hypotheses were:

1. repeated deep validation of the same lifecycle bundle;
2. repeated prepared-query reconstruction and canonical serialization;
3. plaintext-oracle revalidation of the same typed execution plan;
4. SQLite mask-ledger persistence per query;
5. direct `Ax mod t` oracle evaluation.

One-variable prototypes supported hypotheses 1--3. Memoizing only bundle
validation reduced a 32-query ordinary probe from about 1.89 seconds to 1.08
seconds and compilation count from 320 to 128. Validating an internally created
prepared query once reduced it to about 0.97 seconds. Reusing the already
validated typed plan in the plaintext oracle reduced it to about 0.84 seconds.
Canonical-byte memoization did not materially improve the result. A separate
NumPy executor prototype preserved oracle equality but improved only about 9%
for ordinary and 17% for strong execution, so it was not added.

## Candidate fix

The ordinary and strong lifecycle modules now expose one deep producer operation
and one deep replay operation. Each operation owns the complete sequence:

1. validate and bind the compiled bundle once;
2. construct or decode the exact prepared query;
3. serialize or round-trip the canonical retained bytes;
4. consume or verify the exact ledger commitment;
5. execute the already validated typed plan; and
6. return the prepared object, exact bytes, and typed output together.

The caller receives no `skip_validation` flag and cannot mint a validated-plan
capability. Producer-side helpers trust only objects constructed inside the same
module invocation. Replay still treats retained bytes as untrusted: it decodes,
validates, requires exact canonical round-trip, verifies the consumed ledger,
and independently checks the direct oracle in the Route A evaluator.

The structural regression is intentionally a call-count invariant rather than a
wall-clock assertion: one compilation constructs the plan and one independent
compilation binds it, so producer and replay must each remain at no more than two
compilations per query for all three registered strategies.

## Local verification

Low-priority local checks used the project hash-locked Python environment with
two numerical-library threads:

- structural producer/replay regression: `6 passed`;
- ordinary lifecycle, strong lifecycle, and Route A evaluation: `56 passed`;
- Ruff on the four changed source/test files: `All checks passed!`;
- `git diff --check`: pass.

An exact registered formal-S trace (`scale=S`, seed `20260822`, rho `1`) was then
run once per strategy as a NON-EVIDENCE diagnostic. Each cell contained 512
queries and 512 windows:

| Strategy | Wall (s) | Result/lifecycle (s) | State transition (s) | Oracle |
|---|---:|---:|---:|---|
| periodic repack | 12.009 | 7.984 | 3.617 | equal |
| padding reuse | 10.976 | 7.813 | 2.765 | equal |
| strong packed COO | 27.055 | 22.993 | 2.982 | equal |

These timings establish that the identified validation depth was a real
bottleneck. They do **not** predict a provider-run M-scale qualification, prove
the old 45-minute gate would pass, or authorize a formal campaign.

## Review gate

Before any commit is treated as a candidate experimental source, independent
review must answer one bounded question:

> Does the deep lifecycle interface preserve all producer and replay validation,
> canonical-byte, single-consumption, ledger, and direct-oracle boundaries while
> eliminating only redundant revalidation, or has it introduced an authority or
> evidence-semantic bypass?

The requested reviewer output is `PASS`, `AMEND`, or `FAIL`, with P0/P1/P2
findings, explicit assumptions, and the cheapest falsifying checks. Reviewers
must distinguish a system defect from an evidence-pipeline defect. Even a PASS
does not authorize a new experiment; CI and a separate preregistration remain
mandatory.
