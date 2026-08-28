# Day 1A bounded-fix gate review (2026-08-28)

## Scope and authority

This record covers the one bounded implementation permitted after diagnostic run
`33099397289` failed the unrelaxed 300-minute producer-to-replay-guard gate. It is an
engineering review record, not experimental evidence and not permission to dispatch
formal Day 1A.

The obsolete review commit `7f3cd61` must not be cited. The only current object is:

| Field | Exact value |
|---|---|
| Branch | `codex/day1a-stream-hoist-clean` |
| Commit | `efdd9af894842a219080f93c8d36fb09ee93b161` |
| Tree | `1c27b664227b859f43af2fb6cab3807534dd9dc9` |
| Sole parent | `50d8adece05bf2e1f0dd7f29a8e336da494d43d7` |
| Binary diff SHA-256 | `a6d6464a8edb5a274a47abe41b036424f0493a15e5b661c6bd94f8a69237b44e` |
| Diff size | 14 files, 614 insertions, 60 deletions |
| Commit message | `publication: bound Day1A logical-state traversal` |

The disposable S2 `bf25f10fff30ce294656d6ecef80a2658d3b4f63` is not an
ancestor. `config/day1-registration-anchors.json` remains the exact empty v1 anchor
set. The branch was pushed without rewriting its reviewed object.

## Implemented boundary

The diff contains only four linked changes:

1. Generate and freeze one deterministic base event stream per shard, outside the
   nine-rho producer and replay loops. Tests compare every rho's events and publication
   windows with the former per-rho regeneration behavior.
2. Preserve the validator's first logical-state copy as the successor's unique mapping
   and remove only the redundant second copy. Query-only transitions reuse the unchanged
   predecessor mapping. Ordinary strategies and the strong path have ownership and
   mutation-isolation tests.
3. Retain the original cross-target deep-equality guard. An in-place divergence fault
   injection proves that the guard still fails closed; the rejected identity-only
   shortcut is not present.
4. Add diagnostic-only, stderr-only timing with exact phase/workload/freshness/rho
   identity. The producer separates ordinary transitions, strong transitions, and
   result assembly. Replay separates window construction, trace validation, five full
   transition evaluations, four exact rescalings, artifact validation, cell totals,
   base-stream construction, and shard total.

The plan, seed, matrix, rows, events, 14 candidate roles, nine rho cells, 300-minute
gate, receipt schemas, and all authority flags are unchanged. The Day 1 Behavior Set is
v4 so the changed execution path and its tests are bound before any fresh registration.

## Mechanical checks

- exact targeted gate: 29 passed in 11.28 seconds;
- Ruff: pass;
- workflow YAML parse: pass;
- `git diff --check`: pass;
- worktree: clean before and after push.

These local results do not substitute for GitHub's exact-head Linux CI. Push run
`33125107658` completed successfully with P-1, syntax, 2,147 passing Linux tests, two
expected skips for the unbuilt real OpenFHE runner, predicted smoke, and R0 packaging
all green. R0 Artifact `9668701772` has provider digest
`sha256:3f35ee46222e901e50974a9370faf27d4845bc44c44ee052d1addebd74736a8b`.
The R0 artifact is a review bundle, not publication evidence.

## Independent review results

### Specification

`PASS`, zero P0/P1/P2. The first review of the obsolete commit returned `AMEND` because
state-transition timing was not separately attributable. The amended exact commit
closes that finding and binds five full plus four exact-rescaled replay paths and their
exact stage multiplicities.

### Standards

`PASS`, zero P0/P1. Two P2 refactors were explicitly deferred: replace the four-string
timing identity with a small frozen type, and later consolidate duplicated
ordinary/strong candidate-validation logic. They are not needed for this bounded fix.

### ZCode GLM-5.3 Max

`PASS`, zero P0/P1. ZCode independently reconstructed the commit, tree, binary diff
digest, clean ancestry, empty anchor set, timing stages, and `5 full + 4 rescaled`
contract. Its non-blocking notes concern exact selected-test accounting and optional
local dependencies. A sentence in its proposed next-step order placed the diagnostic
before CI; that sentence is rejected and supplies no authority.

### ChatGPT Pro

The design review found no design P0/P1. Its initial verdict was `AMEND` solely because
the exact object was not yet available on GitHub. After the push, Pro independently
verified the remote branch, commit, tree, parent, bounded compare, empty anchor set,
ownership and deep-guard behavior, timing isolation, and Behavior Set v4. The final
exact-object verdict is `PASS` with zero P0/P1. Pro explicitly retained exact-head Linux
CI as the next gate and denied any formal, held-out, or empirical-claim authority.

## Required order after review

1. Exact-head Linux CI must succeed. **Completed:** run `33125107658`.
2. Produce a fresh descriptive registration archive from the same exact head.
   **Completed:** run `33126982746`; 63 tests and Ruff passed. Artifact `9668914243`
   has provider digest
   `sha256:670e16ee73447e016dbc12d9294a39c1d8f5b2a533f98b3e5a71ff41e372734a`.
3. Independently inspect that archive and preserve its non-authorizing status.
   **Completed:** all six internal checksums passed; exact-head inspection reproduced
   manifest `3a27b6a7…dee3`, registration `e5086c7d…c2cd`, source/tree/run identity,
   and all three authority flags as false. ZCode and Pro both returned PASS/no P0/P1.
4. Install only the reviewed data anchor on a disposable S2 descendant.
   **Completed:** commit `2db4bc87c54d3b5d448f17e4e8d62eae668f16d1`, whose sole
   parent is `efdd9af`; only `config/day1-registration-anchors.json` changed. The
   installed required-fields canonical SHA-256 is `f8fa94ea…f79b`.
5. Pass the exact S2 CI. **Completed:** run `33128190265` reported 2,147 passed,
   two expected unbuilt-real-runner skips, and successful P-1, syntax, predicted
   smoke, R0 creation, and upload. R0 Artifact `9669813773` has provider digest
   `sha256:1991618539e224c2d94316fa325a95c018e0e2562c4b5cdc5f5ee0ec0e40cdfe`.
6. Dispatch exactly one same-input, single-shard, NON-ADMISSIBLE diagnostic using seed
   `20260821`, workload `mixed-insert-delete-modify`, and freshness `1s`.
   **In progress:** run `33130154591` is bound to exact disposable S2
   `2db4bc87c54d3b5d448f17e4e8d62eae668f16d1`; its producer started at
   `2026-08-28T00:35:25Z`.
7. Measure producer-job start through successful replay guard against the unchanged
   300.00-minute threshold. The exact stop-loss is `2026-08-28T05:35:25Z`
   (`13:35:25` China Standard Time). If it fails, stop full-system expansion and
   choose the narrowed or negative-result paper path. Do not attempt a second
   performance fix.

External model agreement is advisory. Only exact source, CI, registered lineage, and
the bounded runtime observation can close their respective gates.
