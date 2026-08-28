# Day 1B production-admission contract review (2026-08-28)

- Review state: `NON-AUTHORIZING-PRE-IMPLEMENTATION-REVIEW`
- Reviewed source Git SHA: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`
- Reviewed source tree: `b02fb36ba262f592a400bb197cc8bab7dffc1f07`
- Verdict: existing pre-anchor behavior `PASS`; production-admission gate `AMEND`
- Execution performed by this review: none

## Authority boundary

This review identifies the smallest production-admission change that can close
the repository-owned Day 1B execution seam. It is not a Day 1B registration,
TRACE anchor, Day 2 profile, production run, or publication result. The current
source remains correctly fail-closed and has no P0 finding. Completing this
contract would still leave the independent TRACE authority and final
registration/evidence gates on `HOLD`.

## P1 findings

### 1. The production admission bridge does not exist

The worker protocol has a pytest-only issuer. Its invocation binding carries no
typed runtime admission, and both success and terminal receipt paths currently
emit `runtime_state_continuity_verified=false` and
`production_execution_admissible=false`. Filling only the repository adapter
factory therefore cannot produce an admissible production worker receipt.

The minimum change is one repository-private production issuer that consumes:

1. the capability returned by `prepare_day1b_expected_f1m_registry(...)`;
2. the existing composed `ExecutedDay1BRepresentativeOpenFHE` result;
3. the exact controller, worker-build, runtime, Day 2, replay, READY/DONE, and
   payload audits already represented by the current types.

After exact verification, the issuer may derive the two existing v11 admission
booleans through the invocation binding. It must reuse the present
registry-to-spool-to-invocation lifecycle rather than create a parallel worker
protocol.

### 2. Repository-owned plan bytes and worker identity are not yet closed

The Day 2 key-plan gate requires the exact canonical
`rotation-key-plan.json` bytes. The public producer/factory path currently has
only digest/size authority, not a repository-owned bytes or path seam. Those
bytes must be acquired from a fixed repository/workflow source before any
held-out trace is read, and a fresh single-use plan capability must be minted
for every candidate cell.

The native runtime's canonical runner-build and mapping projection must also
equal the controller context's worker-build/runtime digests. The adapter may not
self-assert those strings and must not gain caller-supplied `--plan`,
`--runner`, or `--scratch` arguments.

### 3. Runtime-limit exceptions lose the typed observation

The current native runtime limit-exception path discards the `wait4`
observation. The first production gate must therefore treat every native
admission, READY/DONE, or resource-limit exception as a whole-unit `HOLD` with
zero output. It must not parse exception text to synthesize a terminal receipt.
If controller-terminal null projections are required later, they first need a
typed failure observation; that is outside this minimum bridge.

## Minimum orchestration contract

Keep the existing `_Day1BExecutionAdapter.execute_candidate_cell(...)` port.
The repository-owned implementation should execute this sequence:

1. consume the unit windows once, form the existing audits, and bind the seed;
2. call `prepare_day1b_expected_f1m_registry(...)` and reuse its scratch and
   receipt lifecycle;
3. mint a fresh Day 2 rotation-plan capability per cell and pass it directly to
   `execute_day1b_representative_openfhe_query(...)`;
4. reuse that function's ordinary/strong, same-replay, ledger, and READY/DONE
   composition; do not add a second native wrapper;
5. verify the actual payload taxonomy and Day 2 sizes, then build the bounded
   transcript with the existing metadata/key framing and worker frame v2;
6. require exactly one representative OpenFHE execution per candidate-cell and
   zero worker-reported F1-M frames;
7. have the production issuer consume the registry capability and composed
   execution before the existing launch boundary emits the worker receipt.

No artifact, worker-frame, registry, runtime, or Day 2 receipt schema bump is
needed for this first gate. The existing worker receipt v11 already reserves the
admission fields. The behavior change must, however, bump the Day 1B Behavior
Set from v31 to v32 and include the new adapter implementation, tests, and
workflow path.

## Required fault and Linux coverage

- Reject forged registries, unconsumed replay, absent READY/DONE mappings,
  Day 2 or runner-identity mismatch, and payload size/category mismatch.
- Exercise every registry/plan/replay/invocation failure point and prove each
  capability is consumed or abandoned with zero installed output.
- On pinned `ubuntu-24.04`, CPython 3.12.13, and OpenFHE 1.5.1, run one ordinary
  and one strong cell. Each must have exactly one native launch, a non-empty
  mapping admission, pathless anonymous scratch, zero F1-M worker frames, and a
  frame-to-receipt round trip.
- Prove zero-query windows do not add compilation or native launches.
- Prove repository authorities and adapter material close before trace
  execution.
- Run targeted tests, Ruff, and `git diff --check` in an isolated clean Linux
  worktree. Before S1, run one complete non-authorizing synthetic unit; do not
  make PR CI execute the full 252-cell campaign.

## Explicitly out of scope

Do not add a second READY/DONE parser, scratch capability, Day 2 wrapper, worker
input protocol, simulator, replay path, checkpoint/retry system, or receipt
hierarchy. Do not execute OpenFHE once per phase or query arrival. Do not let the
worker self-report F1-M masks, replay authority, or malicious-worker proofs. Do
not add caller booleans or caller-selected resource integers. Do not reinterpret
adapter completion as TRACE authority or permission to dispatch Day 1B.

The current `publication_day1b.py` is already a large divergent-change surface.
The concrete orchestration should live in one repository-private module while
the existing adapter remains the sole public seam.
