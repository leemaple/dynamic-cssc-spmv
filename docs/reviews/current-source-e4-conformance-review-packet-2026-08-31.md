# Current-source E4 conformance replication — external review packet

Review date: 2026-08-31 (Asia/Shanghai)

## Review object

The controller will present one exact candidate Git commit with sole parent
`187347f80ad4333749528229891bd65b8f3a518b`.  The candidate SHA is deliberately
not embedded in its own tree.  A valid review must quote the exact candidate
commit supplied by the controller and verify that its parent-relative diff
contains only:

1. `config/current-source-e4-conformance-study.json` — SHA-256
   `2c61aca5a45899e278ce2771edd171e37e925f2ac7d8c886a147b2d44e40e2d5`;
2. `docs/paper/current-source-e4-conformance-preregistration.md` — SHA-256
   `7966710b677a4eefc9366538d43ea3f7cadec5ed87618be17421745e076c0f85`;
3. this packet.

The packet does not authorize dispatch.  Both named external reviews must bind
the same exact commit and return P0=0/P1=0 before the create-once source tag may
be created.  It must be a lightweight ref pointing directly to the candidate
commit; annotated tags are forbidden.  It may never be force-updated, and both
the direct ref object and its `^{commit}` peel must equal that candidate commit
immediately before dispatch and after provider completion.

## Superseded pre-dispatch review

The first untagged candidate
`5e729f903772eb2397b12d019ca536901aaac9ca` was never dispatched.  Its external
reviews returned ZCode `AMEND — P0=0, P1=2, P2=2` and ChatGPT Pro
`AMEND — P0=0, P1=3, P2=0`.  The second untagged candidate
`b22d82c2636b319db0b7d5d7b938eeb683ce9f2e` was also never dispatched.  Its
exact-head CI run `33372289114` passed 2,667 tests with the same two expected
unbuilt-runner skips.  ChatGPT Pro returned `AMEND — P0=0, P1=2, P2=0`; ZCode
verified all three document hashes before its quota expired and returned no
successor verdict, so no ZCode verdict is carried forward.

This successor makes only the resulting
non-expansive control-plane clarifications: it fixes the tag as a direct
lightweight ref; maps machine checks to named artifacts and RFC 6901 JSON
Pointers; places `evidence_valid` under `RUN_STATUS`; discloses the specification
change between the two historical workflow-path runs; binds `RUN_STATUS.json`
to literal pointers; and makes the no-step-executed replacement predicate a
direct provider jobs-API receipt rather than a finalizer/artifact inference.  It
changes no workflow, code, dependency, seed, fixture, expected current vector,
threshold, or claim rule.
The prior reviews do not authorize this successor; both reviewers must bind and
pass its new exact commit independently.

## Parent and implementation status

- Parent main merge: `187347f80ad4333749528229891bd65b8f3a518b`.
- Parent tree: `f10f5fbb7615d26f771e498898768132fd09ab23`.
- Provider-message repair PR: #50, merged after exact-head push CI
  `33364421048` and synthetic-merge CI `33364459945` both passed 2,667 tests
  with the same two expected unbuilt-runner skips.
- Exact parent-main CI: `33366506948`; candidate review and source-tag
  creation are forbidden unless it completes `success` on exact parent
  `187347f80ad4333749528229891bd65b8f3a518b`.
- The candidate changes no Python, C++, workflow, schema, dependency, seed,
  fixture, threshold, expected result, or experiment runner.

## Frozen scientific object

Question: at the exact reviewed current source, do the eight deterministic
property cases (35 records, seed `20260822`) pass, and does one real pinned
OpenFHE 1.5.1 BFVRNS whole-query fixture for CSSC base plus strong delta decrypt
to the exact sparse vector `[(0, 128), (4095, 5)]` while matching both the typed
plaintext oracle and direct SpMV oracle?

The fixed fixture is 4096-by-8193 with global column 8192, segment width 128,
active delta payload 127, padding offset 127, and three returned ciphertexts.
The fixed workflow is `.github/workflows/strong-whole-query-witness.yml`, whose
SHA-256 is
`81a34751d4ec39c1328632df8374957403bfa114c4637a6e2b8f8cd96ee4fcb0`.
The C++ witness, binding generator, validator, and case specification are also
hash-frozen in the machine plan.

The estimand contains no time, memory, bytes, cost, strategy, rank, speedup,
threshold, or population quantity.

## Complete predecessor outcome disclosure

1. Primary Route A performance qualification run `33261434612` is terminal
   NO-GO at its frozen deadline and minted no formal authority.
2. Separately preregistered follow-up performance run `33348855548` is terminal
   NO-GO under its one-shot rule before checkout, registered-seed execution, or
   artifact creation and minted no formal authority.
3. The complete pre-study provider inventory for this workflow ID/path has two
   runs whose workflow/witness specifications were not byte-identical.
   The earlier passed at `fbd9712fc15e687489a58655b6e5faa7a7e43ec3`, run
   `32567669739`, artifact `9474520924`, provider digest
   `sha256:010997ec7afdff79dd894044304f05eedfe4d0d9b584f7dcc49cf87ddb858aaa`;
   its earlier fixture produced `[(0, 123), (4095, 20)]`.
4. The later historical evidence anchor passed at
   `fcb00e0d7f111f3ab5003c111b124df83ae11813`, run `32581653504`, artifact
   `9477963854`, provider digest
   `sha256:c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe`;
   by this anchor, the present fixture and expected output
   `[(0, 128), (4095, 5)]` were in place.  Between the two runs, fixed-query
   values at columns 1, 7, and 8192 changed respectively from `2` to `1`, `4`
   to `1`, and `-3` to `-1`.

The first two outcomes caused the project to abandon the comparative
performance estimand.  Both same-workflow-ID/path successes and their different
witness specifications are known and are not hidden.  The current-source
outcome is unobserved; nine sources listed in the later historical
property/runtime provenance changed after that witness:

- `scripts/property_contract.py`;
- `scripts/validate_property_contract.py`;
- `src/dynamic_cssc/cssc.py`;
- `src/dynamic_cssc/events.py`;
- `src/dynamic_cssc/mask_ledger.py`;
- `src/dynamic_cssc/query_compiler.py`;
- `src/dynamic_cssc/strategy_state.py`;
- `src/dynamic_cssc/strong_execution.py`; and
- `tests/test_strong_property_contract.py`.

The workflow, C++ witness, binding generator, witness validator, case
specification, seed, fixture, and expected vector were not changed after the
later historical witness at `fcb00e0d7f111f3ab5003c111b124df83ae11813`.

## Attempt rule

One run is intended.  The GitHub rerun button is forbidden.  One and only one
provider-only replacement is allowed only when the first run is terminal
non-success, checkout never succeeded, the property step never started, the
complete all-pages provider jobs-API receipt shows no returned step ever entered
`in_progress` or `completed` and every returned step has null start/completion
timestamps, the provider job `total_count` is complete, the artifact count is
zero, and the exact tag/workflow/plan/code are unchanged.
Once checkout succeeds or any scientific step begins, a non-success is terminal
NO-GO for this study.  There is no post-outcome repair or second scientific
attempt.

The no-step-executed condition is proved directly from the provider jobs API;
it is not inferred from artifact count or finalizer behavior.  Missing, partial,
inconsistent, or unavailable jobs/steps data fails closed.  The replacement can
therefore hold only for a provider failure before any job step executes.

## PASS and artifact boundary

PASS requires the exact run/job/ref/head/attempt; all steps success; exactly one
success-named 30-day artifact; exactly 19 required regular files and no extras;
raw ZIP digest equal to the provider digest; strict internal `SHA256SUMS`;
provenance rehashed against a fresh detached exact-source checkout; eight cases,
35 records, zero property failures; `RUN_STATUS` pass/evidence-valid; exact
fixture identity; valid decryptions; exact sparse vector; and both oracle-match
flags true.  Any unmet item is NO-GO.

The machine plan binds each JSON expectation to an exact artifact path and an
RFC 6901 JSON Pointer.  `RUN_STATUS.json` is included explicitly: fixed fields
are pointer expectations, while `/github_run_id` and `/source_git_sha` are
pointer-bound comparison rules.  A validator must apply those pointers
literally; a semantic or flattened-key reinterpretation is not permitted.

The independent controller may verify and report existing bytes.  It may not
change the artifact, regenerate missing evidence, infer pass from logs alone,
or run a repaired scientific attempt.

## Claim boundary

On PASS, the manuscript may make exactly one version-bound statement: at the
named source/run/artifact, the one fixed fixture matched both oracles and all 35
records in the eight-case deterministic corpus passed.  Candidate admission,
mixed-circuit parameter safety, security, end-to-end deployment, performance,
cost, rank, speedup, population inference, and universal correctness remain
forbidden.  On NO-GO, only the exact terminal disposition may be stated.

## Requested adversarial verdict

Review the exact candidate and answer all five axes:

1. **Scientific independence:** Is this genuinely a deterministic functional
   conformance question rather than a third attempt at the closed performance
   estimand?  Are all outcome-informed deltas disclosed?
2. **Optional stopping:** Does the provider-only replacement rule prevent a
   second scientific attempt or selective rerun after any result-bearing work?
3. **Identity and artifact closure:** Are tag, run, provenance, raw provider
   digest, exact file set, internal checksums, and detached-source rehashing
   sufficient and non-self-referential?
4. **Success/failure exactness:** Can two implementers reach different PASS or
   NO-GO decisions from the frozen inputs?  Identify every ambiguity.
5. **Claim discipline:** Can the proposed result sentence be mistaken for
   performance, security, candidate admission, end-to-end, or universal
   correctness evidence?

Return exactly one top-level verdict:

- `PASS — P0=0, P1=0, P2=<n>`; or
- `AMEND — P0=<n>, P1=<n>, P2=<n>`.

For every finding, quote the affected file/section and give the smallest
non-expansive correction.  Treat P0/P1 as dispatch blockers.  P2 may be recorded
without changing the frozen scientific object only if it cannot alter the
outcome, authority, or permitted claim.
