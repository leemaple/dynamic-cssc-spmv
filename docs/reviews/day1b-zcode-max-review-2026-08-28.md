# Day 1B ZCode GLM-5.3 Max narrow review — 2026-08-28

## Review setup

- Reviewer: ZCode, GLM-5.3, Max reasoning, Full access mode.
- Review mode: read-only. The reviewer was instructed not to edit the repository,
  run workflows or OpenFHE, dispatch experiments, download artifacts, or inspect
  held-out outcomes.
- Reviewed worktree: `/Users/lifeng/Developer/dynamic-cssc-spmv-day1b-production-admission`.
- Reviewed base HEAD: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`.
- Packet: `pro-review-packet-day1b-production-admission-2026-08-28.md`.

## Verdict returned

ZCode returned **PASS for the bounded pre-admission diff**, with no P0/P1 items
within its stated scope. It explicitly limited that verdict to:

1. the opaque, single-use representative-execution capability;
2. the descriptive worker-build receipt projection; and
3. expected/observed runtime-identity projection.

It explicitly did **not** claim that the repository adapter, production issuer,
TRACE authority, dispatch authority, or publication authority was complete.
It required a separate review when the production issuer and exact Day 2 plan-byte
seam are implemented.

## Caveats identified by ZCode

ZCode also identified four non-blocking caveats in the reviewed snapshot:

1. raw CMake cache, compile-command, and related generated-build digests can embed
   absolute build paths, so the proposed worker-build root was stable only under a
   fixed build layout;
2. exact operating-system and CPU-affinity values deliberately bind a runner image
   generation and can cause fail-closed drift;
3. the worker-adapter schema token is controller policy rather than a runtime-observed
   fact; and
4. the real mint/claim lifecycle remains Linux-CI-only because the local Mac has no
   built OpenFHE runner.

## Root reconciliation

The root review treats the first two caveats as **P1 before production admission**,
not as acceptable publication-time drift. This is the stricter interpretation and
also matches the independent standards review:

- path-bearing generated-build digests must not enter the cross-root stable build
  projection;
- Linux system libraries need a closed system/non-system partition;
- observed CPU indices may validate a frozen controller rule, but the stable identity
  must carry only the rule token; and
- tests must start from an independently fixed controller policy, rather than derive
  the policy from the same runtime receipt being checked.

Therefore the ZCode PASS is retained as useful evidence for the bounded capability
design, but it does not override the stricter AMEND gate. No production HOLD is
lifted by this review.

## Follow-up gate

After the amendments above, re-run the narrow unit/Ruff gates and obtain a fresh
review of the exact diff before implementing the production issuer. The issuer
review must additionally cover exact repository-owned Day 2 plan bytes, capability
consumption order, mismatch/duplicate-use rejection, zero-query no-launch behavior,
whole-unit HOLD on missing typed runtime observation, and the Behavior Set bump.

## Exact final-snapshot review

After the stricter reviewer findings were implemented, ZCode was sent a third,
frozen-snapshot packet. It independently reported:

- base HEAD `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`;
- exactly four modified tracked files and no authority-bearing adapter change;
- `git diff --binary` SHA-256
  `cc05173f4b18d25275be51c4629f725c1ad29d82f7234b837ee0418c56069fe4`;
- diff size `+1241/-23`;
- 33 passing contract tests, with only the two real-runner tests skipped locally;
  and
- **PASS**, with no P0/P1 in the four requested areas.

The four reviewed areas were:

1. full system and non-system file-backed closure remains in the raw identity and
   READY/DONE admission set, while only the stable projection omits system bytes;
2. resolved libraries are classified into the pinned OpenFHE install root, closed
   Linux distribution roots, or fail-closed untrusted roots;
3. system load names form a unique subset of the complete file-backed library set,
   with at least one content-bound OpenFHE library required; and
4. CPU affinity uses the sole token
   `linux-controller-affinity-exact-match-v1`, while the actual tuple is checked but
   excluded from the stable document.

ZCode retained one material P2 boundary: any library physically under the closed
distribution roots is an environment-class dependency bound by load name rather than
bytes in the stable projection. The raw single-execution receipt and READY/DONE mapping
still bind its actual bytes. This projection is therefore a root-independent execution-
equivalence identity, not a hermetic or reproducible-build attestation.

This exact PASS closes the earlier ZCode snapshot and the independent standards
reviewer's three implementation P1s. It still does not lift the production HOLD. The
two real-runner tests must run without skip on exact-head Linux CI before the private
issuer is implemented.

## Bidirectional root-overlap amendment

The `cc05173f…` snapshot above is now superseded for exact-diff traceability. A later
local Standards/Spec review found one additional P1: the pinned install root was
rejected when it lay inside a distribution root, but not when it was an ancestor such
as `/usr` or `/`. Because classification checks the install root first, that inverse
overlap could bypass the distribution-root branch.

The amended snapshot adds the inverse containment rejection before `ldd` and an
ancestor-overlap regression. ZCode independently reconstructed the final diff and
returned `PASS`, zero P0/P1:

- commit: `9d7b7b744ea59b611bb706ad56d098846619d1e9`;
- tree: `cbe4f1a0c4ff390a01c2ce0abe4bbda7d3e424fd`;
- base: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`;
- binary diff SHA-256:
  `743190dfcfbae66b5afa5bff5c47e828a5dde8b9db70b1ce57daefa5ee3636a0`;
- four files, 1,270 insertions and 23 deletions;
- local targeted gate: 34 passed, two real-runner skips; Ruff passed.

ZCode confirmed that real-path normalization occurs before the overlap check, both
containment directions now fail closed before linkage probing, and the existing three-
way library classification is unchanged. Its prior P2 wording remains: the stable
projection is an execution-equivalence identity, never a hermetic-build attestation.
Exact-head push CI `33126848523` completed successfully with 2,153 passed and the two
expected unbuilt-real-runner skips. Dedicated Ubuntu/OpenFHE run `33128272572` then
built the pinned OpenFHE 1.5.1 runner, executed ordinary and strong non-authorizing
smokes, and passed the 607-test closed PENDING-FREEZE contract with no skip report;
Ruff also passed. The final boundary record still says that the production worker and
admission receipt are absent and that no publication execution is permitted.
Production authority therefore remains false.

## Exact production-invocation issuer review

ZCode GLM-5.3 Max subsequently reviewed the exact pushed issuer commit in read-only
mode:

- branch: `codex/day1b-production-issuer`;
- commit: `8a37c930edd1f404f7828dd574a4a2d0c29864e9`;
- tree: `8b8472fdea3465fdbaabc119b67a4aa20593c778`;
- parent: `9d7b7b744ea59b611bb706ad56d098846619d1e9`;
- binary diff SHA-256:
  `d8bfb8af895ae834daff43bf99f663ded917d0c84d14686ff3fc8767f0315c59`;
- scope: 15 files, 2,162 insertions and 70 deletions.

It independently reproduced the exact Git object identities and remote branch tip,
then returned **PASS**, with zero P0 and zero P1. Its local narrow replay reported 467
passing tests and four Linux-only skips; Ruff, `py_compile`, and `git diff --check`
passed. That replay is advisory engineering evidence and does not replace the exact-head
Linux gate.

The review explicitly confirmed all five bounded issuer requirements:

1. no caller-supplied admission Boolean can authorize the receipt; the two existing
   worker-v11 fields are derived only from the private production admission after
   successful finalization;
2. the typed runtime receipt is obtained only from the claimed opaque representative
   execution capability;
3. placeholder/test-only runtime lineage is structurally rejected;
4. the Day 2 authorization, ciphertext-size profile, and the one-time evaluation-key
   stream remain exactly bound; and
5. issuer, resource, projection, or decoder failure remains whole-unit HOLD with no
   admissible output.

ZCode also verified the new native-payload boundary: the issuer rehashes actual bytes
and orders them against the verified result inventory; only the closed non-F1M physical
taxonomy enters the worker projection; the decoder checks every projected frame/spool
line and requires complete exhaustion before deriving `true/true`. Fixture and terminal
paths remain `false/false`; physical F1-M frames remain zero and the logical registry is
bound separately. Worker receipt v11, input binding v11, frame v2, unit/runtime schemas,
the external adapter, and all dispatch/publication authority remain unchanged.

Its only non-blocking notes were to document the private phase-major/category-minor
projection order near the implementation and to remember that a future repository
adapter must construct real controller lineage. It also recorded that push CI run
`33135852470` was still running at review time. These are a documentation reminder, a
future-gate precondition, and a pending external gate respectively; they are not a
request to expand this bounded commit.

This PASS covers only the private issuer, private admission projection, decoder binding,
and Behavior Set v32. The repository adapter remains unconditional HOLD. Day 2 plan
preimage acquisition, TRACE, real candidate-worker wiring, dispatch, artifact creation,
held-out access, and publication authority remain separate gates.

After the review, exact-head push CI run `33135852470` completed successfully on the
same branch and commit. It reported 2,178 passed and two expected skips, both the real
OpenFHE-runner tests that the ordinary CI job deliberately does not build. P-1, syntax,
the predicted-only smoke, R0 bundle creation, and upload all succeeded. The sole
Artifact is `9672305443`, named
`r0-freeze-8a37c930edd1f404f7828dd574a4a2d0c29864e9`, with 257 files,
3,161,265 bytes, and provider digest
`sha256:5afb621ee46109041b35e2f864b75e767c8321248d3b80f5970b138d3b75fd36`.
No artifact was downloaded or installed. The dedicated PRE-S1/OpenFHE gate remains a
separate required observation because it builds the real runner and executes the two
tests without skip.
