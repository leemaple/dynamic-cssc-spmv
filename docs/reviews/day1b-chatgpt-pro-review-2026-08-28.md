# Day 1B ChatGPT Pro design review — 2026-08-28

## Scope and authority

ChatGPT Pro was asked to perform a read-only stop-loss/protocol review of the Day 1B
pre-admission design. It was explicitly denied repository, workflow, OpenFHE,
experiment, data, and held-out authority. Its response is advisory and is neither a
source attestation nor publication evidence.

Reviewed base HEAD: `50d8adece05bf2e1f0dd7f29a8e336da494d43d7`.

## Verdict

Pro returned **PASS** for the pre-admission design, with no current-diff P0/P1. It
explicitly kept the production adapter, production issuer, TRACE, dispatch, formal
loader/analyzer, publication authority, and held-out execution on HOLD.

The review accepted:

- removal of raw path-bearing generated-build digests from the cross-root stable
  projection, while retaining raw execution identity for same-run replacement checks;
- an independently fixed controller policy rather than deriving expected facts from
  the receipt being checked;
- an opaque single-use capability around canonical representative execution;
- use of the two existing worker-v11 booleans by a future private issuer without a
  worker receipt schema bump, accompanied by a Day 1B Behavior Set bump;
- adapter-construction-time acquisition of exact repository-owned Day 2 plan bytes,
  with a fresh single-use capability per cell; and
- whole-unit HOLD with zero admissible output whenever typed runtime observation is
  incomplete.

## Reconciliation with the final snapshot

The Pro prompt described an intermediate Linux library-name whitelist. The final
frozen diff instead uses resolved-root classification while retaining all file-backed
libraries in the raw READY/DONE closure. Therefore no exact Pro verdict is attributed
to that final classification detail; the exact final-diff review is the ZCode review
recorded separately.

Pro's remaining P1 before the private issuer is actionable and unchanged: both real
OpenFHE runner tests must execute without skip on Linux, and the real ELF `ldd v2`
closure must pass. A future issuer must consume the opaque capability and must never
accept a public descriptive receipt, policy document, digest, or caller-supplied bool
as authority.

The review also recommends calling the stable object a root-independent execution-
equivalence identity, not a hermetic/reproducible-build attestation.

## Exact bidirectional-overlap re-review

After the review above, a local Standards/Spec pass identified one inverse-containment
gap in the exact implementation: an install root that was an ancestor of a Linux
distribution root was not rejected. The amended diff rejects both
`install_root ⊆ distribution_root` and `distribution_root ⊆ install_root` before
`ldd`, and adds an ancestor-overlap regression.

Pro returned `PASS`, zero P0/P1, for this amendment. It confirmed that `/usr` and `/`
can no longer cause `/usr/lib` to take the install-root branch, while normalized real-
path, symlink-component, and three-way classification behavior remain unchanged. Its
only non-blocking P2 was an optional explicit equality-case test; equality is already
covered by the original `Path.is_relative_to` direction, so the bounded patch was not
expanded.

Final exact object:

- commit `9d7b7b744ea59b611bb706ad56d098846619d1e9`;
- tree `cbe4f1a0c4ff390a01c2ce0abe4bbda7d3e424fd`;
- binary diff SHA-256
  `743190dfcfbae66b5afa5bff5c47e828a5dde8b9db70b1ce57daefa5ee3636a0`;
- four files, `+1270/-23`.

This exact PASS is advisory. Exact-head CI and the dedicated unskipped real-OpenFHE
Linux gate remained mandatory before any private issuer work. Both gates subsequently
passed: push CI `33126848523` reported 2,153 passed and two expected local-runner skips;
dedicated run `33128272572` built pinned OpenFHE 1.5.1, exercised ordinary and strong
real execution, and reported 607 passed with Ruff green and no skip report. Its terminal
boundary text explicitly kept the production worker/admission receipt absent and
forbade publication execution.

## Exact private production-issuer review

Pro later reviewed the bounded D1 implementation itself at the exact frozen object:

- branch `codex/day1b-production-issuer`;
- commit `8a37c930edd1f404f7828dd574a4a2d0c29864e9`;
- tree `8b8472fdea3465fdbaabc119b67a4aa20593c778`;
- sole parent `9d7b7b744ea59b611bb706ad56d098846619d1e9`;
- binary diff SHA-256
  `d8bfb8af895ae834daff43bf99f663ded917d0c84d14686ff3fc8767f0315c59`.

The verdict was **PASS**, with zero P0, zero P1, and no substantive P2. Pro
independently confirmed all of the following:

- payload ingress reconstructs each retained payload from the actual bytes, thereby
  recomputing its SHA-256, and then binds canonical path, category, subject, byte count,
  digest, index, and order back to `VerifiedOpenFHEQueryResult.serialized_objects`;
- the private `_ProductionInvocationAdmission` retains the exact non-F1-M physical
  projection derived from native execution, and the decoder grants the two existing
  worker-v11 admission states only after observed final frame/spool lines are exhausted
  and their root, line count, and byte count agree;
- formal F1-M remains physically absent from the worker stream while its logical
  multiplicity remains separately registry-bound;
- failed and controller-terminal paths keep both states false;
- a fixture-issuer failure after registry claim leaves the capability consumed and
  closes the registry/scratch resources; and
- worker input-binding v11, worker receipt v11, unit, frame, runtime, and native
  request/result serialization remain unchanged; the behavior change is instead bound
  by the Day 1B preparatory Behavior Set bump from v31 to v32.

Pro also confirmed that both repository adapter seams remain unconditional HOLD and
that this review grants no TRACE, dispatch, held-out, formal-loader, analyzer, or
publication authority. The subsequent exact-head Linux push CI `33135852470` completed
successfully with 2,178 passed and two expected skips caused solely by the ordinary CI
job not building the real OpenFHE query runner. The dedicated PRE-S1/OpenFHE gate
therefore remained a separate mandatory step. That exact gate, run `33138110298`, then
completed successfully on the same commit: pinned OpenFHE
`1.5.1@1306d14f8c26bb6150d3e6ad54f28dfe1007689e` was built; ordinary and strong
real-runner smokes both produced verified pre-admission-only runtime receipts; the
closed contract reported 632 passed and Ruff reported all checks passed; and the
GitHub artifact API reported zero artifacts. The terminal log still states that the
issuer is non-dispatching, the repository adapter/dispatch/artifact are absent, and no
publication execution or artifact production is permitted.
