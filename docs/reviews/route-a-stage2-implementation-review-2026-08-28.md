# Route A Stage-2 implementation review — 2026-08-28

## Authority boundary

This review covers a non-authorizing implementation slice only.  It does not
authorize SNAP acquisition, qualification dispatch, formal execution, artifact
installation, claim release, or manuscript-result release.  Those actions remain
behind the frozen Stage-2 and downstream admission gates.

The implementation was reviewed relative to Git commit
`a112e5d48194653e91f44adc9b04c4c22424ac61` (tree
`93006b58cecc4f402eb8754775e4218a253ceb81`), whose subject is
`publication: freeze Route A strategy input reduction`.  The four Stage-1 files
remained byte-identical throughout the implementation review:

- machine plan: `c391119d36ea882919cf787167baa9c80f346d2860fce9e3b8f98421a034fbfb`,
  1,103 lines;
- preregistration: `caea6c5a15baf3b1ee8f988a82b1271ce82eadb7ba8cd87d51dc0970fab6baa0`,
  1,438 lines;
- bounded novelty review:
  `62028624787d4f900bb4b833c30f6e2a28c850a0b7c74588ebeca4534afc048e`,
  293 lines; and
- claim ledger: `44bc11b2401bdb94c3b7a4d9c063178ec50527f4f4b8136d1706b1e2f15a47ec`,
  129 lines.

## Initial implementation review

The initial twelve-file implementation packet was reviewed read-only by ZCode
GLM-5.3 Max and ChatGPT Pro in the existing paper Project.  Local focused gates
were green before external review, but the external review remained advisory
until every finding was mapped back to source and a reproducing test.

ZCode returned `PASS` with no P0/P1 and three P2 suggestions.  ChatGPT Pro
returned `AMEND`, with five reproducible P1 findings and two future-S1 P2 items.
The five accepted P1 findings were:

1. qualification seed `20260821` and formal seeds `20260822`--`20260824`
   were not separated by a retained typed suite role;
2. candidate state did not own exact next-window and next-global-query cursors;
3. state mutation accepted a caller-constructed derived adapted window;
4. public authorization and claim APIs accepted caller-supplied clock values;
   and
5. the one-shot capability retained authority-bearing state on the caller-held
   object rather than exclusively in the controller registry.

All five were accepted because direct source inspection and focused RED tests
confirmed them.  The first repair introduced disjoint typed qualification and
formal constructors without changing canonical known-answer bytes, exact
candidate cursors, internal-only window adaptation before state mutation, a
private live-clock seam, and a registry-owned opaque token and binding.  After
that repair, 71 Route A tests and 140 affected core tests passed; targeted Ruff
and `git diff --check` also passed.

The exact counterreview packet was
`/tmp/route-a-stage2-p1fix-a112e5d-20260828-2155.zip`, SHA-256
`54fb182f1f1775f1523ade2f66e1a9371ddf16a1ed5fa129208079bfcbecb64e`,
52,243 bytes.  ChatGPT Pro confirmed four closures but found two additional P1
counterexamples in the capability path:

1. `_QualificationBinding` still stored the caller's original frozen dataclass
   object, which a same-process caller could retarget with `object.__setattr__`;
   and
2. `claim_route_a_qualification_capability` validated a presented request before
   consuming the capability, so a malformed retarget could fail without burning
   the one-shot authority.

## Final request-binding repair

Both counterexamples were reproduced before source changes.  Three new focused
assertions failed on the old implementation: one same-object mutation case and
two malformed-retarget cases (`not-main` branch and attempt `2`).

The minimum repair then:

- added a private frozen `_QualificationRequestIdentity` containing detached
  primitive values;
- made authorization freeze and validate that identity before provider lookup,
  use it for run comparison, and store only it in the registry binding; and
- reordered claim so the capability is atomically consumed before any presented
  request type/domain validation or identity comparison.

The three tests turned green after the repair.  At that point the focused
results were:

- Route A tests: `74 passed`;
- affected strategy/simulator/accounting tests: `140 passed`;
- targeted Ruff: `All checks passed!`; and
- `git diff --check`: pass.

The resulting intermediate twelve-file packet was
`/tmp/route-a-stage2-p1fix2-a112e5d-20260828.zip`, SHA-256
`cac28edade0576eb45bdbf0dc96683e475fc9980b8ac3247c98e339d4be1c95a`,
51,994 bytes.  ChatGPT Pro confirmed the detached binding and consumption order
but found one last strict-type P1: `expected_head_branch` compared equal to
`"main"` without first requiring an exact `str`.  A `str` subclass with spoofed
equality could therefore cross both the field check and detached-identity
comparison.

That counterexample was again written first and failed on the intermediate
implementation.  The final source fix adds
`type(identity.expected_head_branch) is str` to `_freeze_request`; the regression
mutates an issued request to a `not-main` `str` subclass that reports equality
with `"main"`, proves the claim rejects, and proves the correct retry is already
consumed.  Final focused results are:

- Route A tests: `75 passed`;
- affected strategy/simulator/accounting tests: `140 passed`;
- targeted Ruff: `All checks passed!`; and
- `git diff --check`: pass.

The final exact twelve-file packet is
`/tmp/route-a-stage2-final-a112e5d-20260828.zip`, SHA-256
`e69de86e0ccc7819d236c953cc61ba207c49af727767515ca50cfb2859ff6599`,
52,139 bytes.  Its twelve archive entries were independently rehashed against
the live working tree and all twelve matched byte for byte.  The two files that
changed during the request-binding closure have these final digests:

- `src/dynamic_cssc/route_a_controller.py`:
  `d6a4352457185af0c21eb725f74e4bde8b0601d06263f8611841fccfe6d0bb2f`;
- `tests/test_route_a_controller.py`:
  `a1948f1ee5c3319bb2ad94c3daea793ef03028c292631745fcf901d9fbbf6de1`.

## Final external dispositions

- ZCode GLM-5.3 Max, Full access, existing `dynamic-cssc-spmv` paper task:
  **PASS; P0=0, P1=0, P2=3**.  It directly read the final controller and tests,
  confirmed the detached request identity, consume-before-validation order, and
  exact-`str` branch guard, and judged the slice ready to commit and push for CI.
  Its P2 items are the two future-S1 boundaries below plus recording independent
  hashes in the commit/review record.
- ChatGPT Pro, existing paper Project through Ego Lite:
  **PASS; P0=0, P1=0, P2=2**.  It independently matched the final archive,
  controller, and controller-test hashes; verified that the exact-`str` guard
  precedes the overloaded equality comparison; confirmed the spoofing regression
  and consumption behavior; and judged the exact slice ready to commit and push
  for CI.  Its two P2 items are exactly the future-S1 boundaries below.

## Deferred nonblocking boundaries

Two implementation obligations remain explicitly deferred to the final S1
runner rather than silently claimed complete here:

1. retained source bytes must be intrinsically bound to the typed accepted
   groups consumed by window compilation; and
2. version-only paths must emit and charge exact canonical new-version and plan
   metadata bytes.

These are real downstream gates, not evidence produced by this commit.  They do
not justify changing the Stage-1 documents or weakening any resource, replay,
or authority boundary.

Fable 5 was not triggered.  Every material disagreement so far was decided by
reproducible source-level counterexamples and RED-to-GREEN tests; no unresolved
P0/P1 hypothesis remained that required an additional reviewer.  The next
permitted action after the final external recheck is a bounded source/test/review
commit and GitHub CI, not publication execution.
