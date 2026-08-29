# Route A native q3/q4 material-gate disposition (2026-08-29)

- Review state: `Q3-Q6-LOCAL-IMPLEMENTATION-IN-PROGRESS-NO-DISPATCH`
- Experiment-source base: `5d5c41af2ff8a5a65dd0ea0b4e69296a1c6a7a00`
- Review packet: `route-a-native-q3q4-review-20260829.zip`
- Packet SHA-256: `7bdb24b14938097c2e8158032417f81e135831070a93c2589d06145133ed22b7`
- Packet size and membership: 103,509 bytes; 10 ordinary files
- Empirical authority: none
- Qualification or formal execution performed by this review: none

This note records the bounded architecture decision before the native C++
producer/replay path is changed. It is not S1, S2, a qualification GO, an
OpenFHE result, or permission to dispatch the one-shot M qualification. The
external reviews are now terminal. Their P0/P1 findings are disposed below;
implementation and CI evidence remain incomplete.

## Evidence already closed locally

The Python boundary now has one terminal query-bearing transition after 511
or 2,047 state-only accepted windows, four disjoint process lanes, a fresh
preparation and SQLite ledger per lane, consume-once authorization, typed and
direct \(Ax \bmod 65537\) oracles, an immutable read-only replay, and terminal
pre/post ledger-byte equality. The current local contract evidence is:

- 197 Route A/OpenFHE runner, runtime, controller, native-case, lifecycle,
  package, strategy, workload, and independent-oracle tests;
- Ruff and `git diff --check` success; and
- no Route A S/M-shaped native timing and no one-shot M qualification run.

Those facts close the Python-side query-ID, single-use lifecycle, per-recorded-
lane package, route-specific producer/replay verifier, package reinspection,
and three-package native guard seams. The later local implementation adds the
q3/q4 stage artifacts and the q5/q6 qualification seams, but exact-head Linux
CI, PRE-S1, final external review, S1/S2, and the one-shot qualification remain
unperformed.

## Reviewer status

### ZCode GLM-5.3 Max

The exact packet was reviewed read-only in Full access / Max reasoning mode.
Its verdict was `PASS`, with P0=0, P1=0, and four P2 design-freeze items. It
supports one C++ binary with explicit producer and replay modes, a separate
Python replay verifier, runtime zero-generation counters, exact package-object
digests, and no diagnostic M execution.

Two pieces of that advice are not accepted verbatim:

1. the frozen legacy `D1BKEY01` frame cannot be extended with context, secret,
   or public-key segments because the existing Day 1B contract and regression
   tests require exactly the rotation-key and evaluation-multiplication-key
   segments; and
2. fresh keypairs do not imply that serialized CryptoContext parameter bytes
   differ, so cross-package freshness must be established through disposable
   secret/public/evaluation keys and ciphertexts, not an assumed context-byte
   inequality.

### Fable 5 through Terminal Claude Code

The first read-only Fable review correctly identified the absent q4 C++ and
package layer and supported the same-binary explicit-mode design, but proposed
reconstructing the context with `MakeContext()`. The terminal narrow
counter-review used exact model `claude-fable-5`, `effort=max`, and
`permission-mode=plan`. Its final verdict was `AMEND`, P0=0/P1=3, and it
explicitly withdrew the reconstruction proposal: q3 must retain and q4 must
deserialize the exact producer CryptoContext. It also confirmed that the
canonical manifest is the only outer container and `D1BKEY01` remains one
unchanged two-segment member.

Its three P1 findings were: correct the private-evidence accounting language;
freeze one complete per-package membership list distinct from the q3 handoff
layer; and scope source-level forbidden-call tests to the q4 function rather
than the whole same-binary source. All three are incorporated in the candidate
contract below; the code and Stage-1 documents still require terminal hash/CI
closure.

A second exact-source compile/API audit found one P0 and four P2 items. The P0
was the OpenFHE 1.5.1 generic `Serial::Deserialize` return type; commit
`c52023160c1989e8f8ab294eed2941c13fe31fc0` corrected it and GitHub PRE-S1 run
`33231272745` then built the pinned runner and completed both real OpenFHE
smokes successfully. The follow-up patch also rejects `INT64_MIN` before signed
negation, removes target-width-tautological comparisons, parses the package
from the single already-hashed manifest snapshot, catches deserialization
exceptions, and binds both Python Route A result verifiers to the exact
canonical request re-derived from their typed inputs. These follow-up bytes
still require an exact-head GitHub rerun before the material gate closes.

A later implementation review was run from the local Terminal Claude Code CLI,
not the AIGoCode web chat. It used exact model `claude-fable-5`, `effort=max`,
and read-only `permission-mode=plan`. The first pass returned `AMEND`,
P0=0/P1=2/P2=6. Its two P1s required an externally supplied q3 stage-manifest
address at q4 ingress and direct orchestration/CLI coverage. The P2s requested
cross-checks between retained build identity and inventory, exact file modes,
strict Git source identity, exact receipt shapes, pre-install case rejection,
and hostile archive/output tests. All eight were implemented and regression
tested.

The single permitted counter-review closed all eight original findings, then
found a new P0 in the fixtures and guard: the code required one common
canonical-request digest across fresh-key lanes. That is impossible for the
real path because each lane has a distinct query identity, preparation, fresh
ciphertexts, and canonical request. The corrected invariant is now exact:
producer and replay request bytes are equal *within* each retained package,
while the warm-up and three recorded producer requests are pairwise distinct,
and the three recorded replay requests are pairwise distinct. A real
preparation/request-construction regression proves four distinct lane, query,
preparation, and request roots. The targeted result is 20 passing tests; the
expanded q3/q4 family is 60 passing tests. This closes the counter-review P0
locally, but it is not an exact-commit PASS until the final candidate is
committed and re-reviewed.

### ChatGPT Pro through Ego Lite

The exact packet completed in the existing project conversation through Ego
Lite after 24m58s. Its verdict was `AMEND`, P0=0/P1=5/P2=3. The five P1s were:
retain the exact CryptoContext; split identical Cloud-program operations from
mode-specific lifecycle operations; make the producer launch itself an opaque
single-use capability; forbid replay of the discarded warm-up; and reject the
Python `True == 1` ordinal splice. The last three are closed locally with
strict recorded ordinals 0/1/2 and 16 passing lifecycle tests. The first two
are now frozen in the plan/preregistration and are being implemented in the
same C++ binary and independent Python verifiers.

## Candidate frozen decisions

### 1. One binary, three closed modes

Keep `openfhe_query_runner` as the only binary. Its argument parser first
selects one of these closed modes:

1. no `--route-a-mode`: the current exact five-argument Day 1B path, with its result,
   object inventory, `D1BKEY01`, and READY/DONE behavior unchanged;
2. `--route-a-mode producer`: generate a fresh disposable keypair, generate
   evaluation keys, encrypt the exact request operands, evaluate, decrypt,
   and retain the Route A package objects; or
3. `--route-a-mode replay`: accept only one package directory, obtain the
   canonical request from that package, read and rehash the producer result,
   producer result, and retained objects, deserialize them, evaluate, and
   decrypt without calling any generation or encryption API.

An unknown mode, duplicate/missing/extra argument, nonempty output directory,
unsafe path, or aliased input/output directory fails before READY.

### 2. Preserve `D1BKEY01` byte-exactly

The legacy frame remains an exact two-segment object:

1. rotation-key inventory; and
2. evaluation-multiplication keys.

No context, secret key, public key, ciphertext, mode marker, or Route A header
is added to this frame. Route A uses it as one unchanged retained member.
There is no second copy of either contained segment.

### 3. Retain and deserialize the exact producer CryptoContext

The candidate disposition is to retain the exact serialized producer
CryptoContext instead of reconstructing it with `MakeContext()` during q4.
This follows the pinned OpenFHE example, which serializes the context, clears
the key/context caches, deserializes the context, then deserializes public,
evaluation, ciphertext, and secret-key objects before use:

<https://github.com/openfheorg/openfhe-development/blob/1306d14f8c26bb6150d3e6ad54f28dfe1007689e/src/pke/examples/simple-integers-serial.cpp>

The exact context object is a physical member of the retained package, but is
not a protocol communication category. Context, disposable secret key,
private ledger/preparation/oracles, producer receipt, manifest, and checksums
are reported once as private replay-evidence transport overhead and never
enter the nine-category Cloud communication sum. Only the public key and one
complete unchanged `D1BKEY01` frame enter the one-time evaluation-key material
view; the frame header and two segment sizes are decomposition-only.

An additional Route A binary outer frame is unnecessary: the content-addressed
package manifest already provides the closed ordered outer container. Avoiding
another frame also avoids duplicate headers and a second parser.

### 4. Closed recorded-package membership

Each of the three recorded producer evaluations has one manifest and retains
exactly these physical members:

1. the canonical private request;
2. the exact serialized CryptoContext;
3. the disposable secret key;
4. the corresponding public key;
5. one unchanged `D1BKEY01` evaluation-key frame;
6. every exact encrypted operand;
7. every producer result ciphertext;
8. the producer result receipt;
9. the lane-specific preparation bytes and authorization receipt;
10. the consumed SQLite ledger snapshot;
11. the typed and direct oracle bindings;
12. the case binding, lane/query binding, and structural vector; and
13. one canonical manifest containing the build-manifest binding and the exact
    role, subject, byte count, relative path, and SHA-256 of every member.

The q3 provider handoff is a distinct outer artifact: one content-addressed
build package, one discarded warm-up receipt, the three closed packages above,
one stage ledger, and its checksum inventory. Build binaries and the warm-up
receipt are not copied into each recorded package.

The warm-up retains a receipt but no reusable package. Private request,
preparation, ledger, secret-key, and oracle bytes never enter a formal case
receipt or final paper artifact.

### 5. q4 is loaded-object replay, not regeneration

The replay branch must clear evaluation-multiplication and automorphism-key
caches and release all contexts, then load the retained objects in this order:
context, secret key, public key, evaluation-multiplication keys, automorphism
keys, and input ciphertexts ordered by ciphertext ID. It
checks the package byte inventory before deserialization and checks the common
key tag and context/profile bindings after deserialization. The public key is
identity-only in q4 and is never passed to `Encrypt`.

Output-ciphertext byte equality is not an acceptance predicate. Acceptance
requires exact producer package/input identity, a newly produced valid replay
ciphertext, and decrypted equality to both independently bound plaintext
oracles.

### 6. Multi-layer zero-generation proof

The q4 proof is the conjunction of:

1. a source-scoped regression over the q4 function (not the whole shared
   source file) that it has no reachable `MakeContext`, `GenCryptoContext`,
   `KeyGen`, `EvalMultKeyGen`, `EvalRotateKeyGen`, or `Encrypt`
   call site;
2. dispatch to the replay branch before the producer generation block;
3. a closed replay operation receipt with all five generation counters equal
   to zero;
4. nonzero, exact deserialization counts and digest equality for every loaded
   package member;
5. exact request, program, query-ID, preparation, ledger, case, and lane
   bindings; and
6. valid replay evaluation plus secret-key decryption to both oracles.

The legacy producer verifier remains unchanged. Route A gets separate producer
and replay verifiers so a mode flag cannot weaken the Day 1B count contract.

### 7. Fresh-key cross-package guard

For the three recorded packages in one case, the guard requires equal typed-
oracle, direct-oracle, case, structural-vector, and Cloud-program operation
inventories. For each package, producer request bytes must equal its exact
replay request bytes. Across the three recorded lanes, canonical request roots
must be pairwise distinct, as must the disposable secret-key, public-key,
evaluation-key-frame, encrypted-operand-inventory, and producer-result roots.
The CryptoContext profile binding must be equal; its serialized bytes are not
used as a freshness discriminator.

## Remaining P0/P1 implementation work

The material gate does not pass merely because the candidate decisions above
are coherent. Before q3/q4 can be called runnable, the implementation must add:

1. commit the complete q3–q6 candidate and rerun pinned OpenFHE PRE-S1 on that
   exact head;
2. close the exact six-job workflow, Behavior Set, workflow-contract, and
   stage-artifact tests under exact-head Linux CI;
3. obtain terminal exact-candidate reviews from ChatGPT Pro, ZCode when
   available, and one final read-only Fable 5 pass;
4. freeze S1, produce and independently inspect the descriptive registration,
   install only the reviewed data anchor as S2, and re-prove S1/S2 compatibility;
5. dispatch the qualification exactly once from terminal S2 only if every
   prior gate is green, with the external 45-minute stop-loss; and
6. let the external live controller—not q6 or this note—make the final fresh
   55-minute postrun decision.

Until those items and all terminal external-review P0/P1 findings are closed,
qualification dispatch remains forbidden.
