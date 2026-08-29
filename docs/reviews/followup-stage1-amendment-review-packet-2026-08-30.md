# Follow-up performance Stage-1 amendment review packet

> **State:** exact-file, pre-implementation, non-authorizing re-review packet.
> Review the five successor Stage-1 files named below. Do not edit source,
> execute any registered seed, dispatch a workflow, or infer performance.

## Decision requested

Do the exact successor files close the union of the original ChatGPT Pro and
ZCode findings without creating a new P0 or P1 defect in the scientific
contract, authority state machine, optional-stopping boundary, claim-release
rules, identity/lineage model, or evidence admission boundary?

Return `PASS`, `AMEND`, or `FAIL`; P0/P1/P2 counts; exact remaining findings;
and an explicit statement whether experiment dispatch remains unauthorized.

## Immutable base and non-evidence boundary

- Repository base commit:
  `4f328afc079b328c31f2e0790cb65cdf96fcc1d7`.
- Base tree: `ab48bd66a2a8ae99da17c6cd960b71fffffb71bc`.
- The prior qualification run `33261434612` is terminal NO-GO and cannot be
  rerun or reinterpreted.
- Its only provider artifact, ID `9717884587`, digest
  `sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`,
  is permanently NON-EVIDENCE.
- No follow-up registered seed has been executed. No qualification or formal
  workflow is authorized by this packet.
- Implementation repair PR #42 merged as the base commit. Main CI run
  `33277015441` succeeded with 2,416 passed and two expected runner-dependent
  skips; R0 artifact `9722079150` has provider digest
  `sha256:a25a1f33ad47e54ce757b5084fa21896e48615991160546a730f876bc9127a12`.
  This is implementation provenance only, never experimental evidence.

## Exact successor Stage-1 object set

The detached manifest is intentionally not self-listed. Its exact bytes are
bound by this review packet and later by the immutable Stage-1 Git tree.

| Path | SHA-256 | Bytes | LF count |
|---|---|---:|---:|
| `config/followup-performance-study.json` | `56acb6730175fe4f8672602702583b6fcb4e0fd7777cf1ad340d96499a303ff9` | 20,995 | 312 |
| `docs/paper/followup-performance-claim-ledger.md` | `1badff6598e81837230913ff75f491c0314ad506240b438d218a21f75e8ea9d2` | 5,133 | 58 |
| `docs/paper/followup-performance-preregistration.md` | `4d2dc63c80d68cb0028be8e2a6b6928ef42387975eebca8470cafd73ad1b004b` | 16,686 | 292 |
| `docs/research/followup-performance-novelty-inheritance-review-2026-08-30.md` | `0fc36653cce4913c12474421da31a07068b143a53487e11a1c182514af75060c` | 4,658 | 95 |
| `config/followup-performance-stage1-manifest.json` | `f4a8d23d7504d1ea254d5dd16ee55e2198f859e5a36af5489a8623efea94a969` | 1,982 | 43 |

The manifest's canonical `objects`-array digest is
`2d352fff8a2d00cab4a031bf6d39058c4f6416c1dcdabbf361b0956fd5d15095`.
Its construction is frozen in both the manifest and preregistration: ascending
binary-UTF-8 paths; exact file SHA-256, byte count, and LF count; canonical
compact JSON with lexicographically sorted object keys, ASCII escaping,
`allow_nan=false`, and one terminal LF.

## Original review provenance

The original four-file packet is preserved unchanged at
`docs/reviews/followup-stage1-review-packet-2026-08-30.md`, SHA-256
`ab206318d6a0612f2822dfd8ace61d68234f85a448b85c6b94e25db83925db69`.
Its candidate manifest digest was
`594eb7a60640d44eb1210a106c042a4b1840081266ef5ee3b84cbb4db04f4abe`.

- ChatGPT Pro returned `AMEND`, P0/P1/P2 = `0/3/2`.
- ZCode GLM-5.3 Max returned `AMEND`, P0/P1/P2 = `0/1/6`.
- Local review added one P1 seed-observation leak that neither external review
  had identified.

## P1 disposition matrix

### Authority deadlock and capability conflation — closed

The machine plan now separates authority-false prerequisite control workflows
from experiment dispatch. It freezes two different nonserialized, single-use
capabilities:

1. `dynamic-cssc-followup-performance-qualification-dispatch-capability-v1`,
   minted only after the exact Stage-1/Stage-2 prerequisite chain passes and
   consumed only by the sole qualification; and
2. `dynamic-cssc-followup-performance-formal-dispatch-capability-v1`, minted
   only after q1--q6 success within both frozen deadlines plus a fresh provider
   and resource reread, and consumed only to open one serial formal campaign.

Wrong-type, replayed, consumed, wrong-study, wrong-S1/S2, wrong-attempt, and
predecessor capabilities reject before dispatch. CI, PRE-S1, registration,
data-only S2, and review consume neither capability.

### Five seed replacements versus namespace changes — closed

The five-replacement materialization digest
`0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e`
is now explicitly a predecessor comparison baseline, not executable authority,
lineage, or an outer evidence namespace. All inherited inner scientific schema
identifiers, reserved-column identities, canonical byte domains, and source
paths remain byte-exact after only the five registered seed replacements.
Only a new outer envelope and evidence-control identities use the follow-up
namespace. Every one of the predecessor plan's 21 top-level keys has an exact
disposition in `base_top_level_disposition`.

### Qualification early-stop evidence and formal-outcome conflation — closed

The claim ledger now separates mutually exclusive `FU-Q-GO` and `FU-Q-NOGO`
claims. GO requires successful q1--q6 guards and both provider-time gates.
NO-GO requires the exact executed prefix, explicit downstream non-execution,
the controller record, and proof that no formal capability was minted; it never
requires a guard that the frozen DAG correctly did not run. The separate
`FU-FORMAL-OUTCOME` row preserves factual qualification GO if a later formal
unit or terminal admission fails.

### Registered-seed pre-observation leak — closed

Before its exact authorized run, every registered seed may only be parsed,
compared, and hash-bound as an opaque scalar. Stage-2 tests and smokes must use
disjoint sentinel seeds and retain no study-derived trace, query vector,
snapshot, or cell. Qualification seed `20260901` first enters a generator only
inside the sole qualification. Formal/query seeds first enter their builders
only after qualification GO in their exact formal units. Any violation
terminally invalidates the study ID and cannot be repaired by replacing a seed.

## P2 disposition matrix

- The exact Stage-1 name-to-path-to-hash/size/line map is now the detached
  manifest; the prose enumerates all five objects.
- Manifest construction and its no-self-reference rule are now explicit.
- Untracked-file whitespace validation uses `git diff --no-index --check`
  against `/dev/null` and requires empty diagnostic output; it no longer relies
  on a vacuous ordinary `git diff --check`.
- The prose table now exposes all five changed JSON pointers, including the two
  separate paths that share the new native/plaintext seed value.
- Stage 2 must create
  `schemas/followup-performance-study-v1.schema.json` and an exact semantic
  delta validator before any experimental dispatch.
- If this follow-up closes NO-GO, no third same-estimand/same-threshold study may
  be tuned, dispatched, or used to support this paper.
- The release rule now says “empirical performance or result sentence,” leaving
  design, implementation provenance, and factual GO/NO-GO chronology to their
  separate ledger rules.
- The former selected-domain list is replaced by an exhaustive 21-key
  predecessor top-level disposition.

## Reproduced local checks

- Both JSON files parse and reject duplicate keys.
- The predecessor plan hashes to
  `ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c`.
- Applying exactly the five registered JSON-pointer replacements and the frozen
  canonical serialization independently reproduces baseline digest
  `0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e`.
- Every detached-manifest file hash, byte count, LF count, path order, and object
  set digest reproduces.
- The registered seeds do not occur elsewhere in the base tree or outside the
  bounded Stage-1/review objects.
- Untracked-file whitespace checks are clean.

## Review limits

This is still Stage 1. It contains no workflow, controller, schema, source, or
test implementation. A PASS only permits an immutable Stage-1 commit and a
separately reviewed Stage-2 implementation. It does not permit qualification or
formal experiment dispatch, release any empirical claim, predict gate success,
or alter the permanent predecessor NO-GO.
