# Follow-up performance Stage-1 final closure review packet

> **State:** exact-file, read-only, non-authorizing final re-review. This packet
> preserves both prior review rounds and asks only whether the final narrow
> corrections close their remaining findings without creating a new P0/P1.

## Required decision

Review the five exact Stage-1 files below as one pre-implementation object.
Return `PASS`, `AMEND`, or `FAIL`; P0/P1/P2 counts; the disposition of the one
ChatGPT Pro seed-observation P1 and two ZCode P2s; every new P0/P1; whether an
immutable Stage-1 commit is ready; and the exact phrase
`EXPERIMENT DISPATCH NOT AUTHORIZED`.

Do not edit files, execute a registered seed, run a workflow, reopen the closed
predecessor, relax a threshold, or widen the novelty search.

## Immutable ancestry and permanent stop

- Base commit: `4f328afc079b328c31f2e0790cb65cdf96fcc1d7`.
- Base tree: `ab48bd66a2a8ae99da17c6cd960b71fffffb71bc`.
- Predecessor qualification `33261434612` remains terminal NO-GO and cannot be
  rerun or reinterpreted.
- Artifact `9717884587`, provider digest
  `sha256:51cbfc2a5473c0fe78d6d169cc2c4a7278ac39d7472ff37e5642e190b7e2c008`,
  remains permanently NON-EVIDENCE.
- Main CI `33277015441` is implementation provenance only.
- No registered follow-up seed has been executed and no experiment capability
  exists.

## Exact final Stage-1 object set

| Path | SHA-256 | Bytes | LF count |
|---|---|---:|---:|
| `config/followup-performance-study.json` | `a4600fbcbf630ab3a11e5004511f6b449645021ea2553243ddda80ed69f3484c` | 21,683 | 313 |
| `docs/paper/followup-performance-claim-ledger.md` | `02cd27744d5cb2bbcdc91ad1c8ecdba82c5ee566b0a22a97dc1617e6c5ff28fc` | 5,588 | 60 |
| `docs/paper/followup-performance-preregistration.md` | `306bf17e1391ca181ed9f3ac2d81387f0eed6dfa9c6cc96413dea495b7162734` | 17,245 | 299 |
| `docs/research/followup-performance-novelty-inheritance-review-2026-08-30.md` | `0fc36653cce4913c12474421da31a07068b143a53487e11a1c182514af75060c` | 4,658 | 95 |
| `config/followup-performance-stage1-manifest.json` | `7e52a743d8df08a21ab5bb9b84b7b7f90d443ae8ae8dbfae37ee88b968c141b3` | 1,982 | 43 |

The canonical manifest `objects`-array digest is
`e79c174adde762f515a1be69c56c83867b1b3ffa254ff6b356795d19a7f4b8f3`.
The detached no-self-reference construction remains unchanged.

## Review history preserved byte-for-byte

### Initial round

- Original review packet SHA-256:
  `ab206318d6a0612f2822dfd8ace61d68234f85a448b85c6b94e25db83925db69`.
- ChatGPT Pro: `AMEND`, P0/P1/P2 = `0/3/2`.
- ZCode GLM-5.3 Max: `AMEND`, P0/P1/P2 = `0/1/6`.

### First successor round

- Amendment packet SHA-256:
  `fdc3620acd63ace5b0f4f34351c144d26d01106134b1eac9513cdf4fcdba8fc0`.
- Detached manifest SHA-256:
  `f4a8d23d7504d1ea254d5dd16ee55e2198f859e5a36af5489a8623efea94a969`.
- ChatGPT Pro: `AMEND`, P0/P1/P2 = `0/1/0`. It independently confirmed
  closure of all three original Pro P1s and all original P2s, but found that
  the observation embargo incorrectly withheld the global query-vector seed
  until after qualification even though qualification executes query cells.
- ZCode: `PASS`, P0/P1/P2 = `0/0/2`. It closed all original P1s and the local
  embargo under its reading, but found two non-blocking wording edges: an
  unmapped post-qualification/pre-campaign failure and prose saying the
  predecessor external controller itself was inherited exactly.

The first successor files and packet remain unchanged as review provenance.

## Independent source check of the Pro finding

The finding is real, not accepted merely on model authority. In exact-base
source:

- `src/dynamic_cssc/route_a_contract.py` freezes global query-vector seed
  `2026082302` as `_QUERY_VECTOR_SEED`;
- `RouteAQueryVectorDomain.qualification_synthetic(...)` constructs an exact
  qualification domain;
- `src/dynamic_cssc/route_a_evaluation.py::_query_domain(...)` selects that
  domain when `trace.suite_role == "qualification"`; and
- `_evaluate_route_a_synthetic_cell(...)` calls
  `generate_route_a_query_vector(_query_domain(trace))` before executing the
  qualification's query-bearing cells.

Therefore a follow-up global query-vector seed must first be used inside the
sole authorized qualification, while pre-qualification tests and smokes must
still use sentinel seeds.

## Final narrow corrections

### Registered-seed observation boundary

- Qualification seed `20260901` and global query-vector seed `2026090202` may
  first enter their respective generators only inside the sole authorized
  qualification.
- Formal workload/snapshot/plaintext-context seeds `20260902..20260904` remain
  unobserved until their exact formal units after qualification GO.
- After GO, the same already frozen global seed `2026090202` may re-enter the
  query-vector generator only for each exact authorized formal domain.
- The seed value is reused; vector bytes remain domain-specific. Qualification
  vector bytes cannot substitute for a different formal domain.
- Every pre-qualification Stage-2 executable test/smoke remains sentinel-only.
  Any unauthorized early use terminally invalidates the study ID with no seed
  substitution.

### Post-GO pre-campaign terminal edge

- `FU-Q-GO` now depends only on exact q1--q6 success, provider times, both
  frozen deadline calculations, and the external controller's qualification-GO
  calculation record. It does not presume a formal capability mint.
- `FU-FORMAL-OUTCOME` now separately covers post-GO provider/resource reread
  failure with proof that no formal capability was minted, as well as later
  in-campaign terminal admission or NO-GO.
- A post-GO failure never rewrites factual qualification GO and leaves every
  empirical result claim on HOLD.

### Controller wording

Section 5 now says the six-job shape, probes, handoffs, guards, and controller
**decision function** are inherited. The operative controller identity and
program paths are explicitly the new follow-up-only values from Section 3, not
the predecessor controller.

## Reproduced final checks

- Both JSON files parse with duplicate-key rejection.
- The detached manifest reproduces every file SHA-256, byte count, LF count,
  binary-UTF-8 path order, and objects-array digest.
- All 21 predecessor top-level keys remain exactly dispositioned.
- Applying only the five frozen seed replacements still reproduces comparison
  baseline digest
  `0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e`.
- The two capability types remain distinct and unminted.
- Registered seeds remain absent outside the bounded Stage-1/review documents.
- `git diff --no-index --check /dev/null FILE` emits no whitespace diagnostic
  for every untracked candidate/review file.

## Gate boundary

A PASS permits only an immutable Stage-1 commit. Stage 2 must still implement
the schema, semantic-delta validator, follow-up outer envelope, controller,
workflows, Behavior Sets, sentinel-only tests, exact-head Linux CI, PRE-S1
native/resource validation, descriptive registration, data-only S2 anchor, and
another exact-source independent review. Only a later fresh live-controller
decision could mint the single-use qualification capability. This packet can
never authorize qualification or formal execution.
