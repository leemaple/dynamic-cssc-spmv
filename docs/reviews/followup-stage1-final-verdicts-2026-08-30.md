# Follow-up performance Stage-1 final verdicts

> **State:** external-review and local-adjudication record. This note is
> non-authorizing and is not one of the five immutable Stage-1 scientific
> objects. It records the gate that permits only their immutable Git commit.

## Exact reviewed boundary

- Base commit: `4f328afc079b328c31f2e0790cb65cdf96fcc1d7`.
- Base tree: `ab48bd66a2a8ae99da17c6cd960b71fffffb71bc`.
- Final closure packet SHA-256:
  `b62ed63d79748441b217abea3d27eeaca87d02b2fff2b26b582dfef21bcdc3a6`.
- Detached Stage-1 manifest SHA-256:
  `7e52a743d8df08a21ab5bb9b84b7b7f90d443ae8ae8dbfae37ee88b968c141b3`.
- Canonical manifest `objects`-array SHA-256:
  `e79c174adde762f515a1be69c56c83867b1b3ffa254ff6b356795d19a7f4b8f3`.
- Materialized predecessor-comparison SHA-256:
  `0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e`.

The five final Stage-1 objects and the closure packet were supplied
byte-identically to both external reviewers. Neither reviewer edited the
repository, executed a registered seed, or dispatched a workflow.

## ChatGPT Pro verdict

ChatGPT Pro returned `PASS`, with P0/P1/P2 = `0/0/0`.

- Query-vector seed-observation P1: `CLOSED`.
- Post-GO pre-campaign terminal edge: `CLOSED`.
- Controller-function versus controller-identity wording: `CLOSED`.
- New P0/P1: none.
- Stage-1 immutable-commit gate: `READY`.
- `EXPERIMENT DISPATCH NOT AUTHORIZED`.

## ZCode GLM-5.3 Max verdict

ZCode returned `PASS`, with P0/P1/P2 = `0/0/1`.

- Query-vector seed-observation P1: `CLOSED`, independently confirmed against
  the exact-base query-vector source path.
- Post-GO pre-campaign terminal edge: `CLOSED`.
- Controller-function versus controller-identity wording: `CLOSED`.
- New P0/P1: none.
- Stage-1 immutable-commit gate: `READY`.
- `EXPERIMENT DISPATCH NOT AUTHORIZED`.

Its sole P2 is packet-only wording: the final closure packet says, “The first
successor files and packet remain unchanged as review provenance.” The precise
meaning is instead:

> The first-successor review packet remains byte-identical. The
> first-successor candidate files were superseded by the final five objects;
> their historical bytes remain identified by the exact hashes and counts in
> the preserved amendment packet.

The operative final hash table, detached manifest, and object-set digest are
unambiguous. To preserve the exact packet reviewed by both reviewers, this
record carries the erratum rather than changing that packet after review.

## Local adjudication

Local read-only validation reproduced all of the following from the working
tree and exact base:

1. duplicate-free parsing of both final JSON files;
2. all four manifest-listed object hashes, byte counts, LF counts, binary-UTF-8
   path order, and the canonical objects-array digest;
3. the five path/value-exact seed replacements and the materialized predecessor
   comparison digest;
4. exact disposition of all 21 predecessor top-level plan keys;
5. exact hashes of the original, amendment, and final review packets;
6. absence of every registered follow-up seed from the exact base commit; and
7. a working tree containing only the five Stage-1 files and three review
   packets as untracked files before this verdict record was added.

There is no unresolved P0 or P1. The P2 does not alter the scientific contract,
authority state machine, seed boundary, threshold, manifest binding, or
evidence admission rule. The only permitted next action is an immutable
Stage-1 commit followed by a separately implemented and reviewed Stage 2.

**Gate:** `PASS` — immutable Stage-1 commit ready.

**Authority:** `EXPERIMENT DISPATCH NOT AUTHORIZED`.
