# Install the Day 2 profile anchor after terminal registration

- Status: Accepted
- Date: 2026-08-24

## Context

The Day 2 pre-dispatch profile anchor binds the exact Day1A authority receipt,
rotation inventory, count bundle, registered-candidate receipt, rotation-key
plan, operation-profile set, and accounting contracts. Those digests cannot
exist before the clean pre-anchor experiment snapshot `S1`: candidate
registration is generated from `S1`, installed at the Terminal Registration
Freeze `S2`, and formal Day1A consumes that installed registration.

Treating the profile-anchor blob as Day 2 and analyzer behavior that must be
present in `S1` therefore creates two impossible dependencies. The registration
receipt binds the `S1` tree that would contain its own digest, and the Day1A
receipt required by the profile cannot be generated until after `S2`.

## Decision

The profile-anchor schema, validators, producer, workflow, accounting rules,
and every other behavior-bearing input remain frozen at `S1`. The repository
file `config/day2-calibration-profile-anchors.json` is data-only and is not a
member of the Day 2 or analyzer Behavior Set.

After the Terminal Registration Freeze, formal Day1A runs from that exact `S2`.
One prior shared compatibility-anchor commit must then install exactly one
`role=day1-registration` record whose experiment source is `S2`, Behavior Set
identity is the frozen registration/Day1A identity, and artifact digest is the
selected Day1A authority receipt. Only after that record's unique first
installation may one reviewed commit replace the empty profile-anchor set with
one binding carrying the same receipt digest and mechanically derived from the
already frozen artifacts. The profile commit changes only the profile-anchor
data path. The binding may never be deleted, replaced, emptied, or reinstalled,
including through another side of a merge. The profile is required to be empty
at both registration `S1` and the Terminal Registration Freeze `S2`.

The unique profile installation must precede every formal Day1B held-out run
and every Day 2 calibration run. Both production entrypoints consume the
registration/profile history; Day 2 post-run compatibility also requires the
experiment source itself to contain the profile. Repository history rejects a
profile first appearance at or after a Day 2 post-run binding. The Day 2
pre-dispatch seam requires the post-run anchor set to remain empty and rechecks
both anchor documents around source attestation. The workflow records its
actual clean profile-bearing source commit and the frozen Day 2 Behavior Set
digest at run time; the profile contains no future source commit identity.

The post-run anchor uses schema v3. In addition to the outer archive, raw
measurement, profile, rotation-plan, and projection digests, it binds the exact
`contract-bindings.json` digest. Final repository authority cross-checks the
profile, rotation plan, and contract bindings against the pre-dispatch profile
anchor, so bypassing the dispatch seam cannot splice different Day1A,
registration, catalog, experiment-contract, or accounting identities into the
archive.

## Consequences

- The full registered-candidate and Day1A digest binding is preserved without
  a Git self-reference.
- The Day1A evidence anchor and the profile-only installation remain two
  auditable monotonic commits; the latter cannot silently select an unanchored
  Day1A run.
- The only newly admitted post-registration state transition is one monotonic,
  installation-only data commit before outcomes. Existing remove, retarget,
  restore, merge-history, blob-mode, and unexpected-drift checks remain
  fail-closed.
- A profile commit mixed with another data change, a second independent first
  installation, or any profile change after Day 2 evidence invalidates the
  lineage.
- Formal Day1B and Day 2 entrypoints must remain HOLD until they consume this
  repository-owned pre-dispatch authority. A manually executed exploratory
  binary never acquires publication authority.

## Rejected alternatives

- A pre-`S1` static rotation-plan commitment does not remove the registration
  receipt self-reference and would weaken the exact Day1A inventory binding.
- A non-authorizing roster either fails to constrain dispatch or becomes a
  duplicate profile anchor with a larger consistency surface.
- Installing the profile only after measurement permits run-until-success
  selection and is therefore inadmissible.
