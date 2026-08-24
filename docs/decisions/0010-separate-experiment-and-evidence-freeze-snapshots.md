# Separate experiment, evidence-freeze, and analysis snapshots

- Status: Accepted; Git-object compatibility verifier implemented, publication
  anchors/runtime isolation/role integration still pending
- Date: 2026-08-23

An experiment runs from an exact **Experiment Source Snapshot** `S1`, but its
provider artifact digest does not exist until after that run. Installing the
digest-addressed trust anchor therefore creates a later **Evidence-Freeze
Snapshot** `S2`; analysis may run from an **Analysis Source Snapshot** `S3`.
The repository must not require `S1 == S2 == S3`, because embedding a commit's
own SHA or its future artifact digest in that commit creates an impossible Git
self-reference. Instead, every artifact binds the actual run SHA and a
repository-owned, role-specific Behavior Set digest. A later clean snapshot may
consume it only through an Evidence Compatibility Receipt that independently
compares the exact required paths, entry modes/types, and Git blobs, rejects
missing or extra behavior entries, and confines all remaining changes to an
exact evidence-only allowlist. No post-outcome analysis-code allowlist is
currently authorized.

The snapshots for one publication-scale campaign form a **Publication Evidence
Lineage**. Before that lineage is opened, every behavior-bearing source file,
workflow, repository policy, preregistration rule, sampling rule, decision rule,
and analyzer is reviewed and frozen at a clean pre-anchor `S1`. Installing the
Day-1 registration anchor from `S1`-generated evidence is the lineage's
**Terminal Registration Freeze** and its last behavior-freeze action. After that
boundary, the lineage may grow only by monotonic addition of repository-owned
data-only anchors; an existing anchor path, record, target, or identity may not
be deleted or changed.

## Consequences

- Pre-dispatch policy anchors bind canonical contract/Behavior Set identities,
  not a self-referential future HEAD SHA; the workflow records its actual source
  SHA at run time.
- Post-run anchors live in isolated evidence-only tracked data. Validators and
  behavior code remain inside their role-specific Behavior Sets and cannot be
  excluded merely because they also read anchors.
- Day-1 registration remains valid while later roles monotonically append only
  the shared compatibility-anchor data, the one post-registration Day-2
  profile binding authorized by ADR 0011, and the Day-2 post-run calibration
  anchor. The profile schema and all code that derives or consumes it are
  frozen at `S1`; its mechanically derived data binding is installed once only
  after the Terminal Registration Freeze and after a distinct shared
  `role=day1-registration` compatibility record anchors the selected formal
  Day1A receipt. It must precede any formal held-out or Day-2 outcome access.
  Every earlier anchor record and identity must remain
  unchanged; a later role's valid addition does not invalidate an earlier
  role's receipt. The exact Behavior Set must still match `S1` at current HEAD;
  no source, workflow, policy, preregistration, analysis rule, or other
  documentation drift is admitted.
- A malformed anchor installation, required behavior change, or requested
  withdrawal invalidates the current Publication Evidence Lineage. Recovery
  starts a fresh branch from the pre-anchor `S1`, applies the reviewed change,
  establishes a new terminal freeze, and regenerates every affected artifact.
  Removing and re-adding an anchor in the same ancestry cannot restore
  publication authority.
- Trace acquisition, strong correctness, candidate registration, Day1A,
  Day1B, Day2, mixed-circuit, R4, and analysis each have explicit Behavior Set
  inventories. Producers may report those inventories but never select them.
- Compatibility requires Git-object comparison with replace refs disabled:
  ancestry alone, equal textual SHAs, a caller Boolean, or a producer-supplied
  file list is insufficient.
- The preregistration, decision thresholds, analyzer, sampler, input schema,
  and analysis CLI form a decision Behavior Set frozen before held-out access.
  They are never an analysis-only allowlist: any blob or mode drift rejects the
  compatibility receipt.
- Publication authority additionally requires a fresh detached checkout,
  isolated interpreter and bytecode cache, disabled user-site and caller import
  paths, hash-locked runtime dependencies, recorded import origins/hashes, and
  identical hardened source attestations before and after execution.
- The installed runtime receipt and four statistics artifacts remain descriptive
  and are never rewritten with an internal success bit. Central admission accepts
  only the live runner receipt, rehashes the complete installed receipt/checksum
  and statistics artifact set, and returns an ephemeral non-Boolean capability.
  Its audit projection contains no replayable authority bit. The `ANALYZER` role
  has no post-run compatibility phase and cannot gain authority from a post-run
  compatibility anchor; it relies on the exact `S3` identity and isolated
  runtime admission in the same run.
- Publication verdicts report experiment, evidence-freeze, and analysis source
  identities separately. A behavior-bearing drift fails closed; it is not
  relabeled as an evidence-only change.
