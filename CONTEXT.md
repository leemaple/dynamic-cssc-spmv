# Dynamic CSSC SpMV

This context describes mutable encrypted sparse matrix–vector multiplication and the evidence used to evaluate its maintenance strategies.

## Language

**Publication Window**:
A causally closed interval whose updates become visible together and whose `query_count` records every query served from that published state.
_Avoid_: Batch, epoch

**Logical Coordinate**:
One authorized position in the final output vector, independent of any ciphertext slot or row permutation.
_Avoid_: Slot, physical row

**Result Component**:
One independently evaluated source of contributions to the final output, such as a base, delta, or overflow segment.
_Avoid_: Partial answer

**Published Component**:
A version-bound physical CSSC representation of one Result Component, including its real global ColumnIndex lanes, RowMaps, and horizontal Output Blocks.
_Avoid_: Row-length proxy, static layout

**Physical Lane**:
One ciphertext position classified as actual, tombstone, natural padding, reserved, or tail. Only a row-owned reusable lane is capacity.
_Avoid_: Slot when ownership and reuse semantics matter

**Output Block**:
A set of logical coordinates returned together that is disjoint from other horizontal blocks unless the OutputPlan explicitly says otherwise.
_Avoid_: Chunk

**Output Share**:
One returned ciphertext together with its Result Component, Output Block, and physical-slot-to-logical-coordinate coverage.
_Avoid_: Result ciphertext when coverage matters

**OutputPlan**:
The complete per-version reconstruction map from Output Shares to the authorized logical output. Its full contents include RowMap-sensitive information.
_Avoid_: Merge plan, layout metadata

**OutputPlan Digest**:
The public canonical hash that binds an evaluation to one OutputPlan without disclosing the RowMap-sensitive plan itself.
_Avoid_: OutputPlan, RowMap

**Contributor Multiplicity**:
The number of Output Share lanes that reconstruct one Logical Coordinate. Multiplicity one means concatenate/reorder; larger multiplicity means modular summation and zero-sum blinding.

**Mask Binding**:
The identity tuple that makes an encrypted one-time mask valid for exactly one query, version, OutputPlan, Result Component, and Output Block.

**Noise-Budget Profile**:
A mutually exclusive OpenFHE estimator configuration for one isolated operation class. It is not a mixed-circuit parameterization.

**Evidence Scope**:
The strongest claim directly supported by an artifact, independent of whether the generating workflow completed successfully.
_Avoid_: Result status

**Outcome-Blind Structure Pilot**:
A feasibility run that must finish before the clean pre-anchor `S1`, over exactly the first `floor(V/10)` events of each canonical schema-valid real corpus, where `V` is that corpus's full schema-valid event count. It covers T1 and T2 for partitions 0 through 4, but may report only aggregate structure/cardinality, health, and resource facts. Its only files are `structure-pilot-report.json` and `checksums.sha256`; both are permanently non-admissible and cannot enter a Publication Evidence Lineage.
_Avoid_: Day1B dry run, evidence run, promotable pilot

**Publication Evidence Lineage**:
The causally ordered history of one frozen publication behavior identity and its evidence. Once invalidated, it cannot be repaired in place.
_Avoid_: Mutable evidence chain, working branch

**Terminal Registration Freeze**:
The boundary after all publication behavior and decision rules are fixed and Day-1 registration is anchored; only evidence may follow within that Publication Evidence Lineage.
The selected formal Day1A receipt is first installed as its own monotonic shared compatibility record; the single later ADR-0011 Day-2 profile binding is a distinct post-registration data-only evidence commitment, not a later behavior freeze, and must precede all formal held-out and Day-2 outcome access.
_Avoid_: Partial freeze, provisional registration

**Experiment Source Snapshot**:
The exact Git commit that executed an experiment, together with its repository-defined role-specific Behavior Set identity.
_Avoid_: Current HEAD, evidence commit

**Evidence-Freeze Snapshot**:
A later clean Git commit that installs repository-owned trust anchors for already generated artifacts without changing the corresponding Experiment Source Snapshot's Behavior Set.
_Avoid_: Experiment source, self-authenticating anchor

**Analysis Source Snapshot**:
The clean Git commit whose analyzer and evidence validators produce a publication verdict. It may follow the Experiment Source Snapshot only when an Evidence Compatibility Receipt validates the separation.
_Avoid_: Experiment source when the commits differ

**Behavior Set**:
A repository-owned, exact, role-specific inventory of path, Git entry mode/type, and blob identity that determines an experiment, evidence stage, or analysis. An artifact cannot choose or omit its own Behavior Set members.
_Avoid_: Source-file list supplied by a producer

**Evidence Compatibility Receipt**:
A repository-generated verification record that an older evidence source and a current execution or analysis snapshot have identical required Behavior Set entries, while any differences are confined to an exact allowlist of evidence-only paths. It is not an external signature or a self-authorizing proof; publication authority separately requires the frozen runtime-isolation receipt.
_Avoid_: Equal commit SHA, ancestor check, caller-supplied compatibility Boolean

**Runtime Execution Isolation Receipt**:
A closed record that the analyzer ran from a fresh detached Analysis Source Snapshot under the frozen interpreter and invocation, without caller import paths, user-site hooks, `.pth` files, or shared bytecode state, and that source/import identities remained stable through output installation.
_Avoid_: Clean-HEAD Boolean, virtual-environment name, dependency-lock presence alone

**Final Runtime Admission Capability**:
An ephemeral, non-Boolean in-process result minted only after central code rehashes the installed runtime receipt/checksum and all four statistics artifacts and repeats the frozen source, policy, import, lock, interpreter, and invocation checks. Its audit projection is descriptive and has no replayable success bit; the statistics artifacts are not rewritten.
_Avoid_: Persisted `runtime_verified=true`, caller-loaded receipt Boolean, post-hoc mutation of a statistics verdict

**Strategy Snapshot**:
The complete persistent state of one maintenance strategy after a Publication Window, including logical state, Published Components, reusable capacity, and repack counters.
_Avoid_: WindowShape, shared strategy state

**Tuned Fixed Policy**:
A strategy configuration chosen only from tuning-prefix evidence and then frozen for held-out evaluation from its own post-tuning Strategy Snapshot.
_Avoid_: Hybrid, online selector

**Best Fixed Offline Oracle**:
A held-out hindsight diagnostic lower bound that is excluded from selector inputs and gate candidates.
_Avoid_: Hybrid, selected policy

**Registered Candidate**:
A maintenance strategy admitted by the repository-owned, zero-argument evidence gate for one frozen identity and policy.
_Avoid_: Implemented strategy, witnessed fixture

**Reference Candidate**:
A Registered Candidate eligible for tuning, selection, and the primary fixed-reference comparison.
_Avoid_: Baseline when eligibility is unclear

**Ablation Candidate**:
A Registered Candidate emitted for diagnostic comparison but excluded from tuning, selection, and oracle ranking.
_Avoid_: Weak reference, selectable baseline

**Complete Reference Set**:
The exact admitted role catalog required by an experiment contract, with every Reference Candidate and Ablation Candidate present and independently validated. It is not a caller-supplied Boolean.
_Avoid_: Nonempty candidate list, partial baseline suite
