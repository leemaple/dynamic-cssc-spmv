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
