# R1 native lifecycle: bounded Stage A engineering

Baseline: `fd75df66789cad79b504b3e0da4c969a8ac456bb`. This change adds an
engineering-only, persistent OpenFHE adapter around existing state transitions,
compiler, query preparation, SQLite ledger and typed native primitives. It does
not alter the old studies, their NO-GO status, or the 54-cell validation study.

The author delegated the choice of the post-review revision plan after receiving
the old stopping/use restriction. The selected, explicitly disclosed departure
is recorded outside this repository in the SA038 revision checkpoint and
`R1-最佳补证方案.md` (SHA-256
`8d9b6c1f8598b984a28b496e31192ebea72c5688133209818f270a6a8397d227`).
Pro approved the plan, not this code or any experimental claim.

## Scope of this first candidate

- One context/key set and persistent matrix-ciphertext cache per complete trace.
- Initial publication and every subsequent publication actually executed.
- Dirty/rebuilt pages reencrypted; unchanged physical pages may be reused only
  with matching plaintext and physical fingerprints. Repack forces rebuilds.
- Each query prepares and consumes its existing single-use ledger binding.
- New rotation keys generated on demand; each augmentation sends/receives the
  actual full serialized rotation-key inventory. No future keys are free.
- Matrix, query, mask and result ciphertexts serialize and deserialize at their
  intended role directions. Matrix/mask material is never counted as B traffic.
- Public Cloud program (including current operand-to-cache bindings) and private
  B metadata are separate full JSON snapshots
  with actual encode/decode checks. No hypothetical incremental metadata saving
  is credited. The colocated receiver is not an isolated network role.
- All returned effective slots checked against the typed plaintext DAG;
  reconstructed outputs also checked against direct logical SpMV. Native code
  checks the remaining physical slots and cache non-mutation.
- Whole-process time includes Python validation, compiler, IPC, ledger, native
  operations, payload serialization, oracles and event logging. Initial setup is
  also separately visible. Native timings are subintervals, not replacement totals.
- Existing old runners remain unchanged except an explicit additional mode.

Only a handwritten disjoint 16-row, 65-column, two-window, two-queries-per-window
fixture is exposed. It includes modify/delete/insert, padding overflow, delta
creation/update, and repeated queries. The runner rejects non-engineering IDs;
there are no formal seeds, registered inputs, formal dispatch entry points, or
automatic reruns. These sentinel values must never become paper performance data.

## Bounds and remaining gates

The first engineering run `37306573066` on `20d1f4f` built OpenFHE and the
native runner, then failed before setup because the new command fields did not
match the reused strict canonical-key-order validator. It spent 220 runner
seconds and produced no successful native trace. Independent source review also
found a 4096-raw versus 8192-normalized matrix-fingerprint mismatch. Neither is
a scientific result. This follow-up fixes both representations, includes signed
matrix values in the disjoint fixture, and adds remote native regressions for
canonical frames, signed reuse, changed-reuse rejection, stale/replayed queries
and incremental rotation-key generation with prior-key reuse.

It also prevents the CLI from writing failure metadata into a pre-existing run
directory, includes workload validation in the whole-trace timer, and reconciles
native operation/encryption counts against the actual typed program and dirty
page set. Low-rate Linux samples report non-atomic sampled Python+native RSS sums
and trace-file disk sums as estimates, not guaranteed bounds on simultaneous
peaks, alongside individual process high-water marks and their explicitly
labelled upper-bound sum. Sampling cost is
included. These additions still require remote witnesses and review.

Stage A: at most two focused engineering days and six aggregate runner-hours,
including CI/build/test/sentinel. This workflow reserves at most 70 minutes;
simultaneous ordinary CI reserves at most 60 minutes. The aggregate budget is
tracked in the external current checkpoint before another push/run. Standard
public Linux runners only, at most these two jobs. Each trace has a 600-second
alarm; any failure stops the three-strategy serial sentinel. Private request
vectors and SQLite ledger are not uploaded. Only named public receipts and
diagnostic logs are uploaded, never an entire results directory.

This is an engineering feasibility candidate, NOT a frozen scientific protocol.
Remaining before formal execution: native build/sentinel including negative
protocol tests and count reconciliation, scaled resource calibration, review of
combined memory/disk measurement, independent code/material review, full
exact-SHA CI, frozen workload generator/seeds/limits and source tag. No formal
dispatch is authorized by this document or green engineering CI.

The proposed later matrix and 48-hour overall cap remain planning constraints;
infeasible calibration means no formal start, not a post-result grid reduction.
The current manuscript and unsent QQ draft are unchanged and R1 remains partial.
