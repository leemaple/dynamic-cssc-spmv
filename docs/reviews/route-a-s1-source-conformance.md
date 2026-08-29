# Route A S1 source-conformance record

Status: S1-candidate, authority false. At freeze, “exact S1” means the clean
commit containing these exact bytes and the complete registered Behavior Set.
The registration inventory, not a self-written commit hash in this document,
binds every path, mode, Git object type, and blob ID. This review maps each
definition-level proof conjunct to the implementation that must be frozen at
that S1. It does not report experimental success.

## P1 binding predicate and authority order

| Proof conjunct | Frozen implementation seam | Rejection/evidence coverage |
|---|---|---|
| Version, query, lane, workload, strategy, scale, seed, freshness and attempt identity | `route_a_contract.RouteAEvaluationLane`, `RouteAQueryIdentity`, `generate_route_a_query_vector`; `route_a_native_invocation._validate_producer_lane` and `_validate_replay_lane` | `tests/test_route_a_contract.py`, `tests/test_route_a_native_invocation.py` |
| Logical state and ordered component identity | `route_a_strategy`, `route_a_evaluation`, `route_a_native_case.compile_route_a_terminal_native_case` | Route A evaluation/case tests and q3/q4 material-gate negatives |
| Global ColumnIndex, component RowMap, OutputPlan and private-plan identity | `query_compiler`, `ordinary_query_lifecycle.canonical_ordinary_private_plan_bytes`, `strong_execution.canonical_private_plan_payload`, `output_plan.canonical_output_plan_payload` | `tests/test_query_compiler.py`, `tests/test_ordinary_query_lifecycle.py`, `tests/test_output_plan.py`, `tests/test_strong_execution_bundle.py` |
| Prepared-query, query-vector, modulus, manifest and execution-plan identity | ordinary/strong preparation decoders and authorization functions; `route_a_native_invocation.authorize_route_a_native_invocation`; `route_a_openfhe_package.inspect_route_a_openfhe_package` | ordinary/strong lifecycle, native invocation, OpenFHE package and native guard tests |
| Ordered serialized payload bytes, counts and roots | `route_a_artifacts.inspect_route_a_synthetic_cell_archive`, `route_a_replay`, `route_a_openfhe_package`, `route_a_native_suite.inspect_route_a_native_qualification_artifact` | archive/package tamper tests plus `tests/test_route_a_native_suite.py` |
| Independent exact replay | `route_a_replay.replay_route_a_synthetic_cell`, `route_a_native_invocation.replay_route_a_native_invocation_read_only`, `route_a_native_runtime.execute_route_a_native_replay` | q2/q4 replay tests, including request-byte mismatch and nonzero replay-lifecycle rejection |
| Provider wrapper and run binding | `route_a_qualification_guard._provider_bindings`, `route_a_postrun_admission`, `route_a_controller.GitHubActionsQualificationProvider` | combined-guard, postrun-admission, GitHub-provider and controller tests |

The authority order is intentionally deeper than any one decoder. Ordinary and
strong execution capabilities are lifecycle-minted only after exact preparation
and ledger consumption. Native producer capability is unforgeable and
single-use. q1/q3 handoffs are one-day private `NON-EVIDENCE`; q2/q4 produce
guarded but still non-authorizing records; q5 combines functional and structural
checks while remaining authority false; q6 records terminal resource admission
while remaining authority false. Only the external controller, after a fresh
complete provider reread, may return a nonserialized ephemeral dispatch
capability. No module on an earlier branch exposes a formal-artifact issuer.

## P2 component decomposition and OutputPlan

| Proof obligation | Frozen implementation seam | Registered checks |
|---|---|---|
| Complete component construction and embedding | `route_a_strategy.initialize_route_a_candidate`, state advances, `route_a_native_case._bundle_views` and direct oracle | candidate/evaluation/native-case tests compare direct logical state and component views |
| Unique physical lanes and in-range logical mappings | `output_plan._validate` | duplicate share, duplicate slot, out-of-range and empty-share negatives in `tests/test_output_plan.py` |
| Overlap summation and disjoint concatenation | `plaintext_oracle.reconstruct_output`, `output_plan.analyze_output_plan` | overlap, partial-overlap and disjoint-block tests |
| Implicit zeros | `plaintext_oracle.reconstruct_output` initializes the complete logical vector to zero | all-zero/implicit-zero OutputPlan tests |
| Direct-product oracle equality | `plaintext_oracle.direct_spmv`, `execute_cloud_plan`, `reconstruct_output`; native direct-oracle object in `route_a_native_case` | ordinary/strong execution tests and native q3/q4 guard equality |

The Cloud-facing plan contains only public program structure and opaque result
identities. The private RowMap/OutputPlan route stays in Client A/Client B and
the private validator boundary, matching the proof's privacy qualifier.

## P3 F1-M masks and durable lifecycle

`output_plan.prepare_f1m_masks` derives contributors in canonical logical and
share order, calls `ledger.reserve_all` before the first `secrets.randbelow`,
samples exactly `g-1` values for an overlap group, and constructs the final
negative sum modulo `t`. Size-zero/one groups are skipped. Ordinary and strong
preparation convert these masks to typed random-zero-sum operands; encrypted
zero dummies remain a separate kind and are checked to contain only zeros.

`mask_ledger.SQLiteMaskBindingLedger` supplies the durable state transitions:

- `reserve_all` uses one transaction and a unique five-field binding;
- `commit_prepared_f1m` issues one token and stores exact batch commitments;
- `verify_and_consume_prepared_f1m` atomically compares and consumes once;
- `verify_consumed_prepared_f1m` is read-only replay verification;
- read-only replay closure checks exact expected batches/commitments and SQLite
  foreign-key integrity, rejecting missing, extra, duplicated, orphan, or
  unconsumed rows.

`tests/test_output_plan.py`, `tests/test_ordinary_query_lifecycle.py`, strong
execution tests, native replay tests, and ledger-closure regression cases cover
reserve-before-randomness, restart persistence, all five identity fields,
commitment mismatch, duplicate consumption, orphan records, and read-only
replay. `route_a_contract.RouteAEvaluationLane` includes
`unit_attempt_ordinal`; its digest feeds the query/lane identity used by the
reservation key, separating the sole permitted provider replacement.

## P4 fixed-segment path

`strong_packed_coo.initialize_segmented_delta` freezes a power-of-two segment
width and `advance_segmented_delta` allocates row-owned canonical segments,
zero-pads their suffix, and gives each segment a physical ordinal, page and
leader slot. `_assert_state_invariants` enforces exact width, alignment, one-row
ownership, bounds, and uniqueness of active coordinates.

`strong_packed_coo.post_aggregation_output_shares` exposes only the segment
leader slot and owner row to the private OutputPlan. The Cloud program built by
the strong execution/compiler path performs the fixed rotate-and-add reduction;
`strong_execution` binds its program digest, private route and OutputPlan before
authorization. `plaintext_oracle.execute_cloud_plan` and
`reconstruct_output` provide the direct reference path. Strong packed-COO state,
witness, OutputPlan, whole-query, OpenFHE runner, native case and native guard
tests cover 127/128/129 entries, multiple row-owned segments, tombstone/padding,
overlap, and direct-oracle equality.

## Freeze and claim disposition

The S1 inventory must include this record, the proof document, all imported
behavior modules, registered tests, workflows, scripts, dependency lock files,
the machine plan and preregistration. S2 may add only the independently reviewed
registration anchor. Any source/path/mode/blob drift selects Route C unless a
new S1 is frozen and reviewed from the beginning.

The qualification Behavior Set therefore registers every `test_route_a_*.py`
module, the native-qualification CLI regression, and the core CSSC, compiler,
OutputPlan, reconstruction, and strong-segment proof-boundary tests. The
control-registration role separately freezes the in-memory terminal provider,
GitHub adapter, lineage, and live stop-loss tests. A recursive AST gate rejects
any registered Python file whose in-repository `dynamic_cssc` import—including
package `__init__.py` execution—is absent from that role's exact path set.

This mapping closes the source side of the P1--P4 proof obligation only when
the exact S1 Behavior Set captures it without omissions. It does not authorize
the qualification run or formal campaign, and it does not change the permanent
non-claims in the preregistration.
