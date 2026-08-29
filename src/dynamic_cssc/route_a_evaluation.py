"""Direct synthetic Route A cell execution with split private/public bindings.

The evaluator owns one candidate state, one crash-persistent F1-M ledger, and
every directly executed query in a cell.  Exact private preparation and ledger
bytes may cross only the short-lived, authority-false replay boundary; formal
receipts and final cells expose canonical redacted identities and digests only.
"""

from __future__ import annotations

import hashlib
import json
import resource
import stat
import sys
import time
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.metrics import StrategyMetrics
from dynamic_cssc.ordinary_query_lifecycle import (
    execute_ordinary_query_lifecycle,
    replay_ordinary_query_lifecycle,
)
from dynamic_cssc.plaintext_oracle import direct_spmv
from dynamic_cssc.route_a_contract import (
    RouteAEvaluationLane,
    RouteAQueryVectorDomain,
    generate_route_a_query_vector,
)
from dynamic_cssc.route_a_results import (
    ROUTE_A_CELL_SCHEMA,
    ROUTE_A_MACHINE_PLAN_SHA256,
    RouteACanonicalStrategyCell,
    canonical_route_a_document,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_schedule import compile_route_a_window_trace
from dynamic_cssc.route_a_serialized_bytes import (
    ROUTE_A_SERIALIZED_CATEGORIES,
    account_route_a_serialized_bytes,
)
from dynamic_cssc.route_a_strategy import (
    ROUTE_A_STRATEGY_CANDIDATES,
    advance_route_a_candidate_timed,
    initialize_route_a_candidate,
)
from dynamic_cssc.route_a_workloads import (
    RouteASyntheticTrace,
    validate_route_a_synthetic_trace,
)
from dynamic_cssc.simulator import (
    account_strong_transition_with_bundle,
    account_transition_with_compiled,
)
from dynamic_cssc.strategy_state import StrongTransition, Transition
from dynamic_cssc.strong_execution import (
    execute_strong_query_lifecycle,
    replay_strong_query_lifecycle,
)

__all__ = (
    "RouteAEvaluationError",
    "RouteASyntheticCellRun",
    "evaluate_route_a_synthetic_cell",
    "replay_route_a_synthetic_cell_read_only",
    "route_a_evidence_stream_root",
)

_MODULUS = 65_537
_DIRECT_RHOS = frozenset({Fraction(1, 100), Fraction(1, 10), Fraction(1)})
_PRIMITIVE_FIELDS = (
    "update_encryptions",
    "update_ciphertexts",
    "compaction_ciphertexts",
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "relinearizations",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_dummy_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
    "ci_patch_entries",
    "ci_full_sync_entries",
    "metadata_units",
    "overflow_updates",
    "absorbed_updates",
)


class RouteAEvaluationError(ValueError):
    """One direct Route A cell failed its source, lifecycle, or oracle contract."""


def route_a_evidence_stream_root(schema: str, documents: tuple[bytes, ...]) -> str:
    """Hash one ordered, length-framed public evidence stream."""

    if type(schema) is not str or not schema or not schema.isascii():
        raise RouteAEvaluationError("evidence stream schema must be nonempty ASCII")
    if type(documents) is not tuple or any(type(document) is not bytes for document in documents):
        raise RouteAEvaluationError("evidence stream must be an exact tuple of bytes")
    digest = hashlib.sha256()
    schema_bytes = schema.encode("ascii")
    digest.update(len(schema_bytes).to_bytes(8, "big"))
    digest.update(schema_bytes)
    digest.update(len(documents).to_bytes(8, "big"))
    for document in documents:
        digest.update(len(document).to_bytes(8, "big"))
        digest.update(document)
    return digest.hexdigest()


def _output_sha256(values: tuple[int, ...]) -> str:
    return hashlib.sha256(
        canonical_route_a_document(
            {
                "ordered_modular_outputs": list(values),
                "schema_version": "dynamic-cssc-route-a-typed-output-v1",
            }
        )
    ).hexdigest()


def _seconds(nanoseconds: int) -> str:
    if type(nanoseconds) is not int or nanoseconds < 0:
        raise RouteAEvaluationError("timing observation must be nonnegative nanoseconds")
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    return f"{seconds}.{remainder:09d}"


def _rho_string(rho: Fraction) -> str:
    return str(rho.numerator) if rho.denominator == 1 else f"{rho.numerator}/{rho.denominator}"


def _scratch_bytes(root: Path) -> int:
    total = 0
    for path in root.iterdir():
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode):
            raise RouteAEvaluationError("controlled scratch contains a non-regular member")
        total += status.st_blocks * 512
    return total


def _peak_rss_kib() -> int:
    observed = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return observed // 1024 if sys.platform == "darwin" else observed


@dataclass(frozen=True, slots=True)
class RouteASyntheticCellRun:
    """One cell plus redacted evidence and short-lived private replay material."""

    cell: RouteACanonicalStrategyCell
    window_trace_bytes: bytes
    window_trace_sha256: str
    query_identity_documents: tuple[bytes, ...]
    preparation_digest_documents: tuple[bytes, ...]
    consumption_receipt_documents: tuple[bytes, ...]
    output_digest_documents: tuple[bytes, ...]
    private_preparation_documents: tuple[bytes, ...]
    ledger_snapshot_bytes: bytes
    ledger_snapshot_sha256: str
    scratch_high_water_bytes: int

    def __post_init__(self) -> None:
        if hashlib.sha256(self.window_trace_bytes).hexdigest() != self.window_trace_sha256:
            raise RouteAEvaluationError("window trace digest does not match its exact bytes")
        bindings = self.cell.document["bindings"]
        expected = {
            "query_id_root": route_a_evidence_stream_root(
                "dynamic-cssc-route-a-query-identity-stream-v1",
                self.query_identity_documents,
            ),
            "prepared_query_root": route_a_evidence_stream_root(
                "dynamic-cssc-route-a-preparation-digest-stream-v1",
                self.preparation_digest_documents,
            ),
            "ledger_root": route_a_evidence_stream_root(
                "dynamic-cssc-route-a-consumption-receipt-stream-v1",
                self.consumption_receipt_documents,
            ),
        }
        if any(bindings[field] != value for field, value in expected.items()):
            raise RouteAEvaluationError("cell binding root differs from its redacted stream")
        query_count = self.cell.document["counts"]["queries"]
        recorded_scratch = self.cell.document["measurements"]["scratch_allocated_bytes"]
        if (
            any(
                len(stream) != query_count
                for stream in (
                    self.query_identity_documents,
                    self.preparation_digest_documents,
                    self.consumption_receipt_documents,
                    self.output_digest_documents,
                    self.private_preparation_documents,
                )
            )
            or type(self.ledger_snapshot_bytes) is not bytes
            or not self.ledger_snapshot_bytes.startswith(b"SQLite format 3\x00")
            or type(self.ledger_snapshot_sha256) is not str
            or hashlib.sha256(self.ledger_snapshot_bytes).hexdigest() != self.ledger_snapshot_sha256
            or type(self.scratch_high_water_bytes) is not int
            or self.scratch_high_water_bytes < 0
            or recorded_scratch != self.scratch_high_water_bytes
        ):
            raise RouteAEvaluationError("Route A replay material does not close the cell")
        for ordinal, private_bytes in enumerate(self.private_preparation_documents):
            try:
                private_document = json.loads(private_bytes.decode("ascii"))
                preparation_document = json.loads(
                    self.preparation_digest_documents[ordinal].decode("ascii")
                )
                receipt_document = json.loads(
                    self.consumption_receipt_documents[ordinal].decode("ascii")
                )
                query_document = json.loads(self.query_identity_documents[ordinal].decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise RouteAEvaluationError(
                    "Route A replay material is not canonical JSON"
                ) from error
            canonical_private = json.dumps(
                private_document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            query_id = hashlib.sha256(self.query_identity_documents[ordinal]).hexdigest()
            if (
                type(private_document) is not dict
                or canonical_private != private_bytes
                or private_document.get("query_id") != query_id
                or private_document.get("ledger_commitment_token")
                != receipt_document.get("ledger_commitment_token")
                or hashlib.sha256(private_bytes).hexdigest()
                != preparation_document.get("query_preparation_sha256")
                or preparation_document.get("query_id") != query_id
                or receipt_document.get("query_id") != query_id
                or query_document.get("global_query_ordinal") != ordinal
            ):
                raise RouteAEvaluationError(
                    "private preparation order or binding differs from redacted evidence"
                )


def _query_domain(trace: RouteASyntheticTrace) -> RouteAQueryVectorDomain:
    if trace.suite_role == "qualification":
        return RouteAQueryVectorDomain.qualification_synthetic(
            scale=trace.scale,
            qualification_seed=trace.formal_seed,
        )
    return RouteAQueryVectorDomain.formal_synthetic(
        scale=trace.scale,
        formal_seed=trace.formal_seed,
    )


def _evaluate_route_a_synthetic_cell(
    trace: RouteASyntheticTrace,
    *,
    strategy_candidate_id: str,
    rho: Fraction,
    shard_identity_sha256: str,
    unit_attempt_ordinal: int,
    machine_plan_bytes: bytes,
    scratch_directory: Path,
    replay_preparation_documents: tuple[bytes, ...] | None,
    replay_ledger_snapshot_bytes: bytes | None,
) -> RouteASyntheticCellRun:
    """Execute every direct query in one exact synthetic strategy cell."""

    trace = validate_route_a_synthetic_trace(trace)
    if strategy_candidate_id not in ROUTE_A_STRATEGY_CANDIDATES:
        raise RouteAEvaluationError("strategy candidate is not preregistered")
    if type(rho) is not Fraction or rho not in _DIRECT_RHOS:
        raise RouteAEvaluationError("direct synthetic rho is not preregistered")
    if (
        type(machine_plan_bytes) is not bytes
        or hashlib.sha256(machine_plan_bytes).hexdigest() != ROUTE_A_MACHINE_PLAN_SHA256
    ):
        raise RouteAEvaluationError("machine plan bytes do not match the frozen digest")
    if not isinstance(scratch_directory, Path):
        raise TypeError("scratch_directory must be a pathlib.Path")
    try:
        root_status = scratch_directory.lstat()
    except OSError as error:
        raise RouteAEvaluationError("controlled scratch directory is unavailable") from error
    if (
        scratch_directory.is_symlink()
        or not stat.S_ISDIR(root_status.st_mode)
        or any(scratch_directory.iterdir())
    ):
        raise RouteAEvaluationError("controlled scratch must be one empty direct directory")

    window_trace = compile_route_a_window_trace(
        trace.accepted_groups,
        source_event_trace_sha256=trace.event_trace_sha256,
        shard_identity_sha256=shard_identity_sha256,
        rho=rho,
        freshness=Fraction(1),
    )
    vector = generate_route_a_query_vector(_query_domain(trace))
    lane = RouteAEvaluationLane.simulator(
        shard_identity_sha256=shard_identity_sha256,
        strategy_candidate_id=strategy_candidate_id,
        rho=rho,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    candidate = initialize_route_a_candidate(
        strategy_candidate_id,
        trace.initial_state(),
        rows=trace.rows,
    )
    replay_mode = replay_preparation_documents is not None
    if replay_mode != (replay_ledger_snapshot_bytes is not None):
        raise RouteAEvaluationError(
            "read-only replay requires both exact preparations and ledger bytes"
        )
    ledger_path = scratch_directory / "mask-ledger.sqlite3"
    if replay_mode:
        if (
            type(replay_preparation_documents) is not tuple
            or any(type(document) is not bytes for document in replay_preparation_documents)
            or type(replay_ledger_snapshot_bytes) is not bytes
            or not replay_ledger_snapshot_bytes.startswith(b"SQLite format 3\x00")
        ):
            raise RouteAEvaluationError("read-only replay material has an invalid exact type")
        ledger_path.write_bytes(replay_ledger_snapshot_bytes)
        if ledger_path.read_bytes() != replay_ledger_snapshot_bytes:
            raise RouteAEvaluationError("read-only replay ledger installation changed bytes")
        ledger = SQLiteMaskBindingLedger.open_existing_read_only(ledger_path)
    else:
        ledger = SQLiteMaskBindingLedger(ledger_path)
    scratch_high_water = _scratch_bytes(scratch_directory)
    metrics = StrategyMetrics(
        strategy=strategy_candidate_id,
        category="reference",
        source="persistent-state-predicted",
    )
    rotations: Counter[int] = Counter()
    required_rotation_indices: set[int] = set()
    transition_nanoseconds = 0
    result_nanoseconds = 0
    accepted_set_transitions = 0
    query_identity_documents: list[bytes] = []
    preparation_digest_documents: list[bytes] = []
    consumption_receipt_documents: list[bytes] = []
    output_digest_documents: list[bytes] = []
    private_preparation_documents: list[bytes] = []
    replay_preparation_ordinal = 0
    commitment_tokens: list[str] = []
    reservation_bindings: list[tuple[str, str, str, str, str]] = []
    ci_metadata_documents: list[bytes] = []
    update_metadata_documents: list[bytes] = []
    query_metadata_documents: list[bytes] = []

    for window in window_trace.ordered_windows:
        timed = advance_route_a_candidate_timed(
            candidate,
            trace.accepted_groups,
            window,
        )
        advanced = timed.advance
        candidate = advanced.candidate
        transition_nanoseconds += timed.state_transition_nanoseconds
        result_nanoseconds += timed.result_assembly_nanoseconds
        accepted_set_transitions += advanced.adapted_window.accepted_set_transition_count
        scratch_high_water = max(scratch_high_water, _scratch_bytes(scratch_directory))

        result_followup_started = time.perf_counter_ns()
        transition = advanced.transition
        if type(transition) is StrongTransition:
            accounting, execution_bundle = account_strong_transition_with_bundle(transition)
            ordinary_compiled = None
        elif type(transition) is Transition:
            accounting, compiled = account_transition_with_compiled(transition)
            execution_bundle = None
            ordinary_compiled = compiled
        else:  # pragma: no cover - Route A candidate union is closed
            raise AssertionError("Route A transition changed exact type")
        metrics.merge(accounting.metrics)
        if accounting.metrics.queries:
            required_rotation_indices.update(dict(accounting.rotations_per_query))
            rotations.update(
                {
                    index: count * accounting.metrics.queries
                    for index, count in accounting.rotations_per_query
                }
            )
        if accounting.metrics.ci_patch_entries or accounting.metrics.ci_full_sync_entries:
            ci_metadata_documents.append(
                canonical_route_a_document(
                    {
                        "ci_full_sync_entries": accounting.metrics.ci_full_sync_entries,
                        "ci_patch_entries": accounting.metrics.ci_patch_entries,
                        "schema_version": "dynamic-cssc-route-a-ci-synchronization-v1",
                        "strategy_candidate_id": strategy_candidate_id,
                        "version_id": transition.state.version_id,
                        "window_ordinal": window.window_ordinal,
                    }
                )
            )
        if window.version_after != window.version_before:
            update_metadata_documents.append(
                canonical_route_a_document(
                    {
                        "active_component_ids": list(transition.facts.active_component_ids),
                        "schema_version": "dynamic-cssc-route-a-update-version-plan-v1",
                        "strategy_candidate_id": strategy_candidate_id,
                        "version_after": window.version_after,
                        "version_before": window.version_before,
                        "window_ordinal": window.window_ordinal,
                    }
                )
            )

        if window.query_count == 0:
            result_nanoseconds += time.perf_counter_ns() - result_followup_started
            continue
        if accounting.query_plan is None or window.first_global_query_ordinal_or_null is None:
            raise RouteAEvaluationError("query-bearing window lacks its exact query plan")
        plan = accounting.query_plan
        for offset in range(window.query_count):
            query_identity = lane.query_identity(window.first_global_query_ordinal_or_null + offset)
            query_identity_documents.append(query_identity.document_bytes)
            if ordinary_compiled is not None:
                if replay_mode:
                    assert replay_preparation_documents is not None
                    if replay_preparation_ordinal >= len(replay_preparation_documents):
                        raise RouteAEvaluationError(
                            "read-only replay preparation stream is truncated"
                        )
                    preparation_bytes = replay_preparation_documents[replay_preparation_ordinal]
                    lifecycle = replay_ordinary_query_lifecycle(
                        ordinary_compiled,
                        preparation_bytes,
                        expected_query_id=query_identity.query_id,
                        expected_vector=vector.values,
                        modulus=_MODULUS,
                        ledger=ledger,
                    )
                else:
                    lifecycle = execute_ordinary_query_lifecycle(
                        ordinary_compiled,
                        query_id=query_identity.query_id,
                        vector=vector.values,
                        modulus=_MODULUS,
                        ledger=ledger,
                    )
                    scratch_high_water = max(
                        scratch_high_water,
                        _scratch_bytes(scratch_directory),
                    )
                prepared = lifecycle.prepared
                preparation_bytes = lifecycle.preparation_bytes
                typed_output = lifecycle.output
            elif execution_bundle is not None:
                if replay_mode:
                    assert replay_preparation_documents is not None
                    if replay_preparation_ordinal >= len(replay_preparation_documents):
                        raise RouteAEvaluationError(
                            "read-only replay preparation stream is truncated"
                        )
                    preparation_bytes = replay_preparation_documents[replay_preparation_ordinal]
                    lifecycle = replay_strong_query_lifecycle(
                        execution_bundle,
                        preparation_bytes,
                        expected_query_id=query_identity.query_id,
                        expected_vector=vector.values,
                        modulus=_MODULUS,
                        ledger=ledger,
                    )
                else:
                    lifecycle = execute_strong_query_lifecycle(
                        execution_bundle,
                        query_id=query_identity.query_id,
                        vector=vector.values,
                        modulus=_MODULUS,
                        ledger=ledger,
                    )
                    scratch_high_water = max(
                        scratch_high_water,
                        _scratch_bytes(scratch_directory),
                    )
                prepared = lifecycle.prepared
                preparation_bytes = lifecycle.preparation_bytes
                typed_output = lifecycle.output
            else:  # pragma: no cover - query plan and bundle are constructed together
                raise AssertionError("query-bearing transition lacks an execution bundle")
            direct_output = direct_spmv(
                candidate.state.logical,
                vector.values,
                rows=trace.rows,
                cols=trace.columns,
                modulus=_MODULUS,
            )
            if typed_output != direct_output:
                raise RouteAEvaluationError("typed query output differs from direct Ax mod t")
            preparation_sha256 = hashlib.sha256(preparation_bytes).hexdigest()
            private_preparation_documents.append(preparation_bytes)
            replay_preparation_ordinal += 1
            commitment_tokens.append(prepared.ledger_commitment_token)
            reservation_bindings.extend(
                operand.binding
                for operand in prepared.f1m_operands
                if operand.kind == "random-zero-sum"
            )
            typed_output_sha256 = _output_sha256(typed_output)
            direct_output_sha256 = _output_sha256(direct_output)
            preparation_digest_documents.append(
                canonical_route_a_document(
                    {
                        "execution_binding_digest": plan.execution_binding_digest,
                        "query_id": query_identity.query_id,
                        "query_preparation_sha256": preparation_sha256,
                        "schema_version": "dynamic-cssc-route-a-preparation-digest-v1",
                        "version_id": plan.version_id,
                    }
                )
            )
            consumption_receipt_documents.append(
                canonical_route_a_document(
                    {
                        "consumed_exactly_once": True,
                        "execution_binding_digest": plan.execution_binding_digest,
                        "ledger_commitment_token": prepared.ledger_commitment_token,
                        "query_id": query_identity.query_id,
                        "query_preparation_sha256": preparation_sha256,
                        "schema_version": "dynamic-cssc-route-a-consumption-receipt-v1",
                        "version_id": plan.version_id,
                    }
                )
            )
            output_digest_documents.append(
                canonical_route_a_document(
                    {
                        "direct_output_sha256": direct_output_sha256,
                        "query_id": query_identity.query_id,
                        "schema_version": "dynamic-cssc-route-a-output-digest-v1",
                        "typed_output_sha256": typed_output_sha256,
                    }
                )
            )
            query_metadata_documents.append(
                canonical_route_a_document(
                    {
                        "cloud_program_digest": plan.cloud_program_digest,
                        "execution_binding_digest": plan.execution_binding_digest,
                        "output_plan_digest": plan.output_plan_digest,
                        "private_plan_digest": plan.private_plan_digest,
                        "query_id": query_identity.query_id,
                        "query_vector_sha256": vector.vector_sha256,
                        "schema_version": "dynamic-cssc-route-a-query-version-plan-v1",
                        "version_id": plan.version_id,
                    }
                )
            )
            scratch_high_water = max(scratch_high_water, _scratch_bytes(scratch_directory))
        result_nanoseconds += time.perf_counter_ns() - result_followup_started

    terminal_result_started = time.perf_counter_ns()
    if metrics.rotations != sum(rotations.values()):
        raise RouteAEvaluationError("rotation stream does not reconcile with primitive counts")
    expected_state = trace.initial_state()
    for group in trace.accepted_groups:
        for source_transition in group.transitions:
            coordinate = (source_transition.row, source_transition.column)
            if expected_state.get(coordinate, 0) != source_transition.before:
                raise RouteAEvaluationError("canonical source transition continuity changed")
            if source_transition.after == 0:
                expected_state.pop(coordinate, None)
            else:
                expected_state[coordinate] = source_transition.after
    if candidate.state.logical != expected_state:
        raise RouteAEvaluationError("terminal candidate state differs from source replay")
    if replay_mode:
        assert replay_preparation_documents is not None
        if replay_preparation_ordinal != len(replay_preparation_documents):
            raise RouteAEvaluationError("read-only replay preparation stream has extra records")
    ledger.verify_closed_consumed_prepared_f1m_ledger(
        commitment_tokens=tuple(commitment_tokens),
        reservation_bindings=tuple(reservation_bindings),
    )
    observed_ledger_snapshot = ledger_path.read_bytes()
    if replay_mode and observed_ledger_snapshot != replay_ledger_snapshot_bytes:
        raise RouteAEvaluationError("read-only replay mutated the exact ledger snapshot")
    ledger_snapshot_bytes = observed_ledger_snapshot
    ledger_snapshot_sha256 = hashlib.sha256(ledger_snapshot_bytes).hexdigest()
    scratch_high_water = max(scratch_high_water, _scratch_bytes(scratch_directory))

    query_identity_tuple = tuple(query_identity_documents)
    preparation_digest_tuple = tuple(preparation_digest_documents)
    consumption_receipt_tuple = tuple(consumption_receipt_documents)
    output_digest_tuple = tuple(output_digest_documents)
    multiplicities = {category: 0 for category in ROUTE_A_SERIALIZED_CATEGORIES}
    multiplicities.update(
        {
            "update-column-index-synchronization": len(ci_metadata_documents),
            "update-publication-ciphertexts": (
                metrics.update_ciphertexts + metrics.compaction_ciphertexts
            ),
            "update-version-plan-metadata": len(update_metadata_documents),
            "query-query-ciphertexts": metrics.query_ciphertexts,
            "query-result-ciphertexts": metrics.result_ciphertexts,
            "query-f1m-random-mask-ciphertexts": metrics.blinding_mask_ciphertexts,
            "query-f1m-encrypted-zero-dummy-ciphertexts": (metrics.blinding_dummy_ciphertexts),
            "query-version-plan-metadata": len(query_metadata_documents),
            "one-time-evaluation-key-material": int(metrics.queries > 0),
        }
    )
    if multiplicities["update-publication-ciphertexts"] != metrics.update_encryptions:
        raise RouteAEvaluationError("update ciphertext inventory does not close encryptions")
    serialized_bytes = account_route_a_serialized_bytes(
        multiplicities,
        emitted_metadata_documents={
            "update-column-index-synchronization": tuple(ci_metadata_documents),
            "update-version-plan-metadata": tuple(update_metadata_documents),
            "query-version-plan-metadata": tuple(query_metadata_documents),
        },
    )
    result_nanoseconds += time.perf_counter_ns() - terminal_result_started
    rho_text = _rho_string(rho)
    cell = validate_route_a_strategy_cell(
        {
            "schema_version": ROUTE_A_CELL_SCHEMA,
            "identity": {
                "formal_seed_or_null": trace.formal_seed,
                "object_sha256_or_null": None,
                "partition_or_null": None,
                "rho": rho_text,
                "scale_or_null": trace.scale,
                "semantics_or_null": None,
                "shard_identity_sha256": shard_identity_sha256,
                "source_kind": "synthetic",
                "strategy_candidate_id": strategy_candidate_id,
                "suite_role": trace.suite_role,
                "unit_attempt_ordinal": unit_attempt_ordinal,
            },
            "evaluation": {
                "mode": "directly-measured",
                "source_rho": None,
                "target_rho": rho_text,
            },
            "counts": {
                "queries": metrics.queries,
                "updates": accepted_set_transitions,
                "windows": metrics.windows,
            },
            "window_query_counts": [window.query_count for window in window_trace.ordered_windows],
            "primitive_counts": {field: getattr(metrics, field) for field in _PRIMITIVE_FIELDS},
            "rotation_inventory": {
                "measured_counts_by_exact_index": [
                    [index, count] for index, count in sorted(rotations.items())
                ],
                "required_indices": sorted(required_rotation_indices),
            },
            "serialized_object_multiplicities": multiplicities,
            "serialized_bytes": serialized_bytes,
            "measurements": {
                "native_latency_seconds": None,
                "peak_rss_kib": _peak_rss_kib(),
                "producer_result_assembly_seconds": _seconds(result_nanoseconds),
                "producer_state_transition_seconds": _seconds(transition_nanoseconds),
                "replay_seconds": None,
                "scratch_allocated_bytes": scratch_high_water,
            },
            "correctness": {
                "binding_acceptance": True,
                "claim_authority": False,
                "execution_performed": True,
                "oracle_equality": True,
                "source_rho": None,
            },
            "bindings": {
                "ledger_root": route_a_evidence_stream_root(
                    "dynamic-cssc-route-a-consumption-receipt-stream-v1",
                    consumption_receipt_tuple,
                ),
                "machine_plan_sha256": ROUTE_A_MACHINE_PLAN_SHA256,
                "prepared_query_root": route_a_evidence_stream_root(
                    "dynamic-cssc-route-a-preparation-digest-stream-v1",
                    preparation_digest_tuple,
                ),
                "query_id_root": route_a_evidence_stream_root(
                    "dynamic-cssc-route-a-query-identity-stream-v1",
                    query_identity_tuple,
                ),
                "source_rho1_document_sha256": None,
                "transform_id": None,
            },
        }
    )
    return RouteASyntheticCellRun(
        cell=cell,
        window_trace_bytes=window_trace.document_bytes,
        window_trace_sha256=window_trace.sha256,
        query_identity_documents=query_identity_tuple,
        preparation_digest_documents=preparation_digest_tuple,
        consumption_receipt_documents=consumption_receipt_tuple,
        output_digest_documents=output_digest_tuple,
        private_preparation_documents=tuple(private_preparation_documents),
        ledger_snapshot_bytes=ledger_snapshot_bytes,
        ledger_snapshot_sha256=ledger_snapshot_sha256,
        scratch_high_water_bytes=scratch_high_water,
    )


def evaluate_route_a_synthetic_cell(
    trace: RouteASyntheticTrace,
    *,
    strategy_candidate_id: str,
    rho: Fraction,
    shard_identity_sha256: str,
    unit_attempt_ordinal: int,
    machine_plan_bytes: bytes,
    scratch_directory: Path,
) -> RouteASyntheticCellRun:
    """Execute a producer cell with fresh single-use masks and a durable ledger."""

    return _evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id=strategy_candidate_id,
        rho=rho,
        shard_identity_sha256=shard_identity_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
        machine_plan_bytes=machine_plan_bytes,
        scratch_directory=scratch_directory,
        replay_preparation_documents=None,
        replay_ledger_snapshot_bytes=None,
    )


def replay_route_a_synthetic_cell_read_only(
    trace: RouteASyntheticTrace,
    *,
    strategy_candidate_id: str,
    rho: Fraction,
    shard_identity_sha256: str,
    unit_attempt_ordinal: int,
    machine_plan_bytes: bytes,
    scratch_directory: Path,
    private_preparation_documents: tuple[bytes, ...],
    ledger_snapshot_bytes: bytes,
) -> RouteASyntheticCellRun:
    """Reexecute one exact producer lane without reserving, sampling, or consuming.

    The caller owns ``scratch_directory`` and must destroy it after guard acceptance
    or after any replay/guard failure; it contains the private immutable ledger copy.
    """

    return _evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id=strategy_candidate_id,
        rho=rho,
        shard_identity_sha256=shard_identity_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
        machine_plan_bytes=machine_plan_bytes,
        scratch_directory=scratch_directory,
        replay_preparation_documents=private_preparation_documents,
        replay_ledger_snapshot_bytes=ledger_snapshot_bytes,
    )
