"""Third-process guard for private Route A handoffs and redacted outputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from dynamic_cssc.route_a_artifacts import inspect_route_a_synthetic_cell_archive
from dynamic_cssc.route_a_evaluation import (
    RouteASyntheticCellRun,
    route_a_evidence_stream_root,
)
from dynamic_cssc.route_a_replay import (
    RouteAOrderedEventCellTarget,
    RouteASyntheticCellTarget,
    inspect_route_a_synthetic_replay_archive,
)
from dynamic_cssc.route_a_results import (
    RouteACanonicalStrategyCell,
    canonical_route_a_document,
)
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)

__all__ = (
    "RouteAGuardError",
    "RouteASyntheticGuard",
    "guard_route_a_ordered_event_replay",
    "guard_route_a_synthetic_replay",
)

_DETERMINISTIC_FIELDS = (
    "schema_version",
    "identity",
    "evaluation",
    "counts",
    "window_query_counts",
    "primitive_counts",
    "rotation_inventory",
    "serialized_object_multiplicities",
    "serialized_bytes",
    "correctness",
    "bindings",
)
_REPLAY_TIMING_SCOPE = (
    "function-entry-through-inspection-rehash-read-only-ledger-verification-"
    "typed-reexecution-oracle-and-final-comparison-before-receipt-serialization"
)
_GUARD_RECEIPT_FIELDS = frozenset(
    {
        "accepted",
        "expected_target_sha256",
        "final_cell_sha256",
        "formal_authority_granted",
        "independent_replay_cell_sha256",
        "machine_plan_sha256",
        "producer_archive_sha256",
        "producer_cell_sha256",
        "publication_evidence",
        "replay_archive_sha256",
        "replay_receipt_sha256",
        "schema_version",
        "source_event_trace_sha256",
        "window_trace_sha256",
    }
)


class RouteAGuardError(ValueError):
    """A producer/replay pair cannot pass the independent Route A guard."""


def _output_root(run: RouteASyntheticCellRun) -> str:
    return route_a_evidence_stream_root(
        "dynamic-cssc-route-a-output-digest-stream-v1",
        run.output_digest_documents,
    )


@dataclass(frozen=True, slots=True)
class RouteASyntheticGuard:
    """One guarded final cell and a permanently non-authorizing receipt."""

    final_cell: RouteACanonicalStrategyCell
    receipt_bytes: bytes
    receipt_sha256: str

    def __post_init__(self) -> None:
        if hashlib.sha256(self.receipt_bytes).hexdigest() != self.receipt_sha256:
            raise RouteAGuardError("guard receipt digest differs from its bytes")
        receipt = self.receipt
        if (
            receipt.get("accepted") is not True
            or set(receipt) != _GUARD_RECEIPT_FIELDS
            or receipt.get("schema_version")
            != "dynamic-cssc-route-a-synthetic-cell-guard-receipt-v2"
            or receipt.get("formal_authority_granted") is not False
            or receipt.get("publication_evidence") is not False
            or receipt.get("final_cell_sha256") != self.final_cell.sha256
        ):
            raise RouteAGuardError("guard receipt authority or final-cell binding changed")

    @property
    def receipt(self) -> dict[str, object]:
        decoded = json.loads(self.receipt_bytes.decode("ascii"))
        if type(decoded) is not dict:
            raise RouteAGuardError("guard receipt is not one canonical object")
        return decoded


def guard_route_a_synthetic_replay(
    *,
    producer_archive_bytes: bytes,
    replay_archive_bytes: bytes,
    expected_target: RouteASyntheticCellTarget | RouteAOrderedEventCellTarget,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteASyntheticGuard:
    """Reinspect both archives and accept only their exact closed intersection."""

    if type(expected_target) not in {
        RouteASyntheticCellTarget,
        RouteAOrderedEventCellTarget,
    }:
        raise TypeError("expected_target must be one exact Route A cell target")
    expected_target._validate()
    producer_inspection = inspect_route_a_synthetic_cell_archive(
        producer_archive_bytes,
        scientific_profile=scientific_profile,
    )
    replay_inspection = inspect_route_a_synthetic_replay_archive(
        replay_archive_bytes,
        scientific_profile=scientific_profile,
    )
    producer = producer_inspection.cell_run
    replay = replay_inspection.replay
    independent = replay.replay_run
    receipt = replay.receipt
    producer_document = producer.cell.document
    independent_document = independent.cell.document
    final_document = replay.final_cell.document

    for field in _DETERMINISTIC_FIELDS:
        if field == "bindings":
            if producer_document[field] != independent_document[field]:
                raise RouteAGuardError("guard observed a stable replay binding drift")
        elif producer_document[field] != independent_document[field]:
            raise RouteAGuardError("guard observed deterministic replay drift")

    expected_final = producer.cell.document
    expected_final["measurements"]["replay_seconds"] = receipt[
        "replay_elapsed_seconds"
    ]
    if final_document != expected_final:
        raise RouteAGuardError("guarded final cell changes more than replay timing")
    window_document = json.loads(producer.window_trace_bytes.decode("ascii"))
    rho_text = (
        str(expected_target.rho.numerator)
        if expected_target.rho.denominator == 1
        else f"{expected_target.rho.numerator}/{expected_target.rho.denominator}"
    )
    if type(expected_target) is RouteASyntheticCellTarget:
        expected_identity = {
            "formal_seed_or_null": expected_target.formal_seed_or_null,
            "rho": rho_text,
            "scale_or_null": expected_target.scale_or_null,
            "shard_identity_sha256": expected_target.shard_identity_sha256,
            "strategy_candidate_id": expected_target.strategy_candidate_id,
            "suite_role": expected_target.suite_role,
            "unit_attempt_ordinal": expected_target.unit_attempt_ordinal,
        }
    else:
        expected_identity = {
            "formal_seed_or_null": None,
            "object_sha256_or_null": expected_target.raw_object_sha256,
            "partition_or_null": expected_target.partition,
            "rho": rho_text,
            "scale_or_null": None,
            "semantics_or_null": expected_target.semantics,
            "shard_identity_sha256": expected_target.shard_identity_sha256,
            "source_kind": "snap-a2q",
            "strategy_candidate_id": expected_target.strategy_candidate_id,
            "suite_role": "formal",
            "unit_attempt_ordinal": expected_target.unit_attempt_ordinal,
        }
    if (
        any(
            producer_document["identity"][field] != value
            for field, value in expected_identity.items()
        )
        or window_document.get("source_event_trace_sha256")
        != expected_target.source_event_trace_sha256
    ):
        raise RouteAGuardError("guarded pair differs from the external expected target")
    producer_bindings = producer_document["bindings"]
    replay_bindings = independent_document["bindings"]
    required_equalities = {
        "deterministic_accounting_equal": True,
        "expected_target_sha256": expected_target.sha256,
        "final_cell_sha256": replay.final_cell.sha256,
        "formal_authority_granted": False,
        "independent_oracle_equality": True,
        "independent_replay_cell_sha256": independent.cell.sha256,
        "machine_plan_sha256": producer_bindings["machine_plan_sha256"],
        "ledger_snapshot_read_only_verified": True,
        "producer_archive_sha256": producer_inspection.archive_sha256,
        "producer_cell_sha256": producer.cell.sha256,
        "producer_ledger_root": producer_bindings["ledger_root"],
        "producer_ledger_snapshot_sha256": producer.ledger_snapshot_sha256,
        "producer_output_digest_root": _output_root(producer),
        "producer_prepared_query_root": producer_bindings["prepared_query_root"],
        "publication_evidence": False,
        "replay_ledger_root": replay_bindings["ledger_root"],
        "replay_ledger_snapshot_sha256": independent.ledger_snapshot_sha256,
        "replay_output_digest_root": _output_root(independent),
        "replay_prepared_query_root": replay_bindings["prepared_query_root"],
        "replay_timing_scope": _REPLAY_TIMING_SCOPE,
        "schema_version": "dynamic-cssc-route-a-synthetic-cell-replay-receipt-v2",
        "source_event_trace_sha256": window_document["source_event_trace_sha256"],
        "window_trace_sha256": producer.window_trace_sha256,
    }
    if any(receipt.get(field) != value for field, value in required_equalities.items()):
        raise RouteAGuardError("replay receipt differs from independently observed bytes")
    if (
        producer.output_digest_documents != independent.output_digest_documents
        or producer.query_identity_documents != independent.query_identity_documents
        or producer.preparation_digest_documents
        != independent.preparation_digest_documents
        or producer.consumption_receipt_documents
        != independent.consumption_receipt_documents
        or producer.private_preparation_documents
        != independent.private_preparation_documents
        or producer.ledger_snapshot_bytes != independent.ledger_snapshot_bytes
        or producer.window_trace_bytes != independent.window_trace_bytes
    ):
        raise RouteAGuardError("guard observed a replay query or output stream drift")

    guard_receipt_bytes = canonical_route_a_document(
        {
            "accepted": True,
            "expected_target_sha256": expected_target.sha256,
            "final_cell_sha256": replay.final_cell.sha256,
            "formal_authority_granted": False,
            "independent_replay_cell_sha256": independent.cell.sha256,
            "machine_plan_sha256": producer_bindings["machine_plan_sha256"],
            "producer_archive_sha256": producer_inspection.archive_sha256,
            "producer_cell_sha256": producer.cell.sha256,
            "publication_evidence": False,
            "replay_archive_sha256": replay_inspection.archive_sha256,
            "replay_receipt_sha256": replay.receipt_sha256,
            "schema_version": "dynamic-cssc-route-a-synthetic-cell-guard-receipt-v2",
            "source_event_trace_sha256": window_document["source_event_trace_sha256"],
            "window_trace_sha256": producer.window_trace_sha256,
        }
    )
    return RouteASyntheticGuard(
        final_cell=replay.final_cell,
        receipt_bytes=guard_receipt_bytes,
        receipt_sha256=hashlib.sha256(guard_receipt_bytes).hexdigest(),
    )


def guard_route_a_ordered_event_replay(
    *,
    producer_archive_bytes: bytes,
    replay_archive_bytes: bytes,
    expected_target: RouteAOrderedEventCellTarget,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteASyntheticGuard:
    """Expose the SNAP-specific guard interface over the shared deep verifier."""

    if type(expected_target) is not RouteAOrderedEventCellTarget:
        raise TypeError("expected_target must be an exact ordered-event target")
    return guard_route_a_synthetic_replay(
        producer_archive_bytes=producer_archive_bytes,
        replay_archive_bytes=replay_archive_bytes,
        expected_target=expected_target,
        scientific_profile=scientific_profile,
    )
