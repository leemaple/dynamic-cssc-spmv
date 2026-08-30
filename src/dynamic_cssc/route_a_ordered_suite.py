"""Closed producer and independent replay packages for one SNAP ordered shard."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.route_a_artifacts import (
    inspect_route_a_synthetic_cell_archive,
    produce_route_a_synthetic_cell_archive,
)
from dynamic_cssc.route_a_evaluation import evaluate_route_a_ordered_event_cell
from dynamic_cssc.route_a_guard import guard_route_a_ordered_event_replay
from dynamic_cssc.route_a_replay import (
    RouteAOrderedEventCellTarget,
    produce_route_a_synthetic_replay_archive,
    replay_route_a_ordered_event_cell,
)
from dynamic_cssc.route_a_results import (
    RouteACanonicalStrategyCell,
    canonical_route_a_document,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)
from dynamic_cssc.route_a_snap import (
    RouteASnapTrace,
    route_a_snap_shard_identity,
    validate_route_a_snap_trace,
)
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    _read_archive,
    _require_empty_scratch,
    _sha256_file,
    _write_archive,
)

__all__ = (
    "RouteAOrderedSuiteError",
    "RouteAOrderedSuiteProducerInspection",
    "RouteAOrderedSuiteReplayInspection",
    "inspect_route_a_ordered_suite_handoff",
    "inspect_route_a_ordered_suite_replay",
    "produce_route_a_ordered_suite_handoff",
    "replay_and_guard_route_a_ordered_suite",
)

_PRODUCER_SCHEMA = "dynamic-cssc-route-a-ordered-event-suite-handoff-v1"
_REPLAY_SCHEMA = "dynamic-cssc-route-a-ordered-event-suite-replay-v1"
_DIRECT_RHOS = (Fraction(1, 10), Fraction(1))
_STRATEGIES = ROUTE_A_STRATEGY_CANDIDATES


class RouteAOrderedSuiteError(ValueError):
    """An ordered-event suite package is open or internally inconsistent."""


def _rho_text(rho: Fraction) -> str:
    return str(rho.numerator) if rho.denominator == 1 else f"{rho.numerator}/{rho.denominator}"


def _cell_stem(strategy_ordinal: int, rho: Fraction) -> str:
    return f"strategy-{strategy_ordinal:02d}-rho-{rho.numerator}d{rho.denominator}"


def _producer_paths() -> tuple[str, ...]:
    paths = [
        "lineage.json",
        "source-mapping.json",
        "source-accepted-trace.json",
        "source-initial-state.json",
        "source-trace.json",
    ]
    for strategy_ordinal, _strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            paths.append(f"cells/{_cell_stem(strategy_ordinal, rho)}.zip")
    paths.append("manifest.json")
    return tuple(paths)


def _replay_paths() -> tuple[str, ...]:
    paths = [
        "lineage.json",
        "source-mapping.json",
        "source-accepted-trace.json",
        "source-trace.json",
    ]
    for strategy_ordinal, _strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            stem = _cell_stem(strategy_ordinal, rho)
            paths.extend(
                (
                    f"cells/{stem}/final-cell.json",
                    f"cells/{stem}/replay-receipt.json",
                    f"cells/{stem}/guard-receipt.json",
                )
            )
    paths.append("manifest.json")
    return tuple(paths)


def _shard(
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    *,
    unit_attempt_ordinal: int,
) -> str:
    if type(unit_attempt_ordinal) is not int or unit_attempt_ordinal not in {0, 1}:
        raise RouteAOrderedSuiteError(
            "ordered suite attempt is outside the inherited retry domain"
        )
    return route_a_snap_shard_identity(
        trace,
        experiment_source_sha=lineage.experiment_source_sha,
        workflow_head_sha=lineage.workflow_head_sha,
        compatibility_receipt_sha256=lineage.compatibility_receipt_sha256,
        provider_run_id=lineage.provider_run_id,
        provider_run_attempt=lineage.provider_run_attempt,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )


def _manifest(
    *,
    schema: str,
    role: str,
    lineage: RouteASyntheticSuiteLineage,
    trace: RouteASnapTrace,
    shard_identity_sha256: str,
    members: tuple[tuple[str, bytes], ...],
) -> bytes:
    return canonical_route_a_document(
        {
            "accepted_trace_sha256": trace.accepted_trace_sha256,
            "authority_granted": False,
            "direct_cell_count": len(_STRATEGIES) * len(_DIRECT_RHOS),
            "formal_evidence": False,
            "lineage_sha256": lineage.sha256,
            "mapping_sha256": trace.mapping_sha256,
            "members": [
                {
                    "byte_count": len(content),
                    "path": path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for path, content in members
            ],
            "package_role": role,
            "partition": trace.partition,
            "private_replay_material_included": role == "private-pre-replay-NON-EVIDENCE",
            "projected_cell_count": 0,
            "raw_object_sha256": trace.raw_object_sha256,
            "retention_days": 1,
            "schema_version": schema,
            "semantics": trace.semantics,
            "shard_identity_sha256": shard_identity_sha256,
            "source_event_trace_sha256": trace.event_trace_sha256,
        }
    )


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    try:
        document = json.loads(content.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAOrderedSuiteError(f"{label} is not ASCII JSON") from error
    if type(document) is not dict or canonical_route_a_document(document) != content:
        raise RouteAOrderedSuiteError(f"{label} is not one canonical object")
    return document


@dataclass(frozen=True, slots=True)
class RouteAOrderedSuiteProducerInspection:
    lineage: RouteASyntheticSuiteLineage
    shard_identity_sha256: str
    cell_archives: tuple[tuple[str, Fraction, bytes], ...]
    archive_sha256: str


@dataclass(frozen=True, slots=True)
class RouteAOrderedSuiteReplayInspection:
    lineage: RouteASyntheticSuiteLineage
    shard_identity_sha256: str
    final_cells: tuple[RouteACanonicalStrategyCell, ...]
    replay_receipts: tuple[bytes, ...]
    guard_receipts: tuple[bytes, ...]
    archive_sha256: str


def produce_route_a_ordered_suite_handoff(
    trace: RouteASnapTrace,
    *,
    lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    scratch_root: Path,
    output_path: Path,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> None:
    """Execute the six direct strategy/rho cells and retain private replay bytes."""

    trace = validate_route_a_snap_trace(trace)
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be one exact RouteASyntheticSuiteLineage")
    try:
        scientific_profile.require_machine_plan_bytes(machine_plan_bytes)
    except (TypeError, ValueError) as error:
        raise RouteAOrderedSuiteError("ordered suite machine plan changed") from error
    _require_empty_scratch(scratch_root)
    shard = _shard(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    members: list[tuple[str, bytes]] = [
        ("lineage.json", lineage.document_bytes),
        ("source-mapping.json", trace.mapping_bytes),
        ("source-accepted-trace.json", trace.accepted_trace_bytes),
        ("source-initial-state.json", trace.initial_state_bytes),
        ("source-trace.json", trace.event_trace_bytes),
    ]
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            scratch = scratch_root / _cell_stem(strategy_ordinal, rho)
            scratch.mkdir(mode=0o700)
            try:
                run = evaluate_route_a_ordered_event_cell(
                    trace,
                    strategy_candidate_id=strategy,
                    rho=rho,
                    shard_identity_sha256=shard,
                    unit_attempt_ordinal=unit_attempt_ordinal,
                    machine_plan_bytes=machine_plan_bytes,
                    scratch_directory=scratch,
                    scientific_profile=scientific_profile,
                )
                members.append(
                    (
                        f"cells/{_cell_stem(strategy_ordinal, rho)}.zip",
                        produce_route_a_synthetic_cell_archive(run),
                    )
                )
            finally:
                shutil.rmtree(scratch)
    members.append(
        (
            "manifest.json",
            _manifest(
                schema=_PRODUCER_SCHEMA,
                role="private-pre-replay-NON-EVIDENCE",
                lineage=lineage,
                trace=trace,
                shard_identity_sha256=shard,
                members=tuple(members),
            ),
        )
    )
    if tuple(path for path, _content in members) != _producer_paths():
        raise AssertionError("ordered producer suite path order changed")
    _write_archive(output_path, tuple(members))


def inspect_route_a_ordered_suite_handoff(
    archive_path: Path,
    *,
    expected_trace: RouteASnapTrace,
    expected_lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteAOrderedSuiteProducerInspection:
    """Rehash and close one complete private ordered producer suite."""

    trace = validate_route_a_snap_trace(expected_trace)
    scientific_profile.require_machine_plan_bytes(machine_plan_bytes)
    members = _read_archive(archive_path, expected_paths=_producer_paths())
    lineage = RouteASyntheticSuiteLineage.from_bytes(members["lineage.json"])
    if (
        lineage != expected_lineage
        or members["source-mapping.json"] != trace.mapping_bytes
        or members["source-accepted-trace.json"] != trace.accepted_trace_bytes
        or members["source-initial-state.json"] != trace.initial_state_bytes
        or members["source-trace.json"] != trace.event_trace_bytes
    ):
        raise RouteAOrderedSuiteError("ordered producer source or lineage changed")
    shard = _shard(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    cell_archives: list[tuple[str, Fraction, bytes]] = []
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            content = members[f"cells/{_cell_stem(strategy_ordinal, rho)}.zip"]
            inspection = inspect_route_a_synthetic_cell_archive(
                content,
                scientific_profile=scientific_profile,
            )
            target = RouteAOrderedEventCellTarget.for_snap_trace(
                trace,
                strategy_candidate_id=strategy,
                rho=rho,
                shard_identity_sha256=shard,
                unit_attempt_ordinal=unit_attempt_ordinal,
            )
            identity = inspection.cell_run.cell.document["identity"]
            if (
                identity["strategy_candidate_id"] != strategy
                or identity["rho"] != _rho_text(rho)
                or identity["shard_identity_sha256"] != shard
                or target.sha256
                != RouteAOrderedEventCellTarget.for_snap_trace(
                    trace,
                    strategy_candidate_id=identity["strategy_candidate_id"],
                    rho=rho,
                    shard_identity_sha256=identity["shard_identity_sha256"],
                    unit_attempt_ordinal=identity["unit_attempt_ordinal"],
                ).sha256
            ):
                raise RouteAOrderedSuiteError("ordered producer cell identity changed")
            cell_archives.append((strategy, rho, content))
    payload = tuple(
        (path, members[path]) for path in _producer_paths() if path != "manifest.json"
    )
    if members["manifest.json"] != _manifest(
        schema=_PRODUCER_SCHEMA,
        role="private-pre-replay-NON-EVIDENCE",
        lineage=lineage,
        trace=trace,
        shard_identity_sha256=shard,
        members=payload,
    ):
        raise RouteAOrderedSuiteError("ordered producer manifest changed")
    return RouteAOrderedSuiteProducerInspection(
        lineage=lineage,
        shard_identity_sha256=shard,
        cell_archives=tuple(cell_archives),
        archive_sha256=_sha256_file(archive_path),
    )


def replay_and_guard_route_a_ordered_suite(
    trace: RouteASnapTrace,
    *,
    lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    producer_archive_path: Path,
    scratch_root: Path,
    output_path: Path,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> None:
    """Replay all six cells read-only, guard them, and discard private bytes."""

    trace = validate_route_a_snap_trace(trace)
    _require_empty_scratch(scratch_root)
    producer = inspect_route_a_ordered_suite_handoff(
        producer_archive_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=machine_plan_bytes,
        unit_attempt_ordinal=unit_attempt_ordinal,
        scientific_profile=scientific_profile,
    )
    archives = {
        (strategy, rho): content for strategy, rho, content in producer.cell_archives
    }
    members: list[tuple[str, bytes]] = [
        ("lineage.json", lineage.document_bytes),
        ("source-mapping.json", trace.mapping_bytes),
        ("source-accepted-trace.json", trace.accepted_trace_bytes),
        ("source-trace.json", trace.event_trace_bytes),
    ]
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            stem = _cell_stem(strategy_ordinal, rho)
            scratch = scratch_root / stem
            scratch.mkdir(mode=0o700)
            try:
                target = RouteAOrderedEventCellTarget.for_snap_trace(
                    trace,
                    strategy_candidate_id=strategy,
                    rho=rho,
                    shard_identity_sha256=producer.shard_identity_sha256,
                    unit_attempt_ordinal=unit_attempt_ordinal,
                )
                replay = replay_route_a_ordered_event_cell(
                    trace,
                    archive_bytes=archives[(strategy, rho)],
                    expected_target=target,
                    machine_plan_bytes=machine_plan_bytes,
                    scratch_directory=scratch,
                    scientific_profile=scientific_profile,
                )
                replay_archive = produce_route_a_synthetic_replay_archive(replay)
                guard = guard_route_a_ordered_event_replay(
                    producer_archive_bytes=archives[(strategy, rho)],
                    replay_archive_bytes=replay_archive,
                    expected_target=target,
                    scientific_profile=scientific_profile,
                )
                members.extend(
                    (
                        (f"cells/{stem}/final-cell.json", guard.final_cell.document_bytes),
                        (f"cells/{stem}/replay-receipt.json", replay.receipt_bytes),
                        (f"cells/{stem}/guard-receipt.json", guard.receipt_bytes),
                    )
                )
            finally:
                shutil.rmtree(scratch)
    members.append(
        (
            "manifest.json",
            _manifest(
                schema=_REPLAY_SCHEMA,
                role="redacted-post-replay-NON-EVIDENCE",
                lineage=lineage,
                trace=trace,
                shard_identity_sha256=producer.shard_identity_sha256,
                members=tuple(members),
            ),
        )
    )
    if tuple(path for path, _content in members) != _replay_paths():
        raise AssertionError("ordered replay suite path order changed")
    _write_archive(output_path, tuple(members))


def inspect_route_a_ordered_suite_replay(
    archive_path: Path,
    *,
    expected_trace: RouteASnapTrace,
    expected_lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteAOrderedSuiteReplayInspection:
    """Reinspect one redacted ordered result without accepting private bytes."""

    trace = validate_route_a_snap_trace(expected_trace)
    scientific_profile.require_machine_plan_bytes(machine_plan_bytes)
    members = _read_archive(archive_path, expected_paths=_replay_paths())
    lineage = RouteASyntheticSuiteLineage.from_bytes(members["lineage.json"])
    if (
        lineage != expected_lineage
        or members["source-mapping.json"] != trace.mapping_bytes
        or members["source-accepted-trace.json"] != trace.accepted_trace_bytes
        or members["source-trace.json"] != trace.event_trace_bytes
    ):
        raise RouteAOrderedSuiteError("ordered replay source or lineage changed")
    shard = _shard(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    final_cells: list[RouteACanonicalStrategyCell] = []
    replay_receipts: list[bytes] = []
    guard_receipts: list[bytes] = []
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            stem = _cell_stem(strategy_ordinal, rho)
            cell = validate_route_a_strategy_cell(
                _canonical_object(
                    members[f"cells/{stem}/final-cell.json"],
                    label="ordered final cell",
                ),
                scientific_profile=scientific_profile,
            )
            replay_receipt = members[f"cells/{stem}/replay-receipt.json"]
            guard_receipt = members[f"cells/{stem}/guard-receipt.json"]
            replay_document = _canonical_object(
                replay_receipt,
                label="ordered replay receipt",
            )
            guard_document = _canonical_object(
                guard_receipt,
                label="ordered guard receipt",
            )
            target = RouteAOrderedEventCellTarget.for_snap_trace(
                trace,
                strategy_candidate_id=strategy,
                rho=rho,
                shard_identity_sha256=shard,
                unit_attempt_ordinal=unit_attempt_ordinal,
            )
            if (
                cell.document["identity"]["strategy_candidate_id"] != strategy
                or cell.document["identity"]["rho"] != _rho_text(rho)
                or cell.document["identity"]["shard_identity_sha256"] != shard
                or replay_document.get("expected_target_sha256") != target.sha256
                or replay_document.get("final_cell_sha256") != cell.sha256
                or guard_document.get("expected_target_sha256") != target.sha256
                or guard_document.get("final_cell_sha256") != cell.sha256
                or guard_document.get("accepted") is not True
                or replay_document.get("formal_authority_granted") is not False
                or guard_document.get("formal_authority_granted") is not False
            ):
                raise RouteAOrderedSuiteError("ordered replay receipt binding changed")
            final_cells.append(cell)
            replay_receipts.append(replay_receipt)
            guard_receipts.append(guard_receipt)
    payload = tuple(
        (path, members[path]) for path in _replay_paths() if path != "manifest.json"
    )
    if members["manifest.json"] != _manifest(
        schema=_REPLAY_SCHEMA,
        role="redacted-post-replay-NON-EVIDENCE",
        lineage=lineage,
        trace=trace,
        shard_identity_sha256=shard,
        members=payload,
    ):
        raise RouteAOrderedSuiteError("ordered replay manifest changed")
    return RouteAOrderedSuiteReplayInspection(
        lineage=lineage,
        shard_identity_sha256=shard,
        final_cells=tuple(final_cells),
        replay_receipts=tuple(replay_receipts),
        guard_receipts=tuple(guard_receipts),
        archive_sha256=_sha256_file(archive_path),
    )
