"""Exact read-only reexecution and redacted receipt production for Route A cells."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import time
import zipfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.route_a_artifacts import (
    inspect_route_a_synthetic_cell_archive,
    produce_route_a_synthetic_cell_archive,
)
from dynamic_cssc.route_a_evaluation import (
    RouteASyntheticCellRun,
    replay_route_a_synthetic_cell_read_only,
    route_a_evidence_stream_root,
)
from dynamic_cssc.route_a_results import (
    RouteACanonicalStrategyCell,
    canonical_route_a_document,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_workloads import RouteASyntheticTrace, validate_route_a_synthetic_trace

__all__ = (
    "RouteAReplayError",
    "RouteASyntheticCellTarget",
    "RouteASyntheticReplayArchiveInspection",
    "RouteASyntheticCellReplay",
    "inspect_route_a_synthetic_replay_archive",
    "produce_route_a_synthetic_replay_archive",
    "replay_route_a_synthetic_cell",
)

_RHO_BY_TEXT = {
    "1/100": Fraction(1, 100),
    "1/10": Fraction(1, 10),
    "1": Fraction(1),
}
_DETERMINISTIC_CELL_FIELDS = (
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
)
_REPLAY_ARCHIVE_PATHS = (
    "final-cell.json",
    "replay-cell.zip",
    "replay-receipt.json",
    "manifest.json",
)
_REPLAY_RECEIPT_FIELDS = frozenset(
    {
        "deterministic_accounting_equal",
        "final_cell_sha256",
        "expected_target_sha256",
        "formal_authority_granted",
        "independent_oracle_equality",
        "independent_replay_cell_sha256",
        "machine_plan_sha256",
        "ledger_snapshot_read_only_verified",
        "producer_archive_sha256",
        "producer_cell_sha256",
        "producer_ledger_root",
        "producer_ledger_snapshot_sha256",
        "producer_output_digest_root",
        "producer_prepared_query_root",
        "publication_evidence",
        "replay_elapsed_seconds",
        "replay_ledger_root",
        "replay_ledger_snapshot_sha256",
        "replay_output_digest_root",
        "replay_prepared_query_root",
        "replay_timing_scope",
        "schema_version",
        "source_event_trace_sha256",
        "window_trace_sha256",
    }
)


class RouteAReplayError(ValueError):
    """Independent Route A replay differs from its redacted producer binding."""


@dataclass(frozen=True, slots=True)
class RouteASyntheticCellTarget:
    """External exact target that prevents matched producer/replay retargeting."""

    source_event_trace_sha256: str
    suite_role: str
    formal_seed_or_null: int | None
    scale_or_null: str | None
    strategy_candidate_id: str
    rho: Fraction
    shard_identity_sha256: str
    unit_attempt_ordinal: int

    @classmethod
    def for_synthetic_trace(
        cls,
        trace: RouteASyntheticTrace,
        *,
        strategy_candidate_id: str,
        rho: Fraction,
        shard_identity_sha256: str,
        unit_attempt_ordinal: int,
    ) -> RouteASyntheticCellTarget:
        trace = validate_route_a_synthetic_trace(trace)
        target = cls(
            source_event_trace_sha256=trace.event_trace_sha256,
            suite_role=trace.suite_role,
            formal_seed_or_null=trace.formal_seed,
            scale_or_null=trace.scale,
            strategy_candidate_id=strategy_candidate_id,
            rho=rho,
            shard_identity_sha256=shard_identity_sha256,
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
        target._validate()
        return target

    def _validate(self) -> None:
        if (
            type(self.source_event_trace_sha256) is not str
            or len(self.source_event_trace_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.source_event_trace_sha256
            )
            or self.suite_role not in ("qualification", "formal")
            or (
                self.formal_seed_or_null is not None
                and type(self.formal_seed_or_null) is not int
            )
            or self.scale_or_null not in ("S", "M")
            or self.strategy_candidate_id not in ROUTE_A_STRATEGY_CANDIDATES
            or type(self.rho) is not Fraction
            or self.rho not in set(_RHO_BY_TEXT.values())
            or type(self.shard_identity_sha256) is not str
            or len(self.shard_identity_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.shard_identity_sha256)
            or type(self.unit_attempt_ordinal) is not int
            or self.unit_attempt_ordinal not in (0, 1)
        ):
            raise RouteAReplayError("synthetic replay expected target is invalid")

    @property
    def document_bytes(self) -> bytes:
        self._validate()
        return canonical_route_a_document(
            {
                "formal_seed_or_null": self.formal_seed_or_null,
                "rho": _rho_text(self.rho),
                "scale_or_null": self.scale_or_null,
                "schema_version": "dynamic-cssc-route-a-synthetic-cell-target-v1",
                "shard_identity_sha256": self.shard_identity_sha256,
                "source_event_trace_sha256": self.source_event_trace_sha256,
                "strategy_candidate_id": self.strategy_candidate_id,
                "suite_role": self.suite_role,
                "unit_attempt_ordinal": self.unit_attempt_ordinal,
            }
        )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.document_bytes).hexdigest()


def _rho_text(rho: Fraction) -> str:
    return str(rho.numerator) if rho.denominator == 1 else f"{rho.numerator}/{rho.denominator}"


def _seconds(nanoseconds: int) -> str:
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    return f"{seconds}.{remainder:09d}"


def _output_root(run: RouteASyntheticCellRun) -> str:
    return route_a_evidence_stream_root(
        "dynamic-cssc-route-a-output-digest-stream-v1",
        run.output_digest_documents,
    )


@dataclass(frozen=True, slots=True)
class RouteASyntheticCellReplay:
    """A final replay-timed cell and its independently generated safe receipt."""

    final_cell: RouteACanonicalStrategyCell
    replay_run: RouteASyntheticCellRun
    receipt_bytes: bytes
    receipt_sha256: str

    def __post_init__(self) -> None:
        if hashlib.sha256(self.receipt_bytes).hexdigest() != self.receipt_sha256:
            raise RouteAReplayError("replay receipt digest differs from its exact bytes")
        receipt = self.receipt
        if (
            receipt.get("final_cell_sha256") != self.final_cell.sha256
            or receipt.get("independent_replay_cell_sha256")
            != self.replay_run.cell.sha256
            or receipt.get("formal_authority_granted") is not False
            or receipt.get("publication_evidence") is not False
        ):
            raise RouteAReplayError("replay receipt authority or cell binding changed")

    @property
    def receipt(self) -> dict[str, object]:
        decoded = json.loads(self.receipt_bytes.decode("ascii"))
        if type(decoded) is not dict:
            raise RouteAReplayError("replay receipt is not one canonical object")
        return decoded


@dataclass(frozen=True, slots=True)
class RouteASyntheticReplayArchiveInspection:
    replay: RouteASyntheticCellReplay
    archive_sha256: str
    nested_replay_cell_archive_sha256: str


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def _replay_manifest(members: dict[str, bytes]) -> bytes:
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "handoff_role": "private-post-replay-NON-EVIDENCE",
            "members": [
                {
                    "byte_count": len(members[path]),
                    "path": path,
                    "sha256": hashlib.sha256(members[path]).hexdigest(),
                }
                for path in _REPLAY_ARCHIVE_PATHS[:-1]
            ],
            "publication_evidence": False,
            "private_preparation_bytes_included": True,
            "retention_days": 1,
            "schema_version": "dynamic-cssc-route-a-synthetic-replay-handoff-v2",
        }
    )


def produce_route_a_synthetic_replay_archive(
    replay: RouteASyntheticCellReplay,
) -> bytes:
    """Serialize a replay result around one independently inspectable nested cell."""

    if type(replay) is not RouteASyntheticCellReplay:
        raise TypeError("replay must be an exact RouteASyntheticCellReplay")
    members = {
        "final-cell.json": replay.final_cell.document_bytes,
        "replay-cell.zip": produce_route_a_synthetic_cell_archive(replay.replay_run),
        "replay-receipt.json": replay.receipt_bytes,
    }
    members["manifest.json"] = _replay_manifest(members)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in _REPLAY_ARCHIVE_PATHS:
            archive.writestr(_zip_info(path), members[path])
    content = buffer.getvalue()
    if len(content) > 4 * 1024 * 1024 * 1024:
        raise RouteAReplayError("replay handoff exceeds its closed byte bound")
    return content


def _read_replay_members(archive_bytes: bytes) -> dict[str, bytes]:
    if type(archive_bytes) is not bytes or not archive_bytes:
        raise RouteAReplayError("replay handoff must be nonempty bytes")
    if len(archive_bytes) > 4 * 1024 * 1024 * 1024:
        raise RouteAReplayError("replay handoff exceeds its closed byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            if tuple(info.filename for info in infos) != _REPLAY_ARCHIVE_PATHS:
                raise RouteAReplayError("replay handoff member set or order changed")
            result: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.flag_bits & 0x1
                    or info.is_dir()
                    or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != 0o644
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.file_size > 2 * 1024 * 1024 * 1024
                ):
                    raise RouteAReplayError("replay handoff member type is unsafe")
                result[info.filename] = archive.read(info)
            return result
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise RouteAReplayError("replay handoff is not a readable ZIP") from error


def _canonical_dict(content: bytes, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(content.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAReplayError(f"{label} is not ASCII JSON") from error
    if type(decoded) is not dict or canonical_route_a_document(decoded) != content:
        raise RouteAReplayError(f"{label} is not one canonical object")
    return decoded


def inspect_route_a_synthetic_replay_archive(
    archive_bytes: bytes,
) -> RouteASyntheticReplayArchiveInspection:
    """Independently reconstruct one replay handoff and its nested replay cell."""

    members = _read_replay_members(archive_bytes)
    if members["manifest.json"] != _replay_manifest(
        {path: members[path] for path in _REPLAY_ARCHIVE_PATHS[:-1]}
    ):
        raise RouteAReplayError("replay handoff manifest differs from its members")
    manifest = _canonical_dict(members["manifest.json"], "replay manifest")
    if (
        manifest.get("schema_version")
        != "dynamic-cssc-route-a-synthetic-replay-handoff-v2"
        or manifest.get("authority_granted") is not False
        or manifest.get("handoff_role") != "private-post-replay-NON-EVIDENCE"
        or manifest.get("publication_evidence") is not False
        or manifest.get("private_preparation_bytes_included") is not True
        or manifest.get("retention_days") != 1
    ):
        raise RouteAReplayError("replay handoff authority boundary changed")
    final_cell = validate_route_a_strategy_cell(
        _canonical_dict(members["final-cell.json"], "final cell")
    )
    receipt = _canonical_dict(members["replay-receipt.json"], "replay receipt")
    if (
        set(receipt) != _REPLAY_RECEIPT_FIELDS
        or receipt.get("schema_version")
        != "dynamic-cssc-route-a-synthetic-cell-replay-receipt-v2"
    ):
        raise RouteAReplayError("replay receipt does not match its closed schema")
    nested = inspect_route_a_synthetic_cell_archive(members["replay-cell.zip"])
    replay = RouteASyntheticCellReplay(
        final_cell=final_cell,
        replay_run=nested.cell_run,
        receipt_bytes=members["replay-receipt.json"],
        receipt_sha256=hashlib.sha256(members["replay-receipt.json"]).hexdigest(),
    )
    return RouteASyntheticReplayArchiveInspection(
        replay=replay,
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        nested_replay_cell_archive_sha256=nested.archive_sha256,
    )


def _validate_producer_identity(
    trace: RouteASyntheticTrace,
    producer: RouteASyntheticCellRun,
    expected_target: RouteASyntheticCellTarget,
) -> tuple[str, Fraction, int, str]:
    if type(expected_target) is not RouteASyntheticCellTarget:
        raise TypeError("expected_target must be an exact RouteASyntheticCellTarget")
    expected_target._validate()
    identity = producer.cell.document["identity"]
    rho_text = identity["rho"]
    if type(rho_text) is not str or rho_text not in _RHO_BY_TEXT:
        raise RouteAReplayError("producer cell rho is not directly replayable")
    expected = {
        "formal_seed_or_null": expected_target.formal_seed_or_null,
        "object_sha256_or_null": None,
        "partition_or_null": None,
        "scale_or_null": expected_target.scale_or_null,
        "semantics_or_null": None,
        "source_kind": "synthetic",
        "suite_role": expected_target.suite_role,
        "strategy_candidate_id": expected_target.strategy_candidate_id,
        "rho": _rho_text(expected_target.rho),
        "shard_identity_sha256": expected_target.shard_identity_sha256,
        "unit_attempt_ordinal": expected_target.unit_attempt_ordinal,
    }
    if (
        expected_target.source_event_trace_sha256 != trace.event_trace_sha256
        or expected_target.formal_seed_or_null != trace.formal_seed
        or expected_target.scale_or_null != trace.scale
        or expected_target.suite_role != trace.suite_role
        or any(identity[field] != value for field, value in expected.items())
    ):
        raise RouteAReplayError("producer cell differs from the external expected target")
    strategy = identity["strategy_candidate_id"]
    attempt = identity["unit_attempt_ordinal"]
    shard_sha256 = identity["shard_identity_sha256"]
    if type(strategy) is not str or type(attempt) is not int or type(shard_sha256) is not str:
        raise RouteAReplayError("producer cell execution identity is malformed")
    return strategy, _RHO_BY_TEXT[rho_text], attempt, shard_sha256


def replay_route_a_synthetic_cell(
    trace: RouteASyntheticTrace,
    *,
    archive_bytes: bytes,
    expected_target: RouteASyntheticCellTarget,
    machine_plan_bytes: bytes,
    scratch_directory: Path,
) -> RouteASyntheticCellReplay:
    """Reinspect a producer handoff and independently execute its exact cell."""

    replay_started = time.perf_counter_ns()
    trace = validate_route_a_synthetic_trace(trace)
    inspection = inspect_route_a_synthetic_cell_archive(archive_bytes)
    producer = inspection.cell_run
    strategy, rho, attempt, shard_sha256 = _validate_producer_identity(
        trace,
        producer,
        expected_target,
    )
    replay = replay_route_a_synthetic_cell_read_only(
        trace,
        strategy_candidate_id=strategy,
        rho=rho,
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=attempt,
        machine_plan_bytes=machine_plan_bytes,
        scratch_directory=scratch_directory,
        private_preparation_documents=producer.private_preparation_documents,
        ledger_snapshot_bytes=producer.ledger_snapshot_bytes,
    )

    producer_document = producer.cell.document
    replay_document = replay.cell.document
    if producer.window_trace_bytes != replay.window_trace_bytes:
        raise RouteAReplayError("independent replay compiled a different window trace")
    if producer.query_identity_documents != replay.query_identity_documents:
        raise RouteAReplayError("independent replay derived different query identities")
    if producer.output_digest_documents != replay.output_digest_documents:
        raise RouteAReplayError("independent replay produced different typed outputs")
    if (
        producer.preparation_digest_documents != replay.preparation_digest_documents
        or producer.consumption_receipt_documents
        != replay.consumption_receipt_documents
        or producer.private_preparation_documents
        != replay.private_preparation_documents
        or producer.ledger_snapshot_bytes != replay.ledger_snapshot_bytes
        or producer.ledger_snapshot_sha256 != replay.ledger_snapshot_sha256
    ):
        raise RouteAReplayError("read-only replay changed private preparation or ledger bytes")
    if any(
        producer_document[field] != replay_document[field]
        for field in _DETERMINISTIC_CELL_FIELDS
    ):
        raise RouteAReplayError("independent replay changed deterministic cell accounting")
    if producer_document["bindings"] != replay_document["bindings"]:
        raise RouteAReplayError("independent replay changed an exact cell binding")

    replay_elapsed_nanoseconds = time.perf_counter_ns() - replay_started
    final_document = producer.cell.document
    final_document["measurements"]["replay_seconds"] = _seconds(
        replay_elapsed_nanoseconds
    )
    final_cell = validate_route_a_strategy_cell(final_document)
    receipt_bytes = canonical_route_a_document(
        {
            "deterministic_accounting_equal": True,
            "expected_target_sha256": expected_target.sha256,
            "final_cell_sha256": final_cell.sha256,
            "formal_authority_granted": False,
            "independent_oracle_equality": True,
            "independent_replay_cell_sha256": replay.cell.sha256,
            "machine_plan_sha256": producer_document["bindings"][
                "machine_plan_sha256"
            ],
            "ledger_snapshot_read_only_verified": True,
            "producer_archive_sha256": inspection.archive_sha256,
            "producer_cell_sha256": producer.cell.sha256,
            "producer_ledger_root": producer_document["bindings"]["ledger_root"],
            "producer_ledger_snapshot_sha256": producer.ledger_snapshot_sha256,
            "producer_output_digest_root": _output_root(producer),
            "producer_prepared_query_root": producer_document["bindings"][
                "prepared_query_root"
            ],
            "publication_evidence": False,
            "replay_elapsed_seconds": _seconds(replay_elapsed_nanoseconds),
            "replay_ledger_root": replay_document["bindings"]["ledger_root"],
            "replay_ledger_snapshot_sha256": replay.ledger_snapshot_sha256,
            "replay_output_digest_root": _output_root(replay),
            "replay_prepared_query_root": replay_document["bindings"][
                "prepared_query_root"
            ],
            "replay_timing_scope": (
                "function-entry-through-inspection-rehash-read-only-ledger-verification-"
                "typed-reexecution-oracle-and-final-comparison-before-receipt-serialization"
            ),
            "schema_version": "dynamic-cssc-route-a-synthetic-cell-replay-receipt-v2",
            "source_event_trace_sha256": trace.event_trace_sha256,
            "window_trace_sha256": producer.window_trace_sha256,
        }
    )
    return RouteASyntheticCellReplay(
        final_cell=final_cell,
        replay_run=replay,
        receipt_bytes=receipt_bytes,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
    )
