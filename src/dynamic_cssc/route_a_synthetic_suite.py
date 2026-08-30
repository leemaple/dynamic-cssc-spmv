"""Closed producer and independent-replay packages for Route A synthetic suites.

The public functions in this module own the complete multi-strategy/rho suite
boundary.  A producer package is private, short lived, and permanently
NON-EVIDENCE.  Its independent replay package retains only final cells and
redacted receipts; private query vectors, masks, and ledger bytes never cross
that second boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.route_a_artifacts import (
    inspect_route_a_synthetic_cell_archive,
    produce_route_a_synthetic_cell_archive,
)
from dynamic_cssc.route_a_evaluation import evaluate_route_a_synthetic_cell
from dynamic_cssc.route_a_guard import guard_route_a_synthetic_replay
from dynamic_cssc.route_a_replay import (
    RouteASyntheticCellTarget,
    produce_route_a_synthetic_replay_archive,
    replay_route_a_synthetic_cell,
)
from dynamic_cssc.route_a_results import (
    RouteACanonicalStrategyCell,
    canonical_route_a_document,
    project_route_a_rho10,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_workloads import (
    RouteASyntheticTrace,
    validate_route_a_synthetic_trace,
)

__all__ = (
    "RouteASyntheticSuiteError",
    "RouteASyntheticSuiteLineage",
    "RouteASyntheticSuiteProducerInspection",
    "RouteASyntheticSuiteReplayInspection",
    "inspect_route_a_synthetic_suite_handoff",
    "inspect_route_a_synthetic_suite_replay",
    "produce_route_a_synthetic_suite_handoff",
    "replay_and_guard_route_a_synthetic_suite",
    "route_a_synthetic_shard_identity",
    "route_a_synthetic_suite_stage_names",
)

_PRODUCER_SCHEMA = "dynamic-cssc-route-a-synthetic-suite-handoff-v1"
_REPLAY_SCHEMA = "dynamic-cssc-route-a-synthetic-suite-replay-v1"
_LINEAGE_SCHEMA = "dynamic-cssc-route-a-execution-lineage-v1"
_SHARD_SCHEMA = "dynamic-cssc-route-a-shard-identity-v1"
_DIRECT_RHOS = (Fraction(1, 100), Fraction(1, 10), Fraction(1))
_STRATEGIES = ROUTE_A_STRATEGY_CANDIDATES
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_SUITE_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024


class RouteASyntheticSuiteError(ValueError):
    """A synthetic suite package is open, ambiguous, or internally inconsistent."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RouteASyntheticSuiteError("Route A suite JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    try:
        document = json.loads(content.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteASyntheticSuiteError(f"{label} is not canonical ASCII JSON") from error
    if type(document) is not dict or canonical_route_a_document(document) != content:
        raise RouteASyntheticSuiteError(f"{label} is not one canonical object")
    return document


def _rho_text(rho: Fraction) -> str:
    return str(rho.numerator) if rho.denominator == 1 else f"{rho.numerator}/{rho.denominator}"


def _cell_stem(strategy_ordinal: int, rho: Fraction) -> str:
    return f"strategy-{strategy_ordinal:02d}-rho-{rho.numerator}d{rho.denominator}"


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def _write_archive(output_path: Path, members: tuple[tuple[str, bytes], ...]) -> None:
    if not isinstance(output_path, Path) or not output_path.is_absolute():
        raise TypeError("output_path must be one absolute pathlib.Path")
    if output_path.exists() or output_path.is_symlink():
        raise RouteASyntheticSuiteError("Route A suite output path must be absent")
    try:
        parent = output_path.parent.lstat()
    except OSError as error:
        raise RouteASyntheticSuiteError("Route A suite output parent is unavailable") from error
    if output_path.parent.is_symlink() or not stat.S_ISDIR(parent.st_mode):
        raise RouteASyntheticSuiteError("Route A suite output parent is not a direct directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(output_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w+b") as stream:
            descriptor = -1
            with zipfile.ZipFile(
                stream, "w", compression=zipfile.ZIP_STORED, allowZip64=True
            ) as archive:
                for path, content in members:
                    if type(content) is not bytes or len(content) > _MAX_MEMBER_BYTES:
                        raise RouteASyntheticSuiteError(
                            "Route A suite member exceeds its closed byte bound"
                        )
                    archive.writestr(_zip_info(path), content)
            stream.flush()
            os.fsync(stream.fileno())
        if output_path.stat().st_size > _MAX_SUITE_ARCHIVE_BYTES:
            raise RouteASyntheticSuiteError("Route A suite archive exceeds its closed byte bound")
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        output_path.unlink(missing_ok=True)
        raise


def _read_archive(
    archive_path: Path,
    *,
    expected_paths: tuple[str, ...],
) -> dict[str, bytes]:
    if not isinstance(archive_path, Path) or not archive_path.is_absolute():
        raise TypeError("archive_path must be one absolute pathlib.Path")
    try:
        observed = archive_path.lstat()
        if (
            archive_path.is_symlink()
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_size <= 0
            or observed.st_size > _MAX_SUITE_ARCHIVE_BYTES
        ):
            raise RouteASyntheticSuiteError("Route A suite archive is not a bounded file")
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if names != expected_paths or len(names) != len(set(names)):
                raise RouteASyntheticSuiteError(
                    "Route A suite members are missing, extra, reordered, or repeated"
                )
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.flag_bits & 0x1
                    or info.is_dir()
                    or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != 0o644
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.file_size > _MAX_MEMBER_BYTES
                ):
                    raise RouteASyntheticSuiteError("Route A suite member type is unsafe")
                content = archive.read(info)
                if len(content) != info.file_size:
                    raise RouteASyntheticSuiteError("Route A suite member size changed")
                members[info.filename] = content
            return members
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, RouteASyntheticSuiteError):
            raise
        raise RouteASyntheticSuiteError("Route A suite archive is unreadable") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RouteASyntheticSuiteError("Route A suite archive cannot be rehashed") from error
    try:
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)
    finally:
        os.close(descriptor)


def _observe_stage(observer: Callable[[str], None] | None, stage: str) -> None:
    if observer is None:
        return
    if not callable(observer):
        raise TypeError("stage_observer must be callable or absent")
    observer(stage)


def route_a_synthetic_suite_stage_names(stage: str) -> tuple[str, ...]:
    """Return the only registered boundary sequence for q1 or q2."""

    if type(stage) is not str or stage not in {"q1", "q2"}:
        raise RouteASyntheticSuiteError("Route A suite stage role is not q1 or q2")
    names = [
        "source-trace-validated" if stage == "q1" else "producer-suite-independently-inspected"
    ]
    cell_prefix = "producer-cell" if stage == "q1" else "replay-guard-cell"
    projection_prefix = "producer-rho10-projection" if stage == "q1" else "replay-rho10-projection"
    for strategy_ordinal in range(len(_STRATEGIES)):
        names.extend(f"{cell_prefix}:{strategy_ordinal}:{_rho_text(rho)}" for rho in _DIRECT_RHOS)
        names.append(f"{projection_prefix}:{strategy_ordinal}")
    names.append(
        "producer-suite-archive-written" if stage == "q1" else "replay-suite-archive-written"
    )
    return tuple(names)


class _RegisteredStageSequence:
    __slots__ = ("_names", "_observer", "_ordinal")

    def __init__(self, stage: str, observer: Callable[[str], None] | None) -> None:
        self._names = route_a_synthetic_suite_stage_names(stage)
        self._observer = observer
        self._ordinal = 0

    def observe_next(self) -> None:
        if self._ordinal >= len(self._names):
            raise RouteASyntheticSuiteError("Route A suite emitted an extra stage")
        _observe_stage(self._observer, self._names[self._ordinal])
        self._ordinal += 1

    def finish(self) -> None:
        if self._ordinal != len(self._names):
            raise RouteASyntheticSuiteError("Route A suite omitted a registered stage")


@dataclass(frozen=True, slots=True)
class RouteASyntheticSuiteLineage:
    """Exact provider-control and detached experiment-source identity."""

    experiment_source_sha: str
    workflow_head_sha: str
    compatibility_receipt_sha256: str
    provider_run_id: int
    provider_run_attempt: int

    def __post_init__(self) -> None:
        if (
            _LOWER_GIT_SHA.fullmatch(self.experiment_source_sha) is None
            or _LOWER_GIT_SHA.fullmatch(self.workflow_head_sha) is None
            or _LOWER_SHA256.fullmatch(self.compatibility_receipt_sha256) is None
            or type(self.provider_run_id) is not int
            or self.provider_run_id <= 0
            or type(self.provider_run_attempt) is not int
            or self.provider_run_attempt != 1
        ):
            raise RouteASyntheticSuiteError("Route A suite lineage identity is malformed")

    @property
    def document_bytes(self) -> bytes:
        return canonical_route_a_document(
            {
                "compatibility_receipt_sha256": self.compatibility_receipt_sha256,
                "experiment_source_sha": self.experiment_source_sha,
                "provider_run_attempt": self.provider_run_attempt,
                "provider_run_id": self.provider_run_id,
                "schema_version": _LINEAGE_SCHEMA,
                "workflow_head_sha": self.workflow_head_sha,
            }
        )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.document_bytes).hexdigest()

    @classmethod
    def from_bytes(cls, content: bytes) -> RouteASyntheticSuiteLineage:
        document = _canonical_object(content, label="Route A suite lineage")
        if (
            set(document)
            != {
                "compatibility_receipt_sha256",
                "experiment_source_sha",
                "provider_run_attempt",
                "provider_run_id",
                "schema_version",
                "workflow_head_sha",
            }
            or document.get("schema_version") != _LINEAGE_SCHEMA
        ):
            raise RouteASyntheticSuiteError("Route A suite lineage schema changed")
        return cls(
            experiment_source_sha=document["experiment_source_sha"],  # type: ignore[arg-type]
            workflow_head_sha=document["workflow_head_sha"],  # type: ignore[arg-type]
            compatibility_receipt_sha256=document["compatibility_receipt_sha256"],  # type: ignore[arg-type]
            provider_run_id=document["provider_run_id"],  # type: ignore[arg-type]
            provider_run_attempt=document["provider_run_attempt"],  # type: ignore[arg-type]
        )


def route_a_synthetic_shard_identity(
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    *,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> str:
    """Derive the one shared simulator/native identity for a synthetic unit."""

    trace = validate_route_a_synthetic_trace(
        trace,
        scientific_profile=scientific_profile,
    )
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    if type(unit_attempt_ordinal) is not int or unit_attempt_ordinal not in {0, 1}:
        raise RouteASyntheticSuiteError(
            "Route A suite attempt is outside the inherited retry domain"
        )
    return hashlib.sha256(
        canonical_route_a_document(
            {
                "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
                "experiment_source_sha": lineage.experiment_source_sha,
                "formal_seed_or_null": trace.formal_seed,
                "object_sha256_or_null": None,
                "partition_or_null": None,
                "provider_run_attempt": lineage.provider_run_attempt,
                "provider_run_id": lineage.provider_run_id,
                "scale_or_null": trace.scale,
                "schema_version": _SHARD_SCHEMA,
                "source_event_trace_sha256": trace.event_trace_sha256,
                "source_kind": "synthetic",
                "suite_role": trace.suite_role,
                "unit_attempt_ordinal": unit_attempt_ordinal,
                "workflow_head_sha": lineage.workflow_head_sha,
            }
        )
    ).hexdigest()


def _producer_paths() -> tuple[str, ...]:
    paths = ["lineage.json", "source-initial-state.json", "source-trace.json"]
    for strategy_ordinal, _strategy in enumerate(_STRATEGIES):
        for rho in _DIRECT_RHOS:
            paths.append(f"cells/{_cell_stem(strategy_ordinal, rho)}.zip")
        paths.extend(
            (
                f"projections/strategy-{strategy_ordinal:02d}-rho-10-cell.json",
                f"projections/strategy-{strategy_ordinal:02d}-rho-10-envelope.json",
            )
        )
    paths.append("manifest.json")
    return tuple(paths)


def _replay_paths() -> tuple[str, ...]:
    paths = ["lineage.json", "source-trace.json"]
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
        paths.extend(
            (
                f"projections/strategy-{strategy_ordinal:02d}-rho-10-cell.json",
                f"projections/strategy-{strategy_ordinal:02d}-rho-10-envelope.json",
            )
        )
    paths.append("manifest.json")
    return tuple(paths)


def _manifest(
    *,
    schema: str,
    role: str,
    lineage: RouteASyntheticSuiteLineage,
    trace: RouteASyntheticTrace,
    shard_identity_sha256: str,
    members: tuple[tuple[str, bytes], ...],
) -> bytes:
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "direct_cell_count": len(_STRATEGIES) * len(_DIRECT_RHOS),
            "formal_evidence": False,
            "lineage_sha256": lineage.sha256,
            "members": [
                {
                    "byte_count": len(content),
                    "path": path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for path, content in members
            ],
            "package_role": role,
            "private_replay_material_included": role == "private-pre-replay-NON-EVIDENCE",
            "projected_rho10_cell_count": len(_STRATEGIES),
            "retention_days": 1,
            "schema_version": schema,
            "shard_identity_sha256": shard_identity_sha256,
            "source_event_trace_sha256": trace.event_trace_sha256,
        }
    )


@dataclass(frozen=True, slots=True)
class RouteASyntheticSuiteProducerInspection:
    lineage: RouteASyntheticSuiteLineage
    shard_identity_sha256: str
    cell_archives: tuple[tuple[str, Fraction, bytes], ...]
    rho10_cells: tuple[RouteACanonicalStrategyCell, ...]
    archive_sha256: str


@dataclass(frozen=True, slots=True)
class RouteASyntheticSuiteReplayInspection:
    lineage: RouteASyntheticSuiteLineage
    shard_identity_sha256: str
    final_cells: tuple[RouteACanonicalStrategyCell, ...]
    replay_receipts: tuple[bytes, ...]
    guard_receipts: tuple[bytes, ...]
    rho10_cells: tuple[RouteACanonicalStrategyCell, ...]
    archive_sha256: str


def _require_empty_scratch(scratch_root: Path) -> None:
    if not isinstance(scratch_root, Path) or not scratch_root.is_absolute():
        raise TypeError("scratch_root must be one absolute pathlib.Path")
    try:
        observed = scratch_root.lstat()
    except OSError as error:
        raise RouteASyntheticSuiteError("Route A suite scratch root is unavailable") from error
    if (
        scratch_root.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o700
        or any(scratch_root.iterdir())
    ):
        raise RouteASyntheticSuiteError("Route A suite scratch root must be empty mode 0700")


def produce_route_a_synthetic_suite_handoff(
    trace: RouteASyntheticTrace,
    *,
    lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    scratch_root: Path,
    output_path: Path,
    unit_attempt_ordinal: int = 0,
    stage_observer: Callable[[str], None] | None = None,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> None:
    """Execute every direct cell once and write one private suite handoff."""

    trace = validate_route_a_synthetic_trace(
        trace,
        scientific_profile=scientific_profile,
    )
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    try:
        scientific_profile.require_machine_plan_bytes(machine_plan_bytes)
    except (TypeError, ValueError) as error:
        raise RouteASyntheticSuiteError(
            "Route A suite machine plan digest changed"
        ) from error
    _require_empty_scratch(scratch_root)
    shard_identity = route_a_synthetic_shard_identity(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        scientific_profile=scientific_profile,
    )
    stages = _RegisteredStageSequence("q1", stage_observer)
    stages.observe_next()
    members: list[tuple[str, bytes]] = [
        ("lineage.json", lineage.document_bytes),
        ("source-initial-state.json", trace.initial_state_bytes),
        ("source-trace.json", trace.event_trace_bytes),
    ]
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        rho1_cell: RouteACanonicalStrategyCell | None = None
        for rho in _DIRECT_RHOS:
            cell_scratch = scratch_root / _cell_stem(strategy_ordinal, rho)
            cell_scratch.mkdir(mode=0o700)
            try:
                run = evaluate_route_a_synthetic_cell(
                    trace,
                    strategy_candidate_id=strategy,
                    rho=rho,
                    shard_identity_sha256=shard_identity,
                    unit_attempt_ordinal=unit_attempt_ordinal,
                    machine_plan_bytes=machine_plan_bytes,
                    scratch_directory=cell_scratch,
                    scientific_profile=scientific_profile,
                )
                archive_bytes = produce_route_a_synthetic_cell_archive(run)
                members.append((f"cells/{_cell_stem(strategy_ordinal, rho)}.zip", archive_bytes))
                if rho == Fraction(1):
                    rho1_cell = run.cell
                stages.observe_next()
            finally:
                shutil.rmtree(cell_scratch)
        if rho1_cell is None:  # pragma: no cover - the closed matrix includes rho=1
            raise AssertionError("Route A suite omitted its rho=1 source cell")
        projection = project_route_a_rho10(
            rho1_cell,
            machine_plan_bytes=machine_plan_bytes,
            scientific_profile=scientific_profile,
        )
        members.extend(
            (
                (
                    f"projections/strategy-{strategy_ordinal:02d}-rho-10-cell.json",
                    projection.target.document_bytes,
                ),
                (
                    f"projections/strategy-{strategy_ordinal:02d}-rho-10-envelope.json",
                    projection.integrity_envelope_bytes,
                ),
            )
        )
        stages.observe_next()
    manifest = _manifest(
        schema=_PRODUCER_SCHEMA,
        role="private-pre-replay-NON-EVIDENCE",
        lineage=lineage,
        trace=trace,
        shard_identity_sha256=shard_identity,
        members=tuple(members),
    )
    members.append(("manifest.json", manifest))
    if tuple(path for path, _content in members) != _producer_paths():
        raise AssertionError("Route A producer suite path order is not closed")
    _write_archive(output_path, tuple(members))
    stages.observe_next()
    stages.finish()


def inspect_route_a_synthetic_suite_handoff(
    archive_path: Path,
    *,
    expected_trace: RouteASyntheticTrace,
    expected_lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteASyntheticSuiteProducerInspection:
    """Independently rehash and close one complete private producer suite."""

    trace = validate_route_a_synthetic_trace(
        expected_trace,
        scientific_profile=scientific_profile,
    )
    if type(expected_lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("expected_lineage must be exact RouteASyntheticSuiteLineage")
    try:
        scientific_profile.require_machine_plan_bytes(machine_plan_bytes)
    except (TypeError, ValueError) as error:
        raise RouteASyntheticSuiteError(
            "Route A suite machine plan digest changed"
        ) from error
    members = _read_archive(archive_path, expected_paths=_producer_paths())
    lineage = RouteASyntheticSuiteLineage.from_bytes(members["lineage.json"])
    if (
        lineage != expected_lineage
        or members["source-initial-state.json"] != trace.initial_state_bytes
        or members["source-trace.json"] != trace.event_trace_bytes
    ):
        raise RouteASyntheticSuiteError("Route A producer suite source or lineage changed")
    shard_identity = route_a_synthetic_shard_identity(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        scientific_profile=scientific_profile,
    )
    cell_archives: list[tuple[str, Fraction, bytes]] = []
    rho10_cells: list[RouteACanonicalStrategyCell] = []
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        rho1_cell: RouteACanonicalStrategyCell | None = None
        for rho in _DIRECT_RHOS:
            path = f"cells/{_cell_stem(strategy_ordinal, rho)}.zip"
            archive_bytes = members[path]
            inspection = inspect_route_a_synthetic_cell_archive(
                archive_bytes,
                scientific_profile=scientific_profile,
            )
            target = RouteASyntheticCellTarget.for_synthetic_trace(
                trace,
                strategy_candidate_id=strategy,
                rho=rho,
                shard_identity_sha256=shard_identity,
                unit_attempt_ordinal=unit_attempt_ordinal,
                scientific_profile=scientific_profile,
            )
            identity = inspection.cell_run.cell.document["identity"]
            if (
                identity["strategy_candidate_id"] != strategy
                or identity["rho"] != _rho_text(rho)
                or identity["shard_identity_sha256"] != shard_identity
                or target.sha256
                != RouteASyntheticCellTarget.for_synthetic_trace(
                    trace,
                    strategy_candidate_id=identity["strategy_candidate_id"],
                    rho=rho,
                    shard_identity_sha256=identity["shard_identity_sha256"],
                    unit_attempt_ordinal=identity["unit_attempt_ordinal"],
                    scientific_profile=scientific_profile,
                ).sha256
            ):
                raise RouteASyntheticSuiteError("Route A producer suite cell identity drifted")
            cell_archives.append((strategy, rho, archive_bytes))
            if rho == Fraction(1):
                rho1_cell = inspection.cell_run.cell
        assert rho1_cell is not None
        projection = project_route_a_rho10(
            rho1_cell,
            machine_plan_bytes=machine_plan_bytes,
            scientific_profile=scientific_profile,
        )
        cell_path = f"projections/strategy-{strategy_ordinal:02d}-rho-10-cell.json"
        envelope_path = f"projections/strategy-{strategy_ordinal:02d}-rho-10-envelope.json"
        if (
            members[cell_path] != projection.target.document_bytes
            or members[envelope_path] != projection.integrity_envelope_bytes
        ):
            raise RouteASyntheticSuiteError("Route A producer rho=10 projection changed")
        rho10_cells.append(projection.target)
    payload_members = tuple(
        (path, members[path]) for path in _producer_paths() if path != "manifest.json"
    )
    expected_manifest = _manifest(
        schema=_PRODUCER_SCHEMA,
        role="private-pre-replay-NON-EVIDENCE",
        lineage=lineage,
        trace=trace,
        shard_identity_sha256=shard_identity,
        members=payload_members,
    )
    if members["manifest.json"] != expected_manifest:
        raise RouteASyntheticSuiteError("Route A producer suite manifest changed")
    return RouteASyntheticSuiteProducerInspection(
        lineage=lineage,
        shard_identity_sha256=shard_identity,
        cell_archives=tuple(cell_archives),
        rho10_cells=tuple(rho10_cells),
        archive_sha256=_sha256_file(archive_path),
    )


def replay_and_guard_route_a_synthetic_suite(
    trace: RouteASyntheticTrace,
    *,
    lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    producer_archive_path: Path,
    scratch_root: Path,
    output_path: Path,
    unit_attempt_ordinal: int = 0,
    stage_observer: Callable[[str], None] | None = None,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> None:
    """Replay all direct cells read-only, guard them, and discard private bytes."""

    trace = validate_route_a_synthetic_trace(
        trace,
        scientific_profile=scientific_profile,
    )
    _require_empty_scratch(scratch_root)
    producer = inspect_route_a_synthetic_suite_handoff(
        producer_archive_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=machine_plan_bytes,
        unit_attempt_ordinal=unit_attempt_ordinal,
        scientific_profile=scientific_profile,
    )
    archive_by_identity = {
        (strategy, rho): content for strategy, rho, content in producer.cell_archives
    }
    stages = _RegisteredStageSequence("q2", stage_observer)
    stages.observe_next()
    members: list[tuple[str, bytes]] = [
        ("lineage.json", lineage.document_bytes),
        ("source-trace.json", trace.event_trace_bytes),
    ]
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        rho1_final: RouteACanonicalStrategyCell | None = None
        for rho in _DIRECT_RHOS:
            stem = _cell_stem(strategy_ordinal, rho)
            cell_scratch = scratch_root / stem
            cell_scratch.mkdir(mode=0o700)
            try:
                target = RouteASyntheticCellTarget.for_synthetic_trace(
                    trace,
                    strategy_candidate_id=strategy,
                    rho=rho,
                    shard_identity_sha256=producer.shard_identity_sha256,
                    unit_attempt_ordinal=unit_attempt_ordinal,
                    scientific_profile=scientific_profile,
                )
                replay = replay_route_a_synthetic_cell(
                    trace,
                    archive_bytes=archive_by_identity[(strategy, rho)],
                    expected_target=target,
                    machine_plan_bytes=machine_plan_bytes,
                    scratch_directory=cell_scratch,
                    scientific_profile=scientific_profile,
                )
                replay_archive = produce_route_a_synthetic_replay_archive(replay)
                guard = guard_route_a_synthetic_replay(
                    producer_archive_bytes=archive_by_identity[(strategy, rho)],
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
                if rho == Fraction(1):
                    rho1_final = guard.final_cell
                stages.observe_next()
            finally:
                shutil.rmtree(cell_scratch)
        if rho1_final is None:  # pragma: no cover - the closed matrix includes rho=1
            raise AssertionError("Route A replay suite omitted its rho=1 source cell")
        projection = project_route_a_rho10(
            rho1_final,
            machine_plan_bytes=machine_plan_bytes,
            scientific_profile=scientific_profile,
        )
        members.extend(
            (
                (
                    f"projections/strategy-{strategy_ordinal:02d}-rho-10-cell.json",
                    projection.target.document_bytes,
                ),
                (
                    f"projections/strategy-{strategy_ordinal:02d}-rho-10-envelope.json",
                    projection.integrity_envelope_bytes,
                ),
            )
        )
        stages.observe_next()
    manifest = _manifest(
        schema=_REPLAY_SCHEMA,
        role="redacted-post-replay-NON-EVIDENCE",
        lineage=lineage,
        trace=trace,
        shard_identity_sha256=producer.shard_identity_sha256,
        members=tuple(members),
    )
    members.append(("manifest.json", manifest))
    if tuple(path for path, _content in members) != _replay_paths():
        raise AssertionError("Route A replay suite path order is not closed")
    _write_archive(output_path, tuple(members))
    stages.observe_next()
    stages.finish()


def inspect_route_a_synthetic_suite_replay(
    archive_path: Path,
    *,
    expected_trace: RouteASyntheticTrace,
    expected_lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteASyntheticSuiteReplayInspection:
    """Reinspect a redacted suite result without accepting any private payload."""

    trace = validate_route_a_synthetic_trace(
        expected_trace,
        scientific_profile=scientific_profile,
    )
    members = _read_archive(archive_path, expected_paths=_replay_paths())
    lineage = RouteASyntheticSuiteLineage.from_bytes(members["lineage.json"])
    if lineage != expected_lineage or members["source-trace.json"] != trace.event_trace_bytes:
        raise RouteASyntheticSuiteError("Route A replay suite source or lineage changed")
    shard_identity = route_a_synthetic_shard_identity(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        scientific_profile=scientific_profile,
    )
    final_cells: list[RouteACanonicalStrategyCell] = []
    replay_receipts: list[bytes] = []
    guard_receipts: list[bytes] = []
    rho10_cells: list[RouteACanonicalStrategyCell] = []
    for strategy_ordinal, strategy in enumerate(_STRATEGIES):
        rho1_final: RouteACanonicalStrategyCell | None = None
        for rho in _DIRECT_RHOS:
            stem = _cell_stem(strategy_ordinal, rho)
            cell = validate_route_a_strategy_cell(
                _canonical_object(members[f"cells/{stem}/final-cell.json"], label="final cell"),
                scientific_profile=scientific_profile,
            )
            replay_receipt = members[f"cells/{stem}/replay-receipt.json"]
            guard_receipt = members[f"cells/{stem}/guard-receipt.json"]
            replay_document = _canonical_object(replay_receipt, label="replay receipt")
            guard_document = _canonical_object(guard_receipt, label="guard receipt")
            expected_target = RouteASyntheticCellTarget.for_synthetic_trace(
                trace,
                strategy_candidate_id=strategy,
                rho=rho,
                shard_identity_sha256=shard_identity,
                unit_attempt_ordinal=unit_attempt_ordinal,
                scientific_profile=scientific_profile,
            )
            if (
                cell.document["identity"]["strategy_candidate_id"] != strategy
                or cell.document["identity"]["rho"] != _rho_text(rho)
                or cell.document["identity"]["shard_identity_sha256"] != shard_identity
                or replay_document.get("expected_target_sha256") != expected_target.sha256
                or replay_document.get("final_cell_sha256") != cell.sha256
                or guard_document.get("expected_target_sha256") != expected_target.sha256
                or guard_document.get("final_cell_sha256") != cell.sha256
                or guard_document.get("accepted") is not True
                or replay_document.get("formal_authority_granted") is not False
                or guard_document.get("formal_authority_granted") is not False
            ):
                raise RouteASyntheticSuiteError("Route A replay suite receipt binding drifted")
            final_cells.append(cell)
            replay_receipts.append(replay_receipt)
            guard_receipts.append(guard_receipt)
            if rho == Fraction(1):
                rho1_final = cell
        assert rho1_final is not None
        projection = project_route_a_rho10(
            rho1_final,
            machine_plan_bytes=machine_plan_bytes,
            scientific_profile=scientific_profile,
        )
        cell_path = f"projections/strategy-{strategy_ordinal:02d}-rho-10-cell.json"
        envelope_path = f"projections/strategy-{strategy_ordinal:02d}-rho-10-envelope.json"
        if (
            members[cell_path] != projection.target.document_bytes
            or members[envelope_path] != projection.integrity_envelope_bytes
        ):
            raise RouteASyntheticSuiteError("Route A replay rho=10 projection changed")
        rho10_cells.append(projection.target)
    payload_members = tuple(
        (path, members[path]) for path in _replay_paths() if path != "manifest.json"
    )
    expected_manifest = _manifest(
        schema=_REPLAY_SCHEMA,
        role="redacted-post-replay-NON-EVIDENCE",
        lineage=lineage,
        trace=trace,
        shard_identity_sha256=shard_identity,
        members=payload_members,
    )
    if members["manifest.json"] != expected_manifest:
        raise RouteASyntheticSuiteError("Route A replay suite manifest changed")
    return RouteASyntheticSuiteReplayInspection(
        lineage=lineage,
        shard_identity_sha256=shard_identity,
        final_cells=tuple(final_cells),
        replay_receipts=tuple(replay_receipts),
        guard_receipts=tuple(guard_receipts),
        rho10_cells=tuple(rho10_cells),
        archive_sha256=_sha256_file(archive_path),
    )
