"""Outer follow-up identity for formal synthetic producer and replay trees.

The inherited Route A ZIP remains byte-exact and authority-false.  A small
follow-up manifest binds that ZIP to the new study, unit, phase, and S1/S2
lineage.  A guarded-final object is only an evidence candidate until the later
terminal admission accepts the complete seventeen-object set.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
    _issue_followup_inner_admission,
    _parse_ascii_json,
    build_followup_unit_identity,
    followup_artifact_name,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    RouteASyntheticSuiteProducerInspection,
    RouteASyntheticSuiteReplayInspection,
    inspect_route_a_synthetic_suite_handoff,
    inspect_route_a_synthetic_suite_replay,
    route_a_synthetic_shard_identity,
)
from dynamic_cssc.route_a_workloads import (
    RouteASyntheticTrace,
    validate_route_a_synthetic_trace,
)

__all__ = (
    "FollowupFormalArtifactError",
    "FollowupFormalSyntheticInspection",
    "expected_followup_formal_synthetic_artifact_name",
    "inspect_followup_formal_synthetic_artifact",
    "produce_followup_formal_synthetic_artifact",
)

FollowupFormalPhase = Literal["private-handoff", "guarded-final"]

_MANIFEST_SCHEMA = "dynamic-cssc-followup-performance-formal-inner-file-v1"
_INNER_FILE = "inner/payload.zip"
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024 * 1024
_MAX_WRAPPER_BYTES = 4 * 1024 * 1024


class FollowupFormalArtifactError(FollowupContractError):
    """One formal outer wrapper or inherited payload failed closed."""


def _direct_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be an exact absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise FollowupFormalArtifactError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupFormalArtifactError(f"{label} is not one direct directory")
    return path


def _direct_file(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be an exact absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise FollowupFormalArtifactError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or not 0 < observed.st_size <= _MAX_PAYLOAD_BYTES
    ):
        raise FollowupFormalArtifactError(f"{label} is not one bounded owned file")
    return path


def _sha256_file(path: Path) -> tuple[str, int]:
    path = _direct_file(path, label="formal payload")
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        total = 0
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > before.st_size:
                raise FollowupFormalArtifactError("formal payload grew while hashed")
            digest.update(block)
        after = os.fstat(descriptor)
        projection = lambda value: (  # noqa: E731 - stable stat projection
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if total != before.st_size or projection(before) != projection(after):
            raise FollowupFormalArtifactError("formal payload changed while hashed")
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _stable_read(path: Path, *, maximum: int = _MAX_WRAPPER_BYTES) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise FollowupFormalArtifactError("formal wrapper member violates its bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise FollowupFormalArtifactError("formal wrapper member changed while read")
        return bytes(content)
    finally:
        os.close(descriptor)


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:  # pragma: no cover - os.write advances or raises
                raise FollowupFormalArtifactError("formal wrapper write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _phase_role(phase: FollowupFormalPhase) -> str:
    if phase == "private-handoff":
        return "formal-synthetic-private-handoff"
    if phase == "guarded-final":
        return "formal-synthetic-guarded-shard"
    raise FollowupFormalArtifactError("formal synthetic phase is outside its closed domain")


def _scope(
    *,
    phase: FollowupFormalPhase,
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
) -> tuple[dict[str, object], str]:
    trace = validate_route_a_synthetic_trace(
        trace,
        scientific_profile=scientific_profile,
    )
    if trace.suite_role != "formal":
        raise FollowupFormalArtifactError("formal synthetic wrapper received qualification bytes")
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    shard_identity = route_a_synthetic_shard_identity(
        trace,
        lineage,
        scientific_profile=scientific_profile,
    )
    return (
        {
            "artifact_phase": phase,
            "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
            "evidence_freeze_S2_sha": lineage.workflow_head_sha,
            "experiment_source_S1_sha": lineage.experiment_source_sha,
            "formal_seed": trace.formal_seed,
            "provider_run_attempt": lineage.provider_run_attempt,
            "provider_run_id": lineage.provider_run_id,
            "scale": trace.scale,
            "shard_identity_sha256": shard_identity,
            "source_event_trace_sha256": trace.event_trace_sha256,
            "source_kind": "synthetic",
        },
        shard_identity,
    )


def _identity(
    *,
    phase: FollowupFormalPhase,
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    unit_attempt_ordinal: int,
) -> tuple[bytes, str, str]:
    if type(unit_attempt_ordinal) is not int or unit_attempt_ordinal != 1:
        raise FollowupFormalArtifactError(
            "formal synthetic replacement is unsupported and fails closed"
        )
    scope, shard_identity = _scope(
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
    )
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind="formal-synthetic",
        unit_attempt_ordinal=unit_attempt_ordinal,
        scope=scope,
    )
    return unit_bytes, unit_sha256, shard_identity


def expected_followup_formal_synthetic_artifact_name(
    *,
    phase: FollowupFormalPhase,
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    unit_attempt_ordinal: int = 1,
) -> str:
    """Derive the exact provider name without executing one scientific cell."""

    _unit_bytes, unit_sha256, _shard = _identity(
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    return followup_artifact_name(
        unit_kind="formal-synthetic",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )


def _inspect_inherited(
    payload_path: Path,
    *,
    phase: FollowupFormalPhase,
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
) -> RouteASyntheticSuiteProducerInspection | RouteASyntheticSuiteReplayInspection:
    if phase == "private-handoff":
        return inspect_route_a_synthetic_suite_handoff(
            payload_path,
            expected_trace=trace,
            expected_lineage=lineage,
            machine_plan_bytes=machine_plan_bytes,
            scientific_profile=scientific_profile,
        )
    return inspect_route_a_synthetic_suite_replay(
        payload_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=machine_plan_bytes,
        scientific_profile=scientific_profile,
    )


def _manifest(
    *,
    phase: FollowupFormalPhase,
    payload_sha256: str,
    payload_bytes: int,
    shard_identity_sha256: str,
) -> bytes:
    return _canonical_json_bytes(
        {
            "authority": False,
            "formal_evidence_candidate": phase == "guarded-final",
            "inherited_inner_schemas_unchanged": True,
            "payload": {
                "byte_count": payload_bytes,
                "path": _INNER_FILE,
                "sha256": payload_sha256,
            },
            "publication_evidence_admitted": False,
            "schema_version": _MANIFEST_SCHEMA,
            "shard_identity_sha256": shard_identity_sha256,
            "study_id": FOLLOWUP_STUDY_ID,
            "unit_phase": phase,
        }
    )


def _checksums(contents: dict[str, bytes]) -> bytes:
    return b"".join(
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in _WRAPPER_FILES
    )


@dataclass(frozen=True, slots=True)
class FollowupFormalSyntheticInspection:
    phase: FollowupFormalPhase
    root: Path
    payload_path: Path
    payload_sha256: str
    payload_byte_count: int
    artifact_name: str
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    inherited: RouteASyntheticSuiteProducerInspection | RouteASyntheticSuiteReplayInspection


def inspect_followup_formal_synthetic_artifact(
    root: Path,
    *,
    phase: FollowupFormalPhase,
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int = 1,
) -> FollowupFormalSyntheticInspection:
    """Rehash the outer tree before independently decoding its inherited ZIP."""

    root = _direct_directory(root, label="formal synthetic artifact root")
    expected_paths = {
        "checksums.sha256",
        "inner",
        _INNER_FILE,
        *_WRAPPER_FILES,
    }
    observed_paths = {
        path.relative_to(root).as_posix() for path in root.rglob("*")
    }
    if observed_paths != expected_paths or not (root / "inner").is_dir():
        raise FollowupFormalArtifactError("formal synthetic wrapper members changed")
    contents = {name: _stable_read(root / name) for name in _WRAPPER_FILES}
    if _stable_read(root / "checksums.sha256") != _checksums(contents):
        raise FollowupFormalArtifactError("formal synthetic wrapper checksums changed")
    manifest_value = _parse_ascii_json(
        contents["inner-payload.json"],
        label="formal synthetic inner manifest",
    )
    if type(manifest_value) is not dict:
        raise FollowupFormalArtifactError("formal synthetic manifest is not an object")
    manifest = manifest_value
    payload_path = _direct_file(root / _INNER_FILE, label="formal synthetic payload")
    payload_sha256, payload_bytes = _sha256_file(payload_path)
    unit_bytes, unit_sha256, shard_identity = _identity(
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    expected_manifest = _manifest(
        phase=phase,
        payload_sha256=payload_sha256,
        payload_bytes=payload_bytes,
        shard_identity_sha256=shard_identity,
    )
    if (
        contents["unit-identity.json"] != unit_bytes
        or contents["inner-payload.json"] != expected_manifest
        or manifest.get("payload")
        != {
            "byte_count": payload_bytes,
            "path": _INNER_FILE,
            "sha256": payload_sha256,
        }
    ):
        raise FollowupFormalArtifactError("formal synthetic wrapper identity changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        contents["inner-payload.json"],
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    if (
        envelope.document["unit_kind"] != "formal-synthetic"
        or envelope.document["inner_role"] != _phase_role(phase)
        or envelope.document["unit_identity_sha256"] != unit_sha256
    ):
        raise FollowupFormalArtifactError("formal synthetic envelope changed")
    inherited = _inspect_inherited(
        payload_path,
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    if inherited.shard_identity_sha256 != shard_identity:
        raise FollowupFormalArtifactError("formal synthetic inherited shard changed")
    return FollowupFormalSyntheticInspection(
        phase=phase,
        root=root,
        payload_path=payload_path,
        payload_sha256=payload_sha256,
        payload_byte_count=payload_bytes,
        artifact_name=followup_artifact_name(
            unit_kind="formal-synthetic",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        inherited=inherited,
    )


def produce_followup_formal_synthetic_artifact(
    source_payload: Path,
    output_directory: Path,
    *,
    phase: FollowupFormalPhase,
    trace: RouteASyntheticTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int = 1,
) -> FollowupFormalSyntheticInspection:
    """Validate and atomically move one fresh inherited ZIP into its outer tree."""

    source_payload = _direct_file(source_payload, label="fresh formal synthetic payload")
    output_parent = _direct_directory(
        output_directory.parent,
        label="formal synthetic output parent",
    )
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupFormalArtifactError("formal synthetic output target already exists")
    _inspect_inherited(
        source_payload,
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    payload_sha256, payload_bytes = _sha256_file(source_payload)
    unit_bytes, unit_sha256, shard_identity = _identity(
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    manifest_bytes = _manifest(
        phase=phase,
        payload_sha256=payload_sha256,
        payload_bytes=payload_bytes,
        shard_identity_sha256=shard_identity,
    )
    admission = _issue_followup_inner_admission(
        inner_role=_phase_role(phase),
        inner_bytes=manifest_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=lineage.experiment_source_sha,
        evidence_freeze_s2_sha=lineage.workflow_head_sha,
        unit_kind="formal-synthetic",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}-",
            dir=output_parent,
        )
    )
    moved = False
    try:
        (temporary / "inner").mkdir(mode=0o700)
        os.replace(source_payload, temporary / _INNER_FILE)
        moved = True
        contents = {
            "inner-payload.json": manifest_bytes,
            "outer-envelope.json": envelope.document_bytes,
            "unit-identity.json": unit_bytes,
        }
        for name in _WRAPPER_FILES:
            _write_new(temporary / name, contents[name])
        _write_new(temporary / "checksums.sha256", _checksums(contents))
        os.replace(temporary, output_directory)
        return inspect_followup_formal_synthetic_artifact(
            output_directory,
            phase=phase,
            trace=trace,
            lineage=lineage,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
    except BaseException:
        if moved and not source_payload.exists():
            candidate = temporary / _INNER_FILE
            if candidate.is_file() and not candidate.is_symlink():
                os.replace(candidate, source_payload)
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
