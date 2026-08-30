"""Follow-up outer identity for one formal native OpenFHE case.

The inherited q3/q4 directory remains byte-for-byte inspectable below
``inner/``.  This module binds that closed tree to one formal strategy/scale
case without changing the inherited Route A schemas.  A guarded case remains
an evidence candidate until the later seventeen-object terminal admission.
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

from dynamic_cssc.followup_performance_campaign import (
    followup_campaign_artifact_binding_scope,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
    _issue_followup_inner_admission,
    _parse_ascii_json,
    build_followup_unit_identity,
    followup_artifact_name,
    followup_inherited_unit_attempt_ordinal,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)
from dynamic_cssc.route_a_native_case import RouteANativeCasePlan
from dynamic_cssc.route_a_native_suite import (
    RouteANativeQualificationInspection,
    compile_route_a_native_formal_case,
    inspect_route_a_native_qualification_artifact,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FollowupFormalNativeArtifactError",
    "FollowupFormalNativeInspection",
    "expected_followup_formal_native_artifact_name",
    "inspect_followup_formal_native_artifact",
    "produce_followup_formal_native_artifact",
)

FollowupFormalNativePhase = Literal["private-handoff", "guarded-final"]

_INNER_TREE_SCHEMA = "dynamic-cssc-followup-performance-formal-native-inner-tree-v2"
_PRODUCER_OBSERVATION_SCHEMA = (
    "dynamic-cssc-followup-performance-formal-native-producer-observations-v2"
)
_PRODUCER_OBSERVATIONS_FILE = "producer-observations.json"
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)
_MAX_INNER_FILES = 4096
_MAX_WRAPPER_BYTES = 4 * 1024 * 1024


class FollowupFormalNativeArtifactError(FollowupContractError):
    """One native formal wrapper or inherited q3/q4 tree failed closed."""


def _direct_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be one absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise FollowupFormalNativeArtifactError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupFormalNativeArtifactError(f"{label} is not one direct directory")
    return path


def _sha256_file(path: Path) -> tuple[str, int]:
    try:
        before = path.lstat()
    except OSError as error:
        raise FollowupFormalNativeArtifactError("native member is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise FollowupFormalNativeArtifactError("native member is not one owned regular file")
    digest = hashlib.sha256()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        observed = os.fstat(descriptor)
        total = 0
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > before.st_size:
                raise FollowupFormalNativeArtifactError("native member grew while hashed")
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    projection = lambda value: (  # noqa: E731 - stable stat projection
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if total != before.st_size or projection(before) != projection(observed) or projection(
        before
    ) != projection(after):
        raise FollowupFormalNativeArtifactError("native member changed while hashed")
    return digest.hexdigest(), total


def _read_small(path: Path) -> bytes:
    digest, byte_count = _sha256_file(path)
    if not 0 < byte_count <= _MAX_WRAPPER_BYTES:
        raise FollowupFormalNativeArtifactError("native wrapper member exceeds its bound")
    content = path.read_bytes()
    if len(content) != byte_count or hashlib.sha256(content).hexdigest() != digest:
        raise FollowupFormalNativeArtifactError("native wrapper member changed after hashing")
    return content


def _tree_rows(root: Path) -> tuple[dict[str, object], ...]:
    root = _direct_directory(root, label="formal native inner root")
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        observed = path.lstat()
        if path.is_symlink():
            raise FollowupFormalNativeArtifactError("formal native tree contains a symlink")
        if stat.S_ISDIR(observed.st_mode):
            continue
        if not stat.S_ISREG(observed.st_mode):
            raise FollowupFormalNativeArtifactError(
                "formal native tree contains a special entry"
            )
        sha256, byte_count = _sha256_file(path)
        rows.append(
            {
                "byte_count": byte_count,
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256,
            }
        )
    if not rows or len(rows) > _MAX_INNER_FILES:
        raise FollowupFormalNativeArtifactError(
            "formal native tree file count is outside its closed bound"
        )
    return tuple(rows)


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write advances or raises
                raise FollowupFormalNativeArtifactError("native wrapper write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _phase_stage(phase: FollowupFormalNativePhase) -> tuple[str, str]:
    if phase == "private-handoff":
        return "q3", "formal-native-private-handoff"
    if phase == "guarded-final":
        return "q4", "formal-native-guarded-case"
    raise FollowupFormalNativeArtifactError("formal native phase is outside its domain")


def _case(
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    *,
    scale: str,
    formal_seed: int,
    strategy_candidate_id: str,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    unit_attempt_ordinal: int,
) -> RouteANativeCasePlan:
    return compile_route_a_native_formal_case(
        repository_root,
        lineage,
        scale=scale,
        formal_seed=formal_seed,
        strategy_candidate_id=strategy_candidate_id,
        unit_attempt_ordinal=followup_inherited_unit_attempt_ordinal(
            unit_kind="formal-native",
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )


def _identity(
    *,
    phase: FollowupFormalNativePhase,
    lineage: RouteASyntheticSuiteLineage,
    case: RouteANativeCasePlan,
    unit_attempt_ordinal: int,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
) -> tuple[bytes, str]:
    scope = {
        "artifact_phase": phase,
        "case_binding_sha256": case.case_binding_sha256,
        "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
        "evidence_freeze_S2_sha": lineage.workflow_head_sha,
        "experiment_source_S1_sha": lineage.experiment_source_sha,
        "formal_seed": case.trace.formal_seed,
        "inherited_unit_attempt_ordinal": case.unit_attempt_ordinal,
        "provider_run_attempt": lineage.provider_run_attempt,
        "provider_run_id": lineage.provider_run_id,
        "scale": case.trace.scale,
        "source_kind": "synthetic-native-snapshot",
        "strategy_candidate_id": case.strategy_candidate_id,
    }
    scope.update(
        followup_campaign_artifact_binding_scope(
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
        )
    )
    return build_followup_unit_identity(
        unit_kind="formal-native",
        unit_attempt_ordinal=unit_attempt_ordinal,
        scope=scope,
    )


def expected_followup_formal_native_artifact_name(
    *,
    phase: FollowupFormalNativePhase,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scale: str,
    formal_seed: int,
    strategy_candidate_id: str,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    unit_attempt_ordinal: int = 1,
) -> str:
    """Derive the provider name for one exact native phase without execution."""

    _phase_stage(phase)
    case = _case(
        repository_root,
        lineage,
        scale=scale,
        formal_seed=formal_seed,
        strategy_candidate_id=strategy_candidate_id,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    _unit_bytes, unit_sha256 = _identity(
        phase=phase,
        lineage=lineage,
        case=case,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
    )
    return followup_artifact_name(
        unit_kind="formal-native",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )


def _manifest(
    *,
    phase: FollowupFormalNativePhase,
    rows: tuple[dict[str, object], ...],
    case: RouteANativeCasePlan,
    producer_observations_bytes: bytes | None,
) -> bytes:
    rows_bytes = _canonical_json_bytes(list(rows))
    return _canonical_json_bytes(
        {
            "authority": False,
            "case_binding_sha256": case.case_binding_sha256,
            "files": list(rows),
            "files_sha256": hashlib.sha256(rows_bytes).hexdigest(),
            "formal_evidence_candidate": phase == "guarded-final",
            "inherited_inner_schemas_unchanged": True,
            "publication_evidence_admitted": False,
            "producer_observations_sha256_or_null": (
                None
                if producer_observations_bytes is None
                else hashlib.sha256(producer_observations_bytes).hexdigest()
            ),
            "schema_version": _INNER_TREE_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
            "unit_phase": phase,
        }
    )


def _wrapper_files(phase: FollowupFormalNativePhase) -> tuple[str, ...]:
    _phase_stage(phase)
    if phase == "guarded-final":
        return (*_WRAPPER_FILES, _PRODUCER_OBSERVATIONS_FILE)
    return _WRAPPER_FILES


def _checksums(
    contents: dict[str, bytes],
    *,
    phase: FollowupFormalNativePhase,
) -> bytes:
    return b"".join(
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in _wrapper_files(phase)
    )


def _producer_observations(
    producer: RouteANativeQualificationInspection,
    *,
    inner: Path,
    case: RouteANativeCasePlan,
) -> bytes:
    if producer.stage != "q3" or producer.case_binding_sha256 != case.case_binding_sha256:
        raise FollowupFormalNativeArtifactError(
            "formal native producer observation source changed"
        )
    stage_ledger = _parse_ascii_json(
        _read_small(inner / "stage-ledger.json"),
        label="formal native q3 stage ledger",
    )
    warmup = _parse_ascii_json(
        _read_small(inner / "warmup-receipt.json"),
        label="formal native q3 warm-up receipt",
    )
    if type(stage_ledger) is not dict or type(warmup) is not dict:
        raise FollowupFormalNativeArtifactError(
            "formal native producer observations are not closed objects"
        )
    packages = []
    for ordinal, package in enumerate(producer.packages):
        bytes_by_role: dict[str, int] = {}
        for member in package.members:
            bytes_by_role[member.role] = (
                bytes_by_role.get(member.role, 0) + member.byte_count
            )
        member_bytes = sum(member.byte_count for member in package.members)
        packages.append(
            {
                "bytes_by_role": dict(sorted(bytes_by_role.items())),
                "member_count": len(package.members),
                "package_manifest_sha256": package.manifest_sha256,
                "process_ordinal": ordinal,
                "serialized_member_bytes": member_bytes,
                "serialized_package_bytes": len(package.manifest_bytes) + member_bytes,
            }
        )
    if len(packages) != 3:
        raise FollowupFormalNativeArtifactError(
            "formal native producer lacks three retained packages"
        )
    return _canonical_json_bytes(
        {
            "authority": False,
            "case_binding_sha256": case.case_binding_sha256,
            "producer_stage_ledger": stage_ledger,
            "publication_evidence_admitted": False,
            "q3_stage_manifest_sha256": producer.manifest_sha256,
            "recorded_packages": packages,
            "schema_version": _PRODUCER_OBSERVATION_SCHEMA,
            "warmup_receipt": warmup,
        }
    )


def _validate_producer_observations(
    content: bytes,
    *,
    inherited: RouteANativeQualificationInspection,
    case: RouteANativeCasePlan,
) -> None:
    value = _parse_ascii_json(content, label="formal native producer observations")
    packages = value.get("recorded_packages") if type(value) is dict else None
    packages_valid = (
        type(packages) is list
        and len(packages) == 3
        and all(
            type(row) is dict
            and set(row)
            == {
                "bytes_by_role",
                "member_count",
                "package_manifest_sha256",
                "process_ordinal",
                "serialized_member_bytes",
                "serialized_package_bytes",
            }
            and row.get("process_ordinal") == ordinal
            and type(row.get("member_count")) is int
            and row["member_count"] > 0
            and type(row.get("serialized_member_bytes")) is int
            and row["serialized_member_bytes"] > 0
            and type(row.get("serialized_package_bytes")) is int
            and row["serialized_package_bytes"] > row["serialized_member_bytes"]
            and type(row.get("package_manifest_sha256")) is str
            and len(row["package_manifest_sha256"]) == 64
            and all(character in "0123456789abcdef" for character in row["package_manifest_sha256"])
            and type(row.get("bytes_by_role")) is dict
            and bool(row["bytes_by_role"])
            and all(
                type(role) is str
                and bool(role)
                and type(byte_count) is int
                and byte_count > 0
                for role, byte_count in row["bytes_by_role"].items()
            )
            and sum(row["bytes_by_role"].values()) == row["serialized_member_bytes"]
            for ordinal, row in enumerate(packages)
        )
    )
    if (
        type(value) is not dict
        or set(value)
        != {
            "authority",
            "case_binding_sha256",
            "producer_stage_ledger",
            "publication_evidence_admitted",
            "q3_stage_manifest_sha256",
            "recorded_packages",
            "schema_version",
            "warmup_receipt",
        }
        or value.get("schema_version") != _PRODUCER_OBSERVATION_SCHEMA
        or value.get("authority") is not False
        or value.get("publication_evidence_admitted") is not False
        or value.get("case_binding_sha256") != case.case_binding_sha256
        or value.get("q3_stage_manifest_sha256")
        != inherited.input_q3_manifest_sha256
        or type(value.get("producer_stage_ledger")) is not dict
        or type(value.get("warmup_receipt")) is not dict
        or not packages_valid
        or _canonical_json_bytes(value) != content
    ):
        raise FollowupFormalNativeArtifactError(
            "formal native producer observations changed"
        )


def _inspect_inherited(
    inner: Path,
    *,
    phase: FollowupFormalNativePhase,
    lineage: RouteASyntheticSuiteLineage,
    case: RouteANativeCasePlan,
) -> RouteANativeQualificationInspection:
    stage, _role = _phase_stage(phase)
    inherited = inspect_route_a_native_qualification_artifact(
        inner,
        expected_stage=stage,
        expected_lineage=lineage,
    )
    if (
        inherited.case_binding_sha256 != case.case_binding_sha256
        or inherited.case_binding_bytes != case.case_binding_bytes
        or inherited.structural_vector_bytes != case.structural_vector_bytes
    ):
        raise FollowupFormalNativeArtifactError(
            "formal native inner case differs from its exact compiled case"
        )
    return inherited


@dataclass(frozen=True, slots=True)
class FollowupFormalNativeInspection:
    phase: FollowupFormalNativePhase
    artifact_name: str
    root: Path
    inner_directory: Path
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    inherited: RouteANativeQualificationInspection
    case: RouteANativeCasePlan
    producer_observations_bytes: bytes | None


def inspect_followup_formal_native_artifact(
    artifact_directory: Path,
    *,
    phase: FollowupFormalNativePhase,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scale: str,
    formal_seed: int,
    strategy_candidate_id: str,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    unit_attempt_ordinal: int = 1,
) -> FollowupFormalNativeInspection:
    """Rehash the outer tree before independently decoding inherited q3/q4."""

    artifact_directory = _direct_directory(
        artifact_directory,
        label="formal native artifact directory",
    )
    entries = {entry.name: entry for entry in artifact_directory.iterdir()}
    wrapper_files = _wrapper_files(phase)
    if set(entries) != {*wrapper_files, "checksums.sha256", "inner"}:
        raise FollowupFormalNativeArtifactError("formal native wrapper members changed")
    inner = _direct_directory(entries["inner"], label="formal native inherited tree")
    contents = {name: _read_small(entries[name]) for name in wrapper_files}
    if _read_small(entries["checksums.sha256"]) != _checksums(
        contents,
        phase=phase,
    ):
        raise FollowupFormalNativeArtifactError("formal native wrapper checksums changed")
    case = _case(
        repository_root,
        lineage,
        scale=scale,
        formal_seed=formal_seed,
        strategy_candidate_id=strategy_candidate_id,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    unit_bytes, unit_sha256 = _identity(
        phase=phase,
        lineage=lineage,
        case=case,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
    )
    if contents["unit-identity.json"] != unit_bytes:
        raise FollowupFormalNativeArtifactError("formal native unit identity changed")
    inherited = _inspect_inherited(
        inner,
        phase=phase,
        lineage=lineage,
        case=case,
    )
    producer_observations = contents.get(_PRODUCER_OBSERVATIONS_FILE)
    if phase == "guarded-final":
        if producer_observations is None:
            raise FollowupFormalNativeArtifactError(
                "formal native final lacks producer observations"
            )
        _validate_producer_observations(
            producer_observations,
            inherited=inherited,
            case=case,
        )
    elif producer_observations is not None:
        raise FollowupFormalNativeArtifactError(
            "formal native handoff contains final producer observations"
        )
    rows = _tree_rows(inner)
    manifest_bytes = _manifest(
        phase=phase,
        rows=rows,
        case=case,
        producer_observations_bytes=producer_observations,
    )
    manifest = _parse_ascii_json(
        contents["inner-payload.json"],
        label="formal native inner manifest",
    )
    if (
        type(manifest) is not dict
        or contents["inner-payload.json"] != manifest_bytes
        or manifest.get("files") != list(rows)
    ):
        raise FollowupFormalNativeArtifactError("formal native inner manifest changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        contents["inner-payload.json"],
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    _stage, role = _phase_stage(phase)
    if (
        envelope.document["unit_kind"] != "formal-native"
        or envelope.document["inner_role"] != role
        or envelope.document["unit_identity_sha256"] != unit_sha256
        or envelope.document["unit_attempt_ordinal"] != unit_attempt_ordinal
    ):
        raise FollowupFormalNativeArtifactError("formal native envelope changed")
    return FollowupFormalNativeInspection(
        phase=phase,
        artifact_name=followup_artifact_name(
            unit_kind="formal-native",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
        root=artifact_directory,
        inner_directory=inner,
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        inherited=inherited,
        case=case,
        producer_observations_bytes=producer_observations,
    )


def produce_followup_formal_native_artifact(
    source_directory: Path,
    output_directory: Path,
    *,
    phase: FollowupFormalNativePhase,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scale: str,
    formal_seed: int,
    strategy_candidate_id: str,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    unit_attempt_ordinal: int = 1,
    producer_artifact_directory: Path | None = None,
) -> FollowupFormalNativeInspection:
    """Validate and atomically install one fresh inherited native tree."""

    source_directory = _direct_directory(
        source_directory,
        label="fresh formal native source",
    )
    _direct_directory(output_directory.parent, label="formal native output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupFormalNativeArtifactError("formal native output already exists")
    case = _case(
        repository_root,
        lineage,
        scale=scale,
        formal_seed=formal_seed,
        strategy_candidate_id=strategy_candidate_id,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    inherited = _inspect_inherited(
        source_directory,
        phase=phase,
        lineage=lineage,
        case=case,
    )
    producer_observations: bytes | None = None
    if phase == "private-handoff":
        if producer_artifact_directory is not None:
            raise FollowupFormalNativeArtifactError(
                "formal native producer wrapper received a producer artifact"
            )
    else:
        if producer_artifact_directory is None:
            raise FollowupFormalNativeArtifactError(
                "formal native final wrapper lacks its producer artifact"
            )
        producer_wrapper = inspect_followup_formal_native_artifact(
            producer_artifact_directory,
            phase="private-handoff",
            repository_root=repository_root,
            lineage=lineage,
            scale=scale,
            formal_seed=formal_seed,
            strategy_candidate_id=strategy_candidate_id,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
        if inherited.input_q3_manifest_sha256 != producer_wrapper.inherited.manifest_sha256:
            raise FollowupFormalNativeArtifactError(
                "formal native final q3 manifest binding changed"
            )
        producer_observations = _producer_observations(
            producer_wrapper.inherited,
            inner=producer_wrapper.inner_directory,
            case=case,
        )
    rows = _tree_rows(source_directory)
    manifest_bytes = _manifest(
        phase=phase,
        rows=rows,
        case=case,
        producer_observations_bytes=producer_observations,
    )
    unit_bytes, unit_sha256 = _identity(
        phase=phase,
        lineage=lineage,
        case=case,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
    )
    _stage, role = _phase_stage(phase)
    admission = _issue_followup_inner_admission(
        inner_role=role,
        inner_bytes=manifest_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=lineage.experiment_source_sha,
        evidence_freeze_s2_sha=lineage.workflow_head_sha,
        unit_kind="formal-native",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    moved = False
    try:
        os.replace(source_directory, temporary / "inner")
        moved = True
        contents = {
            "inner-payload.json": manifest_bytes,
            "outer-envelope.json": envelope.document_bytes,
            "unit-identity.json": unit_bytes,
        }
        if producer_observations is not None:
            contents[_PRODUCER_OBSERVATIONS_FILE] = producer_observations
        for name in _wrapper_files(phase):
            _write_new(temporary / name, contents[name])
        _write_new(
            temporary / "checksums.sha256",
            _checksums(contents, phase=phase),
        )
        os.replace(temporary, output_directory)
        return inspect_followup_formal_native_artifact(
            output_directory,
            phase=phase,
            repository_root=repository_root,
            lineage=lineage,
            scale=scale,
            formal_seed=formal_seed,
            strategy_candidate_id=strategy_candidate_id,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
    except BaseException:
        if moved and not source_directory.exists() and (temporary / "inner").is_dir():
            os.replace(temporary / "inner", source_directory)
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
