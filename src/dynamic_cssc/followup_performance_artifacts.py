"""Follow-up-only outer identity for inherited qualification artifact trees.

The inherited Route A tree remains byte-for-byte inspectable under ``inner/``.
This module adds only a small canonical tree manifest, unit identity, and outer
envelope.  It consumes a freshly produced directory by same-filesystem rename;
it never recompresses or rewrites the potentially large scientific payload.
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
from dynamic_cssc.route_a_native_suite import (
    RouteANativeQualificationInspection,
    compile_route_a_native_qualification_case,
    inspect_route_a_native_qualification_artifact,
)
from dynamic_cssc.route_a_postrun_admission import (
    RouteAPostrunAdmissionInspection,
    inspect_route_a_postrun_admission,
)
from dynamic_cssc.route_a_qualification_guard import (
    RouteACombinedGuardInspection,
    inspect_route_a_combined_guard_artifact,
)
from dynamic_cssc.route_a_qualification_runtime import (
    RouteAQualificationStageArtifactInspection,
    inspect_route_a_qualification_stage_artifact,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    inspect_route_a_synthetic_suite_handoff,
    inspect_route_a_synthetic_suite_replay,
)
from dynamic_cssc.route_a_workloads import generate_route_a_qualification_trace

__all__ = (
    "FollowupQualificationArtifactInspection",
    "expected_followup_qualification_artifact_name",
    "inspect_followup_qualification_artifact",
    "produce_followup_qualification_artifact",
)

FollowupQualificationStage = Literal["q1", "q2", "q3", "q4", "q5", "q6"]

_INNER_TREE_SCHEMA = "dynamic-cssc-followup-performance-inner-tree-v1"
_STAGE_BINDING = {
    "q1": ("qualification-q1", "simulator-private-handoff"),
    "q2": ("qualification-q2", "simulator-guarded-receipt"),
    "q3": ("qualification-q3", "native-private-handoff"),
    "q4": ("qualification-q4", "native-guarded-receipt"),
    "q5": ("qualification-q5", "combined-guard"),
    "q6": ("qualification-q6", "postrun-admission"),
}
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)
_MAX_INNER_FILES = 2048
_MAX_MANIFEST_BYTES = 1024 * 1024


class FollowupArtifactError(FollowupContractError):
    """A follow-up wrapper or inherited inner artifact failed closed."""


def _direct_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be one absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise FollowupArtifactError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupArtifactError(f"{label} is not one direct directory")
    return path


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise FollowupArtifactError("inner artifact member is not one owned regular file")
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
                total += len(block)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise FollowupArtifactError("inner artifact member cannot be read safely") from error
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ) or total != before.st_size:
        raise FollowupArtifactError("inner artifact member changed while hashing")
    return digest.hexdigest(), total


def _tree_rows(root: Path) -> tuple[dict[str, object], ...]:
    root = _direct_directory(root, label="inner artifact root")
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        observed = path.lstat()
        if path.is_symlink():
            raise FollowupArtifactError("inner artifact tree contains a symlink")
        if stat.S_ISDIR(observed.st_mode):
            continue
        if not stat.S_ISREG(observed.st_mode):
            raise FollowupArtifactError("inner artifact tree contains a special entry")
        sha256, byte_count = _sha256_file(path)
        rows.append(
            {
                "byte_count": byte_count,
                "path": relative,
                "sha256": sha256,
            }
        )
    if not rows or len(rows) > _MAX_INNER_FILES:
        raise FollowupArtifactError("inner artifact file count is outside its closed bound")
    return tuple(rows)


def _qualification_scope(
    *,
    stage: FollowupQualificationStage,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
) -> dict[str, object]:
    if stage not in _STAGE_BINDING:
        raise FollowupArtifactError("follow-up qualification stage is not closed")
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    if type(scientific_profile) is not RouteAScientificProfile:
        raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
    return {
        "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
        "evidence_freeze_S2_sha": lineage.workflow_head_sha,
        "experiment_source_S1_sha": lineage.experiment_source_sha,
        "provider_run_attempt": lineage.provider_run_attempt,
        "provider_run_id": lineage.provider_run_id,
        "qualification_seed": scientific_profile.qualification_seed,
        "qualification_stage": stage,
        "rho_values": ["1/100", "1/10", "1", "10"],
        "workload": "mixed-insert-delete-modify",
    }


def _inner_manifest(
    *,
    stage: FollowupQualificationStage,
    rows: tuple[dict[str, object], ...],
) -> bytes:
    rows_bytes = _canonical_json_bytes(list(rows))
    return _canonical_json_bytes(
        {
            "authority": False,
            "files": list(rows),
            "files_sha256": hashlib.sha256(rows_bytes).hexdigest(),
            "inherited_inner_schemas_unchanged": True,
            "publication_evidence": False,
            "qualification_stage": stage,
            "schema_version": _INNER_TREE_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )


def _checksums(contents: dict[str, bytes]) -> bytes:
    return b"".join(
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in _WRAPPER_FILES
    )


@dataclass(frozen=True, slots=True)
class FollowupQualificationArtifactInspection:
    """One closed outer wrapper and its independently inspected inner tree."""

    stage: FollowupQualificationStage
    artifact_name: str
    unit_identity_bytes: bytes
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    inner_manifest_bytes: bytes
    inner_directory: Path
    inherited: (
        RouteAQualificationStageArtifactInspection
        | RouteANativeQualificationInspection
        | RouteACombinedGuardInspection
        | RouteAPostrunAdmissionInspection
    )


def expected_followup_qualification_artifact_name(
    *,
    stage: FollowupQualificationStage,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
) -> str:
    """Derive the sole provider name for one exact qualification stage."""

    scope = _qualification_scope(
        stage=stage,
        lineage=lineage,
        scientific_profile=scientific_profile,
    )
    unit_kind, _inner_role = _STAGE_BINDING[stage]
    _unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind=unit_kind,
        unit_attempt_ordinal=1,
        scope=scope,
    )
    return followup_artifact_name(
        unit_kind=unit_kind,
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )


def _inspect_inherited(
    inner_directory: Path,
    *,
    stage: FollowupQualificationStage,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
) -> (
    RouteAQualificationStageArtifactInspection
    | RouteANativeQualificationInspection
    | RouteACombinedGuardInspection
    | RouteAPostrunAdmissionInspection
):
    if stage in {"q1", "q2"}:
        inherited = inspect_route_a_qualification_stage_artifact(
            inner_directory,
            expected_stage=stage,
            expected_lineage=lineage,
        )
        trace = generate_route_a_qualification_trace(
            scale="M",
            qualification_seed=scientific_profile.qualification_seed,
            scientific_profile=scientific_profile,
        )
        if stage == "q1":
            inspect_route_a_synthetic_suite_handoff(
                inherited.payload_path,
                expected_trace=trace,
                expected_lineage=lineage,
                machine_plan_bytes=machine_plan_bytes,
                scientific_profile=scientific_profile,
            )
        else:
            inspect_route_a_synthetic_suite_replay(
                inherited.payload_path,
                expected_trace=trace,
                expected_lineage=lineage,
                machine_plan_bytes=machine_plan_bytes,
                scientific_profile=scientific_profile,
            )
        return inherited
    if stage == "q5":
        return inspect_route_a_combined_guard_artifact(
            inner_directory,
            expected_lineage=lineage,
            machine_plan_bytes=machine_plan_bytes,
            scientific_profile=scientific_profile,
            expected_q2_provider_name=expected_followup_qualification_artifact_name(
                stage="q2",
                lineage=lineage,
                scientific_profile=scientific_profile,
            ),
            expected_q4_provider_name=expected_followup_qualification_artifact_name(
                stage="q4",
                lineage=lineage,
                scientific_profile=scientific_profile,
            ),
        )
    if stage == "q6":
        return inspect_route_a_postrun_admission(inner_directory)
    inherited_native = inspect_route_a_native_qualification_artifact(
        inner_directory,
        expected_stage=stage,
        expected_lineage=lineage,
    )
    expected_case = compile_route_a_native_qualification_case(
        repository_root,
        lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    if (
        inherited_native.case_binding_sha256 != expected_case.case_binding_sha256
        or inherited_native.case_binding_bytes != expected_case.case_binding_bytes
        or inherited_native.structural_vector_bytes != expected_case.structural_vector_bytes
    ):
        raise FollowupArtifactError("follow-up native inner case differs from its profile")
    return inherited_native


def _inspect_wrapper(
    artifact_directory: Path,
    *,
    stage: FollowupQualificationStage,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    repository_root: Path,
) -> FollowupQualificationArtifactInspection:
    artifact_directory = _direct_directory(
        artifact_directory,
        label="follow-up artifact directory",
    )
    entries = {entry.name: entry for entry in artifact_directory.iterdir()}
    if set(entries) != {*_WRAPPER_FILES, "checksums.sha256", "inner"}:
        raise FollowupArtifactError("follow-up artifact wrapper is missing, extra, or open")
    inner_directory = _direct_directory(entries["inner"], label="follow-up inner directory")
    contents: dict[str, bytes] = {}
    for name in _WRAPPER_FILES:
        path = entries[name]
        digest, byte_count = _sha256_file(path)
        if byte_count <= 0 or byte_count > _MAX_MANIFEST_BYTES:
            raise FollowupArtifactError("follow-up wrapper member exceeds its byte bound")
        contents[name] = path.read_bytes()
        if hashlib.sha256(contents[name]).hexdigest() != digest:
            raise FollowupArtifactError("follow-up wrapper member changed after its stable read")
    if entries["checksums.sha256"].read_bytes() != _checksums(contents):
        raise FollowupArtifactError("follow-up wrapper checksums changed")

    scope = _qualification_scope(
        stage=stage,
        lineage=lineage,
        scientific_profile=scientific_profile,
    )
    unit_kind, inner_role = _STAGE_BINDING[stage]
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind=unit_kind,
        unit_attempt_ordinal=1,
        scope=scope,
    )
    if contents["unit-identity.json"] != unit_bytes:
        raise FollowupArtifactError("follow-up unit identity changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        contents["inner-payload.json"],
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    if (
        envelope.document["unit_kind"] != unit_kind
        or envelope.document["inner_role"] != inner_role
        or envelope.document["unit_identity_sha256"] != unit_sha256
        or envelope.document["unit_attempt_ordinal"] != 1
    ):
        raise FollowupArtifactError("follow-up envelope differs from its exact unit")

    manifest = _parse_ascii_json(
        contents["inner-payload.json"],
        label="follow-up inner tree manifest",
    )
    rows = _tree_rows(inner_directory)
    expected_manifest = _inner_manifest(stage=stage, rows=rows)
    if (
        type(manifest) is not dict
        or contents["inner-payload.json"] != expected_manifest
        or manifest.get("files") != list(rows)
    ):
        raise FollowupArtifactError("follow-up inner tree manifest changed")
    inherited = _inspect_inherited(
        inner_directory,
        stage=stage,
        repository_root=repository_root,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    return FollowupQualificationArtifactInspection(
        stage=stage,
        artifact_name=expected_followup_qualification_artifact_name(
            stage=stage,
            lineage=lineage,
            scientific_profile=scientific_profile,
        ),
        unit_identity_bytes=unit_bytes,
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        inner_manifest_bytes=contents["inner-payload.json"],
        inner_directory=inner_directory,
        inherited=inherited,
    )


def produce_followup_qualification_artifact(
    source_directory: Path,
    output_directory: Path,
    *,
    stage: FollowupQualificationStage,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    repository_root: Path,
) -> FollowupQualificationArtifactInspection:
    """Consume one verified inherited tree and atomically install its outer wrapper."""

    source_directory = _direct_directory(source_directory, label="inherited source directory")
    _direct_directory(output_directory.parent, label="follow-up output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupArtifactError("follow-up output directory must be absent")
    _inspect_inherited(
        source_directory,
        stage=stage,
        repository_root=repository_root,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    scope = _qualification_scope(
        stage=stage,
        lineage=lineage,
        scientific_profile=scientific_profile,
    )
    unit_kind, inner_role = _STAGE_BINDING[stage]
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind=unit_kind,
        unit_attempt_ordinal=1,
        scope=scope,
    )
    rows = _tree_rows(source_directory)
    inner_manifest_bytes = _inner_manifest(stage=stage, rows=rows)
    admission = _issue_followup_inner_admission(
        inner_role=inner_role,
        inner_bytes=inner_manifest_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=lineage.experiment_source_sha,
        evidence_freeze_s2_sha=lineage.workflow_head_sha,
        unit_kind=unit_kind,
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    moved = False
    try:
        os.replace(source_directory, temporary / "inner")
        moved = True
        contents = {
            "inner-payload.json": inner_manifest_bytes,
            "outer-envelope.json": envelope.document_bytes,
            "unit-identity.json": unit_bytes,
        }
        for name in _WRAPPER_FILES:
            path = temporary / name
            with path.open("xb") as output:
                output.write(contents[name])
                output.flush()
                os.fsync(output.fileno())
        with (temporary / "checksums.sha256").open("xb") as output:
            output.write(_checksums(contents))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, output_directory)
        return _inspect_wrapper(
            output_directory,
            stage=stage,
            lineage=lineage,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            repository_root=repository_root,
        )
    except BaseException:
        if moved and not source_directory.exists() and (temporary / "inner").is_dir():
            os.replace(temporary / "inner", source_directory)
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise


def inspect_followup_qualification_artifact(
    artifact_directory: Path,
    *,
    stage: FollowupQualificationStage,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    repository_root: Path,
) -> FollowupQualificationArtifactInspection:
    """Rehash the outer wrapper before exposing the inherited inner directory."""

    return _inspect_wrapper(
        artifact_directory,
        stage=stage,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
        repository_root=repository_root,
    )
