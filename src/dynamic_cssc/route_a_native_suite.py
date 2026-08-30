"""Closed q3 producer and q4 independent replay for Route A qualification.

q3 is the sole owner of the discarded warm-up, three fresh-key recorded
producers, compact retained runner build, and three private replay packages.
q4 accepts only that closed provider tree, restores rather than rebuilds the
runner, replays recorded ordinals 0/1/2, and emits a redacted guard bundle.
Neither output is publication evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.route_a_contract import RouteAEvaluationLane
from dynamic_cssc.route_a_native_build import (
    inspect_route_a_native_build,
    install_route_a_native_build,
    produce_route_a_native_build,
)
from dynamic_cssc.route_a_native_case import (
    RouteANativeCasePlan,
    compile_route_a_terminal_native_case,
)
from dynamic_cssc.route_a_native_guard import guard_route_a_native_replays
from dynamic_cssc.route_a_native_invocation import (
    authorize_route_a_native_invocation,
    prepare_route_a_native_invocation,
)
from dynamic_cssc.route_a_native_runtime import (
    RouteANativeProducerExecution,
    RouteANativeReplayExecution,
    execute_route_a_native_producer,
    execute_route_a_native_replay,
)
from dynamic_cssc.route_a_openfhe_package import (
    RouteAOpenFHEPackageInspection,
    inspect_route_a_openfhe_package,
    read_route_a_openfhe_package_member,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    route_a_synthetic_shard_identity,
)
from dynamic_cssc.route_a_workloads import (
    generate_route_a_formal_trace,
    generate_route_a_qualification_trace,
    validate_route_a_synthetic_trace,
)

__all__ = (
    "RouteANativeQualificationError",
    "RouteANativeQualificationInspection",
    "compile_route_a_native_formal_case",
    "compile_route_a_native_qualification_case",
    "inspect_route_a_native_qualification_artifact",
    "produce_route_a_native_qualification_handoff",
    "replay_and_guard_route_a_native_qualification",
)

_Q3_SCHEMA = "dynamic-cssc-route-a-native-qualification-handoff-v1"
_Q4_SCHEMA = "dynamic-cssc-route-a-native-qualification-replay-v1"
_WARMUP_SCHEMA = "dynamic-cssc-route-a-native-warmup-receipt-v1"
_REPLAY_SCHEMA = "dynamic-cssc-route-a-native-replay-receipt-v1"
_STAGE_LEDGER_SCHEMA = "dynamic-cssc-route-a-native-stage-ledger-v1"
_STRATEGY = "packed-coo-cloud-segmented-delta/segment-width=128"
_RUNNER = "build/cpp/openfhe_query_runner"
_MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_STAGE_ARTIFACT_NAME = {
    "q3": "q3-native-pre-replay-build-plus-three-retained-packages",
    "q4": "q4-native-guarded-case-bundle",
}
_PROCESS_ROW_FIELDS = {
    "elapsed_ns",
    "execution_process_role",
    "lane_sha256",
    "peak_resident_memory_bytes",
    "peak_scratch_bytes",
    "process_ordinal_or_null",
    "request_sha256",
    "runner_build_identity_sha256",
}
_WARMUP_FIELDS = _PROCESS_ROW_FIELDS | {
    "authority_granted",
    "package_retained",
    "publication_evidence",
    "schema_version",
}
_REPLAY_FIELDS = {
    "authority_granted",
    "cloud_program_operation_inventory",
    "elapsed_ns",
    "lane_sha256",
    "lifecycle_operation_inventory",
    "package_manifest_sha256",
    "peak_resident_memory_bytes",
    "peak_scratch_bytes",
    "preparation_sha256",
    "producer_request_sha256",
    "publication_evidence",
    "reconstructed_output_sha256",
    "replay_request_sha256",
    "runner_build_identity_sha256",
    "schema_version",
}
_GUARD_FIELDS = {
    "accepted",
    "authority_granted",
    "build_manifest_sha256",
    "case_binding_sha256",
    "cloud_program_operation_inventory",
    "crypto_context_parameter_sha256",
    "freshness_checks",
    "lane_binding_sha256s",
    "mechanism_coverage",
    "native_resource_observations",
    "package_manifest_sha256s",
    "process_ordinals",
    "publication_evidence",
    "runner_build_identity_sha256",
    "schema_version",
    "structural_vector_sha256",
}


class RouteANativeQualificationError(RuntimeError):
    """One q3/q4 native qualification boundary failed closed."""


def _sha256(value: object, *, field: str) -> str:
    if not _is_sha256(value):
        raise RouteANativeQualificationError(f"{field} must be lowercase SHA-256")
    assert type(value) is str
    return value


def _is_sha256(value: object) -> bool:
    return type(value) is str and _LOWER_SHA256.fullmatch(value) is not None


def _direct_directory(path: Path, *, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{field} must be one absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise RouteANativeQualificationError(f"{field} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise RouteANativeQualificationError(f"{field} must be one direct directory")
    return path


def _remove_private_tree(path: Path, *, field: str) -> None:
    if path.is_symlink():
        raise RouteANativeQualificationError(f"{field} became a symbolic link")
    if path.exists():
        shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        raise RouteANativeQualificationError(f"{field} cleanup failed")


def _canonical_object(content: bytes, *, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteANativeQualificationError(f"{field} contains duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(content.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteANativeQualificationError(f"{field} is not ASCII JSON") from error
    if type(document) is not dict or canonical_route_a_document(document) != content:
        raise RouteANativeQualificationError(f"{field} is not canonical JSON")
    return document


def _stable_read(path: Path, *, maximum: int = _MAX_FILE_BYTES) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteANativeQualificationError("native artifact member is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise RouteANativeQualificationError("native artifact member exceeds its bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        projection = lambda value: (  # noqa: E731 - compact stable stat projection
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or projection(before) != projection(after)
        ):
            raise RouteANativeQualificationError("native artifact member changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _write_new(path: Path, content: bytes, *, mode: int = 0o400) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write raises or advances
                raise RouteANativeQualificationError("native artifact write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _tree_members(root: Path, *, omit_control: bool) -> tuple[tuple[str, bytes], ...]:
    members: list[tuple[str, bytes]] = []
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise RouteANativeQualificationError("native artifact contains a symbolic link")
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode):
            raise RouteANativeQualificationError("native artifact contains a special file")
        if omit_control and relative in {"manifest.json", "checksums.sha256"}:
            continue
        content = _stable_read(path)
        total += len(content)
        if total > _MAX_TOTAL_BYTES:
            raise RouteANativeQualificationError("native artifact exceeds its total byte bound")
        members.append((relative, content))
    return tuple(members)


def _manifest(
    *,
    stage: str,
    lineage: RouteASyntheticSuiteLineage,
    case: RouteANativeCasePlan,
    build_manifest_sha256: str,
    input_q3_manifest_sha256: str | None,
    members: tuple[tuple[str, bytes], ...],
) -> bytes:
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "build_manifest_sha256": build_manifest_sha256,
            "case_binding_sha256": case.case_binding_sha256,
            "formal_artifact": False,
            "input_q3_manifest_sha256_or_null": input_q3_manifest_sha256,
            "lineage_sha256": lineage.sha256,
            "members": [
                {
                    "byte_count": len(content),
                    "path": path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for path, content in members
            ],
            "private_replay_material_included": stage == "q3",
            "provider_artifact_name": _STAGE_ARTIFACT_NAME[stage],
            "retention_days": 1,
            "schema_version": _Q3_SCHEMA if stage == "q3" else _Q4_SCHEMA,
            "stage": stage,
        }
    )


def _checksums(members: tuple[tuple[str, bytes], ...], manifest_bytes: bytes) -> bytes:
    return b"".join(
        f"{hashlib.sha256(content).hexdigest()}  {path}\n".encode("ascii")
        for path, content in (*members, ("manifest.json", manifest_bytes))
    )


def _lane(case: RouteANativeCasePlan, ordinal: int | None) -> RouteAEvaluationLane:
    arguments = {
        "shard_identity_sha256": case.shard_identity_sha256,
        "strategy_candidate_id": case.strategy_candidate_id,
        "rho": Fraction(1),
        "unit_attempt_ordinal": case.unit_attempt_ordinal,
    }
    if ordinal is None:
        return RouteAEvaluationLane.openfhe_warmup(**arguments)
    return RouteAEvaluationLane.openfhe_recorded(
        **arguments,
        process_ordinal=ordinal,
    )


def _process_row(execution: RouteANativeProducerExecution) -> dict[str, object]:
    observation = execution.process_observation
    verified = execution.verified_result
    return {
        "elapsed_ns": observation.elapsed_ns,
        "execution_process_role": execution.lane.execution_process_role,
        "lane_sha256": execution.lane.sha256,
        "peak_resident_memory_bytes": observation.peak_resident_memory_bytes,
        "peak_scratch_bytes": observation.peak_scratch_bytes,
        "process_ordinal_or_null": execution.lane.process_ordinal_or_null,
        "request_sha256": verified.request_sha256,
        "runner_build_identity_sha256": execution.runner_identity.build_identity_sha256,
    }


def _warmup_receipt(execution: RouteANativeProducerExecution) -> bytes:
    if execution.lane.execution_process_role != "openfhe-warmup" or execution.retained_package:
        raise RouteANativeQualificationError("q3 warm-up retention boundary changed")
    return canonical_route_a_document(
        {
            **_process_row(execution),
            "authority_granted": False,
            "package_retained": False,
            "publication_evidence": False,
            "schema_version": _WARMUP_SCHEMA,
        }
    )


def _replay_receipt(execution: RouteANativeReplayExecution) -> bytes:
    replay = execution.replay_result
    lifecycle = execution.lifecycle_inspection
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "cloud_program_operation_inventory": dict(
                replay.cloud_program_operation_inventory
            ),
            "elapsed_ns": execution.process_observation.elapsed_ns,
            "lane_sha256": execution.lane.sha256,
            "lifecycle_operation_inventory": dict(replay.lifecycle_operation_inventory),
            "package_manifest_sha256": execution.package_before.manifest_sha256,
            "peak_resident_memory_bytes": (
                execution.process_observation.peak_resident_memory_bytes
            ),
            "peak_scratch_bytes": execution.process_observation.peak_scratch_bytes,
            "preparation_sha256": lifecycle.preparation_sha256,
            "producer_request_sha256": execution.producer_result.request_sha256,
            "publication_evidence": False,
            "reconstructed_output_sha256": hashlib.sha256(
                canonical_route_a_document(list(replay.reconstructed_output))
            ).hexdigest(),
            "replay_request_sha256": replay.request_sha256,
            "runner_build_identity_sha256": execution.runner_identity.build_identity_sha256,
            "schema_version": _REPLAY_SCHEMA,
        }
    )


@dataclass(frozen=True, slots=True)
class RouteANativeQualificationInspection:
    stage: str
    root: Path
    lineage: RouteASyntheticSuiteLineage
    case_binding_sha256: str
    build_manifest_sha256: str
    input_q3_manifest_sha256: str | None
    manifest_sha256: str
    case_binding_bytes: bytes
    structural_vector_bytes: bytes
    build_archive: Path | None
    packages: tuple[RouteAOpenFHEPackageInspection, ...]
    guard_receipt_bytes: bytes | None


def _validate_inventory(
    root: Path,
    manifest: dict[str, object],
) -> tuple[tuple[str, bytes], ...]:
    rows = manifest.get("members")
    if type(rows) is not list or not rows:
        raise RouteANativeQualificationError("native artifact inventory is absent")
    observed = _tree_members(root, omit_control=True)
    expected_rows = []
    previous = ""
    for row in rows:
        if type(row) is not dict or set(row) != {"byte_count", "path", "sha256"}:
            raise RouteANativeQualificationError("native artifact inventory row changed")
        path = row.get("path")
        if type(path) is not str or not path or path <= previous or ".." in Path(path).parts:
            raise RouteANativeQualificationError("native artifact inventory path changed")
        if type(row.get("byte_count")) is not int or type(row.get("sha256")) is not str:
            raise RouteANativeQualificationError("native artifact inventory type changed")
        previous = path
        expected_rows.append(row)
    actual_rows = [
        {
            "byte_count": len(content),
            "path": path,
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for path, content in observed
    ]
    if expected_rows != actual_rows:
        raise RouteANativeQualificationError("native artifact inventory bytes changed")
    manifest_bytes = _stable_read(root / "manifest.json")
    if _stable_read(root / "checksums.sha256") != _checksums(observed, manifest_bytes):
        raise RouteANativeQualificationError("native artifact checksums changed")
    return observed


def inspect_route_a_native_qualification_artifact(
    root: Path,
    *,
    expected_stage: str,
    expected_lineage: RouteASyntheticSuiteLineage,
) -> RouteANativeQualificationInspection:
    """Rehash one downloaded q3/q4 tree before any private member is used."""

    if expected_stage not in {"q3", "q4"}:
        raise RouteANativeQualificationError("native qualification stage is not closed")
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RouteANativeQualificationError("native qualification root is unsafe")
    manifest_bytes = _stable_read(root / "manifest.json")
    manifest = _canonical_object(manifest_bytes, field="native stage manifest")
    if set(manifest) != {
        "authority_granted",
        "build_manifest_sha256",
        "case_binding_sha256",
        "formal_artifact",
        "input_q3_manifest_sha256_or_null",
        "lineage_sha256",
        "members",
        "private_replay_material_included",
        "provider_artifact_name",
        "retention_days",
        "schema_version",
        "stage",
    }:
        raise RouteANativeQualificationError("native stage manifest shape changed")
    expected_schema = _Q3_SCHEMA if expected_stage == "q3" else _Q4_SCHEMA
    if (
        manifest.get("schema_version") != expected_schema
        or manifest.get("stage") != expected_stage
        or manifest.get("authority_granted") is not False
        or manifest.get("formal_artifact") is not False
        or manifest.get("lineage_sha256") != expected_lineage.sha256
        or manifest.get("provider_artifact_name") != _STAGE_ARTIFACT_NAME[expected_stage]
        or manifest.get("retention_days") != 1
        or manifest.get("private_replay_material_included") is not (expected_stage == "q3")
        or type(manifest.get("case_binding_sha256")) is not str
        or type(manifest.get("build_manifest_sha256")) is not str
        or (
            manifest.get("input_q3_manifest_sha256_or_null") is not None
            if expected_stage == "q3"
            else not _is_sha256(manifest.get("input_q3_manifest_sha256_or_null"))
        )
    ):
        raise RouteANativeQualificationError("native stage manifest identity changed")
    observed = dict(_validate_inventory(root, manifest))
    if observed.get("lineage.json") != expected_lineage.document_bytes:
        raise RouteANativeQualificationError("native stage lineage bytes changed")
    case_bytes = observed.get("case-binding.json")
    structural_bytes = observed.get("structural-vector.json")
    stage_ledger_bytes = observed.get("stage-ledger.json")
    if (
        case_bytes is None
        or hashlib.sha256(case_bytes).hexdigest() != manifest["case_binding_sha256"]
        or structural_bytes is None
        or stage_ledger_bytes is None
    ):
        raise RouteANativeQualificationError("native case or stage-ledger binding changed")
    stage_ledger = _canonical_object(stage_ledger_bytes, field="native stage ledger")
    _canonical_object(case_bytes, field="native case binding")
    structural = _canonical_object(structural_bytes, field="native structural vector")
    if structural.get("schema_version") != "dynamic-cssc-route-a-native-structural-vector-v1":
        raise RouteANativeQualificationError("native structural vector identity changed")
    build_archive: Path | None = None
    packages: list[RouteAOpenFHEPackageInspection] = []
    guard_bytes: bytes | None = None
    if expected_stage == "q3":
        build_archive = root / "build-package.zip"
        build = inspect_route_a_native_build(build_archive)
        if build.manifest_sha256 != manifest["build_manifest_sha256"]:
            raise RouteANativeQualificationError("q3 build manifest binding changed")
        for ordinal in range(3):
            package = inspect_route_a_openfhe_package(root / f"packages/recorded-{ordinal}")
            lane = _canonical_object(
                read_route_a_openfhe_package_member(package, role="lane-binding"),
                field="recorded lane binding",
            )
            if (
                lane.get("process_ordinal") != ordinal
                or package.build_manifest_sha256 != build.manifest_sha256
                or package.case_binding_sha256 != manifest["case_binding_sha256"]
                or read_route_a_openfhe_package_member(package, role="structural-vector")
                != structural_bytes
            ):
                raise RouteANativeQualificationError("q3 recorded package binding changed")
            packages.append(package)
        warmup_bytes = observed.get("warmup-receipt.json")
        if warmup_bytes is None:
            raise RouteANativeQualificationError("q3 warm-up receipt is absent")
        warmup = _canonical_object(warmup_bytes, field="native warm-up receipt")
        processes = stage_ledger.get("processes")
        package_request_sha256s = [
            hashlib.sha256(
                read_route_a_openfhe_package_member(package, role="canonical-request")
            ).hexdigest()
            for package in packages
        ]
        if (
            set(stage_ledger)
            != {
                "authority_granted",
                "elapsed_ns",
                "processes",
                "publication_evidence",
                "schema_version",
                "stage",
            }
            or stage_ledger.get("schema_version") != _STAGE_LEDGER_SCHEMA
            or stage_ledger.get("stage") != "q3"
            or stage_ledger.get("authority_granted") is not False
            or stage_ledger.get("publication_evidence") is not False
            or type(stage_ledger.get("elapsed_ns")) is not int
            or stage_ledger["elapsed_ns"] < 0
            or type(processes) is not list
            or len(processes) != 4
            or any(type(row) is not dict or set(row) != _PROCESS_ROW_FIELDS for row in processes)
            or [row["execution_process_role"] for row in processes]
            != ["openfhe-warmup", "openfhe-recorded", "openfhe-recorded", "openfhe-recorded"]
            or [row["process_ordinal_or_null"] for row in processes] != [0, 0, 1, 2]
            or any(
                type(row[field]) is not int or row[field] < 0
                for row in processes
                for field in ("elapsed_ns", "peak_resident_memory_bytes", "peak_scratch_bytes")
            )
            or any(
                not _is_sha256(row[field])
                for row in processes
                for field in (
                    "lane_sha256",
                    "request_sha256",
                    "runner_build_identity_sha256",
                )
            )
            or len({row["lane_sha256"] for row in processes}) != 4
            or len({row["request_sha256"] for row in processes}) != 4
            or [row["request_sha256"] for row in processes[1:]]
            != package_request_sha256s
            or len({row["runner_build_identity_sha256"] for row in processes}) != 1
            or set(warmup) != _WARMUP_FIELDS
            or warmup.get("schema_version") != _WARMUP_SCHEMA
            or warmup.get("authority_granted") is not False
            or warmup.get("publication_evidence") is not False
            or warmup.get("package_retained") is not False
            or warmup.get("execution_process_role") != "openfhe-warmup"
            or warmup
            != {
                **processes[0],
                "authority_granted": False,
                "package_retained": False,
                "publication_evidence": False,
                "schema_version": _WARMUP_SCHEMA,
            }
        ):
            raise RouteANativeQualificationError("q3 warm-up receipt changed")
        expected_paths = {
            "build-package.zip",
            "case-binding.json",
            "lineage.json",
            "stage-ledger.json",
            "structural-vector.json",
            "warmup-receipt.json",
        }
        for ordinal, package in enumerate(packages):
            expected_paths.update(
                f"packages/recorded-{ordinal}/{path.name}"
                for path in package.package_root.iterdir()
            )
        if set(observed) != expected_paths:
            raise RouteANativeQualificationError("q3 artifact member set changed")
    else:
        guard_bytes = observed.get("native-guard.json")
        if guard_bytes is None:
            raise RouteANativeQualificationError("q4 native guard is absent")
        guard = _canonical_object(guard_bytes, field="native guard receipt")
        package_manifests = guard.get("package_manifest_sha256s")
        lane_bindings = guard.get("lane_binding_sha256s")
        freshness_checks = guard.get("freshness_checks")
        mechanism_coverage = guard.get("mechanism_coverage")
        resource_rows = guard.get("native_resource_observations")
        if (
            set(stage_ledger)
            != {
                "authority_granted",
                "elapsed_ns",
                "package_manifest_sha256s",
                "publication_evidence",
                "schema_version",
                "stage",
            }
            or stage_ledger.get("schema_version") != _STAGE_LEDGER_SCHEMA
            or stage_ledger.get("stage") != "q4"
            or stage_ledger.get("authority_granted") is not False
            or stage_ledger.get("publication_evidence") is not False
            or type(stage_ledger.get("elapsed_ns")) is not int
            or stage_ledger["elapsed_ns"] < 0
            or set(guard) != _GUARD_FIELDS
            or guard.get("accepted") is not True
            or guard.get("authority_granted") is not False
            or guard.get("publication_evidence") is not False
            or guard.get("schema_version")
            != "dynamic-cssc-route-a-native-three-replay-guard-v1"
            or guard.get("case_binding_sha256") != manifest["case_binding_sha256"]
            or guard.get("build_manifest_sha256") != manifest["build_manifest_sha256"]
            or guard.get("structural_vector_sha256")
            != hashlib.sha256(structural_bytes).hexdigest()
            or type(package_manifests) is not list
            or len(package_manifests) != 3
            or any(not _is_sha256(value) for value in package_manifests)
            or len(set(package_manifests)) != 3
            or type(lane_bindings) is not list
            or len(lane_bindings) != 3
            or any(not _is_sha256(value) for value in lane_bindings)
            or len(set(lane_bindings)) != 3
            or type(freshness_checks) is not dict
            or set(freshness_checks)
            != {
                "evaluation_key_frame_roots_pairwise_distinct",
                "input_ciphertext_roots_pairwise_distinct",
                "producer_result_ciphertext_roots_pairwise_distinct",
                "public_key_roots_pairwise_distinct",
                "secret_key_roots_pairwise_distinct",
            }
            or any(value is not True for value in freshness_checks.values())
            or type(mechanism_coverage) is not dict
            or set(mechanism_coverage)
            != {
                "actual_overlap_contributor_group",
                "f1m_random_mask_path",
                "nonempty_auxiliary_segment",
                "padding_or_tombstone_replacement",
            }
            or any(type(value) is not bool for value in mechanism_coverage.values())
            or any(
                mechanism_coverage.get(field) is not True
                for field in (
                    "actual_overlap_contributor_group",
                    "f1m_random_mask_path",
                    "nonempty_auxiliary_segment",
                )
            )
            or guard.get("process_ordinals") != [0, 1, 2]
            or type(resource_rows) is not list
            or len(resource_rows) != 3
            or any(
                type(row) is not dict
                or set(row)
                != {
                    "elapsed_ns",
                    "peak_resident_memory_bytes",
                    "peak_scratch_bytes",
                    "process_ordinal",
                }
                or row["process_ordinal"] != ordinal
                or any(
                    type(row[field]) is not int or row[field] < 0
                    for field in (
                        "elapsed_ns",
                        "peak_resident_memory_bytes",
                        "peak_scratch_bytes",
                    )
                )
                for ordinal, row in enumerate(resource_rows)
            )
            or type(guard.get("cloud_program_operation_inventory")) is not dict
            or not _is_sha256(guard.get("crypto_context_parameter_sha256"))
            or not _is_sha256(guard.get("runner_build_identity_sha256"))
            or stage_ledger.get("package_manifest_sha256s") != package_manifests
        ):
            raise RouteANativeQualificationError("q4 native guard binding changed")
        replay_paths = tuple(sorted(path for path in observed if path.startswith("replays/")))
        if replay_paths != tuple(
            f"replays/recorded-{ordinal}.json" for ordinal in range(3)
        ):
            raise RouteANativeQualificationError("q4 replay receipt set changed")
        replay_lane_sha256s: list[str] = []
        reconstructed_sha256s: list[str] = []
        request_sha256s: list[str] = []
        for ordinal, path in enumerate(replay_paths):
            receipt = _canonical_object(observed[path], field="native replay receipt")
            if (
                set(receipt) != _REPLAY_FIELDS
                or receipt.get("schema_version") != _REPLAY_SCHEMA
                or receipt.get("authority_granted") is not False
                or receipt.get("publication_evidence") is not False
                or receipt.get("package_manifest_sha256") != package_manifests[ordinal]
                or type(receipt.get("cloud_program_operation_inventory")) is not dict
                or receipt.get("cloud_program_operation_inventory")
                != guard.get("cloud_program_operation_inventory")
                or type(receipt.get("lifecycle_operation_inventory")) is not dict
                or any(
                    type(receipt.get(field)) is not int or receipt[field] < 0
                    for field in (
                        "elapsed_ns",
                        "peak_resident_memory_bytes",
                        "peak_scratch_bytes",
                    )
                )
                or any(
                    not _is_sha256(receipt.get(field))
                    for field in (
                        "lane_sha256",
                        "preparation_sha256",
                        "producer_request_sha256",
                        "reconstructed_output_sha256",
                        "replay_request_sha256",
                        "runner_build_identity_sha256",
                    )
                )
                or receipt.get("producer_request_sha256")
                != receipt.get("replay_request_sha256")
                or receipt.get("runner_build_identity_sha256")
                != guard.get("runner_build_identity_sha256")
            ):
                raise RouteANativeQualificationError("q4 replay receipt binding changed")
            replay_lane_sha256s.append(receipt["lane_sha256"])  # type: ignore[arg-type]
            reconstructed_sha256s.append(  # type: ignore[arg-type]
                receipt["reconstructed_output_sha256"]
            )
            request_sha256s.append(receipt["replay_request_sha256"])  # type: ignore[arg-type]
        if (
            len(set(replay_lane_sha256s)) != 3
            or len(set(reconstructed_sha256s)) != 1
            or len(set(request_sha256s)) != 3
        ):
            raise RouteANativeQualificationError("q4 replay identity set changed")
        if set(observed) != {
            "case-binding.json",
            "lineage.json",
            "native-guard.json",
            *replay_paths,
            "stage-ledger.json",
            "structural-vector.json",
        }:
            raise RouteANativeQualificationError("q4 artifact member set changed")
    return RouteANativeQualificationInspection(
        stage=expected_stage,
        root=root,
        lineage=expected_lineage,
        case_binding_sha256=manifest["case_binding_sha256"],  # type: ignore[arg-type]
        build_manifest_sha256=manifest["build_manifest_sha256"],  # type: ignore[arg-type]
        input_q3_manifest_sha256=manifest[  # type: ignore[arg-type]
            "input_q3_manifest_sha256_or_null"
        ],
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        case_binding_bytes=case_bytes,
        structural_vector_bytes=structural_bytes,
        build_archive=build_archive,
        packages=tuple(packages),
        guard_receipt_bytes=guard_bytes,
    )


def _install_stage_tree(
    temporary: Path,
    output_directory: Path,
    *,
    stage: str,
    lineage: RouteASyntheticSuiteLineage,
    case: RouteANativeCasePlan,
    build_manifest_sha256: str,
    input_q3_manifest_sha256: str | None,
) -> None:
    members = _tree_members(temporary, omit_control=True)
    manifest_bytes = _manifest(
        stage=stage,
        lineage=lineage,
        case=case,
        build_manifest_sha256=build_manifest_sha256,
        input_q3_manifest_sha256=input_q3_manifest_sha256,
        members=members,
    )
    _write_new(temporary / "manifest.json", manifest_bytes)
    _write_new(temporary / "checksums.sha256", _checksums(members, manifest_bytes))
    os.replace(temporary, output_directory)


def _case(
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    *,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    machine_plan_bytes: bytes | None = None,
) -> RouteANativeCasePlan:
    trace = generate_route_a_qualification_trace(
        scale="M",
        qualification_seed=scientific_profile.qualification_seed,
        scientific_profile=scientific_profile,
    )
    shard = route_a_synthetic_shard_identity(
        trace,
        lineage,
        scientific_profile=scientific_profile,
    )
    if machine_plan_bytes is None:
        machine_plan_bytes = (
            repository_root / "config/route-a-publication-plan.json"
        ).read_bytes()
    return compile_route_a_terminal_native_case(
        trace,
        strategy_candidate_id=_STRATEGY,
        shard_identity_sha256=shard,
        unit_attempt_ordinal=0,
        machine_plan_bytes=machine_plan_bytes,
        scientific_profile=scientific_profile,
    )


def compile_route_a_native_qualification_case(
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    *,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    machine_plan_bytes: bytes | None = None,
) -> RouteANativeCasePlan:
    """Compile the exact qualification case without executing a native process."""

    return _case(
        repository_root,
        lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )


def compile_route_a_native_formal_case(
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    *,
    scale: str,
    formal_seed: int,
    strategy_candidate_id: str,
    unit_attempt_ordinal: int = 0,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    machine_plan_bytes: bytes | None = None,
) -> RouteANativeCasePlan:
    """Compile one of the six registered formal native cases without execution."""

    trace = generate_route_a_formal_trace(
        scale=scale,
        formal_seed=formal_seed,
        scientific_profile=scientific_profile,
    )
    shard = route_a_synthetic_shard_identity(
        trace,
        lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        scientific_profile=scientific_profile,
    )
    if machine_plan_bytes is None:
        machine_plan_bytes = (
            repository_root / "config/route-a-publication-plan.json"
        ).read_bytes()
    return compile_route_a_terminal_native_case(
        trace,
        strategy_candidate_id=strategy_candidate_id,
        shard_identity_sha256=shard,
        unit_attempt_ordinal=unit_attempt_ordinal,
        machine_plan_bytes=machine_plan_bytes,
        scientific_profile=scientific_profile,
    )


def _resolve_case(
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    *,
    case_plan: RouteANativeCasePlan | None,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes | None,
) -> RouteANativeCasePlan:
    if case_plan is None:
        if (
            scientific_profile is PREDECESSOR_ROUTE_A_PROFILE
            and machine_plan_bytes is None
        ):
            return _case(repository_root, lineage)
        return _case(
            repository_root,
            lineage,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
        )
    if type(case_plan) is not RouteANativeCasePlan:
        raise TypeError("case_plan must be an exact RouteANativeCasePlan or absent")
    if machine_plan_bytes is None:
        machine_plan_bytes = (
            repository_root / "config/route-a-publication-plan.json"
        ).read_bytes()
    trace = validate_route_a_synthetic_trace(
        case_plan.trace,
        scientific_profile=scientific_profile,
    )
    shard = route_a_synthetic_shard_identity(
        trace,
        lineage,
        scientific_profile=scientific_profile,
    )
    expected = compile_route_a_terminal_native_case(
        trace,
        strategy_candidate_id=case_plan.strategy_candidate_id,
        shard_identity_sha256=shard,
        unit_attempt_ordinal=case_plan.unit_attempt_ordinal,
        machine_plan_bytes=machine_plan_bytes,
        scientific_profile=scientific_profile,
    )
    if case_plan != expected:
        raise RouteANativeQualificationError(
            "native case plan differs from its exact lineage and scientific profile"
        )
    return case_plan


def produce_route_a_native_qualification_handoff(
    *,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scratch_parent: Path,
    output_directory: Path,
    runner_relative_path: str = _RUNNER,
    timeout_seconds_per_process: int = 900,
    resident_memory_limit_bytes: int = 7 * 1024**3,
    scratch_limit_bytes: int = 8 * 1024**3,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    machine_plan_bytes: bytes | None = None,
    case_plan: RouteANativeCasePlan | None = None,
) -> RouteANativeQualificationInspection:
    """Run q3: build package, one warm-up, and three fresh-key producers."""

    if platform.system() != "Linux" or not hasattr(os, "wait4"):
        raise RouteANativeQualificationError("q3 native qualification is Linux-only")
    _direct_directory(repository_root, field="q3 repository root")
    _direct_directory(scratch_parent, field="q3 scratch parent")
    _direct_directory(output_directory.parent, field="q3 output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise RouteANativeQualificationError("q3 output already exists")
    case = _resolve_case(
        repository_root,
        lineage,
        case_plan=case_plan,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    temporary = Path(tempfile.mkdtemp(prefix=".route-a-q3-", dir=output_directory.parent))
    try:
        private = Path(tempfile.mkdtemp(prefix="route-a-q3-private-", dir=scratch_parent))
    except BaseException:
        _remove_private_tree(temporary, field="q3 temporary output")
        raise
    started_ns = time.perf_counter_ns()
    process_rows: list[dict[str, object]] = []
    try:
        build = produce_route_a_native_build(
            repository_root,
            runner_relative_path=runner_relative_path,
            output_path=temporary / "build-package.zip",
        )
        for sequence, ordinal in enumerate((None, 0, 1, 2)):
            lane = _lane(case, ordinal)
            ledger = SQLiteMaskBindingLedger(private / f"ledger-{sequence}.sqlite3")
            prepared = prepare_route_a_native_invocation(case, lane, ledger=ledger)
            capability = authorize_route_a_native_invocation(prepared, ledger=ledger)
            execution = execute_route_a_native_producer(
                capability,
                repository_root=repository_root,
                runner_relative_path=runner_relative_path,
                scratch_root=private / f"process-{sequence}",
                build_manifest_sha256=build.manifest_sha256,
                retained_package_directory=(
                    None if ordinal is None else temporary / f"packages/recorded-{ordinal}"
                ),
                timeout_seconds=timeout_seconds_per_process,
                resident_memory_limit_bytes=resident_memory_limit_bytes,
                scratch_limit_bytes=scratch_limit_bytes,
            )
            process_rows.append(_process_row(execution))
            if ordinal is None:
                _write_new(temporary / "warmup-receipt.json", _warmup_receipt(execution))
            elif execution.retained_package is None:
                raise RouteANativeQualificationError("q3 recorded package was not retained")
        _write_new(temporary / "lineage.json", lineage.document_bytes)
        _write_new(temporary / "case-binding.json", case.case_binding_bytes)
        _write_new(temporary / "structural-vector.json", case.structural_vector_bytes)
        _write_new(
            temporary / "stage-ledger.json",
            canonical_route_a_document(
                {
                    "authority_granted": False,
                    "elapsed_ns": time.perf_counter_ns() - started_ns,
                    "processes": process_rows,
                    "publication_evidence": False,
                    "schema_version": _STAGE_LEDGER_SCHEMA,
                    "stage": "q3",
                }
            ),
        )
        _install_stage_tree(
            temporary,
            output_directory,
            stage="q3",
            lineage=lineage,
            case=case,
            build_manifest_sha256=build.manifest_sha256,
            input_q3_manifest_sha256=None,
        )
        return inspect_route_a_native_qualification_artifact(
            output_directory,
            expected_stage="q3",
            expected_lineage=lineage,
        )
    except BaseException:
        _remove_private_tree(temporary, field="q3 temporary output")
        _remove_private_tree(output_directory, field="q3 failed output")
        raise
    finally:
        try:
            _remove_private_tree(private, field="q3 private scratch")
        except BaseException:
            _remove_private_tree(output_directory, field="q3 output after cleanup failure")
            raise


def replay_and_guard_route_a_native_qualification(
    *,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    q3_artifact_directory: Path,
    scratch_parent: Path,
    output_directory: Path,
    expected_q3_manifest_sha256: str,
    timeout_seconds_per_process: int = 900,
    resident_memory_limit_bytes: int = 7 * 1024**3,
    scratch_limit_bytes: int = 8 * 1024**3,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    machine_plan_bytes: bytes | None = None,
    case_plan: RouteANativeCasePlan | None = None,
) -> RouteANativeQualificationInspection:
    """Run q4: install q3 build, replay three packages, and guard the case."""

    if platform.system() != "Linux" or not hasattr(os, "wait4"):
        raise RouteANativeQualificationError("q4 native qualification is Linux-only")
    _direct_directory(repository_root, field="q4 repository root")
    _direct_directory(scratch_parent, field="q4 scratch parent")
    _direct_directory(output_directory.parent, field="q4 output parent")
    expected_q3_manifest_sha256 = _sha256(
        expected_q3_manifest_sha256,
        field="expected q3 stage manifest",
    )
    if output_directory.exists() or output_directory.is_symlink():
        raise RouteANativeQualificationError("q4 output already exists")
    q3 = inspect_route_a_native_qualification_artifact(
        q3_artifact_directory,
        expected_stage="q3",
        expected_lineage=lineage,
    )
    if q3.manifest_sha256 != expected_q3_manifest_sha256:
        raise RouteANativeQualificationError("q4 q3 stage-manifest address changed")
    case = _resolve_case(
        repository_root,
        lineage,
        case_plan=case_plan,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
    )
    if case.case_binding_sha256 != q3.case_binding_sha256:
        raise RouteANativeQualificationError("q4 case binding changed before build install")
    assert q3.build_archive is not None
    build, _identity = install_route_a_native_build(
        q3.build_archive,
        repository_root=repository_root,
    )
    if build.manifest_sha256 != q3.build_manifest_sha256:
        raise RouteANativeQualificationError("q4 retained build binding changed")
    temporary = Path(tempfile.mkdtemp(prefix=".route-a-q4-", dir=output_directory.parent))
    try:
        private = Path(tempfile.mkdtemp(prefix="route-a-q4-private-", dir=scratch_parent))
    except BaseException:
        _remove_private_tree(temporary, field="q4 temporary output")
        raise
    started_ns = time.perf_counter_ns()
    executions: list[RouteANativeReplayExecution] = []
    try:
        for ordinal, package in enumerate(q3.packages):
            execution = execute_route_a_native_replay(
                case,
                _lane(case, ordinal),
                package_root=package.package_root,
                repository_root=repository_root,
                runner_relative_path=build.runner_relative_path,
                scratch_root=private / f"replay-{ordinal}",
                timeout_seconds=timeout_seconds_per_process,
                resident_memory_limit_bytes=resident_memory_limit_bytes,
                scratch_limit_bytes=scratch_limit_bytes,
            )
            executions.append(execution)
            _write_new(
                temporary / f"replays/recorded-{ordinal}.json",
                _replay_receipt(execution),
            )
        if scientific_profile is PREDECESSOR_ROUTE_A_PROFILE:
            guard = guard_route_a_native_replays(
                case,
                tuple(executions),  # type: ignore[arg-type]
            )
        else:
            guard = guard_route_a_native_replays(
                case,
                tuple(executions),  # type: ignore[arg-type]
                scientific_profile=scientific_profile,
            )
        _write_new(temporary / "native-guard.json", guard.receipt_bytes)
        _write_new(temporary / "lineage.json", lineage.document_bytes)
        _write_new(temporary / "case-binding.json", case.case_binding_bytes)
        _write_new(temporary / "structural-vector.json", case.structural_vector_bytes)
        _write_new(
            temporary / "stage-ledger.json",
            canonical_route_a_document(
                {
                    "authority_granted": False,
                    "elapsed_ns": time.perf_counter_ns() - started_ns,
                    "package_manifest_sha256s": list(guard.package_manifest_sha256s),
                    "publication_evidence": False,
                    "schema_version": _STAGE_LEDGER_SCHEMA,
                    "stage": "q4",
                }
            ),
        )
        _install_stage_tree(
            temporary,
            output_directory,
            stage="q4",
            lineage=lineage,
            case=case,
            build_manifest_sha256=build.manifest_sha256,
            input_q3_manifest_sha256=expected_q3_manifest_sha256,
        )
        return inspect_route_a_native_qualification_artifact(
            output_directory,
            expected_stage="q4",
            expected_lineage=lineage,
        )
    except BaseException:
        _remove_private_tree(temporary, field="q4 temporary output")
        _remove_private_tree(output_directory, field="q4 failed output")
        raise
    finally:
        try:
            _remove_private_tree(private, field="q4 private scratch")
        except BaseException:
            _remove_private_tree(output_directory, field="q4 output after cleanup failure")
            raise
