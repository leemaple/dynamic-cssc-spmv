"""Closed q5 combined guard for the non-admissible Route A qualification.

The guard consumes the provider wrappers for q2 and q4, verifies their live
provider identities against the exact wrapper bytes, extracts them into owned
scratch without following archive paths, and then invokes the two stage-native
inspectors.  Its output is a redacted, one-day planning bundle.  It contains no
publication evidence and grants no execution authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from dynamic_cssc.route_a_native_case import (
    RouteANativeCasePlan,
    compile_route_a_terminal_native_case,
)
from dynamic_cssc.route_a_native_suite import (
    inspect_route_a_native_qualification_artifact,
)
from dynamic_cssc.route_a_qualification_runtime import (
    inspect_route_a_qualification_stage_artifact,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_serialized_bytes import (
    route_a_serialized_byte_formula_document,
)
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    inspect_route_a_synthetic_suite_replay,
    route_a_synthetic_shard_identity,
)
from dynamic_cssc.route_a_workloads import (
    generate_route_a_formal_trace,
    generate_route_a_qualification_trace,
)

__all__ = (
    "RouteACombinedGuardError",
    "RouteACombinedGuardInspection",
    "RouteAProviderArtifactBinding",
    "inspect_route_a_combined_guard_artifact",
    "produce_route_a_combined_guard",
)

_SCHEMA = "dynamic-cssc-route-a-combined-qualification-guard-v1"
_MANIFEST_SCHEMA = "dynamic-cssc-route-a-combined-guard-artifact-v1"
_STRUCTURAL_SET_SCHEMA = "dynamic-cssc-route-a-structural-comparability-set-v1"
_STAGE_LEDGER_SCHEMA = "dynamic-cssc-route-a-q5-stage-ledger-v1"
_PROVIDER_BINDING_SCHEMA = "dynamic-cssc-route-a-provider-artifact-binding-v1"
_ARTIFACT_NAME = "q5-combined-guard-bundle"
_Q2_NAME = "q2-simulator-guarded-receipt"
_Q4_NAME = "q4-native-guarded-case-bundle"
_STRONG = "packed-coo-cloud-segmented-delta/segment-width=128"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_PROVIDER_JSON_BYTES = 4 * 1024 * 1024
_MAX_WRAPPER_BYTES = 8 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MEMBER_COUNT = 2_048
_MAX_MANIFEST_BYTES = 128 * 1024 * 1024
_PACKAGE_SINGLETON_MEMBER_COUNT = 14
_EXPECTED_MEMBERS = (
    "combined-guard.json",
    "lineage.json",
    "probe-structural-vector.json",
    "formal-structural-vectors.json",
    "serialized-byte-formula.json",
    "stage-ledger.json",
)


class RouteACombinedGuardError(RuntimeError):
    """q5 input, functional binding, or artifact closure failed closed."""


def _canonical_object(content: bytes, *, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteACombinedGuardError(f"{field} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteACombinedGuardError(f"{field} is not ASCII JSON") from error
    if type(value) is not dict or canonical_route_a_document(value) != content:
        raise RouteACombinedGuardError(f"{field} is not canonical JSON")
    return value


def _provider_object(content: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteACombinedGuardError("provider response repeats a JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteACombinedGuardError("provider response is not readable JSON") from error
    if type(value) is not dict:
        raise RouteACombinedGuardError("provider response is not one JSON object")
    return value


def _stable_read(path: Path, *, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteACombinedGuardError("q5 input member is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RouteACombinedGuardError("q5 input member violates its byte bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        identity = lambda value: (  # noqa: E731 - exact stable stat projection
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
            or identity(before) != identity(after)
        ):
            raise RouteACombinedGuardError("q5 input member changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _file_sha256(path: Path, *, maximum: int) -> tuple[str, int]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteACombinedGuardError("provider wrapper is unavailable") from error
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RouteACombinedGuardError("provider wrapper violates its byte bound")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise RouteACombinedGuardError("provider wrapper violates its byte bound")
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
        ):
            raise RouteACombinedGuardError("provider wrapper changed while hashing")
        return digest.hexdigest(), total
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
        os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write raises or advances
                raise RouteACombinedGuardError("q5 artifact write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_tree(path: Path, *, field: str) -> None:
    if path.is_symlink():
        raise RouteACombinedGuardError(f"{field} became a symbolic link")
    if path.exists():
        shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        raise RouteACombinedGuardError(f"{field} cleanup failed")


@dataclass(frozen=True, slots=True)
class RouteAProviderArtifactBinding:
    database_id: int
    name: str
    digest: str
    size_in_bytes: int
    workflow_run_head_sha: str
    wrapper_sha256: str

    @property
    def document(self) -> dict[str, object]:
        return {
            "database_id": self.database_id,
            "digest": self.digest,
            "name": self.name,
            "schema_version": _PROVIDER_BINDING_SCHEMA,
            "size_in_bytes": self.size_in_bytes,
            "workflow_run_head_sha": self.workflow_run_head_sha,
            "wrapper_sha256": self.wrapper_sha256,
        }


def _provider_bindings(
    provider_bytes: bytes,
    *,
    expected_head_sha: str,
    wrapper_paths: dict[str, Path],
) -> dict[str, RouteAProviderArtifactBinding]:
    if _LOWER_GIT_SHA.fullmatch(expected_head_sha) is None:
        raise RouteACombinedGuardError("q5 expected workflow head is invalid")
    document = _provider_object(provider_bytes)
    rows = document.get("artifacts")
    if (
        type(rows) is not list
        or document.get("total_count") != len(rows)
        or len(rows) > 100
        or any(type(row) is not dict for row in rows)
        or set(wrapper_paths) != {_Q2_NAME, _Q4_NAME}
    ):
        raise RouteACombinedGuardError("provider artifact list is incomplete")
    result: dict[str, RouteAProviderArtifactBinding] = {}
    for expected_name, wrapper_path in wrapper_paths.items():
        matches = [row for row in rows if row.get("name") == expected_name]
        if len(matches) != 1:
            raise RouteACombinedGuardError("required provider artifact is not unique")
        row = matches[0]
        workflow_run = row.get("workflow_run")
        wrapper_sha256, wrapper_size = _file_sha256(
            wrapper_path,
            maximum=_MAX_WRAPPER_BYTES,
        )
        digest = row.get("digest")
        if (
            type(row.get("id")) is not int
            or row["id"] <= 0
            or type(digest) is not str
            or _PROVIDER_DIGEST.fullmatch(digest) is None
            or type(row.get("size_in_bytes")) is not int
            or row["size_in_bytes"] <= 0
            or row.get("expired") is not False
            or type(workflow_run) is not dict
            or workflow_run.get("head_sha") != expected_head_sha
            or row["size_in_bytes"] != wrapper_size
            or digest != f"sha256:{wrapper_sha256}"
        ):
            raise RouteACombinedGuardError("provider artifact identity differs from wrapper")
        result[expected_name] = RouteAProviderArtifactBinding(
            database_id=row["id"],
            name=expected_name,
            digest=digest,
            size_in_bytes=wrapper_size,
            workflow_run_head_sha=expected_head_sha,
            wrapper_sha256=wrapper_sha256,
        )
    if result[_Q2_NAME].database_id == result[_Q4_NAME].database_id:
        raise RouteACombinedGuardError("q2 and q4 provider artifact identities collide")
    return result


def _safe_member_name(value: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RouteACombinedGuardError("provider wrapper contains an unsafe path")
    return path.parts


def _extract_provider_wrapper(wrapper: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise RouteACombinedGuardError("provider extraction target already exists")
    output.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(wrapper, "r") as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                archive.comment
                or not members
                or len(members) > _MAX_MEMBER_COUNT
                or len(names) != len(set(names))
            ):
                raise RouteACombinedGuardError("provider wrapper member set is not closed")
            total = 0
            for member in members:
                parts = _safe_member_name(member.filename.removesuffix("/"))
                unix_type = stat.S_IFMT(member.external_attr >> 16)
                is_directory = member.is_dir()
                if (
                    member.flag_bits & 0x1
                    or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or (unix_type not in {0, stat.S_IFREG, stat.S_IFDIR})
                    or (is_directory and unix_type not in {0, stat.S_IFDIR})
                    or (not is_directory and unix_type == stat.S_IFDIR)
                    or member.file_size < 0
                    or member.file_size > _MAX_MEMBER_BYTES
                ):
                    raise RouteACombinedGuardError("provider wrapper member is inadmissible")
                total += member.file_size
                if total > _MAX_WRAPPER_BYTES:
                    raise RouteACombinedGuardError("provider wrapper expands beyond its bound")
                target = output.joinpath(*parts)
                if is_directory:
                    if target.exists():
                        if target.is_symlink() or not target.is_dir():
                            raise RouteACombinedGuardError(
                                "provider wrapper directory collides with a file"
                            )
                    else:
                        target.mkdir(parents=True, exist_ok=False)
                    os.chmod(target, 0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o400,
                )
                try:
                    os.fchmod(descriptor, 0o400)
                    observed = 0
                    with archive.open(member, "r") as source:
                        while True:
                            block = source.read(1024 * 1024)
                            if not block:
                                break
                            observed += len(block)
                            if observed > member.file_size:
                                raise RouteACombinedGuardError(
                                    "provider wrapper member exceeded its declared size"
                                )
                            view = memoryview(block)
                            while view:
                                written = os.write(descriptor, view)
                                view = view[written:]
                    if observed != member.file_size:
                        raise RouteACombinedGuardError(
                            "provider wrapper member size changed during extraction"
                        )
                finally:
                    os.close(descriptor)
    except RouteACombinedGuardError:
        _remove_tree(output, field="failed provider extraction")
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        _remove_tree(output, field="failed provider extraction")
        raise RouteACombinedGuardError("provider wrapper is not a readable ZIP") from error
    except BaseException:
        _remove_tree(output, field="failed provider extraction")
        raise


def _package_bound(case: RouteANativeCasePlan) -> dict[str, object]:
    structural = _canonical_object(
        case.structural_vector_bytes,
        field="native structural vector",
    )
    ciphertexts = structural.get("ciphertext_input_multiplicities_by_role")
    result_count = structural.get("result_ciphertext_count")
    if (
        type(ciphertexts) is not dict
        or any(type(value) is not int or value < 0 for value in ciphertexts.values())
        or type(result_count) is not int
        or result_count <= 0
    ):
        raise RouteACombinedGuardError("native structural multiplicity is invalid")
    input_count = sum(ciphertexts.values())
    member_count = _PACKAGE_SINGLETON_MEMBER_COUNT + input_count + result_count
    return {
        "exact_input_ciphertext_member_count": input_count,
        "exact_manifest_member_count": member_count,
        "exact_result_ciphertext_member_count": result_count,
        "formula": "exact_manifest_member_count*package_member_max_bytes+manifest_max_bytes",
        "manifest_max_bytes": _MAX_MANIFEST_BYTES,
        "maximum_package_bytes": member_count * _MAX_MEMBER_BYTES + _MAX_MANIFEST_BYTES,
        "package_member_max_bytes": _MAX_MEMBER_BYTES,
        "projection_class": "type-and-cardinality-derived-conservative-maximum-not-measured",
        "schema_version": "dynamic-cssc-route-a-native-package-byte-bound-v1",
    }


def _planning_shard_identity(*, scale: str, strategy: str) -> str:
    return hashlib.sha256(
        canonical_route_a_document(
            {
                "formal_seed": 20260822,
                "identity_class": "q5-planning-only-never-an-execution-shard-identity",
                "scale": scale,
                "strategy_candidate_id": strategy,
            }
        )
    ).hexdigest()


def _structural_row(case: RouteANativeCasePlan) -> dict[str, object]:
    structural = _canonical_object(
        case.structural_vector_bytes,
        field="native structural vector",
    )
    ciphertexts = structural["ciphertext_input_multiplicities_by_role"]
    result_count = structural["result_ciphertext_count"]
    assert type(ciphertexts) is dict and type(result_count) is int
    return {
        "build_and_job_stage_topology": {
            "discarded_warmup_processes": 1,
            "fresh_key_recorded_producer_processes": 3,
            "independent_exact_replay_processes": 3,
            "producer_job": "native-case-shaped-producer",
            "replay_and_guard_job": "native-independent-replay-and-guard",
            "retained_build_packages": 1,
            "retained_replay_packages": 3,
        },
        "formal_seed": case.trace.formal_seed,
        "key_and_ciphertext_object_multiplicities": {
            "crypto_contexts": 1,
            "evaluation_key_frames": 1,
            "input_ciphertexts": sum(ciphertexts.values()),
            "public_keys": 1,
            "result_ciphertexts": result_count,
            "secret_keys": 1,
        },
        "maximum_serialized_package_byte_bound": _package_bound(case),
        "planning_shard_identity_sha256": case.shard_identity_sha256,
        "scale": case.trace.scale,
        "strategy_candidate_id": case.strategy_candidate_id,
        "structural_vector": structural,
        "structural_vector_sha256": case.structural_vector_sha256,
    }


def _operation_types(structural_record: bytes) -> set[str]:
    record = _canonical_object(structural_record, field="structural comparability record")
    if record.get("schema_version") == "dynamic-cssc-route-a-probe-structural-record-v1":
        rows = [record.get("case")]
    else:
        rows = record.get("cases")
    if type(rows) is not list or any(type(row) is not dict for row in rows):
        raise RouteACombinedGuardError("structural comparability rows are malformed")
    result: set[str] = set()
    for row in rows:
        structural = row.get("structural_vector")
        operations = structural.get("ordered_operation_types") if type(structural) is dict else None
        if (
            type(operations) is not list
            or any(type(value) is not str or not value for value in operations)
        ):
            raise RouteACombinedGuardError("structural operation vocabulary is malformed")
        result.update(operations)
    return result


def _formal_structural_set(machine_plan_bytes: bytes) -> bytes:
    rows: list[dict[str, object]] = []
    for strategy in ROUTE_A_STRATEGY_CANDIDATES:
        for scale in ("S", "M"):
            trace = generate_route_a_formal_trace(scale=scale, formal_seed=20260822)
            case = compile_route_a_terminal_native_case(
                trace,
                strategy_candidate_id=strategy,
                shard_identity_sha256=_planning_shard_identity(
                    scale=scale,
                    strategy=strategy,
                ),
                unit_attempt_ordinal=0,
                machine_plan_bytes=machine_plan_bytes,
            )
            rows.append(_structural_row(case))
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "cases": rows,
            "componentwise_relations_are_runtime_theorems": False,
            "formal_execution_authorized": False,
            "publication_evidence": False,
            "schema_version": _STRUCTURAL_SET_SCHEMA,
        }
    )


def _selected_strong_rho1(replay: object) -> object:
    cells = replay.final_cells  # type: ignore[attr-defined]
    matches = [
        cell
        for cell in cells
        if cell.document["identity"]["strategy_candidate_id"] == _STRONG
        and cell.document["identity"]["rho"] == "1"
    ]
    if len(matches) != 1:
        raise RouteACombinedGuardError("q2 lacks one exact strong rho=1 cell")
    return matches[0]


def _artifact_members(root: Path, *, omit_control: bool) -> tuple[tuple[str, bytes], ...]:
    members: list[tuple[str, bytes]] = []
    for path in sorted(root.iterdir()):
        if path.name in {"manifest.json", "checksums.sha256"} and omit_control:
            continue
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise RouteACombinedGuardError("q5 artifact contains an unsafe member")
        members.append((path.name, _stable_read(path, maximum=_MAX_MANIFEST_BYTES)))
    return tuple(members)


def _manifest(
    *,
    lineage: RouteASyntheticSuiteLineage,
    q2: RouteAProviderArtifactBinding,
    q4: RouteAProviderArtifactBinding,
    members: tuple[tuple[str, bytes], ...],
) -> bytes:
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "formal_artifact": False,
            "lineage_sha256": lineage.sha256,
            "members": [
                {
                    "byte_count": len(content),
                    "path": path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for path, content in members
            ],
            "provider_artifact_name": _ARTIFACT_NAME,
            "publication_evidence": False,
            "q2_provider_binding": q2.document,
            "q4_provider_binding": q4.document,
            "retention_days": 1,
            "schema_version": _MANIFEST_SCHEMA,
        }
    )


def _checksums(members: tuple[tuple[str, bytes], ...], manifest: bytes) -> bytes:
    return b"".join(
        f"{hashlib.sha256(content).hexdigest()}  {path}\n".encode("ascii")
        for path, content in (*members, ("manifest.json", manifest))
    )


@dataclass(frozen=True, slots=True)
class RouteACombinedGuardInspection:
    root: Path
    lineage: RouteASyntheticSuiteLineage
    manifest_sha256: str
    q2_provider: RouteAProviderArtifactBinding
    q4_provider: RouteAProviderArtifactBinding
    combined_guard_bytes: bytes
    formal_structural_vectors_bytes: bytes


def _binding_from_document(value: object, *, name: str) -> RouteAProviderArtifactBinding:
    if type(value) is not dict or set(value) != {
        "database_id",
        "digest",
        "name",
        "schema_version",
        "size_in_bytes",
        "workflow_run_head_sha",
        "wrapper_sha256",
    }:
        raise RouteACombinedGuardError("q5 provider binding shape changed")
    if (
        value.get("schema_version") != _PROVIDER_BINDING_SCHEMA
        or value.get("name") != name
        or type(value.get("database_id")) is not int
        or value["database_id"] <= 0
        or type(value.get("digest")) is not str
        or _PROVIDER_DIGEST.fullmatch(value["digest"]) is None
        or type(value.get("size_in_bytes")) is not int
        or value["size_in_bytes"] <= 0
        or type(value.get("workflow_run_head_sha")) is not str
        or _LOWER_GIT_SHA.fullmatch(value["workflow_run_head_sha"]) is None
        or type(value.get("wrapper_sha256")) is not str
        or _LOWER_SHA256.fullmatch(value["wrapper_sha256"]) is None
        or value["digest"] != f"sha256:{value['wrapper_sha256']}"
    ):
        raise RouteACombinedGuardError("q5 provider binding identity changed")
    return RouteAProviderArtifactBinding(
        database_id=value["database_id"],
        name=name,
        digest=value["digest"],
        size_in_bytes=value["size_in_bytes"],
        workflow_run_head_sha=value["workflow_run_head_sha"],
        wrapper_sha256=value["wrapper_sha256"],
    )


def inspect_route_a_combined_guard_artifact(
    root: Path,
    *,
    expected_lineage: RouteASyntheticSuiteLineage,
    machine_plan_bytes: bytes,
    expected_probe_bytes: bytes | None = None,
    expected_formal_vectors_bytes: bytes | None = None,
    expected_case_binding_sha256: str | None = None,
) -> RouteACombinedGuardInspection:
    """Rehash and close a q5 artifact without trusting its own inventory."""

    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RouteACombinedGuardError("q5 artifact root is unsafe")
    names = tuple(sorted(path.name for path in root.iterdir()))
    if names != tuple(sorted((*_EXPECTED_MEMBERS, "manifest.json", "checksums.sha256"))):
        raise RouteACombinedGuardError("q5 artifact member set changed")
    members = _artifact_members(root, omit_control=True)
    manifest_bytes = _stable_read(root / "manifest.json", maximum=_MAX_MANIFEST_BYTES)
    manifest = _canonical_object(manifest_bytes, field="q5 manifest")
    if set(manifest) != {
        "authority_granted",
        "formal_artifact",
        "lineage_sha256",
        "members",
        "provider_artifact_name",
        "publication_evidence",
        "q2_provider_binding",
        "q4_provider_binding",
        "retention_days",
        "schema_version",
    }:
        raise RouteACombinedGuardError("q5 manifest shape changed")
    q2 = _binding_from_document(manifest.get("q2_provider_binding"), name=_Q2_NAME)
    q4 = _binding_from_document(manifest.get("q4_provider_binding"), name=_Q4_NAME)
    if (
        manifest.get("schema_version") != _MANIFEST_SCHEMA
        or manifest.get("authority_granted") is not False
        or manifest.get("formal_artifact") is not False
        or manifest.get("publication_evidence") is not False
        or manifest.get("lineage_sha256") != expected_lineage.sha256
        or manifest.get("provider_artifact_name") != _ARTIFACT_NAME
        or manifest.get("retention_days") != 1
        or q2.workflow_run_head_sha != expected_lineage.workflow_head_sha
        or q4.workflow_run_head_sha != expected_lineage.workflow_head_sha
        or q2.database_id == q4.database_id
        or manifest != _canonical_object(
            _manifest(lineage=expected_lineage, q2=q2, q4=q4, members=members),
            field="expected q5 manifest",
        )
        or _stable_read(root / "checksums.sha256", maximum=_MAX_MANIFEST_BYTES)
        != _checksums(members, manifest_bytes)
    ):
        raise RouteACombinedGuardError("q5 manifest binding changed")
    by_name = dict(members)
    if by_name["lineage.json"] != expected_lineage.document_bytes:
        raise RouteACombinedGuardError("q5 lineage bytes changed")
    guard_bytes = by_name["combined-guard.json"]
    guard = _canonical_object(guard_bytes, field="q5 combined guard")
    formal = _canonical_object(
        by_name["formal-structural-vectors.json"],
        field="q5 formal structural vectors",
    )
    probe = _canonical_object(
        by_name["probe-structural-vector.json"],
        field="q5 probe structural vector",
    )
    formula = _canonical_object(
        by_name["serialized-byte-formula.json"],
        field="q5 serialized-byte formula",
    )
    ledger = _canonical_object(by_name["stage-ledger.json"], field="q5 stage ledger")
    trace = generate_route_a_qualification_trace(scale="M", qualification_seed=20260821)
    expected_shard = route_a_synthetic_shard_identity(trace, expected_lineage)
    supplied_expectations = (
        expected_probe_bytes is not None,
        expected_formal_vectors_bytes is not None,
        expected_case_binding_sha256 is not None,
    )
    if any(supplied_expectations) and not all(supplied_expectations):
        raise RouteACombinedGuardError("q5 in-process expectations are incomplete")
    if (
        expected_probe_bytes is None
        or expected_formal_vectors_bytes is None
        or expected_case_binding_sha256 is None
    ):
        expected_case = compile_route_a_terminal_native_case(
            trace,
            strategy_candidate_id=_STRONG,
            shard_identity_sha256=expected_shard,
            unit_attempt_ordinal=0,
            machine_plan_bytes=machine_plan_bytes,
        )
        expected_probe = canonical_route_a_document(
            {
                "authority_granted": False,
                "case": _structural_row(expected_case),
                "formal_execution_authorized": False,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-probe-structural-record-v1",
            }
        )
        expected_formal = _formal_structural_set(machine_plan_bytes)
        expected_case_sha256 = expected_case.case_binding_sha256
    else:
        if (
            type(expected_probe_bytes) is not bytes
            or type(expected_formal_vectors_bytes) is not bytes
            or not _LOWER_SHA256.fullmatch(expected_case_binding_sha256)
        ):
            raise RouteACombinedGuardError("q5 in-process expected bytes are malformed")
        expected_probe = expected_probe_bytes
        expected_formal = expected_formal_vectors_bytes
        expected_case_sha256 = expected_case_binding_sha256
    functional = guard.get("functional_bindings")
    mechanisms = functional.get("native_mechanism_coverage") if type(functional) is dict else None
    if (
        set(guard)
        != {
            "accepted",
            "authority_granted",
            "formal_execution_authorized",
            "functional_bindings",
            "lineage_sha256",
            "provider_bindings",
            "publication_evidence",
            "schema_version",
            "structural_coverage",
        }
        or guard.get("schema_version") != _SCHEMA
        or guard.get("accepted") is not True
        or guard.get("authority_granted") is not False
        or guard.get("formal_execution_authorized") is not False
        or guard.get("publication_evidence") is not False
        or guard.get("lineage_sha256") != expected_lineage.sha256
        or guard.get("provider_bindings") != {"q2": q2.document, "q4": q4.document}
        or guard.get("structural_coverage")
        != {
            "componentwise_count_or_byte_relations_are_runtime_theorems": False,
            "formal_operation_types_absent_from_probe": [],
            "formal_structural_vectors_sha256": hashlib.sha256(
                by_name["formal-structural-vectors.json"]
            ).hexdigest(),
            "probe_structural_vector_sha256": hashlib.sha256(
                by_name["probe-structural-vector.json"]
            ).hexdigest(),
            "required_native_mechanisms_exercised": True,
        }
        or type(functional) is not dict
        or set(functional)
        != {
            "native_case_binding_sha256",
            "native_guard_sha256",
            "native_input_q3_manifest_sha256",
            "native_mechanism_coverage",
            "qualification_shard_identity_sha256",
            "simulator_direct_guard_count",
            "simulator_strong_rho1_cell_sha256",
            "source_event_trace_sha256",
        }
        or functional.get("native_case_binding_sha256") != expected_case_sha256
        or not _LOWER_SHA256.fullmatch(str(functional.get("native_guard_sha256")))
        or not _LOWER_SHA256.fullmatch(
            str(functional.get("native_input_q3_manifest_sha256"))
        )
        or type(mechanisms) is not dict
        or set(mechanisms)
        != {
            "actual_overlap_contributor_group",
            "f1m_random_mask_path",
            "nonempty_auxiliary_segment",
            "padding_or_tombstone_replacement",
        }
        or any(
            mechanisms.get(field) is not True
            for field in (
                "actual_overlap_contributor_group",
                "f1m_random_mask_path",
                "nonempty_auxiliary_segment",
            )
        )
        or type(mechanisms.get("padding_or_tombstone_replacement")) is not bool
        or functional.get("qualification_shard_identity_sha256") != expected_shard
        or functional.get("simulator_direct_guard_count") != 9
        or not _LOWER_SHA256.fullmatch(
            str(functional.get("simulator_strong_rho1_cell_sha256"))
        )
        or functional.get("source_event_trace_sha256") != trace.event_trace_sha256
        or formal.get("schema_version") != _STRUCTURAL_SET_SCHEMA
        or formal.get("authority_granted") is not False
        or formal.get("formal_execution_authorized") is not False
        or formal.get("publication_evidence") is not False
        or formal.get("componentwise_relations_are_runtime_theorems") is not False
        or type(formal.get("cases")) is not list
        or len(formal["cases"]) != 6
        or by_name["formal-structural-vectors.json"] != expected_formal
        or probe.get("schema_version") != "dynamic-cssc-route-a-probe-structural-record-v1"
        or by_name["probe-structural-vector.json"] != expected_probe
        or formula != route_a_serialized_byte_formula_document()
        or set(ledger) != {
            "authority_granted",
            "phases",
            "publication_evidence",
            "schema_version",
        }
        or ledger.get("schema_version") != _STAGE_LEDGER_SCHEMA
        or ledger.get("authority_granted") is not False
        or ledger.get("publication_evidence") is not False
        or type(ledger.get("phases")) is not list
        or [row.get("phase") for row in ledger["phases"] if type(row) is dict]
        != [
            "provider-wrapper-closure",
            "functional-cross-guard",
            "formal-structural-compilation",
            "artifact-assembly",
        ]
        or any(
            type(row) is not dict
            or set(row) != {"elapsed_ns", "phase"}
            or type(row.get("elapsed_ns")) is not int
            or row["elapsed_ns"] < 0
            for row in ledger["phases"]
        )
    ):
        raise RouteACombinedGuardError("q5 retained record changed")
    return RouteACombinedGuardInspection(
        root=root,
        lineage=expected_lineage,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        q2_provider=q2,
        q4_provider=q4,
        combined_guard_bytes=guard_bytes,
        formal_structural_vectors_bytes=by_name["formal-structural-vectors.json"],
    )


def produce_route_a_combined_guard(
    *,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    provider_artifacts_json_path: Path,
    q2_wrapper_path: Path,
    q4_wrapper_path: Path,
    scratch_parent: Path,
    output_directory: Path,
) -> RouteACombinedGuardInspection:
    """Run q5 and atomically install one redacted combined-guard bundle."""

    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    for field, path in (
        ("repository root", repository_root),
        ("scratch parent", scratch_parent),
        ("output parent", output_directory.parent),
    ):
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise RouteACombinedGuardError(f"q5 {field} is unsafe")
    if output_directory.exists() or output_directory.is_symlink():
        raise RouteACombinedGuardError("q5 output already exists")
    plan_bytes = (repository_root / "config/route-a-publication-plan.json").read_bytes()
    temporary = Path(tempfile.mkdtemp(prefix=".route-a-q5-", dir=output_directory.parent))
    try:
        private = Path(tempfile.mkdtemp(prefix="route-a-q5-private-", dir=scratch_parent))
    except BaseException:
        _remove_tree(temporary, field="q5 temporary output")
        raise
    phases: list[dict[str, object]] = []

    def phase(name: str, started: int) -> None:
        phases.append({"elapsed_ns": time.perf_counter_ns() - started, "phase": name})

    try:
        started = time.perf_counter_ns()
        provider = _provider_bindings(
            _stable_read(provider_artifacts_json_path, maximum=_MAX_PROVIDER_JSON_BYTES),
            expected_head_sha=lineage.workflow_head_sha,
            wrapper_paths={_Q2_NAME: q2_wrapper_path, _Q4_NAME: q4_wrapper_path},
        )
        q2_root = private / "q2"
        q4_root = private / "q4"
        _extract_provider_wrapper(q2_wrapper_path, q2_root)
        _extract_provider_wrapper(q4_wrapper_path, q4_root)
        phase("provider-wrapper-closure", started)

        started = time.perf_counter_ns()
        trace = generate_route_a_qualification_trace(scale="M", qualification_seed=20260821)
        q2_stage = inspect_route_a_qualification_stage_artifact(
            q2_root,
            expected_stage="q2",
            expected_lineage=lineage,
        )
        q2 = inspect_route_a_synthetic_suite_replay(
            q2_stage.payload_path,
            expected_trace=trace,
            expected_lineage=lineage,
            machine_plan_bytes=plan_bytes,
        )
        q4 = inspect_route_a_native_qualification_artifact(
            q4_root,
            expected_stage="q4",
            expected_lineage=lineage,
        )
        expected_shard = route_a_synthetic_shard_identity(trace, lineage)
        expected_case = compile_route_a_terminal_native_case(
            trace,
            strategy_candidate_id=_STRONG,
            shard_identity_sha256=expected_shard,
            unit_attempt_ordinal=0,
            machine_plan_bytes=plan_bytes,
        )
        selected = _selected_strong_rho1(q2)
        identity = selected.document["identity"]
        native_guard = _canonical_object(
            q4.guard_receipt_bytes or b"",
            field="q4 native guard",
        )
        mechanisms = native_guard.get("mechanism_coverage")
        if (
            q2.shard_identity_sha256 != expected_shard
            or q4.case_binding_bytes != expected_case.case_binding_bytes
            or q4.structural_vector_bytes != expected_case.structural_vector_bytes
            or q4.input_q3_manifest_sha256 is None
            or identity.get("strategy_candidate_id") != _STRONG
            or identity.get("rho") != "1"
            or identity.get("shard_identity_sha256") != expected_shard
            or identity.get("formal_seed_or_null") != 20260821
            or native_guard.get("accepted") is not True
            or type(mechanisms) is not dict
            or any(
                mechanisms.get(field) is not True
                for field in (
                    "actual_overlap_contributor_group",
                    "f1m_random_mask_path",
                    "nonempty_auxiliary_segment",
                )
            )
        ):
            raise RouteACombinedGuardError("q2/q4 functional identity does not close")
        functional = {
            "native_case_binding_sha256": expected_case.case_binding_sha256,
            "native_guard_sha256": hashlib.sha256(q4.guard_receipt_bytes or b"").hexdigest(),
            "native_input_q3_manifest_sha256": q4.input_q3_manifest_sha256,
            "native_mechanism_coverage": mechanisms,
            "qualification_shard_identity_sha256": expected_shard,
            "simulator_direct_guard_count": len(q2.guard_receipts),
            "simulator_strong_rho1_cell_sha256": selected.sha256,
            "source_event_trace_sha256": trace.event_trace_sha256,
        }
        if functional["simulator_direct_guard_count"] != 9:
            raise RouteACombinedGuardError("q2 guarded cell count changed")
        phase("functional-cross-guard", started)

        started = time.perf_counter_ns()
        probe_record = canonical_route_a_document(
            {
                "authority_granted": False,
                "case": _structural_row(expected_case),
                "formal_execution_authorized": False,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-probe-structural-record-v1",
            }
        )
        formal_vectors = _formal_structural_set(plan_bytes)
        formula = canonical_route_a_document(route_a_serialized_byte_formula_document())
        missing_operation_types = sorted(
            _operation_types(formal_vectors) - _operation_types(probe_record)
        )
        if missing_operation_types:
            raise RouteACombinedGuardError(
                "formal native operation type is absent from the qualification probe"
            )
        structural_coverage = {
            "componentwise_count_or_byte_relations_are_runtime_theorems": False,
            "formal_operation_types_absent_from_probe": missing_operation_types,
            "formal_structural_vectors_sha256": hashlib.sha256(formal_vectors).hexdigest(),
            "probe_structural_vector_sha256": hashlib.sha256(probe_record).hexdigest(),
            "required_native_mechanisms_exercised": True,
        }
        phase("formal-structural-compilation", started)

        started = time.perf_counter_ns()
        guard_bytes = canonical_route_a_document(
            {
                "accepted": True,
                "authority_granted": False,
                "formal_execution_authorized": False,
                "functional_bindings": functional,
                "lineage_sha256": lineage.sha256,
                "provider_bindings": {
                    "q2": provider[_Q2_NAME].document,
                    "q4": provider[_Q4_NAME].document,
                },
                "publication_evidence": False,
                "schema_version": _SCHEMA,
                "structural_coverage": structural_coverage,
            }
        )
        _write_new(temporary / "combined-guard.json", guard_bytes)
        _write_new(temporary / "lineage.json", lineage.document_bytes)
        _write_new(temporary / "probe-structural-vector.json", probe_record)
        _write_new(temporary / "formal-structural-vectors.json", formal_vectors)
        _write_new(temporary / "serialized-byte-formula.json", formula)
        phases.append(
            {
                "elapsed_ns": time.perf_counter_ns() - started,
                "phase": "artifact-assembly",
            }
        )
        _write_new(
            temporary / "stage-ledger.json",
            canonical_route_a_document(
                {
                    "authority_granted": False,
                    "phases": phases,
                    "publication_evidence": False,
                    "schema_version": _STAGE_LEDGER_SCHEMA,
                }
            ),
        )
        members = _artifact_members(temporary, omit_control=True)
        if tuple(path for path, _content in members) != tuple(sorted(_EXPECTED_MEMBERS)):
            raise RouteACombinedGuardError("q5 output member order changed")
        manifest = _manifest(
            lineage=lineage,
            q2=provider[_Q2_NAME],
            q4=provider[_Q4_NAME],
            members=members,
        )
        _write_new(temporary / "manifest.json", manifest)
        _write_new(temporary / "checksums.sha256", _checksums(members, manifest))
        os.replace(temporary, output_directory)
        return inspect_route_a_combined_guard_artifact(
            output_directory,
            expected_lineage=lineage,
            machine_plan_bytes=plan_bytes,
            expected_probe_bytes=probe_record,
            expected_formal_vectors_bytes=formal_vectors,
            expected_case_binding_sha256=expected_case.case_binding_sha256,
        )
    except BaseException:
        _remove_tree(temporary, field="q5 temporary output")
        _remove_tree(output_directory, field="q5 failed output")
        raise
    finally:
        try:
            _remove_tree(private, field="q5 private scratch")
        except BaseException:
            _remove_tree(output_directory, field="q5 output after cleanup failure")
            raise
