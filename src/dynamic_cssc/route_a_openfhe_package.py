"""Build and re-inspect one closed Route A native producer package.

The package is the sole q3-to-q4 interface.  It owns the canonical request,
the producer receipt, every exact OpenFHE object, and the private lifecycle
evidence.  q4 receives only the package directory; it cannot substitute an
independent request or regenerate cryptographic material.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.openfhe_query_runner import (
    OpenFHESerializedObjectReceipt,
    VerifiedRouteAOpenFHEProducerResult,
    build_ordinary_openfhe_query_request,
    build_strong_openfhe_query_request,
    verify_route_a_ordinary_openfhe_producer_result,
    verify_route_a_strong_openfhe_producer_result,
)
from dynamic_cssc.ordinary_query_lifecycle import OrdinaryExecutionBundle
from dynamic_cssc.route_a_native_invocation import RouteANativeAuthorizedInvocation
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.strong_execution import StrongExecutionBundle

__all__ = (
    "ROUTE_A_OPENFHE_PACKAGE_MANIFEST_SCHEMA",
    "RouteAOpenFHEPackageError",
    "RouteAOpenFHEPackageInspection",
    "RouteAOpenFHEPackageMember",
    "build_route_a_openfhe_package",
    "inspect_route_a_openfhe_package",
    "read_route_a_openfhe_package_member",
)

ROUTE_A_OPENFHE_PACKAGE_MANIFEST_SCHEMA = "dynamic-cssc-route-a-native-package-manifest-v1"
_LANE_BINDING_SCHEMA = "dynamic-cssc-route-a-native-package-lane-binding-v1"
_LOWER_SHA256 = frozenset("0123456789abcdef")
_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MANIFEST_BYTES = 128 * 1024 * 1024
_SINGLETON_ROLES = frozenset(
    {
        "authorization-receipt",
        "canonical-request",
        "case-binding",
        "consumed-ledger",
        "crypto-context",
        "direct-oracle",
        "evaluation-key-frame",
        "lane-binding",
        "preparation",
        "producer-result",
        "public-key",
        "secret-key",
        "structural-vector",
        "typed-oracle",
    }
)
_REPEATED_ROLES = frozenset({"input-ciphertext", "producer-result-ciphertext"})


class RouteAOpenFHEPackageError(RuntimeError):
    """A native retained package is incomplete, mutable, or misbound."""


def _sha256(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _LOWER_SHA256 for character in value)
    ):
        raise RouteAOpenFHEPackageError(f"{field} must be lowercase SHA-256")
    return value


def _canonical_manifest(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise RouteAOpenFHEPackageError("package manifest is not canonical JSON") from error


def _stable_read(path: Path, *, maximum: int, field: str) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteAOpenFHEPackageError(f"{field} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise RouteAOpenFHEPackageError(f"{field} is outside its byte bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        identity = lambda value: (  # noqa: E731 - compact immutable stat projection
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
            raise RouteAOpenFHEPackageError(f"{field} changed while reading")
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
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write raises or advances
                raise RouteAOpenFHEPackageError("package member write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class RouteAOpenFHEPackageMember:
    byte_count: int
    relative_path: str
    role: str
    sha256: str
    subject_id: str


@dataclass(frozen=True, slots=True)
class RouteAOpenFHEPackageInspection:
    package_root: Path
    manifest_bytes: bytes
    manifest_sha256: str
    build_manifest_sha256: str
    case_binding_sha256: str
    lane_binding_sha256: str
    members: tuple[RouteAOpenFHEPackageMember, ...]


def read_route_a_openfhe_package_member(
    inspection: RouteAOpenFHEPackageInspection,
    *,
    role: str,
    subject_id: str | None = None,
) -> bytes:
    """Read one already-inspected member and recheck its exact receipt."""

    if type(inspection) is not RouteAOpenFHEPackageInspection:
        raise TypeError("inspection must be an exact package inspection")
    matches = tuple(
        member
        for member in inspection.members
        if member.role == role and (subject_id is None or member.subject_id == subject_id)
    )
    if len(matches) != 1:
        raise RouteAOpenFHEPackageError("package member selection is not unique")
    member = matches[0]
    content = _stable_read(
        inspection.package_root / member.relative_path,
        maximum=_MAX_MEMBER_BYTES,
        field="inspected package member",
    )
    if len(content) != member.byte_count or hashlib.sha256(content).hexdigest() != member.sha256:
        raise RouteAOpenFHEPackageError("inspected package member changed")
    return content


def _decode_manifest(content: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAOpenFHEPackageError("package manifest repeats a key")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAOpenFHEPackageError("package manifest is not ASCII JSON") from error
    if type(value) is not dict or _canonical_manifest(value) != content:
        raise RouteAOpenFHEPackageError("package manifest is not canonical JSON")
    return value


def inspect_route_a_openfhe_package(
    package_root: Path,
) -> RouteAOpenFHEPackageInspection:
    """Rehash the entire exact package tree without following links."""

    if not isinstance(package_root, Path):
        raise TypeError("package_root must be a Path")
    try:
        root_status = package_root.lstat()
    except OSError as error:
        raise RouteAOpenFHEPackageError("package root is unavailable") from error
    if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
        raise RouteAOpenFHEPackageError("package root must be one direct directory")
    manifest_bytes = _stable_read(
        package_root / "manifest.json",
        maximum=_MAX_MANIFEST_BYTES,
        field="package manifest",
    )
    manifest = _decode_manifest(manifest_bytes)
    if set(manifest) != {
        "build_manifest_sha256",
        "case_binding_sha256",
        "formal_authority_granted",
        "lane_binding_sha256",
        "members",
        "publication_authority",
        "schema_version",
    }:
        raise RouteAOpenFHEPackageError("package manifest keys are not exact")
    if (
        manifest["schema_version"] != ROUTE_A_OPENFHE_PACKAGE_MANIFEST_SCHEMA
        or manifest["formal_authority_granted"] is not False
        or manifest["publication_authority"] is not False
    ):
        raise RouteAOpenFHEPackageError("package manifest authority or schema changed")
    build_sha = _sha256(manifest["build_manifest_sha256"], field="build manifest")
    case_sha = _sha256(manifest["case_binding_sha256"], field="case binding")
    lane_sha = _sha256(manifest["lane_binding_sha256"], field="lane binding")
    raw_members = manifest["members"]
    if type(raw_members) is not list or not raw_members:
        raise RouteAOpenFHEPackageError("package member inventory is empty")
    parsed: list[RouteAOpenFHEPackageMember] = []
    identities: set[tuple[str, str]] = set()
    role_counts: dict[str, int] = {}
    expected_names = {"manifest.json"}
    for ordinal, raw in enumerate(raw_members):
        if type(raw) is not dict or set(raw) != {
            "byte_count",
            "relative_path",
            "role",
            "sha256",
            "subject_id",
        }:
            raise RouteAOpenFHEPackageError("package member keys are not exact")
        relative_path = f"member-{ordinal:06d}.bin"
        role = raw["role"]
        subject_id = raw["subject_id"]
        byte_count = raw["byte_count"]
        digest = _sha256(raw["sha256"], field="package member")
        identity = (role, subject_id)
        if (
            raw["relative_path"] != relative_path
            or type(role) is not str
            or not role
            or type(subject_id) is not str
            or not subject_id
            or type(byte_count) is not int
            or type(byte_count) is bool
            or byte_count <= 0
            or identity in identities
        ):
            raise RouteAOpenFHEPackageError("package member identity is not canonical")
        identities.add(identity)
        role_counts[role] = role_counts.get(role, 0) + 1
        content = _stable_read(
            package_root / relative_path,
            maximum=_MAX_MEMBER_BYTES,
            field="package member",
        )
        if len(content) != byte_count or hashlib.sha256(content).hexdigest() != digest:
            raise RouteAOpenFHEPackageError("package member digest or size changed")
        expected_names.add(relative_path)
        parsed.append(
            RouteAOpenFHEPackageMember(
                byte_count=byte_count,
                relative_path=relative_path,
                role=role,
                sha256=digest,
                subject_id=subject_id,
            )
        )
    try:
        actual_names = {entry.name for entry in os.scandir(package_root)}
    except OSError as error:
        raise RouteAOpenFHEPackageError("package root cannot be enumerated") from error
    if actual_names != expected_names:
        raise RouteAOpenFHEPackageError("package has a missing or extra physical member")
    if (
        set(role_counts) != _SINGLETON_ROLES | _REPEATED_ROLES
        or any(role_counts[role] != 1 for role in _SINGLETON_ROLES)
        or any(role_counts[role] <= 0 for role in _REPEATED_ROLES)
    ):
        raise RouteAOpenFHEPackageError("package role vocabulary/cardinality is not closed")
    by_role = {member.role: member for member in parsed if member.role in _SINGLETON_ROLES}
    if by_role["case-binding"].sha256 != case_sha or by_role["lane-binding"].sha256 != lane_sha:
        raise RouteAOpenFHEPackageError("package case or lane manifest binding changed")
    ledger = _stable_read(
        package_root / by_role["consumed-ledger"].relative_path,
        maximum=_MAX_MEMBER_BYTES,
        field="consumed package ledger",
    )
    if not ledger.startswith(b"SQLite format 3\x00"):
        raise RouteAOpenFHEPackageError("package consumed ledger is not SQLite")
    return RouteAOpenFHEPackageInspection(
        package_root=package_root,
        manifest_bytes=manifest_bytes,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        build_manifest_sha256=build_sha,
        case_binding_sha256=case_sha,
        lane_binding_sha256=lane_sha,
        members=tuple(parsed),
    )


def _lane_binding_bytes(authorized: RouteANativeAuthorizedInvocation) -> bytes:
    lane = authorized.prepared.lane
    if (
        lane.execution_process_role != "openfhe-recorded"
        or type(lane.process_ordinal_or_null) is not int
        or lane.process_ordinal_or_null not in {0, 1, 2}
    ):
        raise RouteAOpenFHEPackageError("only a recorded lane can mint a replay package")
    return canonical_route_a_document(
        {
            "case_binding_sha256": authorized.prepared.case.case_binding_sha256,
            "execution_process_role": lane.execution_process_role,
            "process_ordinal": lane.process_ordinal_or_null,
            "query_id": authorized.prepared.query_identity.query_id,
            "schema_version": _LANE_BINDING_SCHEMA,
            "shard_identity_sha256": lane.shard_identity_sha256,
            "strategy_candidate_id": lane.strategy_candidate_id,
            "unit_attempt_ordinal": lane.unit_attempt_ordinal,
        }
    )


def _producer_object_bytes(
    root: Path,
    receipt: OpenFHESerializedObjectReceipt,
) -> bytes:
    content = _stable_read(
        root / receipt.relative_path,
        maximum=_MAX_MEMBER_BYTES,
        field="verified producer object",
    )
    if len(content) != receipt.byte_count or hashlib.sha256(content).hexdigest() != receipt.sha256:
        raise RouteAOpenFHEPackageError("verified producer object changed before packaging")
    return content


def _verified_producer(
    authorized: RouteANativeAuthorizedInvocation,
    *,
    request_bytes: bytes,
    producer_result_path: Path,
    producer_object_root: Path,
) -> VerifiedRouteAOpenFHEProducerResult:
    bundle = authorized.prepared.case.execution_bundle
    prepared = authorized.prepared.prepared_query
    if type(bundle) is OrdinaryExecutionBundle:
        return verify_route_a_ordinary_openfhe_producer_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=producer_result_path,
            object_root=producer_object_root,
            expected_output=authorized.typed_oracle_output,
        )
    if type(bundle) is StrongExecutionBundle:
        return verify_route_a_strong_openfhe_producer_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=producer_result_path,
            object_root=producer_object_root,
            expected_output=authorized.typed_oracle_output,
        )
    raise RouteAOpenFHEPackageError("producer bundle kind changed")


def _expected_request_bytes(
    authorized: RouteANativeAuthorizedInvocation,
) -> bytes:
    bundle = authorized.prepared.case.execution_bundle
    prepared = authorized.prepared.prepared_query
    if type(bundle) is OrdinaryExecutionBundle:
        return build_ordinary_openfhe_query_request(bundle, prepared)
    if type(bundle) is StrongExecutionBundle:
        return build_strong_openfhe_query_request(bundle, prepared)
    raise RouteAOpenFHEPackageError("producer bundle kind changed")


def build_route_a_openfhe_package(
    authorized: RouteANativeAuthorizedInvocation,
    *,
    request_bytes: bytes,
    producer_result_path: Path,
    producer_object_root: Path,
    build_manifest_sha256: str,
    output_directory: Path,
) -> RouteAOpenFHEPackageInspection:
    """Verify q3 output and atomically install its one exact q4 package."""

    if type(authorized) is not RouteANativeAuthorizedInvocation:
        raise TypeError("authorized must be an exact RouteANativeAuthorizedInvocation")
    if any(
        not isinstance(path, Path)
        for path in (producer_result_path, producer_object_root, output_directory)
    ):
        raise TypeError("Route A package paths must be Path values")
    build_manifest_sha256 = _sha256(
        build_manifest_sha256,
        field="build manifest",
    )
    if request_bytes != _expected_request_bytes(authorized):
        raise RouteAOpenFHEPackageError("producer request differs from the typed invocation")
    verified = _verified_producer(
        authorized,
        request_bytes=request_bytes,
        producer_result_path=producer_result_path,
        producer_object_root=producer_object_root,
    )
    result_bytes = _stable_read(
        producer_result_path,
        maximum=_MAX_MANIFEST_BYTES,
        field="verified producer result",
    )
    lane_binding = _lane_binding_bytes(authorized)
    lane_binding_sha256 = hashlib.sha256(lane_binding).hexdigest()
    case = authorized.prepared.case
    request_document = json.loads(request_bytes.decode("ascii"))
    inputs = {value["ciphertext_id"] for value in request_document["ciphertext_values"]}
    results = set(request_document["program"]["result_ids"])
    physical: list[tuple[str, str, bytes]] = [
        ("canonical-request", "canonical-request", request_bytes),
        ("producer-result", "producer-result", result_bytes),
    ]
    for ordinal, receipt in enumerate(verified.serialized_objects):
        if ordinal == 0:
            role = "crypto-context"
        elif ordinal == 1:
            role = "secret-key"
        elif ordinal == 2:
            role = "public-key"
        elif ordinal == 3:
            role = "evaluation-key-frame"
        elif receipt.subject_id in inputs:
            role = "input-ciphertext"
        elif receipt.subject_id in results:
            role = "producer-result-ciphertext"
        else:  # pragma: no cover - verified receipt vocabulary is closed
            raise RouteAOpenFHEPackageError("producer object role is not closed")
        physical.append(
            (
                role,
                receipt.subject_id,
                _producer_object_bytes(producer_object_root, receipt),
            )
        )
    physical.extend(
        (
            ("preparation", "preparation", authorized.prepared.preparation_bytes),
            (
                "authorization-receipt",
                "authorization-receipt",
                authorized.authorization_receipt_bytes,
            ),
            (
                "consumed-ledger",
                "consumed-ledger",
                authorized.consumed_ledger_snapshot_bytes,
            ),
            ("typed-oracle", "typed-oracle", authorized.typed_oracle_bytes),
            ("direct-oracle", "direct-oracle", case.direct_oracle_bytes),
            ("case-binding", "case-binding", case.case_binding_bytes),
            ("structural-vector", "structural-vector", case.structural_vector_bytes),
            ("lane-binding", "lane-binding", lane_binding),
        )
    )
    parent = output_directory.parent
    if output_directory.exists() or output_directory.is_symlink():
        raise RouteAOpenFHEPackageError("refusing to replace a package output")
    parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=".route-a-package-", dir=parent))
    try:
        members: list[dict[str, object]] = []
        for ordinal, (role, subject_id, content) in enumerate(physical):
            if type(content) is not bytes or not content:
                raise RouteAOpenFHEPackageError("package member must be nonempty bytes")
            relative_path = f"member-{ordinal:06d}.bin"
            _write_new(scratch / relative_path, content)
            members.append(
                {
                    "byte_count": len(content),
                    "relative_path": relative_path,
                    "role": role,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "subject_id": subject_id,
                }
            )
        manifest_bytes = _canonical_manifest(
            {
                "build_manifest_sha256": build_manifest_sha256,
                "case_binding_sha256": case.case_binding_sha256,
                "formal_authority_granted": False,
                "lane_binding_sha256": lane_binding_sha256,
                "members": members,
                "publication_authority": False,
                "schema_version": ROUTE_A_OPENFHE_PACKAGE_MANIFEST_SCHEMA,
            }
        )
        _write_new(scratch / "manifest.json", manifest_bytes)
        os.replace(scratch, output_directory)
        os.chmod(output_directory, 0o500)
    except BaseException:
        if scratch.exists():
            os.chmod(scratch, 0o700)
            shutil.rmtree(scratch)
        raise
    inspection = inspect_route_a_openfhe_package(output_directory)
    if (
        inspection.build_manifest_sha256 != build_manifest_sha256
        or inspection.case_binding_sha256 != case.case_binding_sha256
        or inspection.lane_binding_sha256 != lane_binding_sha256
        or not any(
            member.role == "consumed-ledger"
            and member.sha256 == authorized.consumed_ledger_snapshot_sha256
            for member in inspection.members
        )
    ):
        raise RouteAOpenFHEPackageError("installed package binding changed")
    return inspection
