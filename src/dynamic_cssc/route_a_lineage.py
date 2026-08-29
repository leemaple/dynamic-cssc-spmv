"""Git-object-bound S1 registration and S1-to-S2 compatibility for Route A.

The Behavior Set registry is itself a frozen Git blob.  Registration captures
only exact objects from a named commit; the current worktree can neither add a
path nor substitute bytes.  S2 compatibility accepts exactly one child commit
whose sole changed path is the reviewed registration data anchor.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

__all__ = (
    "ROUTE_A_BEHAVIOR_ROLES",
    "ROUTE_A_REGISTRATION_ANCHOR_PATH",
    "RouteABehaviorInventory",
    "RouteACompatibilityReceipt",
    "RouteALineageError",
    "RouteARegistrationArchive",
    "RouteARegistrationInspection",
    "build_route_a_registration_anchor",
    "capture_route_a_behavior_inventory",
    "inspect_route_a_registration_archive",
    "produce_route_a_registration_archive",
    "verify_route_a_s1_s2_compatibility",
    "verify_route_a_s1_s2_s3_analysis_compatibility",
)


class RouteALineageError(ValueError):
    """A Route A Git object, registration archive, or lineage failed closed."""


ROUTE_A_BEHAVIOR_ROLES = (
    "acquisition",
    "qualification",
    "formal",
    "analyzer",
    "control-registration",
)
ROUTE_A_REGISTRATION_ANCHOR_PATH = "config/route-a-registration-anchors.json"
_BEHAVIOR_REGISTRY_PATH = "config/route-a-behavior-sets.json"
_BEHAVIOR_REGISTRY_SCHEMA = "dynamic-cssc-route-a-behavior-set-registry-v3"
_BEHAVIOR_INVENTORY_SCHEMA = "dynamic-cssc-route-a-behavior-inventory-v1"
_REGISTRATION_EVIDENCE_SCHEMA = "dynamic-cssc-route-a-registration-evidence-v1"
_REGISTRATION_ANCHOR_SET_SCHEMA = "dynamic-cssc-route-a-registration-anchor-set-v1"
_REGISTRATION_ANCHOR_SCHEMA = "dynamic-cssc-route-a-registration-anchor-v1"
_COMPATIBILITY_RECEIPT_SCHEMA = "dynamic-cssc-route-a-adr0010-compatibility-receipt-v1"
_ANALYSIS_COMPATIBILITY_RECEIPT_SCHEMA = (
    "dynamic-cssc-route-a-adr0010-analysis-compatibility-receipt-v1"
)
_EMPTY_ANCHOR_BYTES = (
    b'{"anchors":[],"schema_version":"dynamic-cssc-route-a-registration-anchor-set-v1"}\n'
)
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+\Z")
_MAX_REGISTRY_BYTES = 1024 * 1024
_MAX_BEHAVIOR_BLOB_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise RouteALineageError("Route A lineage document is not canonical JSON") from error


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RouteALineageError("Route A lineage JSON contains a duplicate key")
        result[key] = value
    return result


def _decode_json_object(
    content: bytes,
    field: str,
    maximum: int,
    *,
    require_canonical_bytes: bool,
) -> dict[str, object]:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise RouteALineageError(f"{field} bytes violate the closed bound")
    try:
        decoded = json.loads(content.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteALineageError(f"{field} is not canonical ASCII JSON") from error
    if type(decoded) is not dict or (
        require_canonical_bytes and _canonical_json_bytes(decoded) != content
    ):
        raise RouteALineageError(f"{field} bytes are not canonical")
    return decoded


def _decode_canonical_json(content: bytes, field: str, maximum: int) -> dict[str, object]:
    return _decode_json_object(
        content,
        field,
        maximum,
        require_canonical_bytes=True,
    )


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    repository = repository.resolve(strict=True)
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            input=input_bytes,
            env=environment,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip()
        raise RouteALineageError(f"Git object inspection failed: {detail}") from error
    return result.stdout


def _resolve_commit(repository: Path, git_sha: str, field: str) -> str:
    if type(git_sha) is not str or _LOWER_GIT_SHA.fullmatch(git_sha) is None:
        raise RouteALineageError(f"{field} is not one lowercase Git commit SHA")
    resolved = _git(repository, "rev-parse", "--verify", f"{git_sha}^{{commit}}")
    try:
        value = resolved.decode("ascii").strip()
    except UnicodeDecodeError as error:  # pragma: no cover - Git owns ASCII IDs
        raise RouteALineageError(f"{field} did not resolve to ASCII") from error
    if value != git_sha:
        raise RouteALineageError(f"{field} did not resolve exactly")
    return value


def _require_safe_path(path: object) -> str:
    if (
        type(path) is not str
        or _SAFE_PATH.fullmatch(path) is None
        or path.startswith("/")
        or path.endswith("/")
        or "//" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise RouteALineageError("Behavior Set path is not one safe repository path")
    return path


@dataclass(frozen=True, slots=True)
class _GitBlob:
    path: str
    mode: str
    object_id: str
    content: bytes


def _read_git_blob(repository: Path, git_sha: str, path: str) -> _GitBlob:
    path = _require_safe_path(path)
    listing = _git(repository, "ls-tree", "-z", git_sha, "--", path)
    records = [record for record in listing.split(b"\0") if record]
    if len(records) != 1:
        raise RouteALineageError(f"Git tree does not contain exactly one path: {path}")
    try:
        header, observed_path = records[0].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        decoded_path = observed_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise RouteALineageError(f"Git tree entry is malformed: {path}") from error
    if (
        decoded_path != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
    ):
        raise RouteALineageError(f"Git tree entry is not an admitted regular blob: {path}")
    content = _git(repository, "cat-file", "blob", object_id)
    if len(content) > _MAX_BEHAVIOR_BLOB_BYTES:
        raise RouteALineageError(f"Behavior blob exceeds its closed bound: {path}")
    return _GitBlob(path=path, mode=mode, object_id=object_id, content=content)


def _registry(repository: Path, git_sha: str) -> tuple[dict[str, object], str]:
    blob = _read_git_blob(repository, git_sha, _BEHAVIOR_REGISTRY_PATH)
    # The registry is itself an exact frozen Git blob.  Its reviewed layout may
    # be human-readable JSON; semantic canonicality is enforced below by closed
    # keys and sorted unique paths, while the raw blob SHA binds the exact bytes.
    document = _decode_json_object(
        blob.content,
        "Route A Behavior Set registry",
        _MAX_REGISTRY_BYTES,
        require_canonical_bytes=False,
    )
    if (
        set(document) != {"roles", "schema_version", "stage1_documents"}
        or document["schema_version"] != _BEHAVIOR_REGISTRY_SCHEMA
    ):
        raise RouteALineageError("Route A Behavior Set registry schema is not closed")
    roles = document["roles"]
    if type(roles) is not dict or set(roles) != set(ROUTE_A_BEHAVIOR_ROLES):
        raise RouteALineageError("Route A Behavior Set role registry is not exact")
    stage1 = document["stage1_documents"]
    if type(stage1) is not dict or not stage1 or list(stage1) != sorted(stage1):
        raise RouteALineageError("Route A Stage-1 document registry is not canonical")
    for path, expected_sha256 in stage1.items():
        path = _require_safe_path(path)
        if (
            type(expected_sha256) is not str
            or _LOWER_SHA256.fullmatch(expected_sha256) is None
            or _sha256(_read_git_blob(repository, git_sha, path).content) != expected_sha256
        ):
            raise RouteALineageError(f"Stage-1 document blob is not exact: {path}")
    return document, _sha256(blob.content)


@dataclass(frozen=True, slots=True)
class RouteABehaviorInventory:
    role: str
    source_git_sha: str
    document_bytes: bytes
    sha256: str

    @property
    def document(self) -> dict[str, object]:
        return _decode_canonical_json(
            self.document_bytes, "Route A behavior inventory", _MAX_ARCHIVE_BYTES
        )


@dataclass(frozen=True, slots=True)
class RouteARegistrationArchive:
    source_git_sha: str
    archive_bytes: bytes
    archive_sha256: str
    registration_evidence_sha256: str
    behavior_inventory_sha256: dict[str, str]


@dataclass(frozen=True, slots=True)
class RouteARegistrationInspection:
    source_git_sha: str
    archive_sha256: str
    registration_evidence_sha256: str
    behavior_inventory_sha256: dict[str, str]
    formal_authority_granted: bool = False


@dataclass(frozen=True, slots=True)
class RouteACompatibilityReceipt:
    document_bytes: bytes
    sha256: str

    @property
    def document(self) -> dict[str, object]:
        return _decode_canonical_json(
            self.document_bytes, "Route A compatibility receipt", _MAX_ARCHIVE_BYTES
        )


def capture_route_a_behavior_inventory(
    repository: Path,
    source_git_sha: str,
    role: str,
) -> RouteABehaviorInventory:
    """Capture one closed role inventory from exact Git objects, never worktree bytes."""

    source_git_sha = _resolve_commit(repository, source_git_sha, "source_git_sha")
    if type(role) is not str:
        raise TypeError("role must be one exact Route A behavior-role string")
    if role not in ROUTE_A_BEHAVIOR_ROLES:
        raise RouteALineageError("Route A behavior role is not registered")
    registry, registry_sha256 = _registry(repository, source_git_sha)
    role_document = registry["roles"][role]
    if type(role_document) is not dict or set(role_document) != {
        "paths",
        "schema_version",
    }:
        raise RouteALineageError(f"Route A {role} Behavior Set is not closed")
    schema_version = role_document["schema_version"]
    paths = role_document["paths"]
    if (
        type(schema_version) is not str
        or not schema_version
        or type(paths) is not list
        or not paths
        or paths != sorted(set(paths))
        or _BEHAVIOR_REGISTRY_PATH not in paths
    ):
        raise RouteALineageError(f"Route A {role} Behavior Set path list is not canonical")
    entries: list[dict[str, object]] = []
    for raw_path in paths:
        blob = _read_git_blob(repository, source_git_sha, _require_safe_path(raw_path))
        entries.append(
            {
                "git_object_id": blob.object_id,
                "mode": blob.mode,
                "path": blob.path,
                "sha256": _sha256(blob.content),
                "type": "blob",
            }
        )
    document = {
        "behavior_set_registry_blob_sha256": registry_sha256,
        "behavior_set_schema_version": schema_version,
        "entries": entries,
        "role": role,
        "schema_version": _BEHAVIOR_INVENTORY_SCHEMA,
        "source_git_sha": source_git_sha,
    }
    content = _canonical_json_bytes(document)
    return RouteABehaviorInventory(
        role=role,
        source_git_sha=source_git_sha,
        document_bytes=content,
        sha256=_sha256(content),
    )


def _assert_clean_exact_head(repository: Path, expected_s1: str) -> None:
    head = _git(repository, "rev-parse", "HEAD").decode("ascii").strip()
    dirty = _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    if head != expected_s1 or dirty:
        raise RouteALineageError("Route A registration requires one clean exact S1 checkout")


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[name])
    content = output.getvalue()
    if len(content) > _MAX_ARCHIVE_BYTES:
        raise RouteALineageError("Route A registration archive exceeds its closed bound")
    return content


def _registration_members(
    repository: Path,
    source_git_sha: str,
) -> tuple[dict[str, bytes], str, dict[str, str]]:
    registry, _ = _registry(repository, source_git_sha)
    inventories = {
        role: capture_route_a_behavior_inventory(repository, source_git_sha, role)
        for role in ROUTE_A_BEHAVIOR_ROLES
    }
    inventory_sha256 = {role: inventory.sha256 for role, inventory in inventories.items()}
    stage1_sha256 = dict(registry["stage1_documents"])
    evidence = {
        "authority": {
            "artifact_installation_authorized": False,
            "formal_authority_granted": False,
            "registration_anchor_minted": False,
        },
        "behavior_inventory_sha256": inventory_sha256,
        "machine_plan_sha256": stage1_sha256.get("config/route-a-publication-plan.json"),
        "schema_version": _REGISTRATION_EVIDENCE_SCHEMA,
        "source_git_sha": source_git_sha,
        "stage1_document_sha256": stage1_sha256,
    }
    evidence_bytes = _canonical_json_bytes(evidence)
    members = {
        **{
            f"behavior/{role}.json": inventory.document_bytes
            for role, inventory in inventories.items()
        },
        "registration-evidence.json": evidence_bytes,
    }
    checksums = "".join(
        f"{_sha256(content)}  {name}\n" for name, content in sorted(members.items())
    ).encode("ascii")
    members["checksums.sha256"] = checksums
    return members, _sha256(evidence_bytes), inventory_sha256


def produce_route_a_registration_archive(
    repository: Path,
    expected_s1: str,
) -> RouteARegistrationArchive:
    """Produce deterministic descriptive registration from a clean exact S1."""

    expected_s1 = _resolve_commit(repository, expected_s1, "expected_s1")
    _assert_clean_exact_head(repository, expected_s1)
    members, evidence_sha256, inventory_sha256 = _registration_members(repository, expected_s1)
    archive_bytes = _zip_bytes(members)
    return RouteARegistrationArchive(
        source_git_sha=expected_s1,
        archive_bytes=archive_bytes,
        archive_sha256=_sha256(archive_bytes),
        registration_evidence_sha256=evidence_sha256,
        behavior_inventory_sha256=inventory_sha256,
    )


def _read_archive(archive_bytes: bytes) -> dict[str, bytes]:
    if (
        type(archive_bytes) is not bytes
        or not archive_bytes
        or len(archive_bytes) > (_MAX_ARCHIVE_BYTES)
    ):
        raise RouteALineageError("Route A registration archive violates its byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            if archive.comment:
                raise RouteALineageError("Route A registration archive has a comment")
            names = archive.namelist()
            if len(names) != len(set(names)) or any(
                name.startswith("/") or ".." in Path(name).parts for name in names
            ):
                raise RouteALineageError("Route A registration archive members are unsafe")
            return {name: archive.read(name) for name in names}
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        raise RouteALineageError("Route A registration archive is unreadable") from error


def inspect_route_a_registration_archive(
    repository: Path,
    expected_s1: str,
    archive_bytes: bytes,
) -> RouteARegistrationInspection:
    """Recompute every S1 inventory in a second process-compatible seam."""

    expected_s1 = _resolve_commit(repository, expected_s1, "expected_s1")
    expected_members, evidence_sha256, inventory_sha256 = _registration_members(
        repository, expected_s1
    )
    observed_members = _read_archive(archive_bytes)
    if set(observed_members) != set(expected_members):
        raise RouteALineageError("Route A registration archive has missing or extra members")
    if observed_members != expected_members or _zip_bytes(observed_members) != archive_bytes:
        raise RouteALineageError("Route A registration archive bytes differ from exact S1")
    evidence = _decode_canonical_json(
        observed_members["registration-evidence.json"],
        "Route A registration evidence",
        _MAX_ARCHIVE_BYTES,
    )
    if evidence["authority"] != {
        "artifact_installation_authorized": False,
        "formal_authority_granted": False,
        "registration_anchor_minted": False,
    }:
        raise RouteALineageError("Route A registration evidence escalated authority")
    return RouteARegistrationInspection(
        source_git_sha=expected_s1,
        archive_sha256=_sha256(archive_bytes),
        registration_evidence_sha256=evidence_sha256,
        behavior_inventory_sha256=inventory_sha256,
    )


def build_route_a_registration_anchor(
    inspection: RouteARegistrationInspection,
    *,
    provider_run_id: int,
    provider_artifact_id: int,
    provider_artifact_digest: str,
) -> bytes:
    """Build the sole reviewed data-anchor proposal; this does not install it."""

    if type(inspection) is not RouteARegistrationInspection:
        raise TypeError("inspection must be an exact RouteARegistrationInspection")
    if (
        type(provider_run_id) is not int
        or provider_run_id <= 0
        or type(provider_artifact_id) is not int
        or provider_artifact_id <= 0
        or type(provider_artifact_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(provider_artifact_digest) is None
    ):
        raise RouteALineageError("Route A provider artifact identity is invalid")
    anchor = {
        "archive_sha256": inspection.archive_sha256,
        "behavior_inventory_sha256": inspection.behavior_inventory_sha256,
        "provider_artifact_digest": provider_artifact_digest,
        "provider_artifact_id": provider_artifact_id,
        "provider_run_id": provider_run_id,
        "registration_evidence_sha256": inspection.registration_evidence_sha256,
        "schema_version": _REGISTRATION_ANCHOR_SCHEMA,
        "source_git_sha": inspection.source_git_sha,
    }
    return _canonical_json_bytes(
        {"anchors": [anchor], "schema_version": _REGISTRATION_ANCHOR_SET_SCHEMA}
    )


def _changed_paths(repository: Path, s1: str, s2: str) -> list[str]:
    output = _git(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "-z",
        s1,
        s2,
    )
    try:
        return sorted(path.decode("utf-8") for path in output.split(b"\0") if path)
    except UnicodeDecodeError as error:
        raise RouteALineageError("Route A S1/S2 changed path is not UTF-8") from error


def verify_route_a_s1_s2_compatibility(
    repository: Path,
    *,
    s1: str,
    s2: str,
) -> RouteACompatibilityReceipt:
    """Verify ADR 0010 equality and the one-blob S1-to-S2 transition."""

    s1 = _resolve_commit(repository, s1, "S1")
    s2 = _resolve_commit(repository, s2, "S2")
    parents = _git(repository, "rev-list", "--parents", "-n", "1", s2).decode("ascii").split()
    if parents != [s2, s1]:
        raise RouteALineageError("Route A S2 must be the single direct child of exact S1")
    changed_paths = _changed_paths(repository, s1, s2)
    if changed_paths != [ROUTE_A_REGISTRATION_ANCHOR_PATH]:
        raise RouteALineageError("Route A S2 may change only the registration anchor data blob")
    if _read_git_blob(repository, s1, ROUTE_A_REGISTRATION_ANCHOR_PATH).content != (
        _EMPTY_ANCHOR_BYTES
    ):
        raise RouteALineageError("Route A S1 registration anchor is not empty")

    s1_inventories = {
        role: capture_route_a_behavior_inventory(repository, s1, role)
        for role in ROUTE_A_BEHAVIOR_ROLES
    }
    s2_inventories = {
        role: capture_route_a_behavior_inventory(repository, s2, role)
        for role in ROUTE_A_BEHAVIOR_ROLES
    }
    for role in ROUTE_A_BEHAVIOR_ROLES:
        if _behavior_set_document(s1_inventories[role]) != _behavior_set_document(
            s2_inventories[role]
        ):
            raise RouteALineageError(f"Route A {role} Behavior Set changed across S1/S2")

    anchor_blob = _read_git_blob(repository, s2, ROUTE_A_REGISTRATION_ANCHOR_PATH)
    anchor_set = _decode_canonical_json(
        anchor_blob.content, "Route A registration anchor", _MAX_REGISTRY_BYTES
    )
    if (
        set(anchor_set) != {"anchors", "schema_version"}
        or anchor_set["schema_version"] != _REGISTRATION_ANCHOR_SET_SCHEMA
    ):
        raise RouteALineageError("Route A registration anchor-set schema is invalid")
    anchors = anchor_set["anchors"]
    if type(anchors) is not list or len(anchors) != 1 or type(anchors[0]) is not dict:
        raise RouteALineageError("Route A S2 requires exactly one registration anchor")
    anchor = anchors[0]
    required_anchor_fields = {
        "archive_sha256",
        "behavior_inventory_sha256",
        "provider_artifact_digest",
        "provider_artifact_id",
        "provider_run_id",
        "registration_evidence_sha256",
        "schema_version",
        "source_git_sha",
    }
    if set(anchor) != required_anchor_fields or anchor["schema_version"] != (
        _REGISTRATION_ANCHOR_SCHEMA
    ):
        raise RouteALineageError("Route A registration anchor record is not closed")
    expected_inventory_sha256 = {
        role: inventory.sha256 for role, inventory in s1_inventories.items()
    }
    if (
        anchor["source_git_sha"] != s1
        or anchor["behavior_inventory_sha256"] != expected_inventory_sha256
        or type(anchor["archive_sha256"]) is not str
        or _LOWER_SHA256.fullmatch(anchor["archive_sha256"]) is None
        or type(anchor["registration_evidence_sha256"]) is not str
        or _LOWER_SHA256.fullmatch(anchor["registration_evidence_sha256"]) is None
        or type(anchor["provider_artifact_digest"]) is not str
        or _PROVIDER_DIGEST.fullmatch(anchor["provider_artifact_digest"]) is None
        or type(anchor["provider_artifact_id"]) is not int
        or anchor["provider_artifact_id"] <= 0
        or type(anchor["provider_run_id"]) is not int
        or anchor["provider_run_id"] <= 0
    ):
        raise RouteALineageError("Route A registration anchor identity is invalid")

    receipt_document = {
        "behavior_inventory_sha256": expected_inventory_sha256,
        "changed_paths": changed_paths,
        "compatibility_verified": True,
        "evidence_freeze_git_sha": s2,
        "experiment_source_git_sha": s1,
        "formal_authority_granted": False,
        "registration_anchor_blob_sha256": _sha256(anchor_blob.content),
        "registration_archive_sha256": anchor["archive_sha256"],
        "schema_version": _COMPATIBILITY_RECEIPT_SCHEMA,
    }
    content = _canonical_json_bytes(receipt_document)
    return RouteACompatibilityReceipt(document_bytes=content, sha256=_sha256(content))


def _behavior_set_document(inventory: RouteABehaviorInventory) -> dict[str, object]:
    document = inventory.document
    return {
        field: document[field]
        for field in (
            "behavior_set_registry_blob_sha256",
            "behavior_set_schema_version",
            "entries",
            "role",
            "schema_version",
        )
    }


def verify_route_a_s1_s2_s3_analysis_compatibility(
    repository: Path,
    *,
    s1: str,
    s2: str,
    s3: str,
) -> RouteACompatibilityReceipt:
    """Bind exact S1/S2/S3 identities and prove the analyzer Behavior Set equal."""

    from dynamic_cssc.evidence_compatibility import (
        EvidenceCompatibilityError,
        verify_repository_data_anchor_history,
    )

    registration_receipt = verify_route_a_s1_s2_compatibility(
        repository,
        s1=s1,
        s2=s2,
    )
    s1 = _resolve_commit(repository, s1, "S1")
    s2 = _resolve_commit(repository, s2, "S2")
    s3 = _resolve_commit(repository, s3, "S3")
    merge_bases = _git(repository, "merge-base", "--all", s2, s3).decode("ascii").split()
    if merge_bases != [s2]:
        raise RouteALineageError("Route A analysis S3 must descend from exact S2")
    inventories = {
        label: capture_route_a_behavior_inventory(repository, source, "analyzer")
        for label, source in (("s1", s1), ("s2", s2), ("s3", s3))
    }
    behavior_documents = {
        label: _behavior_set_document(inventory)
        for label, inventory in inventories.items()
    }
    if behavior_documents["s1"] != behavior_documents["s2"] or behavior_documents[
        "s1"
    ] != behavior_documents["s3"]:
        raise RouteALineageError("Route A analyzer Behavior Set changed across S1/S2/S3")
    try:
        verify_repository_data_anchor_history(
            repository,
            start_git_sha=s2,
            end_git_sha=s3,
        )
    except EvidenceCompatibilityError as error:
        raise RouteALineageError(
            f"Route A S2-to-S3 data-only history is invalid: {error}"
        ) from error

    behavior_set_bytes = _canonical_json_bytes(behavior_documents["s1"])
    receipt_document = {
        "analysis_compatibility_verified": True,
        "analysis_execution_authorized": False,
        "analysis_source_git_sha": s3,
        "analyzer_behavior_inventory_sha256": {
            label: inventory.sha256 for label, inventory in inventories.items()
        },
        "analyzer_behavior_set_exact": True,
        "analyzer_behavior_set_sha256": _sha256(behavior_set_bytes),
        "evidence_freeze_git_sha": s2,
        "experiment_source_git_sha": s1,
        "formal_authority_granted": False,
        "git_replace_refs_disabled": True,
        "registration_compatibility_receipt_sha256": registration_receipt.sha256,
        "runtime_execution_isolation_verified": False,
        "s2_to_s3_changed_paths": _changed_paths(repository, s2, s3),
        "schema_version": _ANALYSIS_COMPATIBILITY_RECEIPT_SCHEMA,
    }
    content = _canonical_json_bytes(receipt_document)
    return RouteACompatibilityReceipt(document_bytes=content, sha256=_sha256(content))
