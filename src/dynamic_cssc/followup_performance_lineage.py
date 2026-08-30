"""Git-object-bound S1/S2/S3 lineage for the follow-up performance study.

The data-only anchor is a deterministic function of exact S1 Git blobs.  This
avoids a circular dependency between an S2 commit ID and a provider artifact
that must itself bind S2.  Once the sole direct-child S2 exists, descriptive
registration emits a deterministic outer artifact bound to both S1 and S2.
Nothing in this module grants qualification or formal execution authority.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STAGE1_PLAN_SHA256,
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
    _parse_ascii_json,
    admit_followup_control_inner_payload,
    build_followup_unit_identity,
    followup_artifact_name,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)

__all__ = (
    "FOLLOWUP_BEHAVIOR_ROLES",
    "FOLLOWUP_REGISTRATION_ANCHOR_PATH",
    "FollowupBehaviorInventory",
    "FollowupCompatibilityReceipt",
    "FollowupLineageError",
    "FollowupRegistrationArchive",
    "FollowupRegistrationInspection",
    "build_followup_registration_anchor",
    "capture_followup_behavior_inventory",
    "inspect_followup_registration_archive",
    "produce_followup_registration_archive",
    "verify_followup_s1_s2_compatibility",
    "verify_followup_s1_s2_s3_analysis_compatibility",
)

FOLLOWUP_BEHAVIOR_ROLES = (
    "acquisition",
    "qualification",
    "formal",
    "analyzer",
    "control-registration",
)
FOLLOWUP_REGISTRATION_ANCHOR_PATH = (
    "config/followup-performance-registration-anchors.json"
)
_BEHAVIOR_REGISTRY_PATH = "config/followup-performance-behavior-sets.json"
_BEHAVIOR_REGISTRY_SCHEMA = (
    "dynamic-cssc-followup-performance-behavior-set-registry-v1"
)
_BEHAVIOR_INVENTORY_SCHEMA = (
    "dynamic-cssc-followup-performance-behavior-inventory-v1"
)
_REGISTRATION_EVIDENCE_SCHEMA = (
    "dynamic-cssc-followup-performance-registration-evidence-v1"
)
_REGISTRATION_ANCHOR_SET_SCHEMA = (
    "dynamic-cssc-followup-performance-registration-anchor-set-v1"
)
_REGISTRATION_ANCHOR_SCHEMA = (
    "dynamic-cssc-followup-performance-registration-anchor-v1"
)
_COMPATIBILITY_RECEIPT_SCHEMA = (
    "dynamic-cssc-followup-performance-s1-s2-compatibility-receipt-v1"
)
_ANALYSIS_COMPATIBILITY_RECEIPT_SCHEMA = (
    "dynamic-cssc-followup-performance-s1-s2-s3-analysis-compatibility-receipt-v1"
)
_EMPTY_ANCHOR_BYTES = _canonical_json_bytes(
    {"anchors": [], "schema_version": _REGISTRATION_ANCHOR_SET_SCHEMA}
)
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+\Z")
_MAX_REGISTRY_BYTES = 2 * 1024 * 1024
_MAX_BLOB_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


class FollowupLineageError(FollowupContractError):
    """One follow-up Git object, anchor, or registration object failed closed."""


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _git(repository: Path, *arguments: str) -> bytes:
    root = repository.resolve(strict=True)
    environment = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    try:
        result = subprocess.run(
            ("git", "--no-replace-objects", "-C", os.fspath(root), *arguments),
            check=True,
            capture_output=True,
            env=environment,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode("utf-8", errors="replace").strip()
        raise FollowupLineageError(f"Git object inspection failed: {detail}") from error
    return result.stdout


def _resolve_commit(repository: Path, git_sha: str, *, field: str) -> str:
    if type(git_sha) is not str or _LOWER_GIT_SHA.fullmatch(git_sha) is None:
        raise FollowupLineageError(f"{field} is not one lowercase Git SHA-1")
    observed = _git(repository, "rev-parse", "--verify", f"{git_sha}^{{commit}}")
    try:
        resolved = observed.decode("ascii").strip()
    except UnicodeDecodeError as error:  # pragma: no cover - Git object IDs are ASCII
        raise FollowupLineageError(f"{field} did not resolve to ASCII") from error
    if resolved != git_sha:
        raise FollowupLineageError(f"{field} did not resolve exactly")
    return resolved


def _safe_path(value: object) -> str:
    if (
        type(value) is not str
        or _SAFE_PATH.fullmatch(value) is None
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise FollowupLineageError("Behavior Set path is unsafe")
    return value


@dataclass(frozen=True, slots=True)
class _GitBlob:
    path: str
    mode: str
    object_id: str
    content: bytes


def _read_blob(repository: Path, git_sha: str, path: str) -> _GitBlob:
    path = _safe_path(path)
    rows = [
        row
        for row in _git(repository, "ls-tree", "-z", git_sha, "--", path).split(b"\0")
        if row
    ]
    if len(rows) != 1:
        raise FollowupLineageError(f"Git tree lacks one exact blob: {path}")
    try:
        header, observed_path = rows[0].split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        decoded_path = observed_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise FollowupLineageError(f"Git tree entry is malformed: {path}") from error
    if (
        decoded_path != path
        or mode not in {"100644", "100755"}
        or object_type != "blob"
        or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
    ):
        raise FollowupLineageError(f"Git tree entry is not an admitted blob: {path}")
    content = _git(repository, "cat-file", "blob", object_id)
    if len(content) > _MAX_BLOB_BYTES:
        raise FollowupLineageError(f"Behavior blob exceeds its bound: {path}")
    return _GitBlob(path=path, mode=mode, object_id=object_id, content=content)


def _json_object(content: bytes, *, label: str, canonical: bool) -> dict[str, object]:
    if type(content) is not bytes or not content or len(content) > _MAX_REGISTRY_BYTES:
        raise FollowupLineageError(f"{label} violates its byte bound")
    value = _parse_ascii_json(content, label=label)
    if type(value) is not dict or (canonical and _canonical_json_bytes(value) != content):
        raise FollowupLineageError(f"{label} is not one closed JSON object")
    return value


def _registry(repository: Path, git_sha: str) -> tuple[dict[str, object], str]:
    blob = _read_blob(repository, git_sha, _BEHAVIOR_REGISTRY_PATH)
    document = _json_object(
        blob.content,
        label="follow-up Behavior Set registry",
        canonical=False,
    )
    if (
        set(document) != {"roles", "schema_version", "stage1_documents"}
        or document.get("schema_version") != _BEHAVIOR_REGISTRY_SCHEMA
        or type(document.get("roles")) is not dict
        or set(document["roles"]) != set(FOLLOWUP_BEHAVIOR_ROLES)
        or type(document.get("stage1_documents")) is not dict
        or not document["stage1_documents"]
        or list(document["stage1_documents"]) != sorted(document["stage1_documents"])
    ):
        raise FollowupLineageError("follow-up Behavior Set registry is not closed")
    for path, digest in document["stage1_documents"].items():
        if (
            _LOWER_SHA256.fullmatch(str(digest)) is None
            or _sha256(_read_blob(repository, git_sha, _safe_path(path)).content) != digest
        ):
            raise FollowupLineageError(f"Stage-1 document is not exact: {path}")
    return document, _sha256(blob.content)


@dataclass(frozen=True, slots=True)
class FollowupBehaviorInventory:
    role: str
    source_git_sha: str
    document_bytes: bytes
    sha256: str

    @property
    def document(self) -> dict[str, object]:
        return _json_object(
            self.document_bytes,
            label="follow-up behavior inventory",
            canonical=True,
        )


def capture_followup_behavior_inventory(
    repository: Path,
    source_git_sha: str,
    role: str,
) -> FollowupBehaviorInventory:
    """Capture one role from exact Git blobs, never from worktree bytes."""

    source_git_sha = _resolve_commit(repository, source_git_sha, field="source_git_sha")
    if role not in FOLLOWUP_BEHAVIOR_ROLES:
        raise FollowupLineageError("follow-up behavior role is not registered")
    registry, registry_sha256 = _registry(repository, source_git_sha)
    role_document = registry["roles"][role]
    if type(role_document) is not dict or set(role_document) != {"paths", "schema_version"}:
        raise FollowupLineageError(f"follow-up {role} Behavior Set is open")
    paths = role_document.get("paths")
    schema_version = role_document.get("schema_version")
    if (
        type(paths) is not list
        or not paths
        or paths != sorted(set(paths))
        or _BEHAVIOR_REGISTRY_PATH not in paths
        or type(schema_version) is not str
        or not schema_version.startswith("dynamic-cssc-followup-performance-")
    ):
        raise FollowupLineageError(f"follow-up {role} Behavior Set is not canonical")
    entries = []
    for raw_path in paths:
        blob = _read_blob(repository, source_git_sha, _safe_path(raw_path))
        entries.append(
            {
                "git_object_id": blob.object_id,
                "mode": blob.mode,
                "path": blob.path,
                "sha256": _sha256(blob.content),
                "type": "blob",
            }
        )
    document_bytes = _canonical_json_bytes(
        {
            "behavior_set_registry_blob_sha256": registry_sha256,
            "behavior_set_schema_version": schema_version,
            "entries": entries,
            "role": role,
            "schema_version": _BEHAVIOR_INVENTORY_SCHEMA,
            "source_git_sha": source_git_sha,
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )
    return FollowupBehaviorInventory(
        role=role,
        source_git_sha=source_git_sha,
        document_bytes=document_bytes,
        sha256=_sha256(document_bytes),
    )


def _inventory_hashes(repository: Path, source_git_sha: str) -> dict[str, str]:
    return {
        role: capture_followup_behavior_inventory(repository, source_git_sha, role).sha256
        for role in FOLLOWUP_BEHAVIOR_ROLES
    }


def build_followup_registration_anchor(repository: Path, *, s1: str) -> bytes:
    """Build the deterministic data-only S2 anchor from exact S1 Git blobs."""

    s1 = _resolve_commit(repository, s1, field="S1")
    anchor = {
        "authority": False,
        "behavior_inventory_sha256": _inventory_hashes(repository, s1),
        "formal_execution_authorized": False,
        "qualification_dispatch_authorized": False,
        "schema_version": _REGISTRATION_ANCHOR_SCHEMA,
        "source_git_sha": s1,
        "stage1_plan_sha256": FOLLOWUP_STAGE1_PLAN_SHA256,
        "study_id": FOLLOWUP_STUDY_ID,
    }
    return _canonical_json_bytes(
        {
            "anchors": [anchor],
            "schema_version": _REGISTRATION_ANCHOR_SET_SCHEMA,
        }
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
        raise FollowupLineageError("S1/S2 changed path is not UTF-8") from error


@dataclass(frozen=True, slots=True)
class FollowupCompatibilityReceipt:
    document_bytes: bytes
    sha256: str

    @property
    def document(self) -> dict[str, object]:
        return _json_object(
            self.document_bytes,
            label="follow-up compatibility receipt",
            canonical=True,
        )


def _behavior_projection(inventory: FollowupBehaviorInventory) -> dict[str, object]:
    document = inventory.document
    return {
        key: document[key]
        for key in (
            "behavior_set_registry_blob_sha256",
            "behavior_set_schema_version",
            "entries",
            "role",
            "schema_version",
            "study_id",
        )
    }


def verify_followup_s1_s2_compatibility(
    repository: Path,
    *,
    s1: str,
    s2: str,
) -> FollowupCompatibilityReceipt:
    """Prove S2 is the sole data-anchor child and all behavior blobs are equal."""

    s1 = _resolve_commit(repository, s1, field="S1")
    s2 = _resolve_commit(repository, s2, field="S2")
    parents = _git(repository, "rev-list", "--parents", "-n", "1", s2).decode(
        "ascii"
    ).split()
    if parents != [s2, s1]:
        raise FollowupLineageError("follow-up S2 is not the single direct child of S1")
    changed_paths = _changed_paths(repository, s1, s2)
    if changed_paths != [FOLLOWUP_REGISTRATION_ANCHOR_PATH]:
        raise FollowupLineageError("follow-up S2 may change only its data anchor")
    s1_anchor = _read_blob(repository, s1, FOLLOWUP_REGISTRATION_ANCHOR_PATH)
    if s1_anchor.mode != "100644":
        raise FollowupLineageError("follow-up S1 registration anchor mode is not 100644")
    if s1_anchor.content != _EMPTY_ANCHOR_BYTES:
        raise FollowupLineageError("follow-up S1 registration anchor is not empty")
    inventories_s1 = {
        role: capture_followup_behavior_inventory(repository, s1, role)
        for role in FOLLOWUP_BEHAVIOR_ROLES
    }
    inventories_s2 = {
        role: capture_followup_behavior_inventory(repository, s2, role)
        for role in FOLLOWUP_BEHAVIOR_ROLES
    }
    for role in FOLLOWUP_BEHAVIOR_ROLES:
        if _behavior_projection(inventories_s1[role]) != _behavior_projection(
            inventories_s2[role]
        ):
            raise FollowupLineageError(f"follow-up {role} Behavior Set changed across S1/S2")
    s2_anchor = _read_blob(
        repository,
        s2,
        FOLLOWUP_REGISTRATION_ANCHOR_PATH,
    )
    if s2_anchor.mode != "100644":
        raise FollowupLineageError("follow-up S2 registration anchor mode is not 100644")
    anchor_bytes = s2_anchor.content
    if anchor_bytes != build_followup_registration_anchor(repository, s1=s1):
        raise FollowupLineageError("follow-up S2 data anchor differs from exact S1")
    receipt_bytes = _canonical_json_bytes(
        {
            "authority": False,
            "behavior_inventory_sha256": {
                role: inventory.sha256 for role, inventory in inventories_s1.items()
            },
            "changed_paths": changed_paths,
            "compatibility_verified": True,
            "evidence_freeze_S2_sha": s2,
            "experiment_source_S1_sha": s1,
            "formal_execution_authorized": False,
            "registration_anchor_sha256": _sha256(anchor_bytes),
            "schema_version": _COMPATIBILITY_RECEIPT_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )
    return FollowupCompatibilityReceipt(
        document_bytes=receipt_bytes,
        sha256=_sha256(receipt_bytes),
    )


def verify_followup_s1_s2_s3_analysis_compatibility(
    repository: Path,
    *,
    s1: str,
    s2: str,
    s3: str,
) -> FollowupCompatibilityReceipt:
    """Bind a direct empty S3 child whose analyzer blobs equal exact S1/S2."""

    registration = verify_followup_s1_s2_compatibility(repository, s1=s1, s2=s2)
    s1 = _resolve_commit(repository, s1, field="S1")
    s2 = _resolve_commit(repository, s2, field="S2")
    s3 = _resolve_commit(repository, s3, field="S3")
    parents = _git(repository, "rev-list", "--parents", "-n", "1", s3).decode(
        "ascii"
    ).split()
    if parents != [s3, s2] or _changed_paths(repository, s2, s3):
        raise FollowupLineageError(
            "follow-up analysis S3 must be one direct empty child of exact S2"
        )
    inventories = {
        label: capture_followup_behavior_inventory(repository, source, "analyzer")
        for label, source in (("s1", s1), ("s2", s2), ("s3", s3))
    }
    projections = {
        label: _behavior_projection(inventory)
        for label, inventory in inventories.items()
    }
    if projections["s1"] != projections["s2"] or projections["s1"] != projections["s3"]:
        raise FollowupLineageError(
            "follow-up analyzer Behavior Set changed across S1/S2/S3"
        )
    behavior_bytes = _canonical_json_bytes(projections["s1"])
    receipt_bytes = _canonical_json_bytes(
        {
            "analysis_compatibility_verified": True,
            "analysis_execution_authorized": False,
            "analysis_source_S3_sha": s3,
            "analyzer_behavior_inventory_sha256": {
                label: inventory.sha256 for label, inventory in inventories.items()
            },
            "analyzer_behavior_set_exact": True,
            "analyzer_behavior_set_sha256": _sha256(behavior_bytes),
            "authority": False,
            "evidence_freeze_S2_sha": s2,
            "experiment_source_S1_sha": s1,
            "formal_execution_authorized": False,
            "registration_compatibility_receipt_sha256": registration.sha256,
            "runtime_execution_isolation_verified": False,
            "s2_to_s3_changed_paths": [],
            "schema_version": _ANALYSIS_COMPATIBILITY_RECEIPT_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )
    return FollowupCompatibilityReceipt(
        document_bytes=receipt_bytes,
        sha256=_sha256(receipt_bytes),
    )


def _registration_evidence(
    repository: Path,
    *,
    s1: str,
    s2: str,
) -> tuple[bytes, dict[str, str], FollowupCompatibilityReceipt]:
    compatibility = verify_followup_s1_s2_compatibility(repository, s1=s1, s2=s2)
    inventories = {
        role: capture_followup_behavior_inventory(repository, s1, role)
        for role in FOLLOWUP_BEHAVIOR_ROLES
    }
    hashes = {role: inventory.sha256 for role, inventory in inventories.items()}
    evidence = _canonical_json_bytes(
        {
            "authority": False,
            "behavior_inventories": {
                role: inventory.document for role, inventory in inventories.items()
            },
            "behavior_inventory_sha256": hashes,
            "compatibility_receipt": compatibility.document,
            "compatibility_receipt_sha256": compatibility.sha256,
            "evidence_freeze_S2_sha": s2,
            "experiment_source_S1_sha": s1,
            "formal_execution_authorized": False,
            "qualification_dispatch_authorized": False,
            "registration_anchor_minted": False,
            "schema_version": _REGISTRATION_EVIDENCE_SCHEMA,
            "stage1_plan_sha256": FOLLOWUP_STAGE1_PLAN_SHA256,
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )
    return evidence, hashes, compatibility


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[name])
    result = output.getvalue()
    if len(result) > _MAX_ARCHIVE_BYTES:
        raise FollowupLineageError("follow-up registration archive exceeds its bound")
    return result


def _archive_members(archive_bytes: bytes) -> dict[str, bytes]:
    if type(archive_bytes) is not bytes or not 0 < len(archive_bytes) <= _MAX_ARCHIVE_BYTES:
        raise FollowupLineageError("follow-up registration archive violates its bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            if archive.comment:
                raise FollowupLineageError("follow-up registration archive has a comment")
            names = archive.namelist()
            if (
                len(names) != len(set(names))
                or any(name.startswith("/") or ".." in Path(name).parts for name in names)
                or any(info.compress_type != zipfile.ZIP_STORED for info in archive.infolist())
            ):
                raise FollowupLineageError("follow-up registration archive is unsafe")
            return {name: archive.read(name) for name in names}
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise FollowupLineageError("follow-up registration archive is unreadable") from error


@dataclass(frozen=True, slots=True)
class FollowupRegistrationArchive:
    source_git_sha: str
    evidence_freeze_git_sha: str
    archive_bytes: bytes
    archive_sha256: str
    artifact_name: str
    envelope_sha256: str
    registration_evidence_sha256: str
    compatibility_receipt_sha256: str
    behavior_inventory_sha256: dict[str, str]


@dataclass(frozen=True, slots=True)
class FollowupRegistrationInspection:
    source_git_sha: str
    evidence_freeze_git_sha: str
    archive_sha256: str
    artifact_name: str
    envelope: FollowupEvidenceEnvelope
    registration_evidence_sha256: str
    compatibility_receipt_sha256: str
    behavior_inventory_sha256: dict[str, str]


def _registration_members(
    repository: Path,
    *,
    s1: str,
    s2: str,
) -> tuple[dict[str, bytes], str, str, dict[str, str]]:
    evidence, inventory_hashes, compatibility = _registration_evidence(
        repository,
        s1=s1,
        s2=s2,
    )
    scope = {
        "behavior_inventory_sha256": inventory_hashes,
        "compatibility_receipt_sha256": compatibility.sha256,
        "evidence_freeze_S2_sha": s2,
        "experiment_source_S1_sha": s1,
        "stage1_plan_sha256": FOLLOWUP_STAGE1_PLAN_SHA256,
    }
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind="control-registration",
        unit_attempt_ordinal=1,
        scope=scope,
    )
    admission = admit_followup_control_inner_payload(
        inner_role="descriptive-registration",
        inner_bytes=evidence,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=s1,
        evidence_freeze_s2_sha=s2,
        unit_kind="control-registration",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    contents = {
        "outer-envelope.json": envelope.document_bytes,
        "registration-evidence.json": evidence,
        "unit-identity.json": unit_bytes,
    }
    contents["checksums.sha256"] = b"".join(
        f"{_sha256(content)}  {name}\n".encode("ascii")
        for name, content in sorted(contents.items())
    )
    return contents, compatibility.sha256, envelope.sha256, inventory_hashes


def _assert_clean_exact_head(repository: Path, expected_s2: str) -> None:
    head = _git(repository, "rev-parse", "HEAD").decode("ascii").strip()
    dirty = _git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    if head != expected_s2 or dirty:
        raise FollowupLineageError("registration requires one clean exact-S2 checkout")


def produce_followup_registration_archive(
    repository: Path,
    *,
    s1: str,
    s2: str,
) -> FollowupRegistrationArchive:
    """Produce deterministic descriptive registration from clean exact S2."""

    s1 = _resolve_commit(repository, s1, field="S1")
    s2 = _resolve_commit(repository, s2, field="S2")
    _assert_clean_exact_head(repository, s2)
    members, compatibility_sha256, envelope_sha256, inventory_hashes = (
        _registration_members(repository, s1=s1, s2=s2)
    )
    archive_bytes = _zip_bytes(members)
    evidence_sha256 = _sha256(members["registration-evidence.json"])
    _unit = _json_object(
        members["unit-identity.json"],
        label="follow-up registration unit identity",
        canonical=True,
    )
    artifact_name = followup_artifact_name(
        unit_kind="control-registration",
        unit_identity_sha256=_sha256(members["unit-identity.json"]),
        unit_attempt_ordinal=1,
    )
    return FollowupRegistrationArchive(
        source_git_sha=s1,
        evidence_freeze_git_sha=s2,
        archive_bytes=archive_bytes,
        archive_sha256=_sha256(archive_bytes),
        artifact_name=artifact_name,
        envelope_sha256=envelope_sha256,
        registration_evidence_sha256=evidence_sha256,
        compatibility_receipt_sha256=compatibility_sha256,
        behavior_inventory_sha256=inventory_hashes,
    )


def inspect_followup_registration_archive(
    repository: Path,
    *,
    s1: str,
    s2: str,
    archive_bytes: bytes,
) -> FollowupRegistrationInspection:
    """Independently recompute every inner and outer registration byte."""

    s1 = _resolve_commit(repository, s1, field="S1")
    s2 = _resolve_commit(repository, s2, field="S2")
    expected, compatibility_sha256, envelope_sha256, inventory_hashes = (
        _registration_members(repository, s1=s1, s2=s2)
    )
    observed = _archive_members(archive_bytes)
    if observed != expected or _zip_bytes(observed) != archive_bytes:
        raise FollowupLineageError("follow-up registration archive bytes changed")
    unit_identity_sha256 = _sha256(observed["unit-identity.json"])
    envelope = inspect_followup_outer_envelope(
        observed["outer-envelope.json"],
        observed["registration-evidence.json"],
        expected_experiment_source_s1_sha=s1,
        expected_evidence_freeze_s2_sha=s2,
    )
    if envelope.sha256 != envelope_sha256:
        raise FollowupLineageError("follow-up registration envelope changed")
    artifact_name = followup_artifact_name(
        unit_kind="control-registration",
        unit_identity_sha256=unit_identity_sha256,
        unit_attempt_ordinal=1,
    )
    return FollowupRegistrationInspection(
        source_git_sha=s1,
        evidence_freeze_git_sha=s2,
        archive_sha256=_sha256(archive_bytes),
        artifact_name=artifact_name,
        envelope=envelope,
        registration_evidence_sha256=_sha256(observed["registration-evidence.json"]),
        compatibility_receipt_sha256=compatibility_sha256,
        behavior_inventory_sha256=inventory_hashes,
    )
