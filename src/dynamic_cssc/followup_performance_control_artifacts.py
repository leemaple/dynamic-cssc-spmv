"""Closed outer artifacts for authority-false follow-up control workflows."""

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
    _parse_ascii_json,
    admit_followup_control_inner_payload,
    build_followup_unit_identity,
    followup_artifact_name,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)

__all__ = (
    "FollowupControlArtifactInspection",
    "FollowupControlKind",
    "build_followup_control_receipt",
    "inspect_followup_control_artifact",
    "produce_followup_control_artifact",
)

FollowupControlKind = Literal["ci", "pre-s1", "independent-review", "source-anchor"]

_CONTROL_BINDING = {
    "ci": ("control-ci", "ci-provenance"),
    "pre-s1": ("control-pre-s1", "pre-s1-resource-validation"),
    "independent-review": ("control-independent-review", "independent-review"),
    "source-anchor": ("control-source-anchor", "source-anchor"),
}
_FILES = ("inner-payload.json", "outer-envelope.json", "unit-identity.json")
_MAX_FILE_BYTES = 4 * 1024 * 1024


class FollowupControlArtifactError(FollowupContractError):
    """One control receipt or outer artifact failed closed."""


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _direct_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be an absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise FollowupControlArtifactError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupControlArtifactError(f"{label} is not a direct directory")
    return path


def _stable_read(path: Path) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise FollowupControlArtifactError("control artifact member is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_FILE_BYTES:
            raise FollowupControlArtifactError("control artifact member violates its bound")
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
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise FollowupControlArtifactError("control artifact member changed while read")
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
            if written <= 0:  # pragma: no cover - os.write advances or raises
                raise FollowupControlArtifactError("control artifact write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _binding(kind: FollowupControlKind) -> tuple[str, str]:
    if kind not in _CONTROL_BINDING:
        raise FollowupControlArtifactError("control kind is outside its closed domain")
    return _CONTROL_BINDING[kind]


def build_followup_control_receipt(
    *,
    kind: FollowupControlKind,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    compatibility_receipt_sha256: str,
    provider_run_id: int,
    provider_run_attempt: int,
    details: dict[str, str],
) -> bytes:
    """Build one canonical success-only control receipt."""

    unit_kind, inner_role = _binding(kind)
    if (
        type(details) is not dict
        or not details
        or any(type(key) is not str or not key for key in details)
        or any(type(value) is not str or not value for value in details.values())
        or list(details) != sorted(details)
        or type(provider_run_id) is not int
        or provider_run_id <= 0
        or provider_run_attempt != 1
    ):
        raise FollowupControlArtifactError("control receipt details or run identity changed")
    receipt = _canonical_json_bytes(
        {
            "authority": False,
            "compatibility_receipt_sha256": compatibility_receipt_sha256,
            "control_kind": kind,
            "details": details,
            "details_sha256": _sha256(_canonical_json_bytes(details)),
            "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
            "experiment_source_S1_sha": experiment_source_s1_sha,
            "formal_execution_authorized": False,
            "inner_role": inner_role,
            "outcome": "success",
            "provider_run_attempt": provider_run_attempt,
            "provider_run_id": provider_run_id,
            "schema_version": f"dynamic-cssc-followup-performance-{kind}-control-receipt-v1",
            "study_id": FOLLOWUP_STUDY_ID,
            "unit_kind": unit_kind,
        }
    )
    admit_followup_control_inner_payload(inner_role=inner_role, inner_bytes=receipt)
    return receipt


def _scope(receipt: dict[str, object]) -> dict[str, object]:
    return {
        "compatibility_receipt_sha256": receipt["compatibility_receipt_sha256"],
        "control_kind": receipt["control_kind"],
        "evidence_freeze_S2_sha": receipt["evidence_freeze_S2_sha"],
        "experiment_source_S1_sha": receipt["experiment_source_S1_sha"],
        "provider_run_attempt": receipt["provider_run_attempt"],
        "provider_run_id": receipt["provider_run_id"],
    }


@dataclass(frozen=True, slots=True)
class FollowupControlArtifactInspection:
    kind: FollowupControlKind
    root: Path
    artifact_name: str
    receipt_bytes: bytes
    receipt: dict[str, object]
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope


def inspect_followup_control_artifact(
    root: Path,
    *,
    expected_kind: FollowupControlKind,
    expected_receipt_bytes: bytes | None = None,
) -> FollowupControlArtifactInspection:
    """Rehash and independently decode one exact control artifact tree."""

    root = _direct_directory(root, label="control artifact root")
    if set(path.name for path in root.iterdir()) != {*_FILES, "checksums.sha256"}:
        raise FollowupControlArtifactError("control artifact members are missing or extra")
    contents = {name: _stable_read(root / name) for name in _FILES}
    checksums = b"".join(
        f"{_sha256(contents[name])}  {name}\n".encode("ascii") for name in _FILES
    )
    if _stable_read(root / "checksums.sha256") != checksums:
        raise FollowupControlArtifactError("control artifact checksums changed")
    receipt_value = _parse_ascii_json(
        contents["inner-payload.json"],
        label="follow-up control receipt",
    )
    if type(receipt_value) is not dict:
        raise FollowupControlArtifactError("control receipt is not one JSON object")
    receipt = receipt_value
    unit_kind, inner_role = _binding(expected_kind)
    if (
        expected_receipt_bytes is not None
        and contents["inner-payload.json"] != expected_receipt_bytes
    ):
        raise FollowupControlArtifactError("control receipt differs from expectation")
    expected = build_followup_control_receipt(
        kind=expected_kind,
        experiment_source_s1_sha=str(receipt.get("experiment_source_S1_sha")),
        evidence_freeze_s2_sha=str(receipt.get("evidence_freeze_S2_sha")),
        compatibility_receipt_sha256=str(receipt.get("compatibility_receipt_sha256")),
        provider_run_id=receipt.get("provider_run_id"),  # type: ignore[arg-type]
        provider_run_attempt=receipt.get("provider_run_attempt"),  # type: ignore[arg-type]
        details=receipt.get("details"),  # type: ignore[arg-type]
    )
    if contents["inner-payload.json"] != expected or receipt.get("inner_role") != inner_role:
        raise FollowupControlArtifactError("control receipt content changed")
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind=unit_kind,
        unit_attempt_ordinal=1,
        scope=_scope(receipt),
    )
    if contents["unit-identity.json"] != unit_bytes:
        raise FollowupControlArtifactError("control unit identity changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        contents["inner-payload.json"],
        expected_experiment_source_s1_sha=str(receipt["experiment_source_S1_sha"]),
        expected_evidence_freeze_s2_sha=str(receipt["evidence_freeze_S2_sha"]),
    )
    if (
        envelope.document["unit_kind"] != unit_kind
        or envelope.document["inner_role"] != inner_role
        or envelope.document["unit_identity_sha256"] != unit_sha256
    ):
        raise FollowupControlArtifactError("control envelope differs from its unit")
    return FollowupControlArtifactInspection(
        kind=expected_kind,
        root=root,
        artifact_name=followup_artifact_name(
            unit_kind=unit_kind,
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=1,
        ),
        receipt_bytes=contents["inner-payload.json"],
        receipt=receipt,
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
    )


def produce_followup_control_artifact(
    receipt_bytes: bytes,
    output_directory: Path,
    *,
    kind: FollowupControlKind,
) -> FollowupControlArtifactInspection:
    """Atomically install one already validated control receipt and its envelope."""

    receipt_value = _parse_ascii_json(receipt_bytes, label="follow-up control receipt")
    if type(receipt_value) is not dict:
        raise FollowupControlArtifactError("control receipt is not one JSON object")
    receipt = receipt_value
    unit_kind, inner_role = _binding(kind)
    expected = build_followup_control_receipt(
        kind=kind,
        experiment_source_s1_sha=str(receipt.get("experiment_source_S1_sha")),
        evidence_freeze_s2_sha=str(receipt.get("evidence_freeze_S2_sha")),
        compatibility_receipt_sha256=str(receipt.get("compatibility_receipt_sha256")),
        provider_run_id=receipt.get("provider_run_id"),  # type: ignore[arg-type]
        provider_run_attempt=receipt.get("provider_run_attempt"),  # type: ignore[arg-type]
        details=receipt.get("details"),  # type: ignore[arg-type]
    )
    if expected != receipt_bytes:
        raise FollowupControlArtifactError("control receipt bytes are not exact")
    _direct_directory(output_directory.parent, label="control artifact output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupControlArtifactError("control artifact output must be absent")
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind=unit_kind,
        unit_attempt_ordinal=1,
        scope=_scope(receipt),
    )
    admission = admit_followup_control_inner_payload(
        inner_role=inner_role,
        inner_bytes=receipt_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=str(receipt["experiment_source_S1_sha"]),
        evidence_freeze_s2_sha=str(receipt["evidence_freeze_S2_sha"]),
        unit_kind=unit_kind,
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    contents = {
        "inner-payload.json": receipt_bytes,
        "outer-envelope.json": envelope.document_bytes,
        "unit-identity.json": unit_bytes,
    }
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    try:
        for name in _FILES:
            _write_new(temporary / name, contents[name])
        _write_new(
            temporary / "checksums.sha256",
            b"".join(
                f"{_sha256(contents[name])}  {name}\n".encode("ascii")
                for name in _FILES
            ),
        )
        os.replace(temporary, output_directory)
        return inspect_followup_control_artifact(
            output_directory,
            expected_kind=kind,
            expected_receipt_bytes=receipt_bytes,
        )
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
