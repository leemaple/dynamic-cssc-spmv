"""Build a review-only repository anchor proposal from formal Day 2 output."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path

from dynamic_cssc.day2_calibration_authority import (
    Day2CalibrationAuthorityError,
    inspect_day2_calibration_archive,
    validate_day2_calibration_post_run_anchor_document,
)
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactDirectory,
    PublicationArtifactInstallError,
    install_verified_directory,
    quarantine_owned_directory,
)

__all__ = (
    "Day2CalibrationPostRunError",
    "Day2CalibrationPostRunProposal",
    "propose_repository_day2_calibration_post_run_anchor",
)

_MAX_JSON_BYTES = 1024 * 1024
_PROPOSAL_MEMBERS = (
    "day2-calibration-inspection.json",
    "day2-calibration-post-run-anchor-proposal.json",
    "day2-github-artifact-metadata.json",
)
_MANIFEST_NAME = "POSTRUN-MANIFEST.json"
_CHECKSUMS_NAME = "SHA256SUMS"
_PROPOSAL_FILES = frozenset((*_PROPOSAL_MEMBERS, _MANIFEST_NAME, _CHECKSUMS_NAME))


class Day2CalibrationPostRunError(ValueError):
    """Formal Day 2 output could not yield an exact review proposal."""


@dataclass(frozen=True, slots=True)
class Day2CalibrationPostRunProposal:
    """Identity of one atomically installed, non-authoritative proposal."""

    output_dir: Path
    outer_archive_sha256: str
    anchor_document_sha256: str
    github_metadata_sha256: str
    inspection_sha256: str
    manifest_sha256: str
    checksums_sha256: str
    formal_authority_granted: bool = False


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise Day2CalibrationPostRunError("post-run value is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _decode_canonical_path(path: Path, field: str) -> tuple[dict[str, object], bytes]:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise Day2CalibrationPostRunError(f"{field} must be a regular non-symlink file")
    content = path.read_bytes()
    if not content or len(content) > _MAX_JSON_BYTES:
        raise Day2CalibrationPostRunError(f"{field} exceeds its closed byte bound")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise Day2CalibrationPostRunError(f"{field} contains a duplicate JSON key")
            document[key] = value
        return document

    try:
        document = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationPostRunError(f"{field} is not readable JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise Day2CalibrationPostRunError(f"{field} is not canonical JSON")
    return document, content


def _artifact_behavior_inventory(archive_path: Path) -> dict[str, object]:
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            content = archive.read("source-provenance.json")
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise Day2CalibrationPostRunError(
            "source provenance is unavailable from the inspected archive"
        ) from error
    if not content or len(content) > _MAX_JSON_BYTES:
        raise Day2CalibrationPostRunError("source provenance exceeds its closed byte bound")
    try:
        source = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationPostRunError("source provenance is not JSON") from error
    if type(source) is not dict or _canonical_json_bytes(source) != content:
        raise Day2CalibrationPostRunError("source provenance is not canonical JSON")
    inventory = source.get("behavior_inventory")
    if type(inventory) is not dict:
        raise Day2CalibrationPostRunError("artifact Behavior inventory is unavailable")
    return inventory


def _proposal_documents(
    archive_path: Path,
    github_metadata_path: Path,
) -> tuple[dict[str, bytes], str]:
    metadata, metadata_bytes = _decode_canonical_path(
        github_metadata_path,
        "Day 2 GitHub artifact metadata",
    )
    expected_sha256 = metadata.get("inner_archive_sha256")
    if type(expected_sha256) is not str:
        raise Day2CalibrationPostRunError("Day 2 inner archive identity is unavailable")
    try:
        inspection = inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=expected_sha256,
            github_metadata=metadata,
        )
    except Day2CalibrationAuthorityError as error:
        raise Day2CalibrationPostRunError(
            "Day 2 archive failed descriptive inspection"
        ) from error
    inventory = _artifact_behavior_inventory(archive_path)
    inventory_bytes = _canonical_json_bytes(inventory)
    if _sha256(inventory_bytes) != inspection.artifact_behavior_inventory_sha256:
        raise Day2CalibrationPostRunError("artifact Behavior inventory identity changed")
    anchor = {
        "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-v4",
        "experiment_source_git_sha": inspection.source_git_sha,
        "experiment_behavior_set_schema_version": inspection.behavior_set_schema_version,
        "experiment_behavior_set_sha256": inspection.behavior_set_sha256,
        "artifact_behavior_inventory": inventory,
        "artifact_behavior_inventory_sha256": inspection.artifact_behavior_inventory_sha256,
        "outer_archive_sha256": inspection.outer_archive_sha256,
        "raw_measurement_blocks_sha256": inspection.raw_measurement_blocks_sha256,
        "operation_profile_set_sha256": inspection.operation_profile_set_sha256,
        "rotation_key_plan_sha256": inspection.rotation_key_plan_sha256,
        "generated_key_inventory_sha256": inspection.generated_key_inventory_sha256,
        "runtime_isolation_receipt_sha256": inspection.runtime_isolation_receipt_sha256,
        "contract_bindings_sha256": inspection.contract_bindings_sha256,
        "calibration_projection_sha256": inspection.calibration_projection_sha256,
    }
    anchor_document = {
        "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        "anchors": [anchor],
    }
    anchor_bytes = _canonical_json_bytes(anchor_document)
    try:
        validate_day2_calibration_post_run_anchor_document(anchor_bytes)
    except Day2CalibrationAuthorityError as error:
        raise Day2CalibrationPostRunError("post-run anchor proposal is invalid") from error
    inspection_document = {
        "schema_version": "dynamic-cssc-day2-calibration-inspection-v1",
        **asdict(inspection),
        "formal_authority_granted": False,
    }
    payloads = {
        "day2-calibration-inspection.json": _canonical_json_bytes(inspection_document),
        "day2-calibration-post-run-anchor-proposal.json": anchor_bytes,
        "day2-github-artifact-metadata.json": metadata_bytes,
    }
    manifest = {
        "schema_version": "dynamic-cssc-day2-calibration-post-run-proposal-manifest-v1",
        "formal_authority_granted": False,
        "input_archive_sha256": inspection.outer_archive_sha256,
        "files": [
            {"path": name, "sha256": _sha256(payloads[name]), "bytes": len(payloads[name])}
            for name in _PROPOSAL_MEMBERS
        ],
    }
    payloads[_MANIFEST_NAME] = _canonical_json_bytes(manifest)
    checksummed = sorted((*_PROPOSAL_MEMBERS, _MANIFEST_NAME))
    payloads[_CHECKSUMS_NAME] = "".join(
        f"{_sha256(payloads[name])}  {name}\n" for name in checksummed
    ).encode("ascii")
    return payloads, inspection.outer_archive_sha256


def _write_new_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _verify_proposal(
    view: PublicationArtifactDirectory,
    expected: dict[str, bytes],
) -> tuple[tuple[str, str], ...]:
    if frozenset(view.entries()) != _PROPOSAL_FILES:
        raise Day2CalibrationPostRunError("post-run proposal member set is not closed")
    observed = []
    for name in sorted(expected):
        content = view.read_regular(name)
        if content != expected[name]:
            raise Day2CalibrationPostRunError(f"post-run proposal member changed: {name}")
        observed.append((name, _sha256(content)))
    return tuple(observed)


def propose_repository_day2_calibration_post_run_anchor(
    archive_path: Path,
    github_artifact_metadata_path: Path,
    output_directory: Path,
) -> Day2CalibrationPostRunProposal:
    """Inspect formal output and atomically install one review-only proposal."""

    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a pathlib.Path")
    output_directory = output_directory.absolute()
    if output_directory.exists() or output_directory.is_symlink():
        raise Day2CalibrationPostRunError("post-run proposal output must be absent")
    parent = output_directory.parent
    if parent.is_symlink() or not parent.is_dir():
        raise Day2CalibrationPostRunError(
            "post-run proposal parent must be a regular directory"
        )
    payloads, archive_sha256 = _proposal_documents(
        archive_path,
        github_artifact_metadata_path,
    )
    stage: Path | None = None
    identity: tuple[int, int] | None = None
    try:
        stage = Path(
            tempfile.mkdtemp(prefix=f".{output_directory.name}.stage-", dir=parent)
        )
        observed = stage.stat(follow_symlinks=False)
        identity = (observed.st_dev, observed.st_ino)
        for name in sorted(payloads):
            _write_new_file(stage / name, payloads[name])
        directory_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        install_verified_directory(
            stage,
            output_directory,
            staging_identity=identity,
            verifier=lambda view: _verify_proposal(view, payloads),
            fingerprint=lambda value: value,
        )
        stage = None
    except PublicationArtifactInstallError as error:
        raise Day2CalibrationPostRunError(
            "post-run proposal installation failed closed"
        ) from error
    finally:
        if stage is not None and identity is not None:
            with suppress(OSError, PublicationArtifactInstallError):
                quarantine_owned_directory(stage, staging_identity=identity)
    return Day2CalibrationPostRunProposal(
        output_dir=output_directory,
        outer_archive_sha256=archive_sha256,
        anchor_document_sha256=_sha256(
            payloads["day2-calibration-post-run-anchor-proposal.json"]
        ),
        github_metadata_sha256=_sha256(payloads["day2-github-artifact-metadata.json"]),
        inspection_sha256=_sha256(payloads["day2-calibration-inspection.json"]),
        manifest_sha256=_sha256(payloads[_MANIFEST_NAME]),
        checksums_sha256=_sha256(payloads[_CHECKSUMS_NAME]),
    )
