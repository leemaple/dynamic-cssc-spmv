"""Capture provider-observed GitHub identities for the formal Day 2 chain.

The public seams accept filesystem paths only.  Run and artifact identities
come from repository-owned anchors, the live GitHub workflow environment, and
authenticated provider API responses; callers cannot supply claim semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from dynamic_cssc.day1a_export import (
    AUTHORITY_RECEIPT_FILENAME,
    COUNT_BUNDLE_FILENAME,
    ROTATION_INVENTORY_FILENAME,
)
from dynamic_cssc.day2_calibration_authority import (
    inspect_day2_calibration_archive,
    validate_day2_calibration_profile_anchor_document,
)

__all__ = (
    "Day2CalibrationGitHubError",
    "capture_repository_day1a_github_metadata",
    "capture_repository_day2_github_metadata",
)

_REPOSITORY = "leemaple/dynamic-cssc-spmv"
_REPOSITORY_ID = 1_341_939_625
_DAY1A_WORKFLOW_PATH = ".github/workflows/day1a-publication-cost-model.yml"
_DAY2_WORKFLOW_PATH = ".github/workflows/day2-publication-calibration.yml"
_PROFILE_ANCHOR_PATH = Path("config/day2-calibration-profile-anchors.json")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DAY1A_ARTIFACT_NAME = re.compile(r"r2-day1a-publication-([0-9a-f]{40})-[0-9]{8}\Z")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_API_VERSION = "2022-11-28"


class Day2CalibrationGitHubError(RuntimeError):
    """GitHub did not corroborate a formal calibration artifact identity."""


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
        raise Day2CalibrationGitHubError("GitHub metadata is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _read_regular(path: Path, field: str, maximum_bytes: int) -> bytes:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise Day2CalibrationGitHubError(f"{field} must be a regular non-symlink file")
    observed = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(observed.st_mode) or observed.st_size <= 0:
        raise Day2CalibrationGitHubError(f"{field} must be a nonempty regular file")
    if observed.st_size > maximum_bytes:
        raise Day2CalibrationGitHubError(f"{field} exceeds its closed byte bound")
    return path.read_bytes()


def _decode_canonical_json(path: Path, field: str) -> dict[str, object]:
    content = _read_regular(path, field, _MAX_JSON_BYTES)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise Day2CalibrationGitHubError(f"{field} contains a duplicate JSON key")
            document[key] = value
        return document

    try:
        document = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationGitHubError(f"{field} is not readable JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise Day2CalibrationGitHubError(f"{field} is not canonical JSON")
    return document


def _positive_integer(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise Day2CalibrationGitHubError(f"{field} must be a positive strict integer")
    return value


def _normalize_provider_digest(value: object, field: str) -> str:
    if type(value) is not str:
        raise Day2CalibrationGitHubError(f"{field} is not a SHA-256")
    normalized = value if value.startswith("sha256:") else f"sha256:{value}"
    if _LOWER_SHA256.fullmatch(normalized.removeprefix("sha256:")) is None:
        raise Day2CalibrationGitHubError(f"{field} is not a SHA-256")
    return normalized


def _formal_environment(workflow_path: str) -> dict[str, str]:
    environment = dict(os.environ)
    workflow_ref = environment.get("GITHUB_WORKFLOW_REF")
    if (
        environment.get("GITHUB_ACTIONS") != "true"
        or environment.get("GITHUB_REPOSITORY") != _REPOSITORY
        or environment.get("GITHUB_REPOSITORY_ID") != str(_REPOSITORY_ID)
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or type(workflow_ref) is not str
        or workflow_ref != f"{_REPOSITORY}/{workflow_path}@refs/heads/main"
    ):
        raise Day2CalibrationGitHubError("live GitHub environment is not the formal workflow")
    source_sha = environment.get("GITHUB_SHA")
    if type(source_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_sha) is None:
        raise Day2CalibrationGitHubError("live GitHub source SHA is invalid")
    token = environment.get("GITHUB_TOKEN")
    if type(token) is not str or not token or any(character.isspace() for character in token):
        raise Day2CalibrationGitHubError("GITHUB_TOKEN is unavailable or malformed")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = environment.get(name)
        if type(value) is not str or re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise Day2CalibrationGitHubError(f"{name} is not a positive canonical integer")
    return environment


def _api_json(endpoint: str, token: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{_REPOSITORY}/{endpoint}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": "dynamic-cssc-formal-day2-metadata-capture",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            content = response.read(_MAX_JSON_BYTES + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as error:
        raise Day2CalibrationGitHubError("GitHub provider API request failed") from error
    if not content or len(content) > _MAX_JSON_BYTES:
        raise Day2CalibrationGitHubError("GitHub provider API response is oversized")
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationGitHubError("GitHub provider API response is not JSON") from error
    if type(value) is not dict:
        raise Day2CalibrationGitHubError("GitHub provider API response is not an object")
    return value


def _profile_anchor(repository_root: Path) -> dict[str, object]:
    path = repository_root / _PROFILE_ANCHOR_PATH
    content = _read_regular(path, "Day 2 profile anchor set", _MAX_JSON_BYTES)
    validate_day2_calibration_profile_anchor_document(content)
    document = _decode_canonical_json(path, "Day 2 profile anchor set")
    anchors = document.get("anchors")
    if type(anchors) is not list or len(anchors) != 1 or type(anchors[0]) is not dict:
        raise Day2CalibrationGitHubError("exactly one reviewed Day 2 profile anchor is required")
    return anchors[0]


def _git_blob(repository_root: Path, source_sha: str, path: str) -> bytes:
    git = shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")
    if git is None:
        raise Day2CalibrationGitHubError("git executable is unavailable")
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    try:
        completed = subprocess.run(
            [git, "-C", str(repository_root), "show", f"{source_sha}:{path}"],
            check=True,
            capture_output=True,
            env=environment,
        )
    except subprocess.CalledProcessError as error:
        raise Day2CalibrationGitHubError("historical workflow blob is unavailable") from error
    if not completed.stdout or len(completed.stdout) > _MAX_JSON_BYTES:
        raise Day2CalibrationGitHubError("historical workflow blob exceeds its byte bound")
    return completed.stdout


def _validate_run(
    run: dict[str, object],
    *,
    run_id: int,
    source_sha: str,
) -> int:
    repository = run.get("repository")
    workflow_path = run.get("path")
    accepted_workflow_paths = {
        _DAY1A_WORKFLOW_PATH,
        f"{_DAY1A_WORKFLOW_PATH}@main",
        f"{_DAY1A_WORKFLOW_PATH}@refs/heads/main",
    }
    if (
        run.get("id") != run_id
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_sha") != source_sha
        or run.get("head_branch") != "main"
        or workflow_path not in accepted_workflow_paths
        or type(repository) is not dict
        or repository.get("id") != _REPOSITORY_ID
        or repository.get("full_name") != _REPOSITORY
    ):
        raise Day2CalibrationGitHubError("Day1A workflow run identity is not an exact success")
    return _positive_integer(run.get("run_attempt"), "Day1A run attempt")


def _validate_artifact(
    artifact: dict[str, object],
    *,
    artifact_id: int,
    run_id: int,
    artifact_name: str,
    artifact_digest: str,
    source_sha: str,
) -> None:
    workflow_run = artifact.get("workflow_run")
    if (
        artifact.get("id") != artifact_id
        or artifact.get("name") != artifact_name
        or artifact.get("expired") is not False
        or artifact.get("digest") != artifact_digest
        or type(artifact.get("archive_download_url")) is not str
        or not artifact["archive_download_url"]
        or type(artifact.get("size_in_bytes")) is not int
        or artifact["size_in_bytes"] <= 0
        or type(workflow_run) is not dict
        or workflow_run.get("id") != run_id
        or workflow_run.get("head_sha") != source_sha
        or workflow_run.get("repository_id") != _REPOSITORY_ID
    ):
        raise Day2CalibrationGitHubError("GitHub artifact identity does not match its anchor")


def _write_new_canonical_json(path: Path, value: dict[str, object]) -> None:
    if not isinstance(path, Path):
        raise TypeError("output_path must be a pathlib.Path")
    path = path.absolute()
    if path.exists() or path.is_symlink():
        raise Day2CalibrationGitHubError("metadata output must be absent")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise Day2CalibrationGitHubError("metadata output parent must be a regular directory")
    content = _canonical_json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def capture_repository_day1a_github_metadata(
    day1a_directory: Path,
    output_path: Path,
) -> Path:
    """Corroborate the anchored Day1A provider object and write canonical metadata."""

    if not isinstance(day1a_directory, Path):
        raise TypeError("day1a_directory must be a pathlib.Path")
    if day1a_directory.is_symlink() or not day1a_directory.is_dir():
        raise Day2CalibrationGitHubError("Day1A directory must be a regular directory")
    for filename in (
        COUNT_BUNDLE_FILENAME,
        ROTATION_INVENTORY_FILENAME,
        AUTHORITY_RECEIPT_FILENAME,
    ):
        _read_regular(day1a_directory / filename, filename, _MAX_JSON_BYTES)
    receipt = _decode_canonical_json(
        day1a_directory / AUTHORITY_RECEIPT_FILENAME,
        "Day1A authority receipt",
    )
    source_sha = receipt.get("source_git_sha")
    if type(source_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_sha) is None:
        raise Day2CalibrationGitHubError("Day1A authority receipt source is invalid")
    repository_root = Path(__file__).resolve().parents[2]
    environment = _formal_environment(_DAY2_WORKFLOW_PATH)
    anchor = _profile_anchor(repository_root)
    run_id = _positive_integer(anchor.get("day1a_workflow_run_id"), "Day1A run ID")
    artifact_id = _positive_integer(anchor.get("day1a_artifact_id"), "Day1A artifact ID")
    artifact_name = anchor.get("day1a_artifact_name")
    name_match = (
        _DAY1A_ARTIFACT_NAME.fullmatch(artifact_name)
        if type(artifact_name) is str
        else None
    )
    if name_match is None or name_match.group(1) != source_sha:
        raise Day2CalibrationGitHubError("Day1A anchor artifact name does not bind the receipt")
    artifact_digest = _normalize_provider_digest(
        anchor.get("day1a_artifact_digest"),
        "Day1A anchored artifact digest",
    )
    token = environment["GITHUB_TOKEN"]
    run = _api_json(f"actions/runs/{run_id}", token)
    artifact = _api_json(f"actions/artifacts/{artifact_id}", token)
    run_attempt = _validate_run(run, run_id=run_id, source_sha=source_sha)
    _validate_artifact(
        artifact,
        artifact_id=artifact_id,
        run_id=run_id,
        artifact_name=artifact_name,
        artifact_digest=artifact_digest,
        source_sha=source_sha,
    )
    metadata = {
        "schema_version": "dynamic-cssc-day1a-github-artifact-metadata-v1",
        "repository": _REPOSITORY,
        "repository_id": _REPOSITORY_ID,
        "workflow_path": _DAY1A_WORKFLOW_PATH,
        "workflow_file_sha256": _sha256(
            _git_blob(repository_root, source_sha, _DAY1A_WORKFLOW_PATH)
        ),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main",
        "head_sha": source_sha,
        "artifact_name": artifact_name,
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
    }
    _write_new_canonical_json(output_path, metadata)
    return output_path.absolute()


def _archive_workflow_provenance(archive_path: Path) -> tuple[dict[str, object], str]:
    content = _read_regular(archive_path, "Day 2 evidence archive", _MAX_ARCHIVE_BYTES)
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            member = archive.getinfo("workflow-provenance.json")
            if member.file_size <= 0 or member.file_size > _MAX_JSON_BYTES:
                raise Day2CalibrationGitHubError(
                    "Day 2 workflow provenance exceeds its byte bound"
                )
            provenance_bytes = archive.read(member)
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise Day2CalibrationGitHubError(
            "Day 2 archive workflow provenance is unavailable"
        ) from error
    try:
        provenance = json.loads(provenance_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationGitHubError("Day 2 workflow provenance is not JSON") from error
    if type(provenance) is not dict or _canonical_json_bytes(provenance) != provenance_bytes:
        raise Day2CalibrationGitHubError("Day 2 workflow provenance is not canonical")
    return provenance, _sha256(content)


def capture_repository_day2_github_metadata(
    archive_path: Path,
    output_path: Path,
) -> Path:
    """Capture the uploaded wrapper identity while preserving the inner ZIP identity."""

    environment = _formal_environment(_DAY2_WORKFLOW_PATH)
    provenance, inner_sha256 = _archive_workflow_provenance(archive_path)
    artifact_id_text = environment.get("DAY2_UPLOADED_ARTIFACT_ID")
    if type(artifact_id_text) is not str or re.fullmatch(r"[1-9][0-9]*", artifact_id_text) is None:
        raise Day2CalibrationGitHubError("uploaded Day 2 artifact ID is invalid")
    artifact_id = int(artifact_id_text)
    artifact_digest = _normalize_provider_digest(
        environment.get("DAY2_UPLOADED_ARTIFACT_DIGEST"),
        "uploaded Day 2 artifact digest",
    )
    if (
        provenance.get("run_id") != int(environment["GITHUB_RUN_ID"])
        or provenance.get("run_attempt") != int(environment["GITHUB_RUN_ATTEMPT"])
        or provenance.get("head_sha") != environment["GITHUB_SHA"]
    ):
        raise Day2CalibrationGitHubError("archive workflow provenance differs from the live run")
    artifact_name = provenance.get("artifact_name")
    if type(artifact_name) is not str or not artifact_name:
        raise Day2CalibrationGitHubError("archive artifact name is invalid")
    artifact = _api_json(
        f"actions/artifacts/{artifact_id}",
        environment["GITHUB_TOKEN"],
    )
    _validate_artifact(
        artifact,
        artifact_id=artifact_id,
        run_id=int(environment["GITHUB_RUN_ID"]),
        artifact_name=artifact_name,
        artifact_digest=artifact_digest,
        source_sha=environment["GITHUB_SHA"],
    )
    metadata = {
        **provenance,
        "schema_version": "dynamic-cssc-publication-day2-github-artifact-metadata-v2",
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "inner_archive_sha256": inner_sha256,
    }
    inspection = inspect_day2_calibration_archive(
        archive_path,
        expected_outer_sha256=inner_sha256,
        github_metadata=metadata,
    )
    if inspection.outer_archive_sha256 != inner_sha256:
        raise Day2CalibrationGitHubError("Day 2 archive identity changed during capture")
    _write_new_canonical_json(output_path, metadata)
    return output_path.absolute()
