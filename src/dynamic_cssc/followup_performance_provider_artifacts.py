"""Exact, bounded installation of one GitHub-hosted follow-up artifact."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
)

__all__ = (
    "FollowupProviderArtifactBinding",
    "FollowupProviderArtifactTransport",
    "GitHubCliArtifactTransport",
    "install_followup_provider_artifact",
)

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_ARTIFACT_NAME = re.compile(
    r"followup-performance-v1-[a-z0-9][a-z0-9._-]{0,254}\Z"
)
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
_MAX_MEMBERS = 20_000
_MAX_METADATA_BYTES = 2 * 1024 * 1024


def _pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in rows:
        if key in value:
            raise FollowupCampaignControlError(
                "GitHub artifact metadata has a duplicate key"
            )
        value[key] = item
    return value


def _object(content: bytes) -> dict[str, object]:
    if not content or len(content) > _MAX_METADATA_BYTES:
        raise FollowupCampaignControlError(
            "GitHub artifact metadata bytes changed"
        )
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupCampaignControlError(
            "GitHub artifact metadata is unreadable"
        ) from error
    if type(value) is not dict:
        raise FollowupCampaignControlError(
            "GitHub artifact metadata is not one object"
        )
    return value


@dataclass(frozen=True, slots=True)
class FollowupProviderArtifactBinding:
    provider_artifact_id: int
    artifact_name: str
    provider_digest: str
    size_in_bytes_or_null: int | None = None


def _binding(
    value: FollowupProviderArtifactBinding,
) -> FollowupProviderArtifactBinding:
    if (
        type(value) is not FollowupProviderArtifactBinding
        or type(value.provider_artifact_id) is not int
        or value.provider_artifact_id <= 0
        or type(value.artifact_name) is not str
        or _ARTIFACT_NAME.fullmatch(value.artifact_name) is None
        or type(value.provider_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(value.provider_digest) is None
        or (
            value.size_in_bytes_or_null is not None
            and (
                type(value.size_in_bytes_or_null) is not int
                or not 1 <= value.size_in_bytes_or_null <= _MAX_ARCHIVE_BYTES
            )
        )
    ):
        raise FollowupCampaignControlError(
            "follow-up provider artifact binding changed"
        )
    return value


class FollowupProviderArtifactTransport(Protocol):
    def metadata(self, *, repository: str, artifact_id: int) -> bytes: ...

    def download(
        self,
        *,
        repository: str,
        artifact_id: int,
        output: BinaryIO,
    ) -> None: ...


class GitHubCliArtifactTransport:
    """Production adapter using bounded noninteractive ``gh api`` calls."""

    def __init__(self, *, timeout_seconds: int = 20 * 60) -> None:
        if type(timeout_seconds) is not int or timeout_seconds <= 0:
            raise FollowupCampaignControlError(
                "GitHub artifact timeout changed"
            )
        self._timeout = timeout_seconds

    def _run(
        self,
        arguments: tuple[str, ...],
        *,
        output: int | BinaryIO,
    ) -> bytes:
        environment = os.environ.copy()
        environment["GH_PAGER"] = "cat"
        try:
            completed = subprocess.run(
                ("gh", *arguments),
                check=True,
                stdout=output,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise FollowupCampaignControlError(
                "GitHub artifact request failed"
            ) from error
        if output == subprocess.PIPE:
            if len(completed.stdout) > _MAX_METADATA_BYTES:
                raise FollowupCampaignControlError(
                    "GitHub artifact metadata response is too large"
                )
            return completed.stdout
        return b""

    def metadata(self, *, repository: str, artifact_id: int) -> bytes:
        return self._run(
            (
                "api",
                f"/repos/{repository}/actions/artifacts/{artifact_id}",
            ),
            output=subprocess.PIPE,
        )

    def download(
        self,
        *,
        repository: str,
        artifact_id: int,
        output: BinaryIO,
    ) -> None:
        self._run(
            (
                "api",
                f"/repos/{repository}/actions/artifacts/{artifact_id}/zip",
            ),
            output=output,
        )


def _direct_directory(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise FollowupCampaignControlError(f"{label} is not a direct directory")
    resolved = path.resolve(strict=True)
    if resolved != path or not stat.S_ISDIR(path.lstat().st_mode):
        raise FollowupCampaignControlError(f"{label} is not a direct directory")
    return path


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:  # pragma: no cover
            raise FollowupCampaignControlError(
                "provider artifact extraction write stalled"
            )
        view = view[count:]


def _extract(archive_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    expanded = 0
    with zipfile.ZipFile(archive_path, mode="r") as archive:
        infos = archive.infolist()
        names = tuple(info.filename for info in infos)
        if not infos or len(infos) > _MAX_MEMBERS or len(names) != len(set(names)):
            raise FollowupCampaignControlError(
                "GitHub artifact member set changed"
            )
        for info in infos:
            pure = PurePosixPath(info.filename)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise FollowupCampaignControlError(
                    "GitHub artifact path is unsafe"
                )
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type not in {0, 0o040000, 0o100000}:
                raise FollowupCampaignControlError(
                    "GitHub artifact member is unsafe"
                )
            expanded += info.file_size
            if expanded > _MAX_EXPANDED_BYTES:
                raise FollowupCampaignControlError(
                    "GitHub artifact expands too far"
                )
            target = destination.joinpath(*pure.parts)
            if info.is_dir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o400,
            )
            try:
                with archive.open(info, mode="r") as source:
                    while chunk := source.read(1024 * 1024):
                        _write_all(descriptor, chunk)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def install_followup_provider_artifact(
    *,
    repository: str,
    binding: FollowupProviderArtifactBinding,
    expected_run_id: int,
    expected_head_sha: str,
    target_root: Path,
    transport: FollowupProviderArtifactTransport | None = None,
) -> Path:
    """Download, rehash, and safely install one exact provider artifact."""

    if (
        type(repository) is not str
        or _REPOSITORY.fullmatch(repository) is None
        or type(expected_run_id) is not int
        or expected_run_id <= 0
        or type(expected_head_sha) is not str
        or _LOWER_GIT_SHA.fullmatch(expected_head_sha) is None
    ):
        raise FollowupCampaignControlError(
            "provider artifact installation identity changed"
        )
    binding = _binding(binding)
    target_root = _direct_directory(target_root, label="artifact target root")
    destination = target_root / binding.artifact_name
    archive_path = target_root / f".{binding.provider_artifact_id}.zip"
    if (
        destination.exists()
        or destination.is_symlink()
        or archive_path.exists()
        or archive_path.is_symlink()
    ):
        raise FollowupCampaignControlError(
            "provider artifact destination already exists"
        )
    adapter = transport or GitHubCliArtifactTransport()
    metadata = _object(
        adapter.metadata(
            repository=repository,
            artifact_id=binding.provider_artifact_id,
        )
    )
    workflow_run = metadata.get("workflow_run")
    size = metadata.get("size_in_bytes")
    if (
        metadata.get("id") != binding.provider_artifact_id
        or metadata.get("name") != binding.artifact_name
        or metadata.get("digest") != binding.provider_digest
        or metadata.get("expired") is not False
        or type(size) is not int
        or not 1 <= size <= _MAX_ARCHIVE_BYTES
        or (
            binding.size_in_bytes_or_null is not None
            and size != binding.size_in_bytes_or_null
        )
        or type(workflow_run) is not dict
        or workflow_run.get("id") != expected_run_id
        or workflow_run.get("head_sha") != expected_head_sha
    ):
        raise FollowupCampaignControlError("GitHub artifact identity changed")
    descriptor = os.open(
        archive_path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            adapter.download(
                repository=repository,
                artifact_id=binding.provider_artifact_id,
                output=output,
            )
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    try:
        if archive_path.stat().st_size != size:
            raise FollowupCampaignControlError(
                "GitHub artifact archive size changed"
            )
        digest = hashlib.sha256()
        with archive_path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        if f"sha256:{digest.hexdigest()}" != binding.provider_digest:
            raise FollowupCampaignControlError(
                "GitHub artifact archive digest changed"
            )
        _extract(archive_path, destination)
    except BaseException:
        if destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        if archive_path.exists() and not archive_path.is_symlink():
            archive_path.unlink()
    return destination
