"""Deterministic bounded transport for one closed campaign controller journal."""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from dynamic_cssc.followup_performance_campaign_bundle import (
    FollowupCampaignEvidenceBundle,
    inspect_followup_campaign_evidence_bundle,
)
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

__all__ = (
    "FollowupCampaignTransport",
    "build_followup_campaign_transport",
    "install_followup_campaign_transport",
)

_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_EXPANDED_BYTES = 96 * 1024 * 1024
_MAX_MEMBERS = 512
_MEMBER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\Z")


@dataclass(frozen=True, slots=True)
class FollowupCampaignTransport:
    content: bytes
    sha256: str
    member_count: int
    expanded_bytes: int


def _direct_files(root: Path) -> tuple[tuple[str, Path], ...]:
    root = root.resolve(strict=True)
    files: list[tuple[str, Path]] = []
    for candidate in root.rglob("*"):
        observed = candidate.lstat()
        if stat.S_ISLNK(observed.st_mode):
            raise FollowupCampaignControlError(
                "campaign transport contains a symbolic link"
            )
        if stat.S_ISDIR(observed.st_mode):
            continue
        if not stat.S_ISREG(observed.st_mode):
            raise FollowupCampaignControlError(
                "campaign transport contains a non-regular object"
            )
        relative = candidate.relative_to(root).as_posix()
        if _MEMBER.fullmatch(relative) is None:
            raise FollowupCampaignControlError(
                "campaign transport member name changed"
            )
        files.append((relative, candidate))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    if not files or len(files) > _MAX_MEMBERS:
        raise FollowupCampaignControlError(
            "campaign transport member count changed"
        )
    return tuple(files)


def _read_regular(path: Path) -> bytes:
    before = path.stat()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        content = b""
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content += chunk
            if len(content) > _MAX_EXPANDED_BYTES:
                raise FollowupCampaignControlError(
                    "campaign transport expanded bytes exceeded the bound"
                )
    finally:
        os.close(descriptor)
    after = path.stat()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or len(content) != before.st_size
    ):
        raise FollowupCampaignControlError(
            "campaign transport source changed while read"
        )
    return content


def build_followup_campaign_transport(
    root: Path,
    *,
    scientific_profile: RouteAScientificProfile,
    expected_head_branch: str = "main",
) -> FollowupCampaignTransport:
    """Reinspect and encode every journal file with fixed ZIP metadata."""

    inspect_followup_campaign_evidence_bundle(
        root,
        scientific_profile=scientific_profile,
        expected_head_branch=expected_head_branch,
    )
    files = _direct_files(root)
    expanded = 0
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name, path in files:
            content = _read_regular(path)
            expanded += len(content)
            if expanded > _MAX_EXPANDED_BYTES:
                raise FollowupCampaignControlError(
                    "campaign transport expanded bytes exceeded the bound"
                )
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100400 << 16
            info.flag_bits = 0x800
            archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    content = output.getvalue()
    if not content or len(content) > _MAX_ARCHIVE_BYTES:
        raise FollowupCampaignControlError(
            "campaign transport archive exceeded the bound"
        )
    return FollowupCampaignTransport(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        member_count=len(files),
        expanded_bytes=expanded,
    )


def _new_root(root: Path) -> Path:
    if not root.is_absolute() or root.exists() or root.is_symlink():
        raise FollowupCampaignControlError(
            "campaign transport target must be a new absolute path"
        )
    parent = root.parent.resolve(strict=True)
    observed = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupCampaignControlError(
            "campaign transport parent is not direct"
        )
    root.mkdir(mode=0o700)
    return root


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:  # pragma: no cover
                raise FollowupCampaignControlError(
                    "campaign transport write stalled"
                )
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_followup_campaign_transport(
    transport: FollowupCampaignTransport,
    target: Path,
    *,
    scientific_profile: RouteAScientificProfile,
    expected_head_branch: str = "main",
) -> FollowupCampaignEvidenceBundle:
    """Extract one exact safe member set, then run the normal deep inspector."""

    if (
        type(transport) is not FollowupCampaignTransport
        or not transport.content
        or len(transport.content) > _MAX_ARCHIVE_BYTES
        or hashlib.sha256(transport.content).hexdigest() != transport.sha256
    ):
        raise FollowupCampaignControlError("campaign transport identity changed")
    root = _new_root(target)
    try:
        with zipfile.ZipFile(io.BytesIO(transport.content), mode="r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if (
                len(infos) != transport.member_count
                or not infos
                or len(infos) > _MAX_MEMBERS
                or len(names) != len(set(names))
                or names != tuple(sorted(names, key=lambda value: value.encode("utf-8")))
            ):
                raise FollowupCampaignControlError(
                    "campaign transport member inventory changed"
                )
            expanded = 0
            for info in infos:
                name = info.filename
                pure = PurePosixPath(name)
                if (
                    _MEMBER.fullmatch(name) is None
                    or pure.is_absolute()
                    or ".." in pure.parts
                    or info.is_dir()
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or (info.external_attr >> 16) & 0o170000 != 0o100000
                ):
                    raise FollowupCampaignControlError(
                        "campaign transport contains an unsafe member"
                    )
                expanded += info.file_size
                if expanded > _MAX_EXPANDED_BYTES:
                    raise FollowupCampaignControlError(
                        "campaign transport expanded bytes exceeded the bound"
                    )
                destination = root.joinpath(*pure.parts)
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                _write_new(destination, archive.read(info))
        if expanded != transport.expanded_bytes:
            raise FollowupCampaignControlError(
                "campaign transport expanded size changed"
            )
        return inspect_followup_campaign_evidence_bundle(
            root,
            scientific_profile=scientific_profile,
            expected_head_branch=expected_head_branch,
        )
    except Exception:
        # The caller supplied a new evidence-only path; leave partial bytes for audit.
        raise
