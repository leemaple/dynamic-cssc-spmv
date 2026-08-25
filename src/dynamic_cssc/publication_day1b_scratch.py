"""Linux launcher-owned anonymous scratch creation for publication Day 1B.

The public seam creates one exclusive ephemeral directory beneath an empty
launcher-owned parent, opens the two fixed scratch members relative to held
directory descriptors, opens SQLite through ``/proc/self/fd``, unlinks every
name, removes the ephemeral directory, and only then returns the held handles.
It grants scratch-creation evidence only; it cannot authorize execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import sqlite3
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

DAY1B_ANONYMOUS_SCRATCH_CREATION_RECEIPT_SCHEMA = (
    "dynamic-cssc-publication-day1b-anonymous-scratch-creation-receipt-v1"
)
DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES = (
    "binding-index.sqlite3",
    "object-receipts.jsonl",
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ROOT_NAME_ATTEMPTS = 16
_PATH_TYPE = type(Path())


class Day1BAnonymousScratchCreationError(RuntimeError):
    """The launcher could not prove exact anonymous scratch creation."""


def _canonical_bytes(value: object) -> bytes:
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
    except (TypeError, ValueError) as error:
        raise Day1BAnonymousScratchCreationError(
            "anonymous scratch receipt is not canonical JSON"
        ) from error


@dataclass(frozen=True, slots=True)
class Day1BAnonymousScratchMemberIdentity:
    role: str
    device: int
    inode: int
    mode: int
    owner_uid: int

    def __post_init__(self) -> None:
        if (
            self.role not in DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES
            or type(self.device) is not int
            or self.device < 0
            or type(self.inode) is not int
            or self.inode <= 0
            or self.mode != 0o600
            or type(self.owner_uid) is not int
            or self.owner_uid < 0
        ):
            raise Day1BAnonymousScratchCreationError(
                "anonymous scratch member identity is malformed"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class Day1BAnonymousScratchCreationReceipt:
    launcher_parent_path: str
    parent_device: int
    parent_inode: int
    parent_mode: int
    parent_owner_uid: int
    filesystem_id: int
    ephemeral_root_name_sha256: str
    ephemeral_root_device: int
    ephemeral_root_inode: int
    ephemeral_root_mode: int
    ephemeral_root_owner_uid: int
    members: tuple[Day1BAnonymousScratchMemberIdentity, ...]
    sqlite_connection_identity_verified: bool
    all_member_names_unlinked: bool
    ephemeral_root_removed: bool

    def __post_init__(self) -> None:
        parent = (
            Path(self.launcher_parent_path)
            if type(self.launcher_parent_path) is str
            else Path()
        )
        if (
            type(self.launcher_parent_path) is not str
            or not parent.is_absolute()
            or ".." in parent.parts
            or str(parent) != self.launcher_parent_path
            or type(self.parent_device) is not int
            or self.parent_device < 0
            or type(self.parent_inode) is not int
            or self.parent_inode <= 0
            or self.parent_mode != 0o700
            or type(self.parent_owner_uid) is not int
            or self.parent_owner_uid < 0
            or type(self.filesystem_id) is not int
            or self.filesystem_id < 0
            or _LOWER_SHA256.fullmatch(self.ephemeral_root_name_sha256) is None
            or self.ephemeral_root_device != self.parent_device
            or type(self.ephemeral_root_inode) is not int
            or self.ephemeral_root_inode <= 0
            or self.ephemeral_root_mode != 0o700
            or self.ephemeral_root_owner_uid != self.parent_owner_uid
            or type(self.members) is not tuple
            or any(type(item) is not Day1BAnonymousScratchMemberIdentity for item in self.members)
            or tuple(item.role for item in self.members)
            != DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES
            or any(item.device != self.parent_device for item in self.members)
            or len({item.inode for item in self.members}) != len(self.members)
            or self.sqlite_connection_identity_verified is not True
            or self.all_member_names_unlinked is not True
            or self.ephemeral_root_removed is not True
        ):
            raise Day1BAnonymousScratchCreationError(
                "anonymous scratch creation receipt is malformed"
            )

    def _without_digest(self) -> dict[str, object]:
        return {
            "all_member_names_unlinked": self.all_member_names_unlinked,
            "directory_resolution": "linux-openat-proc-self-fd-v1",
            "ephemeral_root_device": self.ephemeral_root_device,
            "ephemeral_root_inode": self.ephemeral_root_inode,
            "ephemeral_root_mode": self.ephemeral_root_mode,
            "ephemeral_root_name_sha256": self.ephemeral_root_name_sha256,
            "ephemeral_root_owner_uid": self.ephemeral_root_owner_uid,
            "ephemeral_root_removed": self.ephemeral_root_removed,
            "filesystem_id": self.filesystem_id,
            "formal_authority_granted": False,
            "launcher_parent_path": self.launcher_parent_path,
            "members": [item.to_document() for item in self.members],
            "parent_device": self.parent_device,
            "parent_inode": self.parent_inode,
            "parent_mode": self.parent_mode,
            "parent_owner_uid": self.parent_owner_uid,
            "production_execution_admissible": False,
            "publication_authority": False,
            "schema_version": DAY1B_ANONYMOUS_SCRATCH_CREATION_RECEIPT_SCHEMA,
            "sqlite_connection_identity_verified": (
                self.sqlite_connection_identity_verified
            ),
            "status": "verified-linux-anonymous-scratch-creation-only",
        }

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self._without_digest())).hexdigest()

    def to_document(self) -> dict[str, object]:
        return {**self._without_digest(), "receipt_sha256": self.receipt_sha256}


class _OpenedDay1BAnonymousScratch:
    """Temporarily owns handles until the worker-protocol capability binds them."""

    __slots__ = ("_claimed", "members", "receipt", "sqlite_connection")

    def __init__(
        self,
        *,
        members: tuple[tuple[str, BinaryIO, tuple[int, int]], ...],
        sqlite_connection: sqlite3.Connection,
        receipt: Day1BAnonymousScratchCreationReceipt,
    ) -> None:
        self.members = members
        self.sqlite_connection = sqlite_connection
        self.receipt = receipt
        self._claimed = False

    def transfer(
        self,
    ) -> tuple[
        tuple[tuple[str, BinaryIO, tuple[int, int]], ...],
        sqlite3.Connection,
        Day1BAnonymousScratchCreationReceipt,
    ]:
        if self._claimed:
            raise Day1BAnonymousScratchCreationError(
                "anonymous scratch handles were already transferred"
            )
        self._claimed = True
        return self.members, self.sqlite_connection, self.receipt

    def close(self) -> None:
        if self._claimed:
            return
        self._claimed = True
        with suppress(BaseException):
            self.sqlite_connection.close()
        for _name, file, _identity in self.members:
            with suppress(BaseException):
                file.close()


def _open_absolute_directory_without_symlinks(path: Path) -> int:
    """Open every component relative to a held no-follow parent descriptor."""

    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path.anchor, flags)
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        raise Day1BAnonymousScratchCreationError(
            "launcher scratch parent path contains an unavailable or symlink component"
        ) from error


def _open_exclusive_member(
    root_descriptor: int,
    role: str,
) -> BinaryIO:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            role,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=root_descriptor,
        )
        file = os.fdopen(descriptor, "w+b")
        descriptor = None
        return file
    except BaseException:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        raise


def _fd_identity_count(identity: tuple[int, int]) -> int:
    count = 0
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as error:
        raise Day1BAnonymousScratchCreationError(
            "Linux descriptor inventory is unavailable"
        ) from error
    for name in names:
        try:
            observed = os.fstat(int(name))
        except (OSError, ValueError):
            continue
        if (observed.st_dev, observed.st_ino) == identity:
            count += 1
    return count


def _same_directory_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        stat.S_IMODE(before.st_mode),
        before.st_uid,
    ) == (
        after.st_dev,
        after.st_ino,
        stat.S_IMODE(after.st_mode),
        after.st_uid,
    )


def _exclusive_root(parent_descriptor: int) -> str:
    for _attempt in range(_ROOT_NAME_ATTEMPTS):
        name = f".dynamic-cssc-day1b-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:  # pragma: no cover - 128-bit collision retry
            continue
        except OSError as error:
            raise Day1BAnonymousScratchCreationError(
                "exclusive anonymous scratch root could not be created"
            ) from error
        return name
    raise Day1BAnonymousScratchCreationError(
        "exclusive anonymous scratch root name repeatedly collided"
    )


def _cleanup_created_root(
    *,
    parent_descriptor: int | None,
    root_descriptor: int | None,
    root_name: str | None,
    files: list[tuple[str, BinaryIO, tuple[int, int]]],
    connection: sqlite3.Connection | None,
) -> None:
    if connection is not None:
        with suppress(BaseException):
            connection.close()
    if root_descriptor is not None:
        for name, _file, identity in files:
            try:
                visible = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
                if (visible.st_dev, visible.st_ino) == identity:
                    os.unlink(name, dir_fd=root_descriptor)
            except OSError:
                pass
    for _name, file, _identity in files:
        with suppress(BaseException):
            file.close()
    if parent_descriptor is not None and root_name is not None:
        with suppress(OSError):
            os.rmdir(root_name, dir_fd=parent_descriptor)


def open_linux_day1b_anonymous_scratch(
    launcher_scratch_parent: Path,
) -> _OpenedDay1BAnonymousScratch:
    """Create exact anonymous handles without granting worker/dispatch authority."""

    if platform.system() != "Linux":
        raise Day1BAnonymousScratchCreationError(
            "production anonymous scratch creation requires Linux"
        )
    if (
        type(launcher_scratch_parent) is not _PATH_TYPE
        or not launcher_scratch_parent.is_absolute()
        or ".." in launcher_scratch_parent.parts
        or Path(os.path.normpath(launcher_scratch_parent)) != launcher_scratch_parent
    ):
        raise Day1BAnonymousScratchCreationError(
            "launcher_scratch_parent must be one normalized absolute Path"
        )
    parent_descriptor: int | None = None
    root_descriptor: int | None = None
    root_name: str | None = None
    connection: sqlite3.Connection | None = None
    files: list[tuple[str, BinaryIO, tuple[int, int]]] = []
    success = False
    try:
        parent_descriptor = _open_absolute_directory_without_symlinks(
            launcher_scratch_parent
        )
        parent = os.fstat(parent_descriptor)
        visible_parent = os.stat(launcher_scratch_parent, follow_symlinks=False)
        parent_vfs = os.fstatvfs(parent_descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or not stat.S_ISDIR(visible_parent.st_mode)
            or not _same_directory_identity(parent, visible_parent)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
            or os.listdir(parent_descriptor)
        ):
            raise Day1BAnonymousScratchCreationError(
                "launcher scratch parent is not exact empty owner-only storage"
            )

        root_name = _exclusive_root(parent_descriptor)
        root_descriptor = os.open(
            root_name,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
            dir_fd=parent_descriptor,
        )
        root = os.fstat(root_descriptor)
        visible_root = os.stat(root_name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root.st_mode)
            or not _same_directory_identity(root, visible_root)
            or root.st_dev != parent.st_dev
            or stat.S_IMODE(root.st_mode) != 0o700
            or root.st_uid != parent.st_uid
            or os.listdir(root_descriptor)
        ):
            raise Day1BAnonymousScratchCreationError(
                "ephemeral anonymous scratch root identity is not exact"
            )

        member_receipts: list[Day1BAnonymousScratchMemberIdentity] = []
        for role in DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES:
            file = _open_exclusive_member(root_descriptor, role)
            observed = os.fstat(file.fileno())
            identity = observed.st_dev, observed.st_ino
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or observed.st_size != 0
                or observed.st_dev != root.st_dev
                or stat.S_IMODE(observed.st_mode) != 0o600
                or observed.st_uid != root.st_uid
                or identity in {item[2] for item in files}
            ):
                file.close()
                raise Day1BAnonymousScratchCreationError(
                    "anonymous scratch member was not created as one exact new file"
                )
            files.append((role, file, identity))
            member_receipts.append(
                Day1BAnonymousScratchMemberIdentity(
                    role=role,
                    device=observed.st_dev,
                    inode=observed.st_ino,
                    mode=stat.S_IMODE(observed.st_mode),
                    owner_uid=observed.st_uid,
                )
            )

        sqlite_file = files[0][1]
        sqlite_identity = files[0][2]
        descriptors_before = _fd_identity_count(sqlite_identity)
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{root_descriptor}/{DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES[0]}?mode=rw",
            check_same_thread=False,
            uri=True,
        )
        database_list = connection.execute("PRAGMA database_list").fetchall()
        descriptors_after = _fd_identity_count(sqlite_identity)
        if (
            descriptors_before != 1
            or descriptors_after < 2
            or len(database_list) != 1
            or database_list[0][:2] != (0, "main")
        ):
            raise Day1BAnonymousScratchCreationError(
                "SQLite did not open the exact descriptor-relative scratch member"
            )

        for role, file, identity in files:
            visible = os.stat(role, dir_fd=root_descriptor, follow_symlinks=False)
            if (visible.st_dev, visible.st_ino) != identity:
                raise Day1BAnonymousScratchCreationError(
                    "anonymous scratch member name changed before unlink"
                )
            os.unlink(role, dir_fd=root_descriptor)
            unlinked = os.fstat(file.fileno())
            if (
                (unlinked.st_dev, unlinked.st_ino) != identity
                or unlinked.st_nlink != 0
                or unlinked.st_size != 0
            ):
                raise Day1BAnonymousScratchCreationError(
                    "anonymous scratch member did not become exact unlinked storage"
                )
        if os.listdir(root_descriptor):
            raise Day1BAnonymousScratchCreationError(
                "ephemeral anonymous scratch root contains an unexpected member"
            )
        if connection.execute("PRAGMA schema_version").fetchone() != (0,):
            raise Day1BAnonymousScratchCreationError(
                "unlinked SQLite scratch connection is not operational"
            )
        if os.fstat(sqlite_file.fileno()).st_nlink != 0:
            raise Day1BAnonymousScratchCreationError(
                "held SQLite scratch member regained a filesystem name"
            )

        assert root_name is not None
        root_name_sha256 = hashlib.sha256(root_name.encode("ascii")).hexdigest()
        os.rmdir(root_name, dir_fd=parent_descriptor)
        try:
            os.stat(root_name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:  # pragma: no cover - operating-system contract
            raise Day1BAnonymousScratchCreationError(
                "ephemeral anonymous scratch root remained visible after removal"
            )
        root_name = None
        parent_after = os.fstat(parent_descriptor)
        visible_parent_after = os.stat(launcher_scratch_parent, follow_symlinks=False)
        if (
            not _same_directory_identity(parent, parent_after)
            or not _same_directory_identity(parent, visible_parent_after)
            or os.fstatvfs(parent_descriptor).f_fsid != parent_vfs.f_fsid
            or os.listdir(parent_descriptor)
        ):
            raise Day1BAnonymousScratchCreationError(
                "launcher scratch parent changed during anonymous creation"
            )

        receipt = Day1BAnonymousScratchCreationReceipt(
            launcher_parent_path=str(launcher_scratch_parent),
            parent_device=parent.st_dev,
            parent_inode=parent.st_ino,
            parent_mode=stat.S_IMODE(parent.st_mode),
            parent_owner_uid=parent.st_uid,
            filesystem_id=parent_vfs.f_fsid,
            # The name is no longer reachable; retain only its audit root.
            ephemeral_root_name_sha256=root_name_sha256,
            ephemeral_root_device=root.st_dev,
            ephemeral_root_inode=root.st_ino,
            ephemeral_root_mode=stat.S_IMODE(root.st_mode),
            ephemeral_root_owner_uid=root.st_uid,
            members=tuple(member_receipts),
            sqlite_connection_identity_verified=True,
            all_member_names_unlinked=True,
            ephemeral_root_removed=True,
        )
        success = True
        return _OpenedDay1BAnonymousScratch(
            members=tuple(files),
            sqlite_connection=connection,
            receipt=receipt,
        )
    except Day1BAnonymousScratchCreationError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise Day1BAnonymousScratchCreationError(
            "Linux anonymous scratch creation failed closed"
        ) from error
    finally:
        if not success:
            _cleanup_created_root(
                parent_descriptor=parent_descriptor,
                root_descriptor=root_descriptor,
                root_name=root_name,
                files=files,
                connection=connection,
            )
        if root_descriptor is not None:
            with suppress(OSError):
                os.close(root_descriptor)
        if parent_descriptor is not None:
            with suppress(OSError):
                os.close(parent_descriptor)


__all__ = (
    "DAY1B_ANONYMOUS_SCRATCH_CREATION_RECEIPT_SCHEMA",
    "DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES",
    "Day1BAnonymousScratchCreationError",
    "Day1BAnonymousScratchCreationReceipt",
    "Day1BAnonymousScratchMemberIdentity",
    "open_linux_day1b_anonymous_scratch",
)
