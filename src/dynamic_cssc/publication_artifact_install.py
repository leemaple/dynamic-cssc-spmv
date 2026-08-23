"""Descriptor-bound, no-replace installation for publication artifacts."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import secrets
import stat
import sys
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

__all__ = [
    "PublicationArtifactDirectory",
    "PublicationArtifactInstallError",
    "install_verified_directory",
    "quarantine_owned_directory",
    "verify_existing_directory",
]

_T = TypeVar("_T")
_READ_CHUNK_BYTES = 1024 * 1024
_VIEW_TOKEN = object()


class PublicationArtifactInstallError(RuntimeError):
    """A publication directory could not be installed without identity drift."""


@dataclass(frozen=True)
class _HeldEntry:
    descriptor: int
    is_directory: bool
    device: int
    inode: int
    mode: int
    size: int
    content_sha256: str | None
    child_names: tuple[str, ...]

    def exact_fingerprint(self, relative_path: str) -> tuple[object, ...]:
        return (
            relative_path,
            "directory" if self.is_directory else "regular",
            self.device,
            self.inode,
            self.mode,
            self.size,
            self.content_sha256,
        )


class PublicationArtifactDirectory:
    """A verifier view backed only by held directory and regular-file descriptors."""

    __slots__ = ("_closed", "_entries")

    def __init__(self, token: object, entries: dict[str, _HeldEntry]) -> None:
        if token is not _VIEW_TOKEN:
            raise TypeError("PublicationArtifactDirectory instances are created by the installer")
        self._entries = entries
        self._closed = False

    def entries(self) -> tuple[str, ...]:
        """Return the exact sorted set of relative artifact paths."""

        self._require_open()
        return tuple(sorted(relative_path for relative_path in self._entries if relative_path))

    def read_regular(self, relative_path: str) -> bytes:
        """Read an exact regular-file member through its held descriptor."""

        entry = self._regular_entry(relative_path)
        return _read_regular_bytes(entry)

    def sha256_regular(self, relative_path: str) -> str:
        """Hash an exact regular-file member through its held descriptor."""

        entry = self._regular_entry(relative_path)
        return _hash_regular(entry)

    def regular_size(self, relative_path: str) -> int:
        """Return the snapshotted size of an exact regular-file member."""

        entry = self._regular_entry(relative_path)
        _require_exact_descriptor_metadata(entry, relative_path)
        return entry.size

    def _regular_entry(self, relative_path: str) -> _HeldEntry:
        self._require_open()
        normalized = _relative_path(relative_path)
        try:
            entry = self._entries[normalized]
        except KeyError as error:
            raise PublicationArtifactInstallError(
                f"artifact member {normalized!r} is not present"
            ) from error
        if entry.is_directory:
            raise PublicationArtifactInstallError(
                f"artifact member {normalized!r} is not a regular file"
            )
        return entry

    def _require_open(self) -> None:
        if self._closed:
            raise PublicationArtifactInstallError("publication artifact view is closed")

    def _revalidate(
        self,
        root_parent_fd: int,
        root_name: str,
    ) -> tuple[tuple[object, ...], ...]:
        self._require_open()
        root = self._entries[""]
        _require_entry_mapping(
            root_parent_fd,
            root_name,
            root,
            "publication artifact root",
        )
        observed_fingerprint: list[tuple[object, ...]] = []
        for relative_path in sorted(self._entries):
            entry = self._entries[relative_path]
            _require_exact_descriptor_metadata(entry, relative_path or ".")
            if entry.is_directory:
                try:
                    observed_children = tuple(sorted(os.listdir(entry.descriptor)))
                except OSError as error:
                    raise PublicationArtifactInstallError(
                        f"artifact directory {relative_path or '.'!r} could not be enumerated"
                    ) from error
                if observed_children != entry.child_names:
                    raise PublicationArtifactInstallError(
                        f"artifact directory {relative_path or '.'!r} tree changed"
                    )
                for child_name in entry.child_names:
                    child_path = (
                        child_name if not relative_path else f"{relative_path}/{child_name}"
                    )
                    _require_entry_mapping(
                        entry.descriptor,
                        child_name,
                        self._entries[child_path],
                        f"artifact member {child_path!r}",
                    )
            else:
                observed_hash = _hash_regular(entry)
                if observed_hash != entry.content_sha256:
                    raise PublicationArtifactInstallError(
                        f"artifact member {relative_path!r} tree changed"
                    )
            observed_fingerprint.append(entry.exact_fingerprint(relative_path))
        return tuple(observed_fingerprint)

    def _close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for entry in self._entries.values():
            with suppress(OSError):
                os.close(entry.descriptor)


def _component(name: str, field: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\0" in name:
        raise PublicationArtifactInstallError(f"{field} is not one path component")
    return name


def _relative_path(value: object) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\0" in value:
        raise PublicationArtifactInstallError("artifact member path is not relative")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise PublicationArtifactInstallError("artifact member path is not normalized")
    return value


def _identity(value: object) -> tuple[int, int]:
    if (
        type(value) is not tuple
        or len(value) != 2
        or any(type(item) is not int or item < 0 for item in value)
    ):
        raise TypeError("staging_identity must be an exact (device, inode) tuple")
    return value


def _metadata(observed: os.stat_result) -> tuple[int, int, int, int]:
    return observed.st_dev, observed.st_ino, observed.st_mode, observed.st_size


def _entry_metadata(entry: _HeldEntry) -> tuple[int, int, int, int]:
    return entry.device, entry.inode, entry.mode, entry.size


def _open_directory(path: Path, field: str) -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise PublicationArtifactInstallError(
            f"{field} requires directory-descriptor and no-follow support"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublicationArtifactInstallError(f"{field} could not be opened") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PublicationArtifactInstallError(f"{field} is not a directory")
    return descriptor


def _open_directory_at(parent_fd: int, name: str, field: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(_component(name, field), flags, dir_fd=parent_fd)
    except OSError as error:
        raise PublicationArtifactInstallError(f"{field} could not be opened") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PublicationArtifactInstallError(f"{field} is not a directory")
    return descriptor


def _open_regular_at(parent_fd: int, name: str, field: str) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(_component(name, field), flags, dir_fd=parent_fd)
    except OSError as error:
        raise PublicationArtifactInstallError(f"{field} could not be opened") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PublicationArtifactInstallError(f"{field} is not a regular file")
    return descriptor


def _pread_exact(descriptor: int, expected_size: int) -> bytes:
    if not hasattr(os, "pread"):
        raise PublicationArtifactInstallError("descriptor-relative regular reads are unavailable")
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        try:
            chunk = os.pread(descriptor, min(_READ_CHUNK_BYTES, expected_size - offset), offset)
        except OSError as error:
            raise PublicationArtifactInstallError(
                "publication artifact regular file could not be read"
            ) from error
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
    try:
        overflow = os.pread(descriptor, 1, expected_size)
    except OSError as error:
        raise PublicationArtifactInstallError(
            "publication artifact regular file could not be read"
        ) from error
    if offset != expected_size or overflow:
        raise PublicationArtifactInstallError(
            "publication artifact regular file size changed during reading"
        )
    return b"".join(chunks)


def _hash_descriptor(descriptor: int, expected_size: int) -> str:
    if not hasattr(os, "pread"):
        raise PublicationArtifactInstallError("descriptor-relative regular reads are unavailable")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        try:
            chunk = os.pread(descriptor, min(_READ_CHUNK_BYTES, expected_size - offset), offset)
        except OSError as error:
            raise PublicationArtifactInstallError(
                "publication artifact regular file could not be read"
            ) from error
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    try:
        overflow = os.pread(descriptor, 1, expected_size)
    except OSError as error:
        raise PublicationArtifactInstallError(
            "publication artifact regular file could not be read"
        ) from error
    if offset != expected_size or overflow:
        raise PublicationArtifactInstallError(
            "publication artifact regular file size changed during hashing"
        )
    return digest.hexdigest()


def _require_exact_descriptor_metadata(entry: _HeldEntry, field: str) -> None:
    try:
        observed = os.fstat(entry.descriptor)
    except OSError as error:
        raise PublicationArtifactInstallError(f"{field} descriptor became invalid") from error
    if _metadata(observed) != _entry_metadata(entry):
        raise PublicationArtifactInstallError(f"{field} metadata changed")


def _read_regular_bytes(entry: _HeldEntry) -> bytes:
    _require_exact_descriptor_metadata(entry, "artifact regular file")
    value = _pread_exact(entry.descriptor, entry.size)
    _require_exact_descriptor_metadata(entry, "artifact regular file")
    if hashlib.sha256(value).hexdigest() != entry.content_sha256:
        raise PublicationArtifactInstallError(
            "artifact regular file differs from its snapshotted content"
        )
    return value


def _hash_regular(entry: _HeldEntry) -> str:
    _require_exact_descriptor_metadata(entry, "artifact regular file")
    observed = _hash_descriptor(entry.descriptor, entry.size)
    _require_exact_descriptor_metadata(entry, "artifact regular file")
    if observed != entry.content_sha256:
        raise PublicationArtifactInstallError(
            "artifact regular file differs from its snapshotted content"
        )
    return observed


def _require_entry_mapping(
    parent_fd: int,
    name: str,
    expected: _HeldEntry,
    field: str,
) -> None:
    try:
        observed = os.stat(
            _component(name, field),
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as error:
        raise PublicationArtifactInstallError(f"{field} identity changed") from error
    if _metadata(observed) != _entry_metadata(expected):
        raise PublicationArtifactInstallError(f"{field} identity changed")


def _require_current_directory_mapping(
    parent_fd: int,
    directory: Path,
    expected_directory: tuple[int, int],
    *,
    view: PublicationArtifactDirectory,
    expected_tree: tuple[tuple[object, ...], ...],
    field: str,
) -> None:
    expected_parent = os.fstat(parent_fd)
    try:
        current_parent_fd = _open_directory(directory.parent, f"current {field} parent")
    except PublicationArtifactInstallError as error:
        raise PublicationArtifactInstallError(f"{field} parent identity changed") from error
    try:
        current_parent = os.fstat(current_parent_fd)
        if (current_parent.st_dev, current_parent.st_ino) != (
            expected_parent.st_dev,
            expected_parent.st_ino,
        ):
            raise PublicationArtifactInstallError(f"{field} parent identity changed")
        try:
            current_output = os.stat(
                directory.name,
                dir_fd=current_parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise PublicationArtifactInstallError(f"{field} identity changed") from error
        if (current_output.st_dev, current_output.st_ino) != expected_directory:
            raise PublicationArtifactInstallError(f"{field} identity changed")
        if view._revalidate(current_parent_fd, directory.name) != expected_tree:
            raise PublicationArtifactInstallError(f"{field} tree changed")
    finally:
        os.close(current_parent_fd)


def _snapshot_tree(root_fd: int) -> PublicationArtifactDirectory:
    opened: list[int] = [root_fd]
    entries: dict[str, _HeldEntry] = {}
    visited_directories: set[tuple[int, int]] = set()

    def visit_directory(relative_path: str, descriptor: int) -> None:
        before = os.fstat(descriptor)
        directory_identity = before.st_dev, before.st_ino
        if directory_identity in visited_directories:
            raise PublicationArtifactInstallError("artifact tree contains a directory cycle")
        visited_directories.add(directory_identity)
        try:
            child_names = tuple(sorted(os.listdir(descriptor)))
        except OSError as error:
            raise PublicationArtifactInstallError(
                f"artifact directory {relative_path or '.'!r} could not be enumerated"
            ) from error
        entries[relative_path] = _HeldEntry(
            descriptor=descriptor,
            is_directory=True,
            device=before.st_dev,
            inode=before.st_ino,
            mode=before.st_mode,
            size=before.st_size,
            content_sha256=None,
            child_names=child_names,
        )
        for child_name in child_names:
            _component(child_name, "artifact member name")
            child_path = child_name if not relative_path else f"{relative_path}/{child_name}"
            try:
                path_observed = os.stat(
                    child_name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise PublicationArtifactInstallError(
                    f"artifact member {child_path!r} could not be inspected"
                ) from error
            if stat.S_ISDIR(path_observed.st_mode):
                child_fd = _open_directory_at(descriptor, child_name, child_path)
                opened.append(child_fd)
                child_observed = os.fstat(child_fd)
                if _metadata(child_observed) != _metadata(path_observed):
                    raise PublicationArtifactInstallError(
                        f"artifact member {child_path!r} identity changed"
                    )
                visit_directory(child_path, child_fd)
            elif stat.S_ISREG(path_observed.st_mode):
                child_fd = _open_regular_at(descriptor, child_name, child_path)
                opened.append(child_fd)
                child_observed = os.fstat(child_fd)
                if _metadata(child_observed) != _metadata(path_observed):
                    raise PublicationArtifactInstallError(
                        f"artifact member {child_path!r} identity changed"
                    )
                content_sha256 = _hash_descriptor(child_fd, child_observed.st_size)
                if _metadata(os.fstat(child_fd)) != _metadata(child_observed):
                    raise PublicationArtifactInstallError(
                        f"artifact member {child_path!r} metadata changed"
                    )
                entries[child_path] = _HeldEntry(
                    descriptor=child_fd,
                    is_directory=False,
                    device=child_observed.st_dev,
                    inode=child_observed.st_ino,
                    mode=child_observed.st_mode,
                    size=child_observed.st_size,
                    content_sha256=content_sha256,
                    child_names=(),
                )
            else:
                raise PublicationArtifactInstallError(
                    f"artifact member {child_path!r} is not a directory or regular file"
                )
        after = os.fstat(descriptor)
        if _metadata(after) != _metadata(before):
            raise PublicationArtifactInstallError(
                f"artifact directory {relative_path or '.'!r} metadata changed"
            )
        if tuple(sorted(os.listdir(descriptor))) != child_names:
            raise PublicationArtifactInstallError(
                f"artifact directory {relative_path or '.'!r} tree changed"
            )

    try:
        visit_directory("", root_fd)
        return PublicationArtifactDirectory(_VIEW_TOKEN, entries)
    except BaseException:
        for descriptor in opened:
            with suppress(OSError):
                os.close(descriptor)
        raise


def _rename_no_replace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    destination: Path,
) -> None:
    source_name = _component(source_name, "rename source")
    destination_name = _component(destination_name, "rename destination")
    libc = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_name)
    encoded_destination = os.fsencode(destination_name)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        try:
            rename_no_replace = libc.renameatx_np
        except AttributeError as error:
            raise PublicationArtifactInstallError(
                "atomic descriptor-relative no-replace is unavailable"
            ) from error
        rename_no_replace.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            source_parent_fd,
            encoded_source,
            destination_parent_fd,
            encoded_destination,
            0x00000004,
        )
    elif sys.platform.startswith("linux"):
        try:
            rename_no_replace = libc.renameat2
        except AttributeError as error:
            raise PublicationArtifactInstallError(
                "atomic descriptor-relative no-replace is unavailable"
            ) from error
        rename_no_replace.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            source_parent_fd,
            encoded_source,
            destination_parent_fd,
            encoded_destination,
            0x00000001,
        )
    else:
        raise PublicationArtifactInstallError(
            "atomic descriptor-relative no-replace is unavailable"
        )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def _restore(
    parent_fd: int,
    quarantine_name: str,
    original_name: str,
    *,
    original_path: Path,
) -> None:
    try:
        _rename_no_replace(
            parent_fd,
            quarantine_name,
            parent_fd,
            original_name,
            destination=original_path,
        )
    except (OSError, PublicationArtifactInstallError):
        return


def _claim_owned_directory(
    parent_fd: int,
    staging: Path,
    expected: tuple[int, int],
) -> tuple[str, int]:
    quarantine_name = f"{staging.name}.owned-{secrets.token_hex(16)}"
    try:
        _rename_no_replace(
            parent_fd,
            staging.name,
            parent_fd,
            quarantine_name,
            destination=staging.with_name(quarantine_name),
        )
    except OSError as error:
        raise PublicationArtifactInstallError(
            "verified staging could not be claimed without replacement"
        ) from error
    try:
        descriptor = _open_directory_at(
            parent_fd,
            quarantine_name,
            "verified staging",
        )
        observed = os.fstat(descriptor)
        if (observed.st_dev, observed.st_ino) != expected:
            os.close(descriptor)
            raise PublicationArtifactInstallError("verified staging identity changed")
    except BaseException:
        _restore(parent_fd, quarantine_name, staging.name, original_path=staging)
        raise
    return quarantine_name, descriptor


def _quarantine_rejected_output(
    parent_fd: int,
    output: Path,
    expected: tuple[int, int],
) -> None:
    rejected_name = f".{output.name}.rejected-staging-{secrets.token_hex(16)}"
    try:
        _rename_no_replace(
            parent_fd,
            output.name,
            parent_fd,
            rejected_name,
            destination=output.with_name(rejected_name),
        )
    except OSError as error:
        if error.errno == errno.ENOENT:
            return
        raise PublicationArtifactInstallError(
            "rejected artifact could not be claimed from the formal output name"
        ) from error
    try:
        descriptor = _open_directory_at(
            parent_fd,
            rejected_name,
            "rejected artifact",
        )
        observed = os.fstat(descriptor)
        os.close(descriptor)
        if (observed.st_dev, observed.st_ino) != expected:
            _restore(parent_fd, rejected_name, output.name, original_path=output)
            return
    except BaseException:
        _restore(parent_fd, rejected_name, output.name, original_path=output)
        raise
    try:
        os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise PublicationArtifactInstallError(
        "formal output name remained present after rejected installation"
    )


def verify_existing_directory(
    root: Path,
    *,
    verifier: Callable[[PublicationArtifactDirectory], _T],
) -> _T:
    """Verify one existing path through a held, exact directory-tree snapshot."""

    if not isinstance(root, Path):
        raise TypeError("root must be a pathlib.Path")
    if not callable(verifier):
        raise TypeError("verifier must be callable")
    parent_fd = _open_directory(root.parent, "existing artifact parent")
    view: PublicationArtifactDirectory | None = None
    try:
        root_fd = _open_directory_at(parent_fd, root.name, "existing artifact root")
        try:
            observed_root = os.fstat(root_fd)
        except BaseException:
            os.close(root_fd)
            raise
        root_identity = observed_root.st_dev, observed_root.st_ino
        view = _snapshot_tree(root_fd)
        expected_tree = view._revalidate(parent_fd, root.name)
        verified = verifier(view)
        if view._revalidate(parent_fd, root.name) != expected_tree:
            raise PublicationArtifactInstallError(
                "existing artifact tree changed during verification"
            )
        _require_current_directory_mapping(
            parent_fd,
            root,
            root_identity,
            view=view,
            expected_tree=expected_tree,
            field="existing artifact root",
        )
        return verified
    finally:
        if view is not None:
            view._close()
        os.close(parent_fd)


def install_verified_directory(
    staging: Path,
    output: Path,
    *,
    staging_identity: tuple[int, int],
    verifier: Callable[[PublicationArtifactDirectory], _T],
    fingerprint: Callable[[_T], object],
) -> _T:
    """Install one descriptor-verified staging tree without replacing any output."""

    if not isinstance(staging, Path) or not isinstance(output, Path):
        raise TypeError("staging and output must be pathlib.Path values")
    if not callable(verifier) or not callable(fingerprint):
        raise TypeError("verifier and fingerprint must be callable")
    expected_identity = _identity(staging_identity)
    if staging.name == output.name:
        raise PublicationArtifactInstallError("staging and output must be distinct paths")
    parent_fd = _open_directory(output.parent, "artifact output parent")
    staging_parent_fd: int | None = None
    quarantine_name: str | None = None
    view: PublicationArtifactDirectory | None = None
    installed = False
    try:
        staging_parent_fd = _open_directory(staging.parent, "artifact staging parent")
        if _metadata(os.fstat(staging_parent_fd))[:2] != _metadata(os.fstat(parent_fd))[:2]:
            raise PublicationArtifactInstallError(
                "staging and output must share one stable parent directory"
            )
        quarantine_name, staging_fd = _claim_owned_directory(
            parent_fd,
            staging,
            expected_identity,
        )
        view = _snapshot_tree(staging_fd)
        expected_tree = view._revalidate(parent_fd, quarantine_name)
        try:
            before = verifier(view)
            before_fingerprint = fingerprint(before)
        except BaseException as error:
            raise PublicationArtifactInstallError(
                "verified staging failed pre-install verification"
            ) from error
        if view._revalidate(parent_fd, quarantine_name) != expected_tree:
            raise PublicationArtifactInstallError(
                "verified staging tree changed during pre-install verification"
            )
        try:
            _rename_no_replace(
                parent_fd,
                quarantine_name,
                parent_fd,
                output.name,
                destination=output,
            )
        except OSError as error:
            if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                raise PublicationArtifactInstallError("artifact output already exists") from error
            raise PublicationArtifactInstallError(
                "verified staging could not be installed atomically"
            ) from error
        installed = True
        os.fsync(parent_fd)
        if view._revalidate(parent_fd, output.name) != expected_tree:
            raise PublicationArtifactInstallError(
                "installed artifact tree changed during installation"
            )
        try:
            after = verifier(view)
            after_fingerprint = fingerprint(after)
        except BaseException as error:
            raise PublicationArtifactInstallError(
                "installed artifact failed post-install verification"
            ) from error
        if view._revalidate(parent_fd, output.name) != expected_tree:
            raise PublicationArtifactInstallError(
                "installed artifact tree changed during post-install verification"
            )
        if before_fingerprint != after_fingerprint:
            raise PublicationArtifactInstallError(
                "installed artifact verifier fingerprint changed during installation"
            )
        _require_current_directory_mapping(
            parent_fd,
            output,
            expected_identity,
            view=view,
            expected_tree=expected_tree,
            field="artifact output",
        )
        return after
    except BaseException:
        if installed:
            _quarantine_rejected_output(parent_fd, output, expected_identity)
        elif quarantine_name is not None:
            _restore(parent_fd, quarantine_name, staging.name, original_path=staging)
        raise
    finally:
        if view is not None:
            view._close()
        if staging_parent_fd is not None:
            os.close(staging_parent_fd)
        os.close(parent_fd)


def quarantine_owned_directory(
    staging: Path,
    *,
    staging_identity: tuple[int, int],
) -> bool:
    """Atomically move one exact staging root to a retained diagnostic name."""

    if not isinstance(staging, Path):
        raise TypeError("staging must be a pathlib.Path")
    expected_identity = _identity(staging_identity)
    parent_fd = _open_directory(staging.parent, "staging cleanup parent")
    claimed_name = f".{staging.name}.retained-staging-{secrets.token_hex(16)}"
    try:
        try:
            _rename_no_replace(
                parent_fd,
                staging.name,
                parent_fd,
                claimed_name,
                destination=staging.with_name(claimed_name),
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                return False
            raise PublicationArtifactInstallError(
                "owned staging cleanup could not claim its root"
            ) from error
        try:
            descriptor = _open_directory_at(parent_fd, claimed_name, "owned staging cleanup")
            observed = os.fstat(descriptor)
            os.close(descriptor)
        except BaseException:
            _restore(parent_fd, claimed_name, staging.name, original_path=staging)
            raise
        if (observed.st_dev, observed.st_ino) != expected_identity:
            _restore(parent_fd, claimed_name, staging.name, original_path=staging)
            return False
        # POSIX has no portable unlink/rmdir-if-inode primitive.  Retain the
        # complete claimed tree under its random diagnostic name so cleanup can
        # never delete a same-name replacement at any depth.
        return True
    finally:
        os.close(parent_fd)
