"""Outcome-blind structure pilot for the frozen publication corpus.

The production interface deliberately accepts only the root containing the
three closed acquisition bundles and one all-new output directory.  Scientific
options, execution authority, and publication-evidence admission are not caller
inputs.
"""

from __future__ import annotations

import csv
import ctypes
import errno
import hashlib
import json
import os
import platform
import resource
import secrets
import sqlite3
import stat
import sys
import tempfile
import time
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.publication_traces import (
    _PRODUCTION_CONFIG,
    PUBLICATION_SOURCE_PARTITION_COUNT,
    CanonicalRawEvent,
    CanonicalRawEventBatch,
    LicenseTermsObject,
    PublicationTraceRequest,
    _canonical_json_bytes,
    _CanonicalEventStore,
    _current_acquisition_repository_snapshot,
    _read_canonical_raw_events,
    _require_path_outside_repository,
    _TraceConfig,
    _transform_events,
    _transition_payload,
    _validate_config,
    _verified_acquisition_input,
    _verify_clean_repository_snapshot,
    frozen_dataset_release,
    source_partition,
)

PUBLICATION_STRUCTURE_PILOT_SCHEMA = "dynamic-cssc-outcome-blind-structure-pilot-v1"
_ARTIFACT_POLICY = "pre-freeze-pilot-only-permanently-non-admissible"
_REPORT_FILENAME = "structure-pilot-report.json"
_CHECKSUMS_FILENAME = "checksums.sha256"
_DATASET_IDS = (
    "stack-overflow",
    "simplewiki-2026-07",
    "nyc-tlc-yellow-2022",
)
_SEMANTICS = ("T1", "T2")
_SOURCE_PARTITIONS = tuple(range(PUBLICATION_SOURCE_PARTITION_COUNT))
_SCRATCH_ROOT_ENV = "PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT"
_SCRATCH_DIRECTORY_ENV = ("TMPDIR", "SQLITE_TMPDIR")
_SCRATCH_LOCK_FILENAME = ".dynamic-cssc-structure-pilot.lock"
_SCRATCH_IDENTITY_DOMAIN = b"dynamic-cssc-publication-structure-pilot-scratch-root-v1\0"
_FORBIDDEN_OUTCOME_TERMS = (
    "candidate",
    "cost",
    "effect",
    "rank",
    "dominance",
    "dominated",
    "pareto",
    "winner",
    "winning",
    "rho",
    "freshness",
    "query",
    "selector",
    "oracle",
    "heldout",
    "held-out",
    "confirmatory",
    "classification",
    "reference",
    "ablation",
)


class PublicationStructurePilotError(ValueError):
    """The closed pilot contract or one of its inputs failed validation."""


class PublicationStructurePilotHold(RuntimeError):
    """Production pilot prerequisites are unavailable; no output was written."""


class _PilotSerializationError(RuntimeError):
    """A prefix transition could not complete the structural round trip."""


class _OwnedEntryChanged(RuntimeError):
    """A pathname no longer names the invocation-owned filesystem object."""


@dataclass(frozen=True, slots=True)
class PublicationStructurePilotBundle:
    """Paths and digest for one atomically installed non-admissible report."""

    output_dir: Path
    report_path: Path
    checksums_path: Path
    report_sha256: str


@dataclass(frozen=True, slots=True)
class _PilotDatasetInput:
    dataset_id: str
    scan: Callable[[Callable[[CanonicalRawEvent], None]], CanonicalRawEventBatch]
    verified_binding: Mapping[str, object]
    revalidate_binding: Callable[[], Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class _PilotScratchRoot:
    root: Path
    device: int
    inode: int
    identity_sha256: str
    policy: str
    environment_binding_verified: bool


@dataclass(slots=True)
class _OwnedReportStaging:
    path: Path
    identity: tuple[int, int]
    members: tuple[_OwnedReportMember, ...] = ()


@dataclass(frozen=True, slots=True)
class _OwnedReportMember:
    name: str
    descriptor: int
    identity: tuple[int, int]
    mode: int
    byte_count: int
    sha256: str


def _peak_resident_memory_bytes() -> int:
    observed = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return observed if sys.platform == "darwin" else observed * 1024


def _record_preinstall_resource_checkpoint(
    report: dict[str, object],
    *,
    analysis_started_ns: int,
) -> None:
    resource_report = report.get("resource")
    if type(resource_report) is not dict:
        raise TypeError("structure pilot report resource section must be a dictionary")
    resource_report["analysis_wall_clock_ns"] = time.monotonic_ns() - analysis_started_ns
    resource_report["process_high_water_rss_bytes_before_report_install"] = (
        _peak_resident_memory_bytes()
    )


def _require_sqlite_runtime() -> None:
    """Verify the disk-backed mapping runtime before any acquisition work."""

    if sqlite3.sqlite_version_info < (3, 35, 0):
        raise PublicationStructurePilotError(
            "structure pilot requires SQLite 3.35 or newer for bounded prefix mapping"
        )
    try:
        connection = sqlite3.connect(":memory:")
        try:
            compile_options = tuple(
                row[0]
                for row in connection.execute("PRAGMA compile_options")
                if len(row) == 1 and type(row[0]) is str and row[0].startswith("TEMP_STORE=")
            )
            connection.execute("PRAGMA temp_store=FILE")
            observed = connection.execute("PRAGMA temp_store").fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise PublicationStructurePilotError(
            "structure pilot could not verify the SQLite temporary-store policy"
        ) from error
    if observed != (1,):
        raise PublicationStructurePilotError(
            "structure pilot requires the SQLite temporary-store policy FILE"
        )
    if compile_options != ("TEMP_STORE=1",):
        raise PublicationStructurePilotError(
            "structure pilot requires the closed SQLite TEMP_STORE=1 compile option"
        )


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _scratch_root_identity(root: Path, *, device: int, inode: int) -> str:
    return hashlib.sha256(
        _SCRATCH_IDENTITY_DOMAIN
        + os.fsencode(root)
        + b"\0"
        + device.to_bytes(16, "big", signed=False)
        + inode.to_bytes(16, "big", signed=False)
    ).hexdigest()


def _require_private_scratch_directory(root: Path) -> os.stat_result:
    try:
        observed = root.lstat()
    except FileNotFoundError as error:
        raise PublicationStructurePilotError(
            "scratch root must be a pre-existing private directory"
        ) from error
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise PublicationStructurePilotError("scratch root must be a non-symlink directory")
    if stat.S_IMODE(observed.st_mode) != 0o700:
        raise PublicationStructurePilotError("scratch root permissions must be exactly 0700")
    if observed.st_uid != os.geteuid():
        raise PublicationStructurePilotError("scratch root must be owned by the current user")
    if not os.access(root, os.W_OK | os.X_OK):
        raise PublicationStructurePilotError("scratch root must be writable and searchable")
    return observed


def _require_scratch_environment_binding(root: Path) -> None:
    for name in _SCRATCH_DIRECTORY_ENV:
        raw_value = os.environ.get(name)
        if not raw_value:
            raise PublicationStructurePilotError(f"scratch root requires {name} at process start")
        configured = Path(raw_value)
        if not configured.is_absolute():
            raise PublicationStructurePilotError(f"scratch environment {name} must be absolute")
        try:
            resolved = configured.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise PublicationStructurePilotError(
                f"scratch environment {name} must resolve to the verified root"
            ) from error
        if configured != root or resolved != root:
            raise PublicationStructurePilotError(
                f"scratch environment {name} must resolve to the verified root"
            )
    try:
        python_temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PublicationStructurePilotError(
            "Python temporary-directory binding could not be verified"
        ) from error
    configured_python_temporary_root = Path(tempfile.gettempdir())
    if configured_python_temporary_root != root or python_temporary_root != root:
        raise PublicationStructurePilotError(
            "TMPDIR must bind Python temporary files before process startup"
        )


def _production_scratch_root(
    *,
    repository_root: Path,
    acquisition_bundle_root: Path,
    output_dir: Path,
) -> _PilotScratchRoot:
    raw_root = os.environ.get(_SCRATCH_ROOT_ENV)
    if not raw_root:
        raise PublicationStructurePilotError(
            f"scratch root requires the closed {_SCRATCH_ROOT_ENV} environment"
        )
    configured_root = Path(raw_root)
    if not configured_root.is_absolute():
        raise PublicationStructurePilotError("scratch root must be an absolute path")
    observed = _require_private_scratch_directory(configured_root)
    try:
        root = configured_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PublicationStructurePilotError(
            "scratch root must have one stable canonical path"
        ) from error
    if configured_root != root:
        raise PublicationStructurePilotError(
            "scratch root must be canonical and contain no symlink traversal"
        )
    default_roots = {
        Path(value).resolve(strict=False) for value in ("/tmp", "/var/tmp", "/usr/tmp")
    }
    if root in default_roots:
        raise PublicationStructurePilotError("scratch root must not use a system default directory")
    protected_roots = (
        repository_root.resolve(strict=True),
        acquisition_bundle_root.resolve(strict=True),
        output_dir.resolve(strict=False),
    )
    if any(_paths_overlap(root, protected) for protected in protected_roots):
        raise PublicationStructurePilotError(
            "scratch root must be disjoint from source, acquisition, and output trees"
        )
    _require_scratch_environment_binding(root)
    try:
        members = tuple(root.iterdir())
    except OSError as error:
        raise PublicationStructurePilotError("scratch root cannot be enumerated") from error
    if members:
        raise PublicationStructurePilotError("scratch root must be empty before the pilot")
    return _PilotScratchRoot(
        root=root,
        device=observed.st_dev,
        inode=observed.st_ino,
        identity_sha256=_scratch_root_identity(
            root,
            device=observed.st_dev,
            inode=observed.st_ino,
        ),
        policy="workflow-fixed-external-private-empty-exclusive-v1",
        environment_binding_verified=True,
    )


def _test_only_scratch_root(root: Path) -> _PilotScratchRoot:
    observed = _require_private_scratch_directory(root)
    resolved = root.resolve(strict=True)
    return _PilotScratchRoot(
        root=resolved,
        device=observed.st_dev,
        inode=observed.st_ino,
        identity_sha256=_scratch_root_identity(
            resolved,
            device=observed.st_dev,
            inode=observed.st_ino,
        ),
        policy="pytest-only-private-temporary-root-v1",
        environment_binding_verified=False,
    )


def _require_scratch_lock_owner(lock_path: Path, identity: tuple[int, int]) -> None:
    try:
        observed = lock_path.lstat()
    except FileNotFoundError as error:
        raise PublicationStructurePilotError("scratch root ownership lock disappeared") from error
    if not stat.S_ISREG(observed.st_mode) or (observed.st_dev, observed.st_ino) != identity:
        raise PublicationStructurePilotError("scratch root ownership lock changed")


def _require_scratch_root_owner(scratch: _PilotScratchRoot) -> None:
    observed = _require_private_scratch_directory(scratch.root)
    if (observed.st_dev, observed.st_ino) != (scratch.device, scratch.inode):
        raise PublicationStructurePilotError("scratch root identity changed")


def _open_directory_descriptor(directory: Path, *, field: str) -> int:
    """Open one non-symlink directory as a stable lookup capability."""

    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise PublicationStructurePilotError(
            f"{field} requires directory-descriptor and no-follow support"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        raise PublicationStructurePilotError(f"{field} could not be opened securely") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PublicationStructurePilotError(f"{field} is not a directory")
    return descriptor


def _rename_entry_no_replace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    destination: Path,
) -> None:
    """Rename relative to stable parent descriptors without replacing a name."""

    if not source_name or "/" in source_name or not destination_name or "/" in destination_name:
        raise ValueError("atomic rename requires single path components")
    libc = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_name)
    encoded_destination = os.fsencode(destination_name)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        try:
            rename_no_replace = libc.renameatx_np
        except AttributeError as error:
            raise PublicationStructurePilotError(
                "atomic descriptor-relative no-replace is unavailable on this platform"
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
            raise PublicationStructurePilotError(
                "atomic descriptor-relative no-replace is unavailable on this platform"
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
        raise PublicationStructurePilotError(
            "atomic descriptor-relative no-replace is unavailable on this platform"
        )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination)


def _restore_quarantined_entry(
    parent_fd: int,
    quarantine_name: str,
    original_name: str,
    *,
    original_path: Path,
) -> None:
    """Best-effort no-replace restoration; never overwrite a newer object."""

    try:
        _rename_entry_no_replace(
            parent_fd,
            quarantine_name,
            parent_fd,
            original_name,
            destination=original_path,
        )
    except OSError:
        # Both names are preserved if another object claimed the original name.
        return


def _entry_exists_at(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _claim_owned_entry_at(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    *,
    directory: bool,
    field: str,
    path: Path,
) -> tuple[str, int]:
    """Atomically quarantine one name, then prove the moved inode is ours."""

    quarantine_name = f".{name}.owned-quarantine-{secrets.token_hex(16)}"
    _rename_entry_no_replace(
        parent_fd,
        name,
        parent_fd,
        quarantine_name,
        destination=path.with_name(quarantine_name),
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= os.O_DIRECTORY
    else:
        flags |= os.O_NONBLOCK
    try:
        entry_fd = os.open(quarantine_name, flags, dir_fd=parent_fd)
        observed = os.fstat(entry_fd)
    except BaseException:
        _restore_quarantined_entry(
            parent_fd,
            quarantine_name,
            name,
            original_path=path,
        )
        raise
    expected_kind = stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode)
    if not expected_kind or (observed.st_dev, observed.st_ino) != identity:
        os.close(entry_fd)
        _restore_quarantined_entry(
            parent_fd,
            quarantine_name,
            name,
            original_path=path,
        )
        raise _OwnedEntryChanged(f"{field} identity changed")
    return quarantine_name, entry_fd


def _claim_owned_entry(
    path: Path,
    identity: tuple[int, int],
    *,
    directory: bool,
    field: str,
) -> tuple[int, str, int]:
    """Open a stable parent and atomically quarantine one owned entry."""

    parent_fd = _open_directory_descriptor(path.parent, field=f"{field} parent")
    try:
        quarantine_name, entry_fd = _claim_owned_entry_at(
            parent_fd,
            path.name,
            identity,
            directory=directory,
            field=field,
            path=path,
        )
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd, quarantine_name, entry_fd


def _remove_empty_directory_if_owned(
    directory: Path,
    identity: tuple[int, int],
    *,
    field: str,
) -> None:
    """Atomically quarantine and remove the same empty owned directory."""

    try:
        parent_fd, quarantine_name, directory_fd = _claim_owned_entry(
            directory,
            identity,
            directory=True,
            field=field,
        )
    except (FileNotFoundError, _OwnedEntryChanged) as error:
        raise PublicationStructurePilotError(
            f"{field} identity changed; cleanup refused"
        ) from error
    try:
        if os.listdir(directory_fd):
            _restore_quarantined_entry(
                parent_fd,
                quarantine_name,
                directory.name,
                original_path=directory,
            )
            raise PublicationStructurePilotError(f"{field} is not empty; cleanup refused")
        os.rmdir(quarantine_name, dir_fd=parent_fd)
        if _entry_exists_at(parent_fd, directory.name):
            raise PublicationStructurePilotError(
                f"{field} identity changed during cleanup; replacement preserved"
            )
    except OSError as error:
        raise PublicationStructurePilotError(f"{field} cleanup failed") from error
    finally:
        os.close(directory_fd)
        os.close(parent_fd)


@contextmanager
def _owned_empty_directory(
    parent: Path,
    *,
    prefix: str,
    field: str,
) -> Iterator[Path]:
    """Create an owned directory and refuse path-based recursive cleanup."""

    try:
        directory = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
        observed = directory.lstat()
    except OSError as error:
        raise PublicationStructurePilotError(f"{field} creation failed") from error
    identity = (observed.st_dev, observed.st_ino)
    try:
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or directory.parent.resolve(strict=True) != parent.resolve(strict=True)
        ):
            raise PublicationStructurePilotError(
                f"{field} must be a unique child of its verified parent"
            )
        yield directory
    finally:
        _remove_empty_directory_if_owned(directory, identity, field=field)


def _create_owned_store_file(path: Path) -> tuple[int, int]:
    """Reserve one no-follow store pathname and return its inode identity."""

    if not hasattr(os, "O_NOFOLLOW"):
        raise PublicationStructurePilotError("owned store files require OS O_NOFOLLOW support")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        observed = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(observed.st_mode):
        raise PublicationStructurePilotError("canonical store reservation is not a regular file")
    return observed.st_dev, observed.st_ino


def _require_owned_store_file(
    path: Path,
    identity: tuple[int, int],
) -> os.stat_result:
    try:
        observed = path.lstat()
    except FileNotFoundError as error:
        raise PublicationStructurePilotError(
            "canonical store identity changed; cleanup refused"
        ) from error
    if not stat.S_ISREG(observed.st_mode) or (observed.st_dev, observed.st_ino) != identity:
        raise PublicationStructurePilotError("canonical store identity changed; cleanup refused")
    return observed


def _unlink_owned_store_file(path: Path, identity: tuple[int, int]) -> None:
    """Atomically quarantine and unlink the same owned canonical store."""

    _remove_regular_file_if_owned(
        path,
        identity,
        field="canonical store",
    )


def _remove_regular_file_if_owned(
    path: Path,
    identity: tuple[int, int],
    *,
    field: str,
) -> None:
    """Atomically quarantine and unlink one exact owned regular file."""

    try:
        parent_fd, quarantine_name, file_fd = _claim_owned_entry(
            path,
            identity,
            directory=False,
            field=field,
        )
    except (FileNotFoundError, _OwnedEntryChanged) as error:
        raise PublicationStructurePilotError(
            f"{field} identity changed; cleanup refused"
        ) from error
    try:
        os.unlink(quarantine_name, dir_fd=parent_fd)
        if _entry_exists_at(parent_fd, path.name):
            raise PublicationStructurePilotError(
                f"{field} identity changed during cleanup; replacement preserved"
            )
    except OSError as error:
        raise PublicationStructurePilotError(f"{field} cleanup failed") from error
    finally:
        os.close(file_fd)
        os.close(parent_fd)


@contextmanager
def _claimed_scratch_workspace(scratch: _PilotScratchRoot) -> Iterator[Path]:
    if type(scratch) is not _PilotScratchRoot:
        raise TypeError("scratch must be an exact _PilotScratchRoot")
    _require_scratch_root_owner(scratch)
    if scratch.environment_binding_verified:
        _require_scratch_environment_binding(scratch.root)
    try:
        if any(scratch.root.iterdir()):
            raise PublicationStructurePilotError("scratch root must be empty and exclusive")
    except OSError as error:
        raise PublicationStructurePilotError("scratch root cannot be enumerated") from error
    lock_path = scratch.root / _SCRATCH_LOCK_FILENAME
    try:
        lock_handle = lock_path.open("xb")
    except FileExistsError as error:
        raise PublicationStructurePilotError("scratch root is already claimed") from error
    lock_stat = os.fstat(lock_handle.fileno())
    lock_identity = (lock_stat.st_dev, lock_stat.st_ino)
    try:
        lock_handle.write(f"pid={os.getpid()}\n".encode("ascii"))
        lock_handle.flush()
        os.fsync(lock_handle.fileno())
        if {path.name for path in scratch.root.iterdir()} != {_SCRATCH_LOCK_FILENAME}:
            raise PublicationStructurePilotError("scratch root was populated concurrently")
        with _owned_empty_directory(
            scratch.root,
            prefix="dynamic-cssc-structure-pilot-workspace-",
            field="scratch workspace",
        ) as workspace:
            workspace_mode = workspace.lstat().st_mode
            if (
                stat.S_ISLNK(workspace_mode)
                or not stat.S_ISDIR(workspace_mode)
                or workspace.parent.resolve(strict=True) != scratch.root
            ):
                raise PublicationStructurePilotError(
                    "scratch workspace must be a unique child of the verified root"
                )
            _require_scratch_root_owner(scratch)
            _require_scratch_lock_owner(lock_path, lock_identity)
            yield workspace
        _require_scratch_root_owner(scratch)
        if scratch.environment_binding_verified:
            _require_scratch_environment_binding(scratch.root)
        _require_scratch_lock_owner(lock_path, lock_identity)
        if {path.name for path in scratch.root.iterdir()} != {_SCRATCH_LOCK_FILENAME}:
            raise PublicationStructurePilotError("scratch workspace cleanup was incomplete")
    except OSError as error:
        raise PublicationStructurePilotError("scratch workspace operation failed") from error
    finally:
        lock_handle.close()
        _unlink_lock_if_owned(lock_path, lock_identity, strict=True)


def _require_disjoint_input_output(
    acquisition_bundle_root: Path,
    output_dir: Path,
) -> None:
    resolved_input = acquisition_bundle_root.resolve(strict=False)
    resolved_output = output_dir.resolve(strict=False)
    if _paths_overlap(resolved_input, resolved_output):
        raise PublicationStructurePilotError(
            "acquisition_bundle_root and output_dir must be disjoint trees"
        )


def _validate_fixture_batches(
    batches: Mapping[str, CanonicalRawEventBatch],
) -> None:
    if not isinstance(batches, Mapping) or tuple(sorted(batches)) != tuple(sorted(_DATASET_IDS)):
        raise PublicationStructurePilotError(
            "structure pilot requires the exact three frozen dataset batches"
        )
    for dataset_id in _DATASET_IDS:
        batch = batches[dataset_id]
        if type(batch) is not CanonicalRawEventBatch:
            raise TypeError(
                "synthetic pilot batches must contain exact CanonicalRawEventBatch values"
            )
        if batch.dataset_id != dataset_id or batch.dataset_release != frozen_dataset_release(
            dataset_id
        ):
            raise PublicationStructurePilotError(
                "synthetic pilot batch identity does not match the frozen dataset"
            )


def _eligibility_codes(reasons: list[str]) -> list[str]:
    return [reason.split(":", maxsplit=1)[0] for reason in reasons]


def _verified_input_identity(binding: Mapping[str, object]) -> dict[str, str]:
    def digest(value: object, field: str) -> str:
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise PublicationStructurePilotError(
                f"verified acquisition {field} must be a lowercase SHA-256 digest"
            )
        return value

    repository_provenance = binding.get("repository_provenance")
    if not isinstance(repository_provenance, Mapping):
        raise PublicationStructurePilotError(
            "verified acquisition repository provenance is malformed"
        )
    behavior_inventory = repository_provenance.get("behavior_inventory")
    if not isinstance(behavior_inventory, Mapping):
        raise PublicationStructurePilotError("verified acquisition behavior inventory is malformed")
    identity = {
        "acquisition_transaction_sha256": digest(
            binding.get("acquisition_transaction_sha256"),
            "transaction identity",
        ),
        "source_set_sha256": digest(
            binding.get("source_set_sha256"),
            "source-set identity",
        ),
        "acquisition_behavior_set_sha256": digest(
            behavior_inventory.get("behavior_set_sha256"),
            "central behavior-set identity",
        ),
    }
    return {
        **identity,
        "verified_input_binding_sha256": hashlib.sha256(
            _canonical_json_bytes(identity)
        ).hexdigest(),
    }


def _failed_cell_report(
    batch: CanonicalRawEventBatch,
    *,
    semantics: str,
    source_partition_id: int,
    stage: str,
    code: str,
    started: int,
) -> dict[str, object]:
    closed_codes = {
        "mapping": {"mapping-failed"},
        "transform": {"transform-failed"},
        "serialization": {"serialization-failed"},
        "dataset-scan": {"parser-scan-blocked", "canonical-scan-blocked"},
    }
    if code not in closed_codes.get(stage, set()):
        raise RuntimeError("cell failure must use the closed stage/code vocabulary")
    blocked = stage == "dataset-scan"
    return {
        "dataset_id": batch.dataset_id,
        "dataset_release": batch.dataset_release,
        "semantics": semantics,
        "source_partition": source_partition_id,
        "structure": {
            "selected_row_count": None,
            "observed_column_count": None,
            "reserved_empty_column_count": None,
            "peak_row_nonzeros": None,
            "peak_live_coordinate_count": None,
            "maximum_transition_group_size_observed": None,
            "t2_window_peak_groups": None,
        },
        "cardinality": {
            "source_partition_prefix_event_count": None,
            "accepted_prefix_group_count": None,
            "transition_record_count": None,
            "logical_change_count": None,
            "insert_count": None,
            "modify_count": None,
            "delete_count": None,
            "clipped_noop_count": None,
            "filtered_other_partition_count": None,
            "filtered_unselected_source_count": None,
            "filtered_unselected_target_count": None,
        },
        "health": {
            "completion_state": "blocked" if blocked else "failed",
            "prefix_mapping_eligible": None,
            "runtime_healthy": False,
            "eligibility_codes": [],
        },
        "resource": {
            "wall_clock_ns": time.monotonic_ns() - started,
            "process_high_water_rss_bytes_at_cell_completion": (_peak_resident_memory_bytes()),
            "prefix_transition_serialized_bytes": 0,
        },
        "error": {"stage": stage, "code": code},
        "serialization_completeness": {
            "expected_record_count": None,
            "serialized_record_count": None,
            "decoded_record_count": None,
            "canonical_roundtrip_record_count": None,
            "complete": False,
        },
    }


def _cell_report(
    batch: CanonicalRawEventBatch,
    *,
    event_store: _CanonicalEventStore,
    prefix_events: Callable[[], Iterable[CanonicalRawEvent]],
    total_event_count: int,
    semantics: str,
    source_partition_id: int,
    config: _TraceConfig,
) -> dict[str, object]:
    started = time.monotonic_ns()
    try:
        mapping, row_index, column_index, _prefix_count, reasons = _mapping_for_cell(
            event_store,
            batch,
            total_event_count=total_event_count,
            source_partition_id=source_partition_id,
            config=config,
        )
        source_partition_prefix_event_count = sum(
            source_partition(batch.dataset_release, event.canonical_source_id)
            == source_partition_id
            for event in prefix_events()
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return _failed_cell_report(
            batch,
            semantics=semantics,
            source_partition_id=source_partition_id,
            stage="mapping",
            code="mapping-failed",
            started=started,
        )
    serialized_record_count = 0
    decoded_record_count = 0
    canonical_roundtrip_record_count = 0
    prefix_transition_serialized_bytes = 0

    def observe_record(record: object) -> None:
        nonlocal canonical_roundtrip_record_count
        nonlocal decoded_record_count
        nonlocal prefix_transition_serialized_bytes
        nonlocal serialized_record_count
        try:
            chunk = _canonical_json_bytes(_transition_payload(record))  # type: ignore[arg-type]
            payload = json.loads(chunk)
            roundtrip = _canonical_json_bytes(payload) == chunk
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            raise _PilotSerializationError from error
        serialized_record_count += 1
        decoded_record_count += 1
        canonical_roundtrip_record_count += int(roundtrip)
        prefix_transition_serialized_bytes += len(chunk)

    try:
        transform = _transform_events(
            batch,
            ordered_events=enumerate(prefix_events()),
            semantics=semantics,
            source_partition_id=source_partition_id,
            repository_provenance_sha256="0" * 64,
            row_index=row_index,
            column_index=column_index,
            config=config,
            accepted_event_limit=None,
            record_sink=observe_record,
            retain_records=False,
        )
    except _PilotSerializationError:
        return _failed_cell_report(
            batch,
            semantics=semantics,
            source_partition_id=source_partition_id,
            stage="serialization",
            code="serialization-failed",
            started=started,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return _failed_cell_report(
            batch,
            semantics=semantics,
            source_partition_id=source_partition_id,
            stage="transform",
            code="transform-failed",
            started=started,
        )
    accepted_groups = transform.accepted_event_count
    operation_counts = transform.operation_counts
    elapsed = time.monotonic_ns() - started
    return {
        "dataset_id": batch.dataset_id,
        "dataset_release": batch.dataset_release,
        "semantics": semantics,
        "source_partition": source_partition_id,
        "structure": {
            "selected_row_count": len(mapping["row_ids"]),
            "observed_column_count": mapping["observed_column_count"],
            "reserved_empty_column_count": mapping["reserved_empty_column_count"],
            "peak_row_nonzeros": transform.peak_row_nonzeros,
            "peak_live_coordinate_count": transform.peak_live_coordinate_count,
            "maximum_transition_group_size_observed": (
                transform.maximum_transition_group_size_observed
            ),
            "t2_window_peak_groups": transform.event_window_peak_groups,
        },
        "cardinality": {
            "source_partition_prefix_event_count": source_partition_prefix_event_count,
            "accepted_prefix_group_count": accepted_groups,
            "transition_record_count": transform.transition_record_count,
            "logical_change_count": (
                transform.transition_record_count - operation_counts["clipped-no-op"]
            ),
            "insert_count": operation_counts["insert"],
            "modify_count": operation_counts["modify"],
            "delete_count": operation_counts["delete"],
            "clipped_noop_count": operation_counts["clipped-no-op"],
            "filtered_other_partition_count": transform.filter_counts.get(
                "other-source-partition", 0
            ),
            "filtered_unselected_source_count": transform.filter_counts.get("unselected-source", 0),
            "filtered_unselected_target_count": transform.filter_counts.get("unselected-target", 0),
        },
        "health": {
            "completion_state": "complete",
            "prefix_mapping_eligible": not reasons,
            "runtime_healthy": True,
            "eligibility_codes": _eligibility_codes(reasons),
        },
        "resource": {
            "wall_clock_ns": elapsed,
            "process_high_water_rss_bytes_at_cell_completion": (_peak_resident_memory_bytes()),
            "prefix_transition_serialized_bytes": prefix_transition_serialized_bytes,
        },
        "error": {"stage": None, "code": None},
        "serialization_completeness": {
            "expected_record_count": transform.transition_record_count,
            "serialized_record_count": serialized_record_count,
            "decoded_record_count": decoded_record_count,
            "canonical_roundtrip_record_count": canonical_roundtrip_record_count,
            "complete": (
                transform.transition_record_count
                == serialized_record_count
                == decoded_record_count
                == canonical_roundtrip_record_count
            ),
        },
    }


def _mapping_for_cell(
    event_store: _CanonicalEventStore,
    batch: CanonicalRawEventBatch,
    *,
    total_event_count: int,
    source_partition_id: int,
    config: _TraceConfig,
) -> tuple[dict[str, object], dict[str, int], dict[str, int], int, list[str]]:
    """Delegate pilot mapping to the trace module's bounded disk-backed seam."""

    return event_store.mapping_for_partition(
        batch,
        total_event_count=total_event_count,
        source_partition_id=source_partition_id,
        config=config,
    )


def _report_from_inputs(
    dataset_inputs: Mapping[str, Callable[[], _PilotDatasetInput]],
    *,
    config: _TraceConfig,
    scratch: _PilotScratchRoot,
    scratch_workspace: Path,
) -> dict[str, object]:
    if not isinstance(dataset_inputs, Mapping) or tuple(sorted(dataset_inputs)) != tuple(
        sorted(_DATASET_IDS)
    ):
        raise PublicationStructurePilotError(
            "structure pilot requires the exact three frozen dataset inputs"
        )
    if any(not callable(dataset_inputs[dataset_id]) for dataset_id in _DATASET_IDS):
        raise TypeError("structure pilot dataset inputs must be callable")
    _validate_config(config)
    _require_sqlite_runtime()
    if type(scratch) is not _PilotScratchRoot or not isinstance(scratch_workspace, Path):
        raise TypeError("report generation requires one verified scratch capability")
    if scratch_workspace.parent.resolve(strict=True) != scratch.root:
        raise PublicationStructurePilotError(
            "report scratch workspace must be a child of the verified root"
        )
    if (
        config.mapping_prefix_numerator != 1
        or config.mapping_prefix_denominator != 10
        or config.source_partitions != 5
    ):
        raise PublicationStructurePilotError(
            "pilot fixture must retain the frozen 1/10 by 5 coverage"
        )
    dataset_scans: list[dict[str, object]] = []
    cells: list[dict[str, object]] = []
    opened_dataset_inputs: list[_PilotDatasetInput] = []
    maximum_canonical_store_bytes_after_index = 0

    def revalidate(dataset_input: _PilotDatasetInput) -> None:
        observed = dataset_input.revalidate_binding()
        if not isinstance(observed, Mapping) or dict(observed) != dict(
            dataset_input.verified_binding
        ):
            raise RuntimeError("verified acquisition binding changed during the pilot")

    def record_scan_failure(
        *,
        dataset_input: _PilotDatasetInput,
        dataset_id: str,
        stage: str,
        scan_error_code: str,
        blocked_code: str,
        scan_started: int,
    ) -> None:
        revalidate(dataset_input)
        dataset_release = frozen_dataset_release(dataset_id)
        input_identity = _verified_input_identity(dataset_input.verified_binding)
        dataset_scans.append(
            {
                "dataset_id": dataset_id,
                "dataset_release": dataset_release,
                "input_identity": input_identity,
                "cardinality": {
                    "schema_valid_event_count": None,
                    "mapping_prefix_event_count": None,
                    "parser_rejected_event_count": None,
                },
                "health": {"completion_state": "failed", "runtime_healthy": False},
                "resource": {
                    "verification_parser_index_wall_clock_ns": (time.monotonic_ns() - scan_started),
                    "process_high_water_rss_bytes_at_scan_completion": (
                        _peak_resident_memory_bytes()
                    ),
                    "canonical_store_bytes_after_index": None,
                },
                "error": {"stage": stage, "scan_error_code": scan_error_code},
            }
        )
        metadata_batch = CanonicalRawEventBatch(
            dataset_id=dataset_id,
            dataset_release=dataset_release,
            events=(),
            receipts=(),
        )
        for semantics in _SEMANTICS:
            for source_partition_id in _SOURCE_PARTITIONS:
                cells.append(
                    _failed_cell_report(
                        metadata_batch,
                        semantics=semantics,
                        source_partition_id=source_partition_id,
                        stage="dataset-scan",
                        code=blocked_code,
                        started=scan_started,
                    )
                )

    with _owned_empty_directory(
        scratch_workspace,
        prefix="dynamic-cssc-structure-pilot-datasets-",
        field="dataset scratch directory",
    ) as temporary_root:
        for dataset_ordinal, dataset_id in enumerate(_DATASET_IDS):
            scan_started = time.monotonic_ns()
            store_path = temporary_root / f"dataset-{dataset_ordinal}.sqlite3"
            dataset_input = dataset_inputs[dataset_id]()
            if (
                type(dataset_input) is not _PilotDatasetInput
                or dataset_input.dataset_id != dataset_id
                or not callable(dataset_input.scan)
                or not isinstance(dataset_input.verified_binding, Mapping)
                or not callable(dataset_input.revalidate_binding)
            ):
                raise TypeError("dataset input factory returned an invalid pilot input")
            opened_dataset_inputs.append(dataset_input)
            input_identity = _verified_input_identity(dataset_input.verified_binding)
            store_identity: tuple[int, int] | None = None
            try:
                store_identity = _create_owned_store_file(store_path)
                store = _CanonicalEventStore(store_path)
            except (OSError, RuntimeError, sqlite3.Error):
                if store_identity is not None:
                    _unlink_owned_store_file(store_path, store_identity)
                record_scan_failure(
                    dataset_input=dataset_input,
                    dataset_id=dataset_id,
                    stage="canonical-scan",
                    scan_error_code="canonical-scan-failed",
                    blocked_code="canonical-scan-blocked",
                    scan_started=scan_started,
                )
                continue
            try:
                try:
                    batch = dataset_input.scan(store.add)
                except sqlite3.Error:
                    record_scan_failure(
                        dataset_input=dataset_input,
                        dataset_id=dataset_id,
                        stage="canonical-scan",
                        scan_error_code="canonical-scan-failed",
                        blocked_code="canonical-scan-blocked",
                        scan_started=scan_started,
                    )
                    continue
                except (EOFError, OSError, ValueError, csv.Error, zlib.error):
                    record_scan_failure(
                        dataset_input=dataset_input,
                        dataset_id=dataset_id,
                        stage="parser",
                        scan_error_code="parser-failed",
                        blocked_code="parser-scan-blocked",
                        scan_started=scan_started,
                    )
                    continue
                if type(batch) is not CanonicalRawEventBatch or batch.events != ():
                    raise TypeError(
                        "pilot scans must return metadata without retaining canonical events"
                    )
                if batch.dataset_id != dataset_id or batch.dataset_release != (
                    frozen_dataset_release(dataset_id)
                ):
                    raise PublicationStructurePilotError(
                        "pilot scan identity does not match the frozen dataset"
                    )
                try:
                    store.finalize()
                    total_event_count = store.count
                    canonical_store_bytes_after_index = _require_owned_store_file(
                        store_path,
                        store_identity,
                    ).st_size
                except (OSError, RuntimeError, sqlite3.Error):
                    record_scan_failure(
                        dataset_input=dataset_input,
                        dataset_id=dataset_id,
                        stage="canonical-scan",
                        scan_error_code="canonical-scan-failed",
                        blocked_code="canonical-scan-blocked",
                        scan_started=scan_started,
                    )
                    continue
                prefix_count = (
                    total_event_count
                    * config.mapping_prefix_numerator
                    // config.mapping_prefix_denominator
                )
                maximum_canonical_store_bytes_after_index = max(
                    maximum_canonical_store_bytes_after_index,
                    canonical_store_bytes_after_index,
                )
                rejected_event_count = sum(
                    sum(receipt.rejected_event_counts.values()) for receipt in batch.receipts
                )
                dataset_scans.append(
                    {
                        "dataset_id": dataset_id,
                        "dataset_release": batch.dataset_release,
                        "input_identity": input_identity,
                        "cardinality": {
                            "schema_valid_event_count": total_event_count,
                            "mapping_prefix_event_count": prefix_count,
                            "parser_rejected_event_count": rejected_event_count,
                        },
                        "health": {"completion_state": "complete", "runtime_healthy": True},
                        "resource": {
                            "verification_parser_index_wall_clock_ns": (
                                time.monotonic_ns() - scan_started
                            ),
                            "process_high_water_rss_bytes_at_scan_completion": (
                                _peak_resident_memory_bytes()
                            ),
                            "canonical_store_bytes_after_index": (
                                canonical_store_bytes_after_index
                            ),
                        },
                        "error": {"stage": None, "scan_error_code": None},
                    }
                )
                for semantics in _SEMANTICS:
                    for source_partition_id in _SOURCE_PARTITIONS:
                        cell = _cell_report(
                            batch,
                            event_store=store,
                            prefix_events=lambda store=store, prefix_count=prefix_count: (
                                store.ordered_events(limit=prefix_count)
                            ),
                            total_event_count=total_event_count,
                            semantics=semantics,
                            source_partition_id=source_partition_id,
                            config=config,
                        )
                        cells.append(cell)
                revalidate(dataset_input)
            finally:
                try:
                    store.close()
                finally:
                    _unlink_owned_store_file(store_path, store_identity)
        for dataset_input in opened_dataset_inputs:
            revalidate(dataset_input)
    completed_cell_count = sum(
        cell["health"]["completion_state"] == "complete"  # type: ignore[index]
        for cell in cells
    )
    completed_dataset_scan_count = sum(
        scan["health"]["completion_state"] == "complete"  # type: ignore[index]
        for scan in dataset_scans
    )
    return {
        "schema_version": PUBLICATION_STRUCTURE_PILOT_SCHEMA,
        "artifact_policy": _ARTIFACT_POLICY,
        "prefix_rule": {
            "basis": "chronological-schema-valid-events",
            "numerator": 1,
            "denominator": 10,
            "count_rule": "floor(schema-valid-event-count/10)",
            "structure_scope": "all-mapped-groups-induced-by-prefix-only",
        },
        "coverage": {
            "dataset_ids": list(_DATASET_IDS),
            "semantics": list(_SEMANTICS),
            "source_partitions": list(_SOURCE_PARTITIONS),
            "expected_dataset_scan_count": 3,
            "observed_dataset_scan_count": len(dataset_scans),
            "expected_cell_count": 30,
            "observed_cell_count": len(cells),
            "completed_cell_count": completed_cell_count,
        },
        "health": {
            "python_implementation": platform.python_implementation().lower(),
            "python_version": platform.python_version(),
            "platform_system": platform.system().lower(),
            "machine": platform.machine().lower(),
            "sqlite_library_version": sqlite3.sqlite_version,
            "sqlite_temp_store_policy": "FILE",
            "required_runtime_ok": True,
            "all_dataset_scans_completed": completed_dataset_scan_count == 3,
            "all_cells_completed": completed_cell_count == 30,
        },
        "resource": {
            "worker_concurrency": 1,
            "maximum_canonical_store_bytes_after_index": (
                maximum_canonical_store_bytes_after_index
            ),
            "total_prefix_transition_serialized_bytes": sum(
                int(cell["resource"]["prefix_transition_serialized_bytes"])  # type: ignore[index]
                for cell in cells
            ),
            "scratch_root_policy": scratch.policy,
            "scratch_root_identity_sha256": scratch.identity_sha256,
        },
        "dataset_scans": dataset_scans,
        "cells": cells,
    }


def _report_from_batches(
    batches: Mapping[str, CanonicalRawEventBatch],
    *,
    config: _TraceConfig,
) -> dict[str, object]:
    _validate_fixture_batches(batches)
    inputs: dict[str, Callable[[], _PilotDatasetInput]] = {}
    for dataset_id in _DATASET_IDS:
        batch = batches[dataset_id]
        fixture_binding: Mapping[str, object] = {
            "acquisition_transaction_sha256": hashlib.sha256(
                f"test-only-transaction:{dataset_id}".encode("ascii")
            ).hexdigest(),
            "source_set_sha256": hashlib.sha256(
                f"test-only-source-set:{dataset_id}".encode("ascii")
            ).hexdigest(),
            "repository_provenance": {
                "behavior_inventory": {
                    "behavior_set_sha256": hashlib.sha256(
                        f"test-only-acquisition-behavior:{dataset_id}".encode("ascii")
                    ).hexdigest()
                }
            },
        }

        def open_fixture_input(
            batch: CanonicalRawEventBatch = batch,
            fixture_binding: Mapping[str, object] = fixture_binding,
        ) -> _PilotDatasetInput:
            def scan(
                event_sink: Callable[[CanonicalRawEvent], None],
            ) -> CanonicalRawEventBatch:
                for event in batch.events:
                    event_sink(event)
                return CanonicalRawEventBatch(
                    dataset_id=batch.dataset_id,
                    dataset_release=batch.dataset_release,
                    events=(),
                    receipts=batch.receipts,
                )

            return _PilotDatasetInput(
                dataset_id=batch.dataset_id,
                scan=scan,
                verified_binding=fixture_binding,
                revalidate_binding=lambda: fixture_binding,
            )

        inputs[dataset_id] = open_fixture_input
    analysis_started_ns = time.monotonic_ns()
    with tempfile.TemporaryDirectory(
        prefix="dynamic-cssc-structure-pilot-pytest-scratch-root-"
    ) as temporary:
        scratch_root = Path(temporary)
        scratch_root.chmod(0o700)
        scratch = _test_only_scratch_root(scratch_root)
        with _claimed_scratch_workspace(scratch) as scratch_workspace:
            report = _report_from_inputs(
                inputs,
                config=config,
                scratch=scratch,
                scratch_workspace=scratch_workspace,
            )
    _record_preinstall_resource_checkpoint(report, analysis_started_ns=analysis_started_ns)
    return report


def _unlink_lock_if_owned(
    lock_path: Path,
    identity: tuple[int, int],
    *,
    strict: bool = False,
) -> None:
    """Remove only the same lock inode created by this invocation."""

    try:
        parent_fd, quarantine_name, lock_fd = _claim_owned_entry(
            lock_path,
            identity,
            directory=False,
            field="ownership lock",
        )
    except (OSError, PublicationStructurePilotError, _OwnedEntryChanged) as error:
        if strict:
            raise PublicationStructurePilotError(
                "scratch ownership lock cleanup refused after identity change"
            ) from error
        return
    try:
        try:
            os.unlink(quarantine_name, dir_fd=parent_fd)
        except OSError as error:
            if strict:
                raise PublicationStructurePilotError(
                    "scratch ownership lock cleanup did not remove the owned lock"
                ) from error
            return
        if strict and _entry_exists_at(parent_fd, lock_path.name):
            raise PublicationStructurePilotError("scratch ownership lock changed during cleanup")
    finally:
        os.close(lock_fd)
        os.close(parent_fd)


def _remove_staging_if_owned(
    staging: Path,
    staging_identity: tuple[int, int],
    file_identities: Mapping[str, tuple[int, int]],
) -> None:
    """Quarantine staging, then remove only its exact owned files and inode."""

    try:
        parent_fd, quarantine_name, staging_fd = _claim_owned_entry(
            staging,
            staging_identity,
            directory=True,
            field="report staging directory",
        )
    except (FileNotFoundError, _OwnedEntryChanged):
        return
    try:
        for name, identity in file_identities.items():
            try:
                file_quarantine, file_fd = _claim_owned_entry_at(
                    staging_fd,
                    name,
                    identity,
                    directory=False,
                    field=f"report staging file {name}",
                    path=staging / name,
                )
            except (FileNotFoundError, _OwnedEntryChanged):
                continue
            try:
                os.unlink(file_quarantine, dir_fd=staging_fd)
            finally:
                os.close(file_fd)
        if os.listdir(staging_fd):
            _restore_quarantined_entry(
                parent_fd,
                quarantine_name,
                staging.name,
                original_path=staging,
            )
            return
        try:
            os.rmdir(quarantine_name, dir_fd=parent_fd)
        except FileNotFoundError:
            return
    finally:
        os.close(staging_fd)
        os.close(parent_fd)


def _descriptor_content_identity(descriptor: int) -> tuple[int, str]:
    if not hasattr(os, "pread"):
        raise PublicationStructurePilotError(
            "report staging verification requires descriptor-relative reads"
        )
    digest = hashlib.sha256()
    byte_count = 0
    while True:
        chunk = os.pread(descriptor, 1024 * 1024, byte_count)
        if not chunk:
            return byte_count, digest.hexdigest()
        byte_count += len(chunk)
        digest.update(chunk)


def _verify_owned_staging_member_content(
    directory_fd: int,
    staging: _OwnedReportStaging,
) -> None:
    expected_names = {_REPORT_FILENAME, _CHECKSUMS_FILENAME}
    capability_names = [member.name for member in staging.members]
    if len(capability_names) != 2 or set(capability_names) != expected_names:
        raise _OwnedEntryChanged("report staging capability must bind the exact two members")
    if set(os.listdir(directory_fd)) != expected_names:
        raise _OwnedEntryChanged("report staging directory members changed")
    for member in staging.members:
        try:
            member_fd = os.open(
                member.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise _OwnedEntryChanged("report staging member changed") from error
        try:
            held_stat = os.fstat(member.descriptor)
            installed_stat = os.fstat(member_fd)
            held_identity = _descriptor_content_identity(member.descriptor)
            installed_identity = _descriptor_content_identity(member_fd)
        finally:
            os.close(member_fd)
        if (
            not stat.S_ISREG(held_stat.st_mode)
            or not stat.S_ISREG(installed_stat.st_mode)
            or (held_stat.st_dev, held_stat.st_ino) != member.identity
            or (installed_stat.st_dev, installed_stat.st_ino) != member.identity
        ):
            raise _OwnedEntryChanged("report staging member identity changed")
        if (
            member.mode != 0o644
            or stat.S_IMODE(held_stat.st_mode) != member.mode
            or stat.S_IMODE(installed_stat.st_mode) != member.mode
        ):
            raise _OwnedEntryChanged("report staging member mode changed")
        expected_identity = (member.byte_count, member.sha256)
        if held_identity != expected_identity or installed_identity != expected_identity:
            raise _OwnedEntryChanged("report staging member content changed")


def _quarantine_rejected_output(output_parent_fd: int, output_dir: Path) -> None:
    if not _entry_exists_at(output_parent_fd, output_dir.name):
        return
    rejected_name = f".{output_dir.name}.rejected-staging-{secrets.token_hex(16)}"
    _rename_entry_no_replace(
        output_parent_fd,
        output_dir.name,
        output_parent_fd,
        rejected_name,
        destination=output_dir.with_name(rejected_name),
    )
    if _entry_exists_at(output_parent_fd, output_dir.name):
        raise PublicationStructurePilotError(
            "report output name could not be cleared after staging drift"
        )


def _install_owned_staging(
    staging: _OwnedReportStaging,
    output_dir: Path,
) -> None:
    """Keep staging capabilities live through installation and verification."""

    try:
        parent_fd, quarantine_name, staging_fd = _claim_owned_entry(
            staging.path,
            staging.identity,
            directory=True,
            field="report staging directory",
        )
    except (FileNotFoundError, _OwnedEntryChanged) as error:
        raise PublicationStructurePilotHold(
            "HOLD: report staging ownership changed before installation"
        ) from error
    staging.path = staging.path.with_name(quarantine_name)
    output_parent_fd = _open_directory_descriptor(
        output_dir.parent,
        field="report output parent",
    )
    installed_fd: int | None = None
    try:
        try:
            _verify_owned_staging_member_content(staging_fd, staging)
        except (OSError, PublicationStructurePilotError, _OwnedEntryChanged) as error:
            raise PublicationStructurePilotHold(
                "HOLD: report staging members changed before installation"
            ) from error
        try:
            _rename_entry_no_replace(
                parent_fd,
                quarantine_name,
                output_parent_fd,
                output_dir.name,
                destination=output_dir,
            )
        except FileNotFoundError as error:
            raise PublicationStructurePilotHold(
                "HOLD: report staging ownership changed before installation"
            ) from error
        try:
            installed_fd = os.open(
                output_dir.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=output_parent_fd,
            )
            installed_stat = os.fstat(installed_fd)
        except OSError as error:
            _quarantine_rejected_output(output_parent_fd, output_dir)
            raise PublicationStructurePilotHold(
                "HOLD: installed report identity could not be verified"
            ) from error
        if (
            not stat.S_ISDIR(installed_stat.st_mode)
            or (installed_stat.st_dev, installed_stat.st_ino) != staging.identity
        ):
            _quarantine_rejected_output(output_parent_fd, output_dir)
            raise PublicationStructurePilotHold(
                "HOLD: report staging ownership changed before installation"
            )
        try:
            _verify_owned_staging_member_content(installed_fd, staging)
        except (OSError, PublicationStructurePilotError, _OwnedEntryChanged) as error:
            _quarantine_rejected_output(output_parent_fd, output_dir)
            raise PublicationStructurePilotHold(
                "HOLD: installed report members changed during installation"
            ) from error
    finally:
        if installed_fd is not None:
            os.close(installed_fd)
        os.close(output_parent_fd)
        os.close(staging_fd)
        os.close(parent_fd)


def _install_report(
    report: Mapping[str, object],
    output_dir: Path,
) -> PublicationStructurePilotBundle:
    def reject_forbidden(value: object) -> None:
        if type(value) is str:
            normalized = value.casefold()
            if any(term in normalized for term in _FORBIDDEN_OUTCOME_TERMS):
                raise PublicationStructurePilotError(
                    "structure pilot report contains a forbidden outcome field"
                )
            return
        if isinstance(value, Mapping):
            for key, item in value.items():
                reject_forbidden(key)
                reject_forbidden(item)
            return
        if isinstance(value, (list, tuple)):
            for item in value:
                reject_forbidden(item)

    reject_forbidden(report)
    if output_dir.exists() or output_dir.is_symlink():
        raise PublicationStructurePilotError("output_dir must be a new path")
    try:
        parent_mode = output_dir.parent.lstat().st_mode
    except FileNotFoundError as error:
        raise PublicationStructurePilotError("output_dir parent must already exist") from error
    if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
        raise PublicationStructurePilotError("output_dir parent must be a non-symlink directory")
    report_bytes = _canonical_json_bytes(dict(report))
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    checksums_bytes = f"{report_sha256}  {_REPORT_FILENAME}\n".encode("ascii")
    lock_path = output_dir.with_name(f".{output_dir.name}.structure-pilot.lock")
    try:
        lock_handle = lock_path.open("xb")
    except FileExistsError as error:
        raise PublicationStructurePilotError(
            "another structure pilot is already claiming output_dir"
        ) from error
    lock_stat = os.fstat(lock_handle.fileno())
    lock_identity = (lock_stat.st_dev, lock_stat.st_ino)
    try:
        lock_handle.write(f"pid={os.getpid()}\n".encode("ascii"))
        lock_handle.flush()
        os.fsync(lock_handle.fileno())
        staging = Path(
            tempfile.mkdtemp(prefix=f".{output_dir.name}.structure-pilot-", dir=output_dir.parent)
        )
        staging_stat = staging.lstat()
        staging_identity = (staging_stat.st_dev, staging_stat.st_ino)
        owned_staging = _OwnedReportStaging(
            path=staging,
            identity=staging_identity,
        )
        staging_file_identities: dict[str, tuple[int, int]] = {}
        staging_members: list[_OwnedReportMember] = []
        staging_member_descriptors: list[int] = []
        installed = False
        try:
            staging_fd = _open_directory_descriptor(
                staging,
                field="report staging directory",
            )
            try:
                staging_observed = os.fstat(staging_fd)
                if (staging_observed.st_dev, staging_observed.st_ino) != staging_identity:
                    raise PublicationStructurePilotHold(
                        "HOLD: report staging ownership changed before writing"
                    )
                for path, content in (
                    (staging / _REPORT_FILENAME, report_bytes),
                    (staging / _CHECKSUMS_FILENAME, checksums_bytes),
                ):
                    flags = (
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0)
                    )
                    descriptor = os.open(path.name, flags, 0o600, dir_fd=staging_fd)
                    staging_member_descriptors.append(descriptor)
                    with os.fdopen(os.dup(descriptor), "wb") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                        os.fchmod(handle.fileno(), 0o644)
                        written_stat = os.fstat(handle.fileno())
                        staging_file_identities[path.name] = (
                            written_stat.st_dev,
                            written_stat.st_ino,
                        )
                        staging_members.append(
                            _OwnedReportMember(
                                name=path.name,
                                descriptor=descriptor,
                                identity=(written_stat.st_dev, written_stat.st_ino),
                                mode=0o644,
                                byte_count=len(content),
                                sha256=hashlib.sha256(content).hexdigest(),
                            )
                        )
            finally:
                os.close(staging_fd)
            owned_staging.members = tuple(staging_members)
            if output_dir.exists() or output_dir.is_symlink():
                raise PublicationStructurePilotError("output_dir was claimed concurrently")
            try:
                _install_owned_staging(owned_staging, output_dir)
            except OSError as error:
                if error.errno in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise PublicationStructurePilotError(
                        "output_dir was claimed concurrently"
                    ) from error
                raise
            installed = True
        finally:
            for descriptor in staging_member_descriptors:
                os.close(descriptor)
            if not installed:
                _remove_staging_if_owned(
                    owned_staging.path,
                    staging_identity,
                    staging_file_identities,
                )
    finally:
        lock_handle.close()
        _unlink_lock_if_owned(lock_path, lock_identity)
    return PublicationStructurePilotBundle(
        output_dir=output_dir,
        report_path=output_dir / _REPORT_FILENAME,
        checksums_path=output_dir / _CHECKSUMS_FILENAME,
        report_sha256=report_sha256,
    )


def _test_only_produce_publication_structure_pilot(
    batches: Mapping[str, CanonicalRawEventBatch],
    output_dir: Path,
    *,
    config: _TraceConfig,
) -> PublicationStructurePilotBundle:
    """Run the fixed pilot over synthetic batches with permanent non-admissible scope."""

    marker = os.environ.get("PYTEST_CURRENT_TEST", "")
    if not marker.startswith("tests/test_publication_structure_pilot.py::"):
        raise RuntimeError("the private structure-pilot fixture seam is unavailable to production")
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    report = _report_from_batches(batches, config=config)
    return _install_report(report, output_dir)


def _verify_production_source(repository_root: Path) -> object:
    """Return the existing hardened TRACE source attestation."""

    return _verify_clean_repository_snapshot(repository_root)


def _production_acquisition_snapshot(repository_root: Path) -> object:
    """Capture the existing hardened acquisition verifier snapshot once per pilot."""

    return _current_acquisition_repository_snapshot(repository_root)


def _load_verified_production_input(
    dataset_id: str,
    bundle_dir: Path,
    repository_root: Path,
    acquisition_repository_snapshot: object,
) -> _PilotDatasetInput:
    """Open one verified bundle as a streaming pilot input."""

    def verify_once() -> object:
        verified = _verified_acquisition_input(
            PublicationTraceRequest(
                dataset_id=dataset_id,
                semantics="T1",
                source_partition=0,
                acquisition_bundle_dir=bundle_dir,
            ),
            repository_root=repository_root,
            acquisition_repository_snapshot=acquisition_repository_snapshot,
        )
        for source in verified.request.sources:
            _require_path_outside_repository(
                source.path,
                repository_root,
                field=f"raw source object {source.role}",
            )
            if type(source.license_terms_objects) is not tuple or any(
                type(terms) is not LicenseTermsObject for terms in source.license_terms_objects
            ):
                raise TypeError(
                    "verified source license_terms_objects must contain exact "
                    "LicenseTermsObject values"
                )
            for terms in source.license_terms_objects:
                _require_path_outside_repository(
                    terms.path,
                    repository_root,
                    field=f"license terms object {terms.source_url}",
                )
        if not isinstance(verified.binding, Mapping):
            raise TypeError("verified acquisition binding must be a mapping")
        return verified

    verified = verify_once()

    def scan(
        event_sink: Callable[[CanonicalRawEvent], None],
    ) -> CanonicalRawEventBatch:
        return _read_canonical_raw_events(
            dataset_id,
            verified.request.sources,  # type: ignore[attr-defined]
            config=_PRODUCTION_CONFIG,
            event_sink=event_sink,
        )

    return _PilotDatasetInput(
        dataset_id=dataset_id,
        scan=scan,
        verified_binding=verified.binding,  # type: ignore[attr-defined]
        revalidate_binding=lambda: verify_once().binding,  # type: ignore[attr-defined]
    )


def produce_publication_structure_pilot(
    acquisition_bundle_root: Path,
    output_dir: Path,
) -> PublicationStructurePilotBundle:
    """Produce the fixed coverage-complete structure pilot, or fail before writing."""

    if not isinstance(acquisition_bundle_root, Path) or not isinstance(output_dir, Path):
        raise TypeError("acquisition_bundle_root and output_dir must be pathlib.Path values")
    _require_disjoint_input_output(acquisition_bundle_root, output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise PublicationStructurePilotError("output_dir must be a new path")
    repository_root = Path(__file__).resolve().parents[2]
    resolved_repository = repository_root.resolve()
    for path, field in (
        (acquisition_bundle_root, "acquisition bundle root"),
        (output_dir, "pilot output directory"),
    ):
        resolved = path.resolve(strict=False)
        if resolved == resolved_repository or resolved_repository in resolved.parents:
            raise PublicationStructurePilotError(f"{field} must live outside the source checkout")
    try:
        root_mode = acquisition_bundle_root.lstat().st_mode
    except FileNotFoundError as error:
        raise PublicationStructurePilotHold(
            "HOLD: all three closed publication acquisition bundles are required"
        ) from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise PublicationStructurePilotHold(
            "HOLD: acquisition bundle root must be a non-symlink directory"
        )
    try:
        members = {member.name: member for member in acquisition_bundle_root.iterdir()}
    except OSError as error:
        raise PublicationStructurePilotHold(
            "HOLD: acquisition bundle root cannot be enumerated"
        ) from error
    if set(members) != set(_DATASET_IDS):
        raise PublicationStructurePilotHold(
            "HOLD: structure pilot requires the exact three dataset bundle directories"
        )
    for dataset_id in _DATASET_IDS:
        member_mode = members[dataset_id].lstat().st_mode
        if stat.S_ISLNK(member_mode) or not stat.S_ISDIR(member_mode):
            raise PublicationStructurePilotHold(
                "HOLD: structure pilot requires the exact three dataset bundle directories"
            )
    try:
        parent_mode = output_dir.parent.lstat().st_mode
    except FileNotFoundError as error:
        raise PublicationStructurePilotError("output_dir parent must already exist") from error
    if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
        raise PublicationStructurePilotError("output_dir parent must be a non-symlink directory")
    try:
        scratch = _production_scratch_root(
            repository_root=repository_root,
            acquisition_bundle_root=acquisition_bundle_root,
            output_dir=output_dir,
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise PublicationStructurePilotHold(
            "HOLD: scratch root prerequisites are unavailable"
        ) from error
    analysis_started_ns = time.monotonic_ns()
    try:
        with _claimed_scratch_workspace(scratch) as scratch_workspace:
            try:
                _require_sqlite_runtime()
            except PublicationStructurePilotError as error:
                raise PublicationStructurePilotHold(
                    "HOLD: SQLite runtime prerequisites are unavailable"
                ) from error
            source_snapshot_before = _verify_production_source(repository_root)
            acquisition_snapshot = _production_acquisition_snapshot(repository_root)
            inputs = {
                dataset_id: (
                    lambda dataset_id=dataset_id: _load_verified_production_input(
                        dataset_id,
                        members[dataset_id],
                        repository_root,
                        acquisition_snapshot,
                    )
                )
                for dataset_id in _DATASET_IDS
            }
            report = _report_from_inputs(
                inputs,
                config=_PRODUCTION_CONFIG,
                scratch=scratch,
                scratch_workspace=scratch_workspace,
            )
            source_snapshot_after = _verify_production_source(repository_root)
            if source_snapshot_after != source_snapshot_before:
                raise PublicationStructurePilotHold(
                    "HOLD: TRACE source attestation changed during structure pilot generation"
                )
        _record_preinstall_resource_checkpoint(report, analysis_started_ns=analysis_started_ns)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        if isinstance(error, PublicationStructurePilotHold):
            raise
        raise PublicationStructurePilotHold(
            "HOLD: verified publication structure pilot prerequisites are unavailable"
        ) from error
    return _install_report(report, output_dir)


__all__ = (
    "PublicationStructurePilotBundle",
    "PublicationStructurePilotError",
    "PublicationStructurePilotHold",
    "produce_publication_structure_pilot",
)
