"""Fail-closed Linux executable-mapping admission for one paused OpenFHE runner.

The launcher pauses the child at READY and DONE.  This module reads the paused
process through ``/proc``, proves that every file-backed executable mapping is
the pre-admitted runner/library inode, rejects any additional executable map,
and binds both raw snapshots without retaining their bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

OPENFHE_PROCESS_MAPPING_SNAPSHOT_SCHEMA = (
    "dynamic-cssc-openfhe-process-executable-mapping-snapshot-v1"
)
OPENFHE_RUNTIME_MAPPING_ADMISSION_SCHEMA = (
    "dynamic-cssc-openfhe-runtime-mapping-admission-v1"
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_BINARY_ID = re.compile(r"[0-9a-f]{8,128}\Z")
_PROC_MAP_LINE = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+) ([rwxps-]{4}) ([0-9a-f]+) "
    r"([0-9a-f]+):([0-9a-f]+) ([0-9]+)(?: +(.*))?$"
)
_PROC_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")
_ALLOWED_KERNEL_EXECUTABLE_MAPPINGS = frozenset({"[vdso]", "[vsyscall]"})
_PROC_FILE_BYTES_MAXIMUM = 4 * 1024 * 1024


class OpenFHERuntimeAdmissionError(RuntimeError):
    """A paused runner's executable mapping identity is not exactly admitted."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise OpenFHERuntimeAdmissionError(
            "runtime mapping receipt is not canonical JSON"
        ) from error


@dataclass(frozen=True, slots=True)
class AdmittedExecutableFile:
    """One exact runner or linked-library file admitted before child launch."""

    path: str
    device: int
    inode: int
    mode: int
    byte_count: int
    sha256: str
    binary_format: str
    binary_id: str

    def __post_init__(self) -> None:
        candidate = Path(self.path)
        if (
            type(self.path) is not str
            or not self.path
            or not candidate.is_absolute()
            or ".." in candidate.parts
            or str(candidate) != self.path
            or type(self.device) is not int
            or self.device < 0
            or type(self.inode) is not int
            or self.inode <= 0
            or type(self.mode) is not int
            or not 0 <= self.mode <= 0o7777
            or type(self.byte_count) is not int
            or self.byte_count <= 0
            or _LOWER_SHA256.fullmatch(self.sha256) is None
            or self.binary_format != "elf-v1"
            or _LOWER_BINARY_ID.fullmatch(self.binary_id) is None
        ):
            raise OpenFHERuntimeAdmissionError(
                "admitted executable-file identity is malformed"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "binary_format": self.binary_format,
            "binary_id": self.binary_id,
            "byte_count": self.byte_count,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "path": self.path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class OpenFHEProcessMappingSnapshot:
    """A normalized executable mapping set plus its exact raw ``/proc`` root."""

    stage: str
    pid: int
    process_start_time_ticks: int
    raw_maps_byte_count: int
    raw_maps_sha256: str
    proc_map_entry_count: int
    executable_map_entry_count: int
    admitted_executable_files: tuple[AdmittedExecutableFile, ...]
    kernel_executable_mappings: tuple[str, ...]
    admitted_executable_file_set_sha256: str
    executable_mapping_set_sha256: str

    def __post_init__(self) -> None:
        if (
            self.stage not in {"READY", "DONE"}
            or type(self.pid) is not int
            or self.pid <= 0
            or type(self.process_start_time_ticks) is not int
            or self.process_start_time_ticks <= 0
            or type(self.raw_maps_byte_count) is not int
            or self.raw_maps_byte_count <= 0
            or _LOWER_SHA256.fullmatch(self.raw_maps_sha256) is None
            or type(self.proc_map_entry_count) is not int
            or self.proc_map_entry_count <= 0
            or type(self.executable_map_entry_count) is not int
            or self.executable_map_entry_count < len(self.admitted_executable_files)
            or type(self.admitted_executable_files) is not tuple
            or not self.admitted_executable_files
            or tuple(sorted(self.admitted_executable_files, key=lambda item: item.path))
            != self.admitted_executable_files
            or len({item.path for item in self.admitted_executable_files})
            != len(self.admitted_executable_files)
            or type(self.kernel_executable_mappings) is not tuple
            or tuple(sorted(set(self.kernel_executable_mappings)))
            != self.kernel_executable_mappings
            or not set(self.kernel_executable_mappings).issubset(
                _ALLOWED_KERNEL_EXECUTABLE_MAPPINGS
            )
            or _LOWER_SHA256.fullmatch(self.admitted_executable_file_set_sha256)
            is None
            or _LOWER_SHA256.fullmatch(self.executable_mapping_set_sha256) is None
        ):
            raise OpenFHERuntimeAdmissionError(
                "OpenFHE executable-mapping snapshot is malformed"
            )

    def _without_snapshot_digest(self) -> dict[str, object]:
        return {
            "admitted_executable_file_set_sha256": (
                self.admitted_executable_file_set_sha256
            ),
            "executable_map_entry_count": self.executable_map_entry_count,
            "executable_mapping_set_sha256": self.executable_mapping_set_sha256,
            "executable_mappings": [
                item.to_document() for item in self.admitted_executable_files
            ],
            "kernel_executable_mappings": list(self.kernel_executable_mappings),
            "pid": self.pid,
            "proc_map_entry_count": self.proc_map_entry_count,
            "process_start_time_ticks": self.process_start_time_ticks,
            "raw_maps_byte_count": self.raw_maps_byte_count,
            "raw_maps_sha256": self.raw_maps_sha256,
            "schema_version": OPENFHE_PROCESS_MAPPING_SNAPSHOT_SCHEMA,
            "stage": self.stage,
        }

    @property
    def snapshot_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self._without_snapshot_digest())).hexdigest()

    def to_document(self) -> dict[str, object]:
        return {
            **self._without_snapshot_digest(),
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True, slots=True)
class OpenFHERuntimeMappingAdmission:
    """READY/DONE mapping continuity derived from two paused-process snapshots."""

    ready: OpenFHEProcessMappingSnapshot
    done: OpenFHEProcessMappingSnapshot
    admitted_executable_file_set_sha256: str
    executable_mapping_set_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.ready) is not OpenFHEProcessMappingSnapshot
            or type(self.done) is not OpenFHEProcessMappingSnapshot
            or self.ready.stage != "READY"
            or self.done.stage != "DONE"
            or self.ready.pid != self.done.pid
            or self.ready.process_start_time_ticks != self.done.process_start_time_ticks
            or self.ready.admitted_executable_files != self.done.admitted_executable_files
            or self.ready.kernel_executable_mappings
            != self.done.kernel_executable_mappings
            or self.ready.admitted_executable_file_set_sha256
            != self.done.admitted_executable_file_set_sha256
            or self.ready.executable_mapping_set_sha256
            != self.done.executable_mapping_set_sha256
            or self.admitted_executable_file_set_sha256
            != self.ready.admitted_executable_file_set_sha256
            or self.executable_mapping_set_sha256
            != self.ready.executable_mapping_set_sha256
        ):
            raise OpenFHERuntimeAdmissionError(
                "READY/DONE OpenFHE executable mappings are not continuous"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "admitted_executable_file_set_sha256": (
                self.admitted_executable_file_set_sha256
            ),
            "done": self.done.to_document(),
            "executable_mapping_set_sha256": self.executable_mapping_set_sha256,
            "formal_authority_granted": False,
            "publication_authority": False,
            "ready": self.ready.to_document(),
            "runtime_state_continuity_verified": True,
            "schema_version": OPENFHE_RUNTIME_MAPPING_ADMISSION_SCHEMA,
            "status": "verified-linux-ready-done-pre-admission-only",
        }


def _read_proc_file(path: Path, *, field: str) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OpenFHERuntimeAdmissionError(f"{field} cannot be opened directly") from error
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise OpenFHERuntimeAdmissionError(f"{field} is not a proc regular file")
        content = bytearray()
        while len(content) <= _PROC_FILE_BYTES_MAXIMUM:
            chunk = os.read(descriptor, min(64 * 1024, _PROC_FILE_BYTES_MAXIMUM + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if not content or len(content) > _PROC_FILE_BYTES_MAXIMUM:
            raise OpenFHERuntimeAdmissionError(f"{field} is outside its byte bounds")
        return bytes(content)
    finally:
        os.close(descriptor)


def _process_start_time_ticks(content: bytes, *, pid: int) -> int:
    try:
        text = content.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise OpenFHERuntimeAdmissionError("process stat is not ASCII") from error
    closing = text.rfind(")")
    if closing <= 0 or not text.startswith(f"{pid} ("):
        raise OpenFHERuntimeAdmissionError("process stat identity is malformed")
    fields = text[closing + 1 :].strip().split()
    if len(fields) < 20:
        raise OpenFHERuntimeAdmissionError("process stat lacks its start-time field")
    try:
        value = int(fields[19], 10)
    except ValueError as error:
        raise OpenFHERuntimeAdmissionError("process start time is not an integer") from error
    if value <= 0:
        raise OpenFHERuntimeAdmissionError("process start time must be positive")
    return value


def _decode_proc_path(value: str) -> str:
    return _PROC_OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _admitted_file_set_sha256(files: tuple[AdmittedExecutableFile, ...]) -> str:
    return hashlib.sha256(
        _canonical_bytes(
            {
                "executable_files": [item.to_document() for item in files],
                "schema_version": "dynamic-cssc-openfhe-admitted-executable-file-set-v1",
            }
        )
    ).hexdigest()


def _verify_live_executable_file(item: AdmittedExecutableFile) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(item.path, flags)
    except OSError as error:
        raise OpenFHERuntimeAdmissionError(
            "mapped executable file cannot be opened directly"
        ) from error
    try:
        before = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            stat.S_IMODE(before.st_mode),
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink <= 0
            or before_identity[:4]
            != (item.device, item.inode, item.mode, item.byte_count)
        ):
            raise OpenFHERuntimeAdmissionError(
                "mapped executable file metadata differs from pre-launch identity"
            )
        digest = hashlib.sha256()
        observed_bytes = 0
        while observed_bytes <= item.byte_count:
            chunk = os.read(descriptor, min(1024 * 1024, item.byte_count + 1 - observed_bytes))
            if not chunk:
                break
            digest.update(chunk)
            observed_bytes += len(chunk)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            stat.S_IMODE(after.st_mode),
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            after_identity != before_identity
            or observed_bytes != item.byte_count
            or digest.hexdigest() != item.sha256
        ):
            raise OpenFHERuntimeAdmissionError(
                "mapped executable file bytes changed from pre-launch identity"
            )
    finally:
        os.close(descriptor)


def capture_linux_process_mapping_snapshot(
    *,
    pid: int,
    stage: str,
    admitted_executable_files: tuple[AdmittedExecutableFile, ...],
    proc_root: Path = Path("/proc"),
) -> OpenFHEProcessMappingSnapshot:
    """Capture one paused Linux process and require its exact executable closure."""

    if (
        type(pid) is not int
        or pid <= 0
        or stage not in {"READY", "DONE"}
        or type(admitted_executable_files) is not tuple
        or not admitted_executable_files
        or not isinstance(proc_root, Path)
        or not proc_root.is_absolute()
    ):
        raise OpenFHERuntimeAdmissionError("mapping snapshot invocation is malformed")
    expected = tuple(sorted(admitted_executable_files, key=lambda item: item.path))
    if expected != admitted_executable_files or len({item.path for item in expected}) != len(
        expected
    ):
        raise OpenFHERuntimeAdmissionError(
            "admitted executable files are not one unique canonical tuple"
        )
    process_root = proc_root / str(pid)
    start_before = _process_start_time_ticks(
        _read_proc_file(process_root / "stat", field="process stat before maps"),
        pid=pid,
    )
    maps = _read_proc_file(process_root / "maps", field=f"process {stage} maps")
    start_after = _process_start_time_ticks(
        _read_proc_file(process_root / "stat", field="process stat after maps"),
        pid=pid,
    )
    if start_before != start_after:
        raise OpenFHERuntimeAdmissionError("process identity changed while reading maps")
    try:
        lines = maps.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise OpenFHERuntimeAdmissionError("process maps are not UTF-8") from error
    if not lines:
        raise OpenFHERuntimeAdmissionError("process maps are empty")

    expected_by_path = {item.path: item for item in expected}
    mapped: dict[str, tuple[int, int]] = {}
    kernel: set[str] = set()
    executable_entries = 0
    for line in lines:
        match = _PROC_MAP_LINE.fullmatch(line)
        if match is None:
            raise OpenFHERuntimeAdmissionError("process maps contain a malformed row")
        permissions = match.group(3)
        if "x" not in permissions:
            continue
        executable_entries += 1
        raw_path = match.group(8)
        if raw_path is None:
            raise OpenFHERuntimeAdmissionError("process has an anonymous executable mapping")
        mapped_path = _decode_proc_path(raw_path)
        if mapped_path.startswith("["):
            if mapped_path not in _ALLOWED_KERNEL_EXECUTABLE_MAPPINGS:
                raise OpenFHERuntimeAdmissionError(
                    "process has an unapproved kernel executable mapping"
                )
            kernel.add(mapped_path)
            continue
        if not mapped_path.startswith("/") or mapped_path.endswith(" (deleted)"):
            raise OpenFHERuntimeAdmissionError(
                "process has a non-absolute or deleted executable mapping"
            )
        try:
            device = os.makedev(int(match.group(5), 16), int(match.group(6), 16))
            inode = int(match.group(7), 10)
        except (OverflowError, ValueError) as error:
            raise OpenFHERuntimeAdmissionError(
                "process executable mapping identity is malformed"
            ) from error
        previous = mapped.setdefault(mapped_path, (device, inode))
        if previous != (device, inode):
            raise OpenFHERuntimeAdmissionError(
                "one executable path maps multiple physical files"
            )

    if set(mapped) != set(expected_by_path):
        raise OpenFHERuntimeAdmissionError(
            "process executable file set differs from the admitted closure"
        )
    for path, (device, inode) in mapped.items():
        admitted = expected_by_path[path]
        if (device, inode) != (admitted.device, admitted.inode):
            raise OpenFHERuntimeAdmissionError(
                "mapped executable file differs from its pre-launch inode"
            )
        _verify_live_executable_file(admitted)

    admitted_set_sha256 = _admitted_file_set_sha256(expected)
    mapping_set_sha256 = hashlib.sha256(
        _canonical_bytes(
            {
                "admitted_executable_file_set_sha256": admitted_set_sha256,
                "executable_files": [item.to_document() for item in expected],
                "kernel_executable_mappings": sorted(kernel),
                "schema_version": "dynamic-cssc-openfhe-executable-mapping-set-v1",
            }
        )
    ).hexdigest()
    return OpenFHEProcessMappingSnapshot(
        stage=stage,
        pid=pid,
        process_start_time_ticks=start_before,
        raw_maps_byte_count=len(maps),
        raw_maps_sha256=hashlib.sha256(maps).hexdigest(),
        proc_map_entry_count=len(lines),
        executable_map_entry_count=executable_entries,
        admitted_executable_files=expected,
        kernel_executable_mappings=tuple(sorted(kernel)),
        admitted_executable_file_set_sha256=admitted_set_sha256,
        executable_mapping_set_sha256=mapping_set_sha256,
    )


def admit_linux_runtime_mapping_continuity(
    ready: OpenFHEProcessMappingSnapshot,
    done: OpenFHEProcessMappingSnapshot,
) -> OpenFHERuntimeMappingAdmission:
    """Derive the exact READY/DONE continuity receipt; no caller boolean exists."""

    if (
        type(ready) is not OpenFHEProcessMappingSnapshot
        or type(done) is not OpenFHEProcessMappingSnapshot
    ):
        raise TypeError("mapping continuity requires exact typed snapshots")
    return OpenFHERuntimeMappingAdmission(
        ready=ready,
        done=done,
        admitted_executable_file_set_sha256=(
            ready.admitted_executable_file_set_sha256
        ),
        executable_mapping_set_sha256=ready.executable_mapping_set_sha256,
    )


__all__ = (
    "OPENFHE_PROCESS_MAPPING_SNAPSHOT_SCHEMA",
    "OPENFHE_RUNTIME_MAPPING_ADMISSION_SCHEMA",
    "AdmittedExecutableFile",
    "OpenFHEProcessMappingSnapshot",
    "OpenFHERuntimeAdmissionError",
    "OpenFHERuntimeMappingAdmission",
    "admit_linux_runtime_mapping_continuity",
    "capture_linux_process_mapping_snapshot",
)
