"""Controller-owned launcher for one authorized generic OpenFHE query.

This module closes the boundary between the canonical ordinary-query lifecycle
and the generic C++ OpenFHE runner.  It owns an exclusive scratch tree, consumes
the prepared F1-M batch immediately before launch, observes the child process,
verifies every result/object byte, and removes all private runtime material.

The receipt is deliberately pre-admission evidence.  Resource-policy and
publication authority remain outside this module and are always false here.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from dynamic_cssc.mask_ledger import PreparedF1MCommitmentLedger
from dynamic_cssc.openfhe_query_runner import (
    OpenFHEKeyGenerationPlan,
    OpenFHESerializedObjectReceipt,
    VerifiedOpenFHEQueryResult,
    build_ordinary_openfhe_query_request,
    verify_ordinary_openfhe_query_result,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionAuthorizationReceipt,
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    authorize_ordinary_execution,
    claim_ordinary_execution,
)
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
)

OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA = "dynamic-cssc-full-openfhe-runtime-receipt-v3"
OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA = "dynamic-cssc-openfhe-runner-build-identity-v2"
OPENFHE_SERIALIZED_PAYLOAD_SCHEMA = "dynamic-cssc-openfhe-serialized-payload-v2"

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_PATHS = (
    "config/params_manifest.json",
    "cpp/CMakeLists.txt",
    "cpp/openfhe_query_runner.cpp",
    "scripts/bootstrap_openfhe.sh",
    "scripts/build_cpp.sh",
)
_CMAKE_CACHE_KEYS = (
    "CMAKE_BUILD_TYPE",
    "CMAKE_CXX_COMPILER",
    "CMAKE_CXX_FLAGS",
    "CMAKE_CXX_FLAGS_RELEASE",
)
_FIXED_TARGET_FLAGS = ("-std=c++17", "-Wall", "-Wextra", "-Wpedantic")
_LOG_BYTES_MAXIMUM = 1024 * 1024
_LINKED_LIBRARY_BYTES_MAXIMUM = 512 * 1024 * 1024
_OBSERVATION_INTERVAL_SECONDS = 0.01


class OpenFHEQueryRuntimeError(RuntimeError):
    """The runner identity, process observation, or private cleanup failed closed."""


@dataclass(frozen=True, slots=True)
class OpenFHELinkedLibraryIdentity:
    load_name: str
    resolved_path: str
    byte_count: int
    sha256: str

    def to_document(self) -> dict[str, object]:
        return {
            "byte_count": self.byte_count,
            "load_name": self.load_name,
            "resolved_path": self.resolved_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class OpenFHERunnerBuildIdentity:
    runner_relative_path: str
    runner_sha256: str
    runner_byte_count: int
    source_sha256: tuple[tuple[str, str], ...]
    compiler_path: str
    compiler_identity_sha256: str
    compiler_flags: tuple[str, ...]
    linkage_inspection_format: str
    linked_libraries: tuple[OpenFHELinkedLibraryIdentity, ...]
    linked_system_library_load_names: tuple[str, ...]
    build_identity_sha256: str

    def to_document(self) -> dict[str, object]:
        return {
            "build_identity_sha256": self.build_identity_sha256,
            "compiler_flags": list(self.compiler_flags),
            "compiler_identity_sha256": self.compiler_identity_sha256,
            "compiler_path": self.compiler_path,
            "linkage_inspection_format": self.linkage_inspection_format,
            "linked_libraries": [item.to_document() for item in self.linked_libraries],
            "linked_system_library_load_names": list(
                self.linked_system_library_load_names
            ),
            "runner_byte_count": self.runner_byte_count,
            "runner_relative_path": self.runner_relative_path,
            "runner_sha256": self.runner_sha256,
            "schema_version": OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA,
            "source_sha256": dict(self.source_sha256),
        }


@dataclass(frozen=True, slots=True)
class OpenFHESerializedPayload:
    category: str
    subject_id: str
    binary_framing_schema: str | None
    sha256: str
    payload: bytes

    def __post_init__(self) -> None:
        if (
            type(self.category) is not str
            or not self.category
            or type(self.subject_id) is not str
            or not self.subject_id
            or (
                self.binary_framing_schema
                != (
                    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA
                    if self.category == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
                    else None
                )
            )
            or _LOWER_SHA256.fullmatch(self.sha256) is None
            or type(self.payload) is not bytes
            or not self.payload
            or hashlib.sha256(self.payload).hexdigest() != self.sha256
        ):
            raise OpenFHEQueryRuntimeError("serialized OpenFHE payload binding is invalid")

    def receipt_document(self) -> dict[str, object]:
        return {
            "binary_framing_schema": self.binary_framing_schema,
            "byte_count": len(self.payload),
            "category": self.category,
            "schema_version": OPENFHE_SERIALIZED_PAYLOAD_SCHEMA,
            "sha256": self.sha256,
            "subject_id": self.subject_id,
        }


@dataclass(frozen=True, slots=True)
class OpenFHEQueryRuntimeReceipt:
    runner: OpenFHERunnerBuildIdentity
    authorization: OrdinaryExecutionAuthorizationReceipt
    request_sha256: str
    request_byte_count: int
    result_sha256: str
    result_byte_count: int
    elapsed_ns: int
    timeout_seconds: int
    peak_resident_memory_bytes: int
    resident_memory_limit_bytes: int
    peak_scratch_bytes: int
    scratch_limit_bytes: int
    stdout_sha256: str
    stdout_byte_count: int
    stderr_sha256: str
    stderr_byte_count: int
    serialized_object_count: int
    serialized_object_bytes: int
    host_identity_sha256: str
    operating_system_identity: str
    cpu_affinity: tuple[int, ...] | None

    def to_document(self) -> dict[str, object]:
        return {
            "authorization": self.authorization.to_document(),
            "cpu_affinity": None if self.cpu_affinity is None else list(self.cpu_affinity),
            "elapsed_ns": self.elapsed_ns,
            "formal_authority_granted": False,
            "host_identity_sha256": self.host_identity_sha256,
            "operating_system_identity": self.operating_system_identity,
            "peak_resident_memory_bytes": self.peak_resident_memory_bytes,
            "peak_scratch_bytes": self.peak_scratch_bytes,
            "publication_authority": False,
            "request_byte_count": self.request_byte_count,
            "request_sha256": self.request_sha256,
            "resident_memory_limit_bytes": self.resident_memory_limit_bytes,
            "result_byte_count": self.result_byte_count,
            "result_sha256": self.result_sha256,
            "runner": self.runner.to_document(),
            "schema_version": OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA,
            "scratch_limit_bytes": self.scratch_limit_bytes,
            "serialized_object_bytes": self.serialized_object_bytes,
            "serialized_object_count": self.serialized_object_count,
            "status": "verified-pre-admission-only",
            "stderr_byte_count": self.stderr_byte_count,
            "stderr_sha256": self.stderr_sha256,
            "stdout_byte_count": self.stdout_byte_count,
            "stdout_sha256": self.stdout_sha256,
            "timeout_seconds": self.timeout_seconds,
        }

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.to_document())).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutedOpenFHEQuery:
    verified_result: VerifiedOpenFHEQueryResult
    runtime_receipt: OpenFHEQueryRuntimeReceipt
    serialized_payloads: tuple[OpenFHESerializedPayload, ...]


@dataclass(frozen=True, slots=True)
class _ProcessObservation:
    elapsed_ns: int
    peak_resident_memory_bytes: int
    peak_scratch_bytes: int
    stdout: bytes
    stderr: bytes


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
        raise OpenFHEQueryRuntimeError("runtime receipt is not canonical JSON") from error


def _absolute_path(value: object, *, field: str) -> Path:
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or ".." in value.parts
        or Path(os.path.normpath(value)) != value
    ):
        raise OpenFHEQueryRuntimeError(f"{field} must be one normalized absolute Path")
    return value


def _reject_symlink_components(path: Path, *, missing_leaf_allowed: bool) -> None:
    current = Path(path.anchor)
    for index, component in enumerate(path.parts[1:], start=1):
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if missing_leaf_allowed and index == len(path.parts) - 1:
                return
            raise OpenFHEQueryRuntimeError(f"runtime path component is absent: {current}") from None
        except OSError as error:
            raise OpenFHEQueryRuntimeError(
                f"runtime path component cannot be inspected: {current}"
            ) from error
        if stat.S_ISLNK(mode):
            raise OpenFHEQueryRuntimeError(f"runtime symlink component is forbidden: {current}")


def _read_direct_file(
    path: Path,
    *,
    field: str,
    maximum: int = 256 * 1024 * 1024,
    allow_empty: bool = False,
) -> bytes:
    _reject_symlink_components(path, missing_leaf_allowed=False)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OpenFHEQueryRuntimeError(f"{field} cannot be opened directly") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_size == 0 and not allow_empty)
            or before.st_size > maximum
        ):
            raise OpenFHEQueryRuntimeError(f"{field} is outside its regular-file bounds")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not chunk:
                raise OpenFHEQueryRuntimeError(f"{field} ended before its observed size")
            content.extend(chunk)
        if os.read(descriptor, 1):
            raise OpenFHEQueryRuntimeError(f"{field} grew while reading")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise OpenFHEQueryRuntimeError(f"{field} changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _parse_cmake_cache(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError("CMake cache is not UTF-8") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line or ":" not in line:
            continue
        name_and_type, value = line.split("=", 1)
        name, _cache_type = name_and_type.split(":", 1)
        if name in _CMAKE_CACHE_KEYS:
            values[name] = value
    if set(values) != set(_CMAKE_CACHE_KEYS) or values["CMAKE_BUILD_TYPE"] != "Release":
        raise OpenFHEQueryRuntimeError("runner CMake cache lacks the exact Release identity")
    return values


def _compiler_identity(compiler: Path) -> tuple[str, bytes]:
    compiler = _absolute_path(compiler, field="CMake C++ compiler")
    try:
        compiler = compiler.resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError("C++ compiler path cannot be resolved") from error
    _reject_symlink_components(compiler, missing_leaf_allowed=False)
    try:
        completed = subprocess.run(
            (str(compiler), "--version"),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpenFHEQueryRuntimeError("C++ compiler identity probe failed") from error
    identity = completed.stdout + completed.stderr
    if completed.returncode != 0 or not identity or len(identity) > _LOG_BYTES_MAXIMUM:
        raise OpenFHEQueryRuntimeError("C++ compiler identity probe is not exact")
    return str(compiler), identity


def _linkage_tool_output(arguments: tuple[str, ...], *, field: str) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpenFHEQueryRuntimeError(f"{field} probe failed") from error
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or not output or len(output) > _LOG_BYTES_MAXIMUM:
        raise OpenFHEQueryRuntimeError(f"{field} probe is not exact")
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError(f"{field} probe is not UTF-8") from error


def _resolved_linked_path(value: str, *, field: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise OpenFHEQueryRuntimeError(f"{field} is not an absolute resolved path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError(f"{field} cannot be resolved") from error
    _reject_symlink_components(resolved, missing_leaf_allowed=False)
    if not resolved.is_file():
        raise OpenFHEQueryRuntimeError(f"{field} is not a regular file")
    return resolved


def _linux_linked_library_paths(
    runner: Path,
) -> tuple[str, tuple[tuple[str, Path], ...], tuple[str, ...]]:
    executable = shutil.which("ldd", path="/usr/bin:/bin")
    if executable is None:
        raise OpenFHEQueryRuntimeError("ldd is unavailable")
    output = _linkage_tool_output((executable, str(runner)), field="runner ldd identity")
    entries: list[tuple[str, Path]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "not found" in line:
            raise OpenFHEQueryRuntimeError("runner has an unresolved linked library")
        without_address = re.sub(r"\s+\([^)]*\)\s*$", "", line)
        if "=>" in without_address:
            load_name, target = (item.strip() for item in without_address.split("=>", 1))
            if not load_name or not target:
                raise OpenFHEQueryRuntimeError("runner ldd identity is malformed")
        elif without_address.startswith("/"):
            target = without_address
            load_name = Path(target).name
        elif without_address.startswith("linux-vdso"):
            continue
        else:
            raise OpenFHEQueryRuntimeError("runner ldd identity contains an unknown row")
        entries.append(
            (
                load_name,
                _resolved_linked_path(target, field=f"linked library {load_name}"),
            )
        )
    result = tuple(sorted(set(entries), key=lambda item: (item[0], str(item[1]))))
    if not result:
        raise OpenFHEQueryRuntimeError("runner linked-library inventory is empty")
    return "linux-ldd-direct-and-transitive-v1", result, ()


def _darwin_rpaths(otool: str, runner: Path) -> tuple[Path, ...]:
    output = _linkage_tool_output(
        (otool, "-l", str(runner)),
        field="runner LC_RPATH identity",
    )
    raw_paths: list[str] = []
    awaiting_path = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line == "cmd LC_RPATH":
            awaiting_path = True
            continue
        if awaiting_path and line.startswith("path "):
            raw_paths.append(line[5:].split(" (offset ", 1)[0])
            awaiting_path = False
    resolved: list[Path] = []
    for value in raw_paths:
        expanded = value.replace("@loader_path", str(runner.parent)).replace(
            "@executable_path", str(runner.parent)
        )
        candidate = Path(expanded)
        if not candidate.is_absolute():
            raise OpenFHEQueryRuntimeError("runner LC_RPATH is not absolute after expansion")
        try:
            directory = candidate.resolve(strict=True)
        except OSError as error:
            raise OpenFHEQueryRuntimeError("runner LC_RPATH cannot be resolved") from error
        if not directory.is_dir():
            raise OpenFHEQueryRuntimeError("runner LC_RPATH is not a directory")
        resolved.append(directory)
    return tuple(sorted(set(resolved), key=str))


def _darwin_linked_library_paths(
    runner: Path,
) -> tuple[str, tuple[tuple[str, Path], ...], tuple[str, ...]]:
    executable = shutil.which("otool", path="/usr/bin:/bin")
    if executable is None:
        raise OpenFHEQueryRuntimeError("otool is unavailable")
    output = _linkage_tool_output(
        (executable, "-L", str(runner)),
        field="runner otool identity",
    )
    rpaths = _darwin_rpaths(executable, runner)
    entries: list[tuple[str, Path]] = []
    system_load_names: list[str] = []
    lines = tuple(line.strip() for line in output.splitlines() if line.strip())
    if not lines or not lines[0].endswith(":"):
        raise OpenFHEQueryRuntimeError("runner otool identity is malformed")
    for line in lines[1:]:
        load_name = line.split(" (compatibility version ", 1)[0].strip()
        candidates: tuple[Path, ...]
        if load_name.startswith("@rpath/"):
            suffix = load_name.removeprefix("@rpath/")
            candidates = tuple(directory / suffix for directory in rpaths)
        elif load_name.startswith("@loader_path/"):
            candidates = (runner.parent / load_name.removeprefix("@loader_path/"),)
        elif load_name.startswith("@executable_path/"):
            candidates = (runner.parent / load_name.removeprefix("@executable_path/"),)
        else:
            candidates = (Path(load_name),)
        existing = tuple(candidate for candidate in candidates if candidate.exists())
        if not existing:
            if load_name.startswith(("/usr/lib/", "/System/Library/")):
                system_load_names.append(load_name)
                continue
            raise OpenFHEQueryRuntimeError(
                f"linked library {load_name} cannot be resolved through LC_RPATH"
            )
        if len(existing) != 1:
            raise OpenFHEQueryRuntimeError(
                f"linked library {load_name} resolves to multiple physical files"
            )
        entries.append(
            (
                load_name,
                _resolved_linked_path(str(existing[0]), field=f"linked library {load_name}"),
            )
        )
    result = tuple(sorted(set(entries), key=lambda item: (item[0], str(item[1]))))
    if not result:
        raise OpenFHEQueryRuntimeError("runner file-backed linked-library inventory is empty")
    return (
        "darwin-otool-direct-v1",
        result,
        tuple(sorted(set(system_load_names))),
    )


def _inspect_linked_library_paths(
    runner: Path,
) -> tuple[str, tuple[tuple[str, Path], ...], tuple[str, ...]]:
    system = platform.system()
    if system == "Linux":
        return _linux_linked_library_paths(runner)
    if system == "Darwin":
        return _darwin_linked_library_paths(runner)
    raise OpenFHEQueryRuntimeError("runner linked-library inspection OS is unsupported")


def _linked_library_identity(
    runner: Path,
) -> tuple[str, tuple[OpenFHELinkedLibraryIdentity, ...], tuple[str, ...]]:
    inspection_format, paths, system_load_names = _inspect_linked_library_paths(runner)
    identities: list[OpenFHELinkedLibraryIdentity] = []
    for load_name, path in paths:
        content = _read_direct_file(
            path,
            field=f"linked library {load_name}",
            maximum=_LINKED_LIBRARY_BYTES_MAXIMUM,
        )
        identities.append(
            OpenFHELinkedLibraryIdentity(
                load_name=load_name,
                resolved_path=str(path),
                byte_count=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    linked_libraries = tuple(identities)
    if not any(
        "openfhe" in f"{item.load_name} {item.resolved_path}".lower()
        for item in linked_libraries
    ):
        raise OpenFHEQueryRuntimeError("runner is not linked to a file-backed OpenFHE library")
    return inspection_format, linked_libraries, system_load_names


def capture_openfhe_runner_build_identity(
    repository_root: Path,
    runner_relative_path: str,
) -> OpenFHERunnerBuildIdentity:
    """Bind the direct runner bytes to its exact repository/build inputs."""

    root = _absolute_path(repository_root, field="repository_root")
    _reject_symlink_components(root, missing_leaf_allowed=False)
    relative = PurePosixPath(runner_relative_path)
    if (
        type(runner_relative_path) is not str
        or not runner_relative_path
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != runner_relative_path
    ):
        raise OpenFHEQueryRuntimeError("runner_relative_path must be one normalized relative path")
    runner = root.joinpath(*relative.parts)
    runner_content = _read_direct_file(runner, field="OpenFHE runner")
    mode = runner.lstat().st_mode
    if mode & 0o111 == 0:
        raise OpenFHEQueryRuntimeError("OpenFHE runner is not executable")
    source_entries = tuple(
        (
            source,
            hashlib.sha256(
                _read_direct_file(root / source, field=f"runner source {source}")
            ).hexdigest(),
        )
        for source in _SOURCE_PATHS
    )
    cache = _parse_cmake_cache(
        _read_direct_file(runner.parent / "CMakeCache.txt", field="runner CMake cache")
    )
    compiler_path, compiler_version = _compiler_identity(Path(cache["CMAKE_CXX_COMPILER"]))
    compiler_flags = tuple(
        [
            *shlex.split(cache["CMAKE_CXX_FLAGS"]),
            *shlex.split(cache["CMAKE_CXX_FLAGS_RELEASE"]),
            *_FIXED_TARGET_FLAGS,
        ]
    )
    linkage_format, linked_libraries, linked_system_libraries = _linked_library_identity(runner)
    build_binding = {
        "cmake_cache": cache,
        "compiler_flags": list(compiler_flags),
        "compiler_identity_sha256": hashlib.sha256(compiler_version).hexdigest(),
        "linkage_inspection_format": linkage_format,
        "linked_libraries": [item.to_document() for item in linked_libraries],
        "linked_system_library_load_names": list(linked_system_libraries),
        "runner_byte_count": len(runner_content),
        "runner_relative_path": runner_relative_path,
        "runner_sha256": hashlib.sha256(runner_content).hexdigest(),
        "schema_version": OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA,
        "source_sha256": dict(source_entries),
    }
    return OpenFHERunnerBuildIdentity(
        runner_relative_path=runner_relative_path,
        runner_sha256=str(build_binding["runner_sha256"]),
        runner_byte_count=len(runner_content),
        source_sha256=source_entries,
        compiler_path=compiler_path,
        compiler_identity_sha256=str(build_binding["compiler_identity_sha256"]),
        compiler_flags=compiler_flags,
        linkage_inspection_format=linkage_format,
        linked_libraries=linked_libraries,
        linked_system_library_load_names=linked_system_libraries,
        build_identity_sha256=hashlib.sha256(_canonical_bytes(build_binding)).hexdigest(),
    )


def _write_new_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - operating-system contract
                raise OpenFHEQueryRuntimeError("private request write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scratch_bytes(root: Path) -> int:
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError as error:
            raise OpenFHEQueryRuntimeError("controlled scratch cannot be enumerated") from error
        for entry in entries:
            status = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(status.st_mode):
                pending.append(Path(entry.path))
            elif stat.S_ISREG(status.st_mode):
                total += status.st_size
            else:
                raise OpenFHEQueryRuntimeError(
                    "controlled scratch contains a non-directory/non-regular member"
                )
    return total


def _rss_bytes(rusage: resource.struct_rusage) -> int:
    observed = int(rusage.ru_maxrss)
    return observed if sys.platform == "darwin" else observed * 1024


def _read_log(path: Path) -> bytes:
    return _read_direct_file(
        path,
        field=f"runner log {path.name}",
        maximum=_LOG_BYTES_MAXIMUM,
        allow_empty=True,
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        raise OpenFHEQueryRuntimeError("OpenFHE process group could not be terminated") from error


def _wait4_process(
    process: subprocess.Popen[bytes],
    *,
    scratch_root: Path,
    timeout_seconds: int,
    scratch_limit_bytes: int,
) -> tuple[int, resource.struct_rusage, int]:
    deadline = time.monotonic() + timeout_seconds
    peak_scratch = _scratch_bytes(scratch_root)
    failure: str | None = None
    status = 0
    usage: resource.struct_rusage | None = None
    while usage is None:
        try:
            waited_pid, status, observed = os.wait4(process.pid, os.WNOHANG)
        except (ChildProcessError, OSError) as error:
            raise OpenFHEQueryRuntimeError(
                "controller could not observe the OpenFHE child"
            ) from error
        peak_scratch = max(peak_scratch, _scratch_bytes(scratch_root))
        if waited_pid == process.pid:
            usage = observed
            if peak_scratch > scratch_limit_bytes:
                failure = "scratch-limit-exceeded"
            break
        if peak_scratch > scratch_limit_bytes:
            failure = "scratch-limit-exceeded"
        elif time.monotonic() >= deadline:
            failure = "wall-clock-limit-exceeded"
        if failure is not None:
            _terminate_process_group(process)
            try:
                _waited_pid, status, usage = os.wait4(process.pid, 0)
            except (ChildProcessError, OSError) as error:
                raise OpenFHEQueryRuntimeError(
                    "controller could not reap the terminated OpenFHE child"
                ) from error
            break
        time.sleep(_OBSERVATION_INTERVAL_SECONDS)
    process.returncode = os.waitstatus_to_exitcode(status)
    peak_scratch = max(peak_scratch, _scratch_bytes(scratch_root))
    if failure is not None:
        raise OpenFHEQueryRuntimeError(failure)
    return process.returncode, usage, peak_scratch


def _run_process(
    runner: Path,
    *,
    repository_root: Path,
    scratch_root: Path,
    request_path: Path,
    result_path: Path,
    object_root: Path,
    timeout_seconds: int,
    scratch_limit_bytes: int,
) -> _ProcessObservation:
    stdout_path = scratch_root / "stdout.bin"
    stderr_path = scratch_root / "stderr.bin"
    stdout_fd = os.open(
        stdout_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    stderr_fd = os.open(
        stderr_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    started_ns = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            (
                str(runner),
                "--request",
                str(request_path),
                "--result",
                str(result_path),
                "--object-dir",
                str(object_root),
            ),
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            cwd=repository_root,
            env={
                "HOME": str(scratch_root / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "OMP_NUM_THREADS": "1",
                "PATH": "/usr/bin:/bin",
                "TMPDIR": str(scratch_root / "tmp"),
                "TZ": "UTC",
            },
            close_fds=True,
            start_new_session=True,
        )
        try:
            return_code, usage, peak_scratch = _wait4_process(
                process,
                scratch_root=scratch_root,
                timeout_seconds=timeout_seconds,
                scratch_limit_bytes=scratch_limit_bytes,
            )
        except BaseException:
            if process.returncode is None:
                _terminate_process_group(process)
                try:
                    _pid, status, _usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                except (ChildProcessError, OSError):
                    pass
            raise
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    elapsed_ns = time.monotonic_ns() - started_ns
    stdout = _read_log(stdout_path)
    stderr = _read_log(stderr_path)
    if return_code != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        raise OpenFHEQueryRuntimeError(f"OpenFHE runner exited {return_code}: {message}")
    expected_stdout = f"{result_path}\n".encode()
    if stdout != expected_stdout or stderr:
        raise OpenFHEQueryRuntimeError("OpenFHE runner stdout/stderr contract changed")
    return _ProcessObservation(
        elapsed_ns=elapsed_ns,
        peak_resident_memory_bytes=_rss_bytes(usage),
        peak_scratch_bytes=peak_scratch,
        stdout=stdout,
        stderr=stderr,
    )


def _payloads(
    object_root: Path,
    receipts: tuple[OpenFHESerializedObjectReceipt, ...],
) -> tuple[OpenFHESerializedPayload, ...]:
    payloads: list[OpenFHESerializedPayload] = []
    for receipt in receipts:
        content = _read_direct_file(
            object_root / receipt.relative_path,
            field=f"serialized OpenFHE object {receipt.relative_path}",
        )
        if (
            len(content) != receipt.byte_count
            or hashlib.sha256(content).hexdigest() != receipt.sha256
        ):
            raise OpenFHEQueryRuntimeError("serialized OpenFHE object changed after verification")
        payloads.append(
            OpenFHESerializedPayload(
                category=receipt.category,
                subject_id=receipt.subject_id,
                binary_framing_schema=(
                    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA
                    if receipt.category == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
                    else None
                ),
                sha256=receipt.sha256,
                payload=content,
            )
        )
    return tuple(payloads)


def _cpu_affinity() -> tuple[int, ...] | None:
    getter = getattr(os, "sched_getaffinity", None)
    if getter is None:
        return None
    try:
        return tuple(sorted(getter(0)))
    except OSError as error:
        raise OpenFHEQueryRuntimeError("CPU affinity could not be observed") from error


def execute_authorized_openfhe_query(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> ExecutedOpenFHEQuery:
    """Consume, launch, verify, observe, and clean one private query execution."""

    root = _absolute_path(repository_root, field="repository_root")
    scratch = _absolute_path(scratch_root, field="scratch_root")
    if (
        type(timeout_seconds) is not int
        or timeout_seconds <= 0
        or type(resident_memory_limit_bytes) is not int
        or resident_memory_limit_bytes <= 0
        or type(scratch_limit_bytes) is not int
        or scratch_limit_bytes <= 0
    ):
        raise OpenFHEQueryRuntimeError("runtime limits must be exact positive integers")
    _reject_symlink_components(scratch, missing_leaf_allowed=True)
    if scratch.exists() or scratch.is_symlink():
        raise OpenFHEQueryRuntimeError("scratch_root must be one absent path")
    runner_identity = capture_openfhe_runner_build_identity(root, runner_relative_path)
    runner = root.joinpath(*PurePosixPath(runner_relative_path).parts)
    request_bytes = build_ordinary_openfhe_query_request(
        bundle,
        prepared,
        repository_root=root,
        key_generation_plan=key_generation_plan,
    )
    scratch.mkdir(mode=0o700)
    scratch_identity = scratch.lstat()
    request_path = scratch / "request.json"
    result_path = scratch / "result.json"
    object_root = scratch / "objects"
    try:
        object_root.mkdir(mode=0o700)
        (scratch / "home").mkdir(mode=0o700)
        (scratch / "tmp").mkdir(mode=0o700)
        _write_new_file(request_path, request_bytes)
        if _scratch_bytes(scratch) > scratch_limit_bytes:
            raise OpenFHEQueryRuntimeError("scratch-limit-exceeded-before-authorization")
        authorization_capability = authorize_ordinary_execution(
            bundle,
            prepared,
            ledger=ledger,
        )
        authorization = claim_ordinary_execution(
            authorization_capability,
            bundle,
            prepared,
        )
        observation = _run_process(
            runner,
            repository_root=root,
            scratch_root=scratch,
            request_path=request_path,
            result_path=result_path,
            object_root=object_root,
            timeout_seconds=timeout_seconds,
            scratch_limit_bytes=scratch_limit_bytes,
        )
        if observation.peak_resident_memory_bytes > resident_memory_limit_bytes:
            raise OpenFHEQueryRuntimeError("resident-memory-limit-exceeded")
        result_before_verification = _read_direct_file(
            result_path,
            field="OpenFHE result before verification",
            maximum=128 * 1024 * 1024,
        )
        verified = verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=expected_output,
            repository_root=root,
            key_generation_plan=key_generation_plan,
        )
        result_after_verification = _read_direct_file(
            result_path,
            field="OpenFHE result after verification",
            maximum=128 * 1024 * 1024,
        )
        if result_after_verification != result_before_verification:
            raise OpenFHEQueryRuntimeError("OpenFHE result changed during verification")
        payloads = _payloads(object_root, verified.serialized_objects)
        if capture_openfhe_runner_build_identity(root, runner_relative_path) != runner_identity:
            raise OpenFHEQueryRuntimeError("OpenFHE runner/build identity changed during execution")
        final_scratch = _scratch_bytes(scratch)
        peak_scratch = max(observation.peak_scratch_bytes, final_scratch)
        if peak_scratch > scratch_limit_bytes:
            raise OpenFHEQueryRuntimeError("scratch-limit-exceeded")
        host_identity = hashlib.sha256(platform.node().encode("utf-8")).hexdigest()
        os_identity = f"{platform.system()}-{platform.release()}-{platform.machine()}"
        receipt = OpenFHEQueryRuntimeReceipt(
            runner=runner_identity,
            authorization=authorization,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            request_byte_count=len(request_bytes),
            result_sha256=hashlib.sha256(result_after_verification).hexdigest(),
            result_byte_count=len(result_after_verification),
            elapsed_ns=observation.elapsed_ns,
            timeout_seconds=timeout_seconds,
            peak_resident_memory_bytes=observation.peak_resident_memory_bytes,
            resident_memory_limit_bytes=resident_memory_limit_bytes,
            peak_scratch_bytes=peak_scratch,
            scratch_limit_bytes=scratch_limit_bytes,
            stdout_sha256=hashlib.sha256(observation.stdout).hexdigest(),
            stdout_byte_count=len(observation.stdout),
            stderr_sha256=hashlib.sha256(observation.stderr).hexdigest(),
            stderr_byte_count=len(observation.stderr),
            serialized_object_count=len(payloads),
            serialized_object_bytes=sum(len(item.payload) for item in payloads),
            host_identity_sha256=host_identity,
            operating_system_identity=os_identity,
            cpu_affinity=_cpu_affinity(),
        )
        return ExecutedOpenFHEQuery(
            verified_result=verified,
            runtime_receipt=receipt,
            serialized_payloads=payloads,
        )
    finally:
        try:
            current = scratch.lstat()
            if (current.st_dev, current.st_ino) != (
                scratch_identity.st_dev,
                scratch_identity.st_ino,
            ):
                raise OpenFHEQueryRuntimeError("controlled scratch identity changed before cleanup")
            shutil.rmtree(scratch)
        except FileNotFoundError as error:
            raise OpenFHEQueryRuntimeError(
                "controlled scratch disappeared before cleanup"
            ) from error
        except OSError as error:
            raise OpenFHEQueryRuntimeError("controlled scratch cleanup failed") from error


__all__ = (
    "OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA",
    "OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA",
    "ExecutedOpenFHEQuery",
    "OpenFHEQueryRuntimeError",
    "OpenFHEQueryRuntimeReceipt",
    "OpenFHELinkedLibraryIdentity",
    "OpenFHERunnerBuildIdentity",
    "OpenFHESerializedPayload",
    "capture_openfhe_runner_build_identity",
    "execute_authorized_openfhe_query",
)
