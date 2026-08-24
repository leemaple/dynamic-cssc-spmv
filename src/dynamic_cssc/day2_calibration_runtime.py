"""One-use isolated launcher for the formal Day 2 calibration worker."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.day2_calibration_authority import (
    DAY2_RUNTIME_ISOLATION_CHECKS,
    Day2CalibrationProfileAuthority,
)

__all__ = (
    "Day2CalibrationIsolatedRun",
    "Day2CalibrationRuntimeError",
    "Day2RuntimeIsolationCapability",
    "run_day2_calibration_isolated",
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CAPABILITY_DOCUMENT_KEYS = frozenset(
    {
        "schema_version",
        "nonce",
        "source_git_sha",
        "source_checkout",
        "execution_root",
    }
)
_PRESERVED_GITHUB_ENVIRONMENT = (
    "GITHUB_ACTION",
    "GITHUB_ACTIONS",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_EVENT_NAME",
    "GITHUB_JOB",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_PROTECTED",
    "GITHUB_REF_TYPE",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_SERVER_URL",
    "GITHUB_SHA",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
)
_PRESERVED_RUNNER_ENVIRONMENT = (
    "ImageOS",
    "ImageVersion",
    "RUNNER_ARCH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_NAME",
    "RUNNER_OS",
    "RUNNER_TRACKING_ID",
)
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_DAY1A_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_CAPABILITY_BYTES = 16 * 1024
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024


class Day2CalibrationRuntimeError(RuntimeError):
    """The live Day 2 worker could not establish its isolation invariants."""


@dataclass(frozen=True, slots=True)
class _VerifiedRuntimeFacts:
    source_git_sha: str
    fresh_detached_checkout: bool
    clean_environment: bool
    isolated_build_root: bool
    caller_python_and_git_environment_removed: bool
    launcher_source_sha256: str
    producer_source_sha256: str

    def __post_init__(self) -> None:
        if _LOWER_GIT_SHA.fullmatch(self.source_git_sha) is None:
            raise Day2CalibrationRuntimeError("isolated source Git SHA is invalid")
        for field in (
            "fresh_detached_checkout",
            "clean_environment",
            "isolated_build_root",
            "caller_python_and_git_environment_removed",
        ):
            if getattr(self, field) is not True:
                raise Day2CalibrationRuntimeError(
                    f"verified runtime fact {field} must be exact true"
                )
        for field in ("launcher_source_sha256", "producer_source_sha256"):
            if _LOWER_SHA256.fullmatch(getattr(self, field)) is None:
                raise Day2CalibrationRuntimeError(
                    f"verified runtime fact {field} is invalid"
                )


class Day2RuntimeIsolationCapability:
    """A non-Boolean, single-use proof produced inside the isolated worker."""

    __slots__ = ("_consumed", "_facts")

    def __new__(cls) -> Day2RuntimeIsolationCapability:
        raise TypeError(
            "Day2RuntimeIsolationCapability can only be created by a verified isolated worker"
        )

    def __bool__(self) -> bool:
        raise TypeError("runtime isolation capability must be used through consume")

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"_consumed", "_facts"} and not hasattr(self, name):
            object.__setattr__(self, name, value)
            return
        raise AttributeError("runtime isolation capability is immutable")

    def consume(
        self,
        profile_authority: Day2CalibrationProfileAuthority,
        operation_profile_set: object,
        rotation_key_plan: object,
        contract_bindings: object,
    ) -> dict[str, object]:
        """Consume the live proof while validating the exact pre-dispatch documents."""

        if self._consumed:
            raise Day2CalibrationRuntimeError(
                "runtime isolation capability has already been consumed"
            )
        if type(profile_authority) is not Day2CalibrationProfileAuthority:
            raise Day2CalibrationRuntimeError(
                "runtime capability requires repository-minted profile authority"
            )
        if profile_authority.experiment_source_git_sha != self._facts.source_git_sha:
            raise Day2CalibrationRuntimeError(
                "profile authority source differs from the isolated checkout"
            )
        profile_authority.validate_pre_dispatch_contract(
            operation_profile_set,
            rotation_key_plan,
            contract_bindings,
        )
        object.__setattr__(self, "_consumed", True)
        return {
            "schema_version": "dynamic-cssc-publication-day2-runtime-isolation-receipt-v1",
            "authority_state": "descriptive-live-capability-consumed-v1",
            "formal_authority_granted": False,
            "source_git_sha": self._facts.source_git_sha,
            "fresh_detached_checkout": self._facts.fresh_detached_checkout,
            "clean_environment": self._facts.clean_environment,
            "isolated_build_root": self._facts.isolated_build_root,
            "caller_python_and_git_environment_removed": (
                self._facts.caller_python_and_git_environment_removed
            ),
            "profile_authority_consumed_once": True,
            "launcher_source_sha256": self._facts.launcher_source_sha256,
            "producer_source_sha256": self._facts.producer_source_sha256,
            "isolation_checks": list(DAY2_RUNTIME_ISOLATION_CHECKS),
        }


@dataclass(frozen=True, slots=True)
class Day2CalibrationIsolatedRun:
    """Identity of one no-replace archive emitted by the isolated launcher."""

    output_archive: Path
    source_git_sha: str
    archive_sha256: str
    archive_bytes: int
    formal_authority_granted: bool = False


def _runtime_capability_from_verified_facts(
    facts: _VerifiedRuntimeFacts,
) -> Day2RuntimeIsolationCapability:
    if type(facts) is not _VerifiedRuntimeFacts:
        raise TypeError("runtime capability requires exact verified runtime facts")
    capability = object.__new__(Day2RuntimeIsolationCapability)
    object.__setattr__(capability, "_facts", facts)
    object.__setattr__(capability, "_consumed", False)
    return capability


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
        raise Day2CalibrationRuntimeError(
            "runtime invocation is not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clean_worker_environment(
    python_executable: Path,
    caller_environment: dict[str, str] | os._Environ[str],
) -> dict[str, str]:
    """Build a closed environment without inheriting Python/Git injection state."""

    if not isinstance(python_executable, Path) or not python_executable.name:
        raise TypeError("python_executable must be a pathlib.Path")
    if not isinstance(caller_environment, dict | os._Environ):
        raise TypeError("caller_environment must be a string mapping")
    python_directory = str(python_executable.parent)
    environment = {
        "BUILD_JOBS": "2",
        "CI": "true",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "OMP_NUM_THREADS": "2",
        "OMP_PLACES": "cores",
        "OMP_PROC_BIND": "close",
        "PATH": f"{python_directory}:/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    for name in (*_PRESERVED_GITHUB_ENVIRONMENT, *_PRESERVED_RUNNER_ENVIRONMENT):
        value = caller_environment.get(name)
        if type(value) is str and value:
            environment[name] = value
    return environment


def _worker_command(
    *,
    python_executable: Path,
    worker_script: Path,
    day1a_directory: Path,
    metadata_path: Path,
    execution_root: Path,
    staging_archive: Path,
    capability_fd: int,
) -> tuple[str, ...]:
    if type(capability_fd) is not int or capability_fd < 0:
        raise TypeError("capability_fd must be a nonnegative strict integer")
    return (
        str(python_executable),
        "-I",
        "-B",
        str(worker_script),
        "--isolated-worker",
        "--day1a-directory",
        str(day1a_directory),
        "--github-artifact-metadata",
        str(metadata_path),
        "--execution-root",
        str(execution_root),
        "--staging-archive",
        str(staging_archive),
        "--capability-fd",
        str(capability_fd),
    )


def _regular_input(path: Path, field: str, maximum_bytes: int) -> os.stat_result:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise Day2CalibrationRuntimeError(f"{field} must be a regular non-symlink file")
    observed = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(observed.st_mode) or observed.st_size <= 0:
        raise Day2CalibrationRuntimeError(f"{field} must be a nonempty regular file")
    if observed.st_size > maximum_bytes:
        raise Day2CalibrationRuntimeError(f"{field} exceeds its closed byte bound")
    return observed


def _copy_regular_snapshot(
    source: Path,
    destination: Path,
    *,
    field: str,
    maximum_bytes: int,
) -> None:
    before = _regular_input(source, field, maximum_bytes)
    read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    source_fd = os.open(source, read_flags)
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    destination_fd: int | None = None
    try:
        held_before = os.fstat(source_fd)
        if (held_before.st_dev, held_before.st_ino, held_before.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise Day2CalibrationRuntimeError(f"{field} changed before snapshot")
        destination_fd = os.open(destination, write_flags, 0o600)
        remaining = held_before.st_size
        while remaining:
            chunk = os.read(source_fd, min(_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise Day2CalibrationRuntimeError(f"{field} was truncated during snapshot")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise Day2CalibrationRuntimeError(f"{field} snapshot write failed")
                view = view[written:]
            remaining -= len(chunk)
        if os.read(source_fd, 1):
            raise Day2CalibrationRuntimeError(f"{field} grew during snapshot")
        os.fsync(destination_fd)
        held_after = os.fstat(source_fd)
        if (
            held_after.st_dev,
            held_after.st_ino,
            held_after.st_mode,
            held_after.st_size,
            held_after.st_mtime_ns,
        ) != (
            held_before.st_dev,
            held_before.st_ino,
            held_before.st_mode,
            held_before.st_size,
            held_before.st_mtime_ns,
        ):
            raise Day2CalibrationRuntimeError(f"{field} changed during snapshot")
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def _git(
    repository: Path | None,
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    git = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
    if git is None:
        raise Day2CalibrationRuntimeError("git executable is unavailable")
    command = [git]
    if repository is not None:
        command.extend(("-C", str(repository)))
    command.extend(arguments)
    try:
        return subprocess.run(
            command,
            check=check,
            capture_output=True,
            env=environment,
        )
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.decode("utf-8", errors="replace")[-2000:]
        raise Day2CalibrationRuntimeError(f"isolated Git operation failed: {stderr}") from error


def _verify_detached_clean_checkout(
    repository: Path,
    expected_sha: str,
    *,
    environment: dict[str, str],
) -> None:
    head = _git(repository, ("rev-parse", "--verify", "HEAD^{commit}"), environment=environment)
    if head.stdout.decode("ascii").strip() != expected_sha:
        raise Day2CalibrationRuntimeError("isolated checkout HEAD does not match source")
    symbolic = _git(
        repository,
        ("symbolic-ref", "-q", "HEAD"),
        environment=environment,
        check=False,
    )
    if symbolic.returncode == 0:
        raise Day2CalibrationRuntimeError("isolated checkout is not detached")
    status_output = _git(
        repository,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        environment=environment,
    ).stdout
    if status_output:
        raise Day2CalibrationRuntimeError("isolated checkout is not clean")
    if (repository / ".git/objects/info/alternates").exists():
        raise Day2CalibrationRuntimeError("isolated checkout uses a shared object alternate")


def _install_archive_no_replace(staging: Path, output: Path) -> tuple[str, int]:
    observed = _regular_input(staging, "isolated Day 2 archive", _MAX_ARCHIVE_BYTES)
    digest = _sha256_path(staging)
    try:
        os.link(staging, output, follow_symlinks=False)
    except FileExistsError as error:
        raise Day2CalibrationRuntimeError("Day 2 output archive already exists") from error
    except OSError as error:
        raise Day2CalibrationRuntimeError(
            "Day 2 archive could not be installed without replacement"
        ) from error
    output_fd = os.open(output, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        installed = os.fstat(output_fd)
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    if (
        installed.st_dev,
        installed.st_ino,
        installed.st_size,
    ) != (observed.st_dev, observed.st_ino, observed.st_size) or _sha256_path(output) != digest:
        raise Day2CalibrationRuntimeError("installed Day 2 archive identity changed")
    return digest, observed.st_size


def _read_capability_document(descriptor: int) -> dict[str, object]:
    if type(descriptor) is not int or descriptor < 0:
        raise Day2CalibrationRuntimeError("runtime capability descriptor is invalid")
    observed = os.fstat(descriptor)
    if not stat.S_ISFIFO(observed.st_mode):
        raise Day2CalibrationRuntimeError("runtime capability must arrive through a pipe")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(4096, _MAX_CAPABILITY_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_CAPABILITY_BYTES:
            raise Day2CalibrationRuntimeError("runtime capability document is oversized")
    content = b"".join(chunks)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise Day2CalibrationRuntimeError(
                    "runtime capability contains a duplicate JSON key"
                )
            value[key] = item
        return value

    try:
        document = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationRuntimeError("runtime capability is not JSON") from error
    if (
        type(document) is not dict
        or set(document) != _CAPABILITY_DOCUMENT_KEYS
        or _canonical_json_bytes(document) != content
    ):
        raise Day2CalibrationRuntimeError("runtime capability document is not canonical")
    return document


def _worker_environment_is_clean() -> bool:
    expected = _clean_worker_environment(Path(sys.executable), dict(os.environ))
    return dict(os.environ) == expected


def _isolated_worker_capability(
    *,
    capability_fd: int,
    execution_root: Path,
) -> Day2RuntimeIsolationCapability:
    document = _read_capability_document(capability_fd)
    repository_root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    if sys.flags.isolated != 1 or not sys.dont_write_bytecode:
        raise Day2CalibrationRuntimeError("worker Python is not running with -I -B")
    if not _worker_environment_is_clean():
        raise Day2CalibrationRuntimeError("worker environment is not the closed clean environment")
    if document["schema_version"] != "dynamic-cssc-day2-runtime-invocation-v1":
        raise Day2CalibrationRuntimeError("runtime invocation schema is not frozen")
    nonce = document["nonce"]
    if type(nonce) is not str or _LOWER_SHA256.fullmatch(nonce) is None:
        raise Day2CalibrationRuntimeError("runtime invocation nonce is invalid")
    source_sha = document["source_git_sha"]
    if type(source_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_sha) is None:
        raise Day2CalibrationRuntimeError("runtime invocation source SHA is invalid")
    if document["source_checkout"] != str(repository_root):
        raise Day2CalibrationRuntimeError("runtime invocation source path changed")
    if document["execution_root"] != str(execution_root):
        raise Day2CalibrationRuntimeError("runtime invocation execution path changed")
    if repository_root == execution_root or repository_root in execution_root.parents:
        raise Day2CalibrationRuntimeError("runtime build root is inside the source checkout")
    if execution_root == repository_root or execution_root in repository_root.parents:
        raise Day2CalibrationRuntimeError("runtime source checkout is inside the build root")
    _verify_detached_clean_checkout(
        repository_root,
        source_sha,
        environment=environment,
    )
    producer_path = repository_root / "src/dynamic_cssc/day2_calibration_producer.py"
    if not producer_path.is_file() or producer_path.is_symlink():
        raise Day2CalibrationRuntimeError("formal Day 2 producer source is unavailable")
    facts = _VerifiedRuntimeFacts(
        source_git_sha=source_sha,
        fresh_detached_checkout=True,
        clean_environment=True,
        isolated_build_root=True,
        caller_python_and_git_environment_removed=True,
        launcher_source_sha256=_sha256_path(Path(__file__).resolve()),
        producer_source_sha256=_sha256_path(producer_path),
    )
    return _runtime_capability_from_verified_facts(facts)


def _run_isolated_worker(
    *,
    day1a_directory: Path,
    github_artifact_metadata_path: Path,
    execution_root: Path,
    staging_archive: Path,
    capability_fd: int,
) -> None:
    capability = _isolated_worker_capability(
        capability_fd=capability_fd,
        execution_root=execution_root,
    )
    from dynamic_cssc.day2_calibration_producer import (
        produce_day2_calibration_archive_from_isolated_worker,
    )

    produce_day2_calibration_archive_from_isolated_worker(
        day1a_directory=day1a_directory,
        github_artifact_metadata_path=github_artifact_metadata_path,
        execution_root=execution_root,
        output_archive=staging_archive,
        runtime_capability=capability,
    )
    repository_root = Path(__file__).resolve().parents[2]
    _verify_detached_clean_checkout(
        repository_root,
        capability._facts.source_git_sha,  # noqa: SLF001
        environment=dict(os.environ),
    )


def run_day2_calibration_isolated(
    day1a_directory: Path,
    github_artifact_metadata_path: Path,
    output_archive: Path,
) -> Day2CalibrationIsolatedRun:
    """Run the formal producer in a fresh detached checkout and clean interpreter."""

    from dynamic_cssc.day1a_export import (
        AUTHORITY_RECEIPT_FILENAME,
        COUNT_BUNDLE_FILENAME,
        ROTATION_INVENTORY_FILENAME,
    )
    from dynamic_cssc.evidence_compatibility import EvidenceRole, verify_current_role_source

    if not isinstance(day1a_directory, Path):
        raise TypeError("day1a_directory must be a pathlib.Path")
    if day1a_directory.is_symlink() or not day1a_directory.is_dir():
        raise Day2CalibrationRuntimeError("day1a_directory must be a regular directory")
    _regular_input(
        github_artifact_metadata_path,
        "Day1A GitHub artifact metadata",
        _MAX_METADATA_BYTES,
    )
    if not isinstance(output_archive, Path):
        raise TypeError("output_archive must be a pathlib.Path")
    output_archive = output_archive.absolute()
    if output_archive.exists() or output_archive.is_symlink():
        raise Day2CalibrationRuntimeError("Day 2 output archive must be absent")
    if output_archive.parent.is_symlink() or not output_archive.parent.is_dir():
        raise Day2CalibrationRuntimeError("Day 2 output parent must be a regular directory")
    repository_root = Path(__file__).resolve().parents[2]
    before = verify_current_role_source(EvidenceRole.DAY2, repository_root)
    python_executable = Path(sys.executable).resolve()
    worker_environment = _clean_worker_environment(python_executable, os.environ)
    with tempfile.TemporaryDirectory(
        prefix=f".{output_archive.name}.runtime-",
        dir=output_archive.parent,
    ) as temporary:
        runtime_root = Path(temporary)
        input_root = runtime_root / "input"
        day1a_snapshot = input_root / "day1a"
        source_checkout = runtime_root / "source"
        execution_root = runtime_root / "execution"
        input_root.mkdir(mode=0o700)
        day1a_snapshot.mkdir(mode=0o700)
        execution_root.mkdir(mode=0o700)
        for filename in (
            COUNT_BUNDLE_FILENAME,
            ROTATION_INVENTORY_FILENAME,
            AUTHORITY_RECEIPT_FILENAME,
        ):
            _copy_regular_snapshot(
                day1a_directory / filename,
                day1a_snapshot / filename,
                field=filename,
                maximum_bytes=_MAX_DAY1A_MEMBER_BYTES,
            )
        metadata_snapshot = input_root / "day1a-github-artifact-metadata.json"
        _copy_regular_snapshot(
            github_artifact_metadata_path,
            metadata_snapshot,
            field="Day1A GitHub artifact metadata",
            maximum_bytes=_MAX_METADATA_BYTES,
        )
        _git(
            None,
            (
                "-c",
                "protocol.file.allow=always",
                "clone",
                "--quiet",
                "--no-local",
                "--no-hardlinks",
                "--no-checkout",
                str(repository_root),
                str(source_checkout),
            ),
            environment=worker_environment,
        )
        _git(
            source_checkout,
            ("checkout", "--quiet", "--detach", before.git_sha),
            environment=worker_environment,
        )
        _verify_detached_clean_checkout(
            source_checkout,
            before.git_sha,
            environment=worker_environment,
        )
        worker_script = source_checkout / "scripts/run_day2_calibration_isolated.py"
        if worker_script.is_symlink() or not worker_script.is_file():
            raise Day2CalibrationRuntimeError("formal isolated worker entrypoint is unavailable")
        staging_archive = execution_root / "day2-calibration.zip"
        invocation = {
            "schema_version": "dynamic-cssc-day2-runtime-invocation-v1",
            "nonce": secrets.token_hex(32),
            "source_git_sha": before.git_sha,
            "source_checkout": str(source_checkout),
            "execution_root": str(execution_root),
        }
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, _canonical_json_bytes(invocation))
        finally:
            os.close(write_fd)
        command = _worker_command(
            python_executable=python_executable,
            worker_script=worker_script,
            day1a_directory=day1a_snapshot,
            metadata_path=metadata_snapshot,
            execution_root=execution_root,
            staging_archive=staging_archive,
            capability_fd=read_fd,
        )
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                env=worker_environment,
                pass_fds=(read_fd,),
            )
        finally:
            os.close(read_fd)
        if completed.returncode != 0:
            stdout = completed.stdout.decode("utf-8", errors="replace")[-4000:]
            stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
            raise Day2CalibrationRuntimeError(
                "isolated Day 2 worker failed\n"
                f"stdout tail:\n{stdout}\n"
                f"stderr tail:\n{stderr}"
            )
        archive_sha256, archive_bytes = _install_archive_no_replace(
            staging_archive,
            output_archive,
        )
    after = verify_current_role_source(EvidenceRole.DAY2, repository_root)
    if after != before:
        raise Day2CalibrationRuntimeError("Day 2 source changed during isolated production")
    return Day2CalibrationIsolatedRun(
        output_archive=output_archive,
        source_git_sha=before.git_sha,
        archive_sha256=archive_sha256,
        archive_bytes=archive_bytes,
    )
