"""Owned-child runtime for the six-stage Route A qualification DAG.

This module currently exposes the simulator producer and independent replay
stages.  The interface is deliberately stage-shaped: callers cannot submit an
arbitrary subprocess or invent artifact membership.  Internally the launcher
uses Linux ``wait4``, a synchronous stage-observation pipe, one non-followed
scratch root, and an atomic output-directory install.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    inspect_route_a_synthetic_suite_handoff,
    inspect_route_a_synthetic_suite_replay,
    route_a_synthetic_suite_stage_names,
)
from dynamic_cssc.route_a_workloads import generate_route_a_qualification_trace

__all__ = (
    "RouteAQualificationRuntimeError",
    "RouteAQualificationStageArtifactInspection",
    "inspect_route_a_qualification_stage_artifact",
    "run_owned_route_a_qualification_stage",
    "route_a_stage_observer",
)

RouteAQualificationSimulatorStage = Literal["q1", "q2"]

_PROCESS_RECEIPT_SCHEMA = "dynamic-cssc-route-a-owned-child-receipt-v1"
_STAGE_LEDGER_SCHEMA = "dynamic-cssc-route-a-owned-child-stage-ledger-v1"
_ARTIFACT_MANIFEST_SCHEMA = "dynamic-cssc-route-a-qualification-stage-artifact-v1"
_STAGE_EVENT_SCHEMA = "dynamic-cssc-route-a-owned-child-stage-event-v1"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SMALL_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024 * 1024
_MAX_LOG_BYTES = 16 * 1024 * 1024
_POLL_SECONDS = 0.05
_STAGE_PAYLOAD = {
    "q1": "simulator-suite-handoff.zip",
    "q2": "simulator-suite-replay.zip",
}
_STAGE_ROLE = {
    "q1": "qualification-simulator-producer",
    "q2": "qualification-simulator-independent-replay-and-guard",
}
_PROCESS_RECEIPT_FIELDS = frozenset(
    {
        "command_sha256",
        "elapsed_nanoseconds",
        "executable_sha256",
        "formal_authority_granted",
        "operating_system",
        "payload_byte_count",
        "payload_sha256",
        "peak_rss_kib",
        "peak_scratch_allocated_bytes",
        "process_id",
        "process_start_time_ticks",
        "publication_evidence",
        "return_code",
        "schema_version",
        "scratch_cleanup_verified",
        "stage",
        "stderr_byte_count",
        "stderr_sha256",
        "stdout_byte_count",
        "stdout_sha256",
        "wait_api",
    }
)


class RouteAQualificationRuntimeError(RuntimeError):
    """A qualification child, resource observation, or stage artifact failed closed."""


def _stable_file_identity(status: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAQualificationRuntimeError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(content.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAQualificationRuntimeError(f"{label} is not ASCII JSON") from error
    if type(document) is not dict or canonical_route_a_document(document) != content:
        raise RouteAQualificationRuntimeError(f"{label} is not canonical JSON")
    return document


def _sha256_file(path: Path, *, maximum: int) -> tuple[str, int]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RouteAQualificationRuntimeError("qualification file cannot be opened") from error
    digest = hashlib.sha256()
    total = 0
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > maximum:
            raise RouteAQualificationRuntimeError("qualification file exceeds its bound")
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not block:
                if total != observed.st_size:
                    raise RouteAQualificationRuntimeError(
                        "qualification file size changed while hashing"
                    )
                final = os.fstat(descriptor)
                if _stable_file_identity(final) != _stable_file_identity(observed):
                    raise RouteAQualificationRuntimeError(
                        "qualification file identity changed while hashing"
                    )
                return digest.hexdigest(), total
            total += len(block)
            if total > maximum:
                raise RouteAQualificationRuntimeError("qualification file exceeds its bound")
            digest.update(block)
    finally:
        os.close(descriptor)


def _read_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RouteAQualificationRuntimeError("qualification file cannot be opened") from error
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > maximum:
            raise RouteAQualificationRuntimeError("qualification file exceeds its bound")
        content = bytearray()
        while len(content) < observed.st_size:
            block = os.read(
                descriptor,
                min(1024 * 1024, observed.st_size - len(content)),
            )
            if not block:
                break
            content.extend(block)
        if len(content) != observed.st_size or os.read(descriptor, 1):
            raise RouteAQualificationRuntimeError("qualification file changed while reading")
        final = os.fstat(descriptor)
        if _stable_file_identity(final) != _stable_file_identity(observed):
            raise RouteAQualificationRuntimeError(
                "qualification file identity changed while reading"
            )
        return bytes(content)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write either writes or raises
                raise RouteAQualificationRuntimeError("qualification file write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scratch_bytes(root: Path) -> int:
    total = 0
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    status = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(status.st_mode):
                        raise RouteAQualificationRuntimeError(
                            "qualification scratch contains a symbolic link"
                        )
                    if stat.S_ISDIR(status.st_mode):
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(status.st_mode):
                        total += status.st_blocks * 512
                    else:
                        raise RouteAQualificationRuntimeError(
                            "qualification scratch contains an unsafe member"
                        )
        except OSError as error:
            raise RouteAQualificationRuntimeError(
                "qualification scratch cannot be enumerated"
            ) from error
    return total


def _expected_stages(stage: RouteAQualificationSimulatorStage) -> tuple[str, ...]:
    return route_a_synthetic_suite_stage_names(stage)


def route_a_stage_observer(write_fd: int, acknowledgement_fd: int):
    """Return the worker callback for synchronous registered-stage sampling."""

    if (
        type(write_fd) is not int
        or write_fd < 0
        or type(acknowledgement_fd) is not int
        or acknowledgement_fd < 0
    ):
        raise RouteAQualificationRuntimeError("qualification stage descriptors are invalid")
    sequence = 0

    def observe(stage: str) -> None:
        nonlocal sequence
        if type(stage) is not str or not stage or "\n" in stage:
            raise RouteAQualificationRuntimeError("qualification stage name is invalid")
        content = canonical_route_a_document(
            {
                "schema_version": _STAGE_EVENT_SCHEMA,
                "sequence": sequence,
                "stage": stage,
            }
        )
        offset = 0
        while offset < len(content):
            offset += os.write(write_fd, content[offset:])
        acknowledgement = os.read(acknowledgement_fd, 1)
        if acknowledgement != b"\x06":
            raise RouteAQualificationRuntimeError(
                "qualification launcher did not acknowledge its stage sample"
            )
        sequence += 1

    return observe


def _process_start_time_ticks(pid: int) -> int:
    try:
        content = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        closing = content.rfind(")")
        fields = content[closing + 2 :].split()
        value = int(fields[19])
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise RouteAQualificationRuntimeError(
            "qualification child /proc identity cannot be observed"
        ) from error
    if value <= 0:
        raise RouteAQualificationRuntimeError("qualification child start time is invalid")
    return value


def _terminate_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        waited, _status, _usage = os.wait4(pid, os.WNOHANG)
        if waited == pid:
            return
        time.sleep(0.02)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


@dataclass(frozen=True, slots=True)
class _OwnedChildObservation:
    process_receipt_bytes: bytes
    stage_ledger_bytes: bytes
    payload_path: Path


def _run_child(
    *,
    stage: RouteAQualificationSimulatorStage,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scratch_root: Path,
    producer_artifact_directory: Path | None,
    timeout_seconds: int,
) -> _OwnedChildObservation:
    stage_read, stage_write = os.pipe()
    acknowledgement_read, acknowledgement_write = os.pipe()
    stdout_path = scratch_root / "stdout.bin"
    stderr_path = scratch_root / "stderr.bin"
    payload_path = scratch_root / _STAGE_PAYLOAD[stage]
    worker_scratch = scratch_root / "worker-scratch"
    worker_scratch.mkdir(mode=0o700)
    script = repository_root / "scripts/run_route_a_qualification.py"
    command = [
        sys.executable,
        str(script),
        "_worker",
        "--stage",
        stage,
        "--repository-root",
        str(repository_root),
        "--experiment-source-sha",
        lineage.experiment_source_sha,
        "--workflow-head-sha",
        lineage.workflow_head_sha,
        "--compatibility-receipt-sha256",
        lineage.compatibility_receipt_sha256,
        "--provider-run-id",
        str(lineage.provider_run_id),
        "--provider-run-attempt",
        str(lineage.provider_run_attempt),
        "--scratch-root",
        str(worker_scratch),
        "--output",
        str(payload_path),
        "--stage-write-fd",
        str(stage_write),
        "--acknowledgement-read-fd",
        str(acknowledgement_read),
    ]
    if stage == "q2":
        if producer_artifact_directory is None:
            raise RouteAQualificationRuntimeError("q2 requires the exact q1 artifact")
        command.extend(("--producer-artifact-directory", str(producer_artifact_directory)))
    elif producer_artifact_directory is not None:
        raise RouteAQualificationRuntimeError("q1 cannot consume a producer artifact")
    executable = Path(sys.executable).resolve(strict=True)
    executable_sha256, _executable_bytes = _sha256_file(executable, maximum=1024 * 1024 * 1024)
    command_bytes = canonical_route_a_document(
        {
            "arguments": command[1:],
            "executable_sha256": executable_sha256,
            "schema_version": "dynamic-cssc-route-a-owned-child-command-v1",
        }
    )
    environment = {
        "HOME": str(scratch_root / "home"),
        "LC_ALL": "C.UTF-8",
        "OMP_NUM_THREADS": "2",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(repository_root / "src"),
        "TMPDIR": str(scratch_root / "tmp"),
    }
    (scratch_root / "home").mkdir(mode=0o700)
    (scratch_root / "tmp").mkdir(mode=0o700)
    stdout_file = stdout_path.open("xb")
    stderr_file = stderr_path.open("xb")
    started_ns = time.perf_counter_ns()
    timed_out = False
    process: subprocess.Popen[bytes] | None = None
    status: int | None = None
    usage = None
    entries: list[dict[str, object]] = []
    buffer = bytearray()
    peak_scratch = _scratch_bytes(scratch_root)
    try:
        process = subprocess.Popen(
            command,
            cwd=repository_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            close_fds=True,
            pass_fds=(stage_write, acknowledgement_read),
            start_new_session=True,
        )
        os.close(stage_write)
        stage_write = -1
        os.close(acknowledgement_read)
        acknowledgement_read = -1
        process_start_time = _process_start_time_ticks(process.pid)
        deadline = time.monotonic() + timeout_seconds
        expected_stages = _expected_stages(stage)
        while status is None:
            peak_scratch = max(peak_scratch, _scratch_bytes(scratch_root))
            readable, _writable, _exceptional = select.select([stage_read], [], [], _POLL_SECONDS)
            if readable:
                block = os.read(stage_read, 64 * 1024)
                if block:
                    buffer.extend(block)
                    while b"\n" in buffer:
                        line, _, remainder = buffer.partition(b"\n")
                        buffer = bytearray(remainder)
                        event = _canonical_object(line + b"\n", label="stage event")
                        sequence = len(entries)
                        if (
                            set(event) != {"schema_version", "sequence", "stage"}
                            or event.get("schema_version") != _STAGE_EVENT_SCHEMA
                            or event.get("sequence") != sequence
                            or sequence >= len(expected_stages)
                            or event.get("stage") != expected_stages[sequence]
                        ):
                            raise RouteAQualificationRuntimeError(
                                "qualification child stage sequence changed"
                            )
                        observed_scratch = _scratch_bytes(scratch_root)
                        peak_scratch = max(peak_scratch, observed_scratch)
                        entries.append(
                            {
                                "observed_monotonic_ns": time.perf_counter_ns(),
                                "scratch_allocated_bytes": observed_scratch,
                                "sequence": sequence,
                                "stage": event["stage"],
                            }
                        )
                        os.write(acknowledgement_write, b"\x06")
            waited, observed_status, observed_usage = os.wait4(process.pid, os.WNOHANG)
            if waited == process.pid:
                status = observed_status
                usage = observed_usage
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_group(process.pid)
                try:
                    waited, status, usage = os.wait4(process.pid, 0)
                except ChildProcessError:
                    status = 9 << 8
                    usage = None
                if waited == process.pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                break
        elapsed_ns = time.perf_counter_ns() - started_ns
    finally:
        for descriptor in (
            stage_read,
            stage_write,
            acknowledgement_read,
            acknowledgement_write,
        ):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
        stdout_file.close()
        stderr_file.close()
    if process is None or status is None or usage is None:
        raise RouteAQualificationRuntimeError("qualification child was not exactly reaped")
    return_code = os.waitstatus_to_exitcode(status)
    if (
        timed_out
        or return_code != 0
        or buffer
        or tuple(entry["stage"] for entry in entries) != _expected_stages(stage)
        or not payload_path.is_file()
    ):
        raise RouteAQualificationRuntimeError(
            f"qualification {stage} child failed closed with return code {return_code}"
        )
    stdout_sha256, stdout_bytes = _sha256_file(stdout_path, maximum=_MAX_LOG_BYTES)
    stderr_sha256, stderr_bytes = _sha256_file(stderr_path, maximum=_MAX_LOG_BYTES)
    payload_sha256, payload_bytes = _sha256_file(payload_path, maximum=_MAX_PAYLOAD_BYTES)
    peak_scratch = max(peak_scratch, _scratch_bytes(scratch_root))
    ledger_bytes = canonical_route_a_document(
        {
            "entries": entries,
            "formal_authority_granted": False,
            "peak_scratch_allocated_bytes": peak_scratch,
            "publication_evidence": False,
            "schema_version": _STAGE_LEDGER_SCHEMA,
            "stage": stage,
        }
    )
    process_receipt = canonical_route_a_document(
        {
            "command_sha256": hashlib.sha256(command_bytes).hexdigest(),
            "elapsed_nanoseconds": elapsed_ns,
            "executable_sha256": executable_sha256,
            "formal_authority_granted": False,
            "operating_system": platform.platform(),
            "payload_byte_count": payload_bytes,
            "payload_sha256": payload_sha256,
            "peak_rss_kib": int(usage.ru_maxrss),
            "peak_scratch_allocated_bytes": peak_scratch,
            "process_id": process.pid,
            "process_start_time_ticks": process_start_time,
            "publication_evidence": False,
            "return_code": return_code,
            "schema_version": _PROCESS_RECEIPT_SCHEMA,
            "scratch_cleanup_verified": False,
            "stage": stage,
            "stderr_byte_count": stderr_bytes,
            "stderr_sha256": stderr_sha256,
            "stdout_byte_count": stdout_bytes,
            "stdout_sha256": stdout_sha256,
            "wait_api": "linux-wait4-ru_maxrss-kib-v1",
        }
    )
    return _OwnedChildObservation(
        process_receipt_bytes=process_receipt,
        stage_ledger_bytes=ledger_bytes,
        payload_path=payload_path,
    )


def _manifest(
    *,
    stage: RouteAQualificationSimulatorStage,
    lineage: RouteASyntheticSuiteLineage,
    members: tuple[tuple[str, bytes | tuple[str, int]], ...],
) -> bytes:
    inventory = []
    for path, content in members:
        if type(content) is bytes:
            digest = hashlib.sha256(content).hexdigest()
            byte_count = len(content)
        else:
            digest, byte_count = content
        inventory.append({"byte_count": byte_count, "path": path, "sha256": digest})
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "formal_artifact": False,
            "lineage_sha256": lineage.sha256,
            "members": inventory,
            "private_replay_material_included": stage == "q1",
            "provider_artifact_name": (
                "q1-simulator-pre-replay-handoff"
                if stage == "q1"
                else "q2-simulator-guarded-receipt"
            ),
            "retention_days": 1,
            "schema_version": _ARTIFACT_MANIFEST_SCHEMA,
            "stage": stage,
            "stage_role": _STAGE_ROLE[stage],
        }
    )


@dataclass(frozen=True, slots=True)
class RouteAQualificationStageArtifactInspection:
    stage: RouteAQualificationSimulatorStage
    lineage: RouteASyntheticSuiteLineage
    payload_path: Path
    payload_sha256: str
    payload_byte_count: int
    process_receipt_bytes: bytes
    stage_ledger_bytes: bytes


def inspect_route_a_qualification_stage_artifact(
    artifact_directory: Path,
    *,
    expected_stage: RouteAQualificationSimulatorStage,
    expected_lineage: RouteASyntheticSuiteLineage,
) -> RouteAQualificationStageArtifactInspection:
    """Close one downloaded q1/q2 provider tree before any payload use."""

    if expected_stage not in _STAGE_PAYLOAD:
        raise RouteAQualificationRuntimeError("qualification stage is not implemented")
    if not isinstance(artifact_directory, Path) or not artifact_directory.is_absolute():
        raise TypeError("artifact_directory must be one absolute pathlib.Path")
    try:
        root_status = artifact_directory.lstat()
    except OSError as error:
        raise RouteAQualificationRuntimeError("qualification artifact is unavailable") from error
    if artifact_directory.is_symlink() or not stat.S_ISDIR(root_status.st_mode):
        raise RouteAQualificationRuntimeError("qualification artifact root is unsafe")
    expected_names = (
        _STAGE_PAYLOAD[expected_stage],
        "owned-child-receipt.json",
        "stage-ledger.json",
        "manifest.json",
        "checksums.sha256",
    )
    names = tuple(sorted(path.name for path in artifact_directory.iterdir()))
    if names != tuple(sorted(expected_names)):
        raise RouteAQualificationRuntimeError("qualification artifact members are missing or extra")
    for name in expected_names:
        member = artifact_directory / name
        status = member.lstat()
        if member.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise RouteAQualificationRuntimeError("qualification artifact member is unsafe")
    payload_path = artifact_directory / _STAGE_PAYLOAD[expected_stage]
    payload_identity = _sha256_file(payload_path, maximum=_MAX_PAYLOAD_BYTES)
    process_bytes = _read_file(
        artifact_directory / "owned-child-receipt.json",
        maximum=_MAX_SMALL_MEMBER_BYTES,
    )
    ledger_bytes = _read_file(
        artifact_directory / "stage-ledger.json", maximum=_MAX_SMALL_MEMBER_BYTES
    )
    manifest_bytes = _read_file(
        artifact_directory / "manifest.json", maximum=_MAX_SMALL_MEMBER_BYTES
    )
    process = _canonical_object(process_bytes, label="owned child receipt")
    ledger = _canonical_object(ledger_bytes, label="owned child stage ledger")
    manifest = _canonical_object(manifest_bytes, label="stage manifest")
    ledger_entries = ledger.get("entries")
    expected_stages = _expected_stages(expected_stage)
    ledger_closed = (
        set(ledger)
        == {
            "entries",
            "formal_authority_granted",
            "peak_scratch_allocated_bytes",
            "publication_evidence",
            "schema_version",
            "stage",
        }
        and type(ledger_entries) is list
        and len(ledger_entries) == len(expected_stages)
        and all(
            type(entry) is dict
            and set(entry)
            == {
                "observed_monotonic_ns",
                "scratch_allocated_bytes",
                "sequence",
                "stage",
            }
            and entry["sequence"] == ordinal
            and entry["stage"] == expected_stages[ordinal]
            and type(entry["observed_monotonic_ns"]) is int
            and entry["observed_monotonic_ns"] > 0
            and type(entry["scratch_allocated_bytes"]) is int
            and entry["scratch_allocated_bytes"] >= 0
            for ordinal, entry in enumerate(ledger_entries)
        )
        and all(
            ledger_entries[index]["observed_monotonic_ns"]
            < ledger_entries[index + 1]["observed_monotonic_ns"]
            for index in range(len(ledger_entries) - 1)
        )
        and type(ledger.get("peak_scratch_allocated_bytes")) is int
        and ledger["peak_scratch_allocated_bytes"]
        >= max(entry["scratch_allocated_bytes"] for entry in ledger_entries)
        and ledger.get("formal_authority_granted") is False
        and ledger.get("publication_evidence") is False
    )
    if (
        set(process) != _PROCESS_RECEIPT_FIELDS
        or process.get("schema_version") != _PROCESS_RECEIPT_SCHEMA
        or process.get("stage") != expected_stage
        or process.get("return_code") != 0
        or process.get("payload_sha256") != payload_identity[0]
        or process.get("payload_byte_count") != payload_identity[1]
        or process.get("formal_authority_granted") is not False
        or process.get("publication_evidence") is not False
        or process.get("scratch_cleanup_verified") is not True
        or process.get("wait_api") != "linux-wait4-ru_maxrss-kib-v1"
        or type(process.get("peak_rss_kib")) is not int
        or process["peak_rss_kib"] < 0
        or type(process.get("peak_scratch_allocated_bytes")) is not int
        or process["peak_scratch_allocated_bytes"] < 0
        or not ledger_closed
        or ledger.get("schema_version") != _STAGE_LEDGER_SCHEMA
        or ledger.get("stage") != expected_stage
        or tuple(entry["stage"] for entry in ledger_entries) != expected_stages
    ):
        raise RouteAQualificationRuntimeError(
            "qualification artifact process or stage receipt changed"
        )
    expected_manifest = _manifest(
        stage=expected_stage,
        lineage=expected_lineage,
        members=(
            (_STAGE_PAYLOAD[expected_stage], payload_identity),
            ("owned-child-receipt.json", process_bytes),
            ("stage-ledger.json", ledger_bytes),
        ),
    )
    if manifest_bytes != expected_manifest or manifest.get("authority_granted") is not False:
        raise RouteAQualificationRuntimeError("qualification stage manifest changed")
    checksum_bytes = _read_file(
        artifact_directory / "checksums.sha256", maximum=_MAX_SMALL_MEMBER_BYTES
    )
    expected_checksums = b"".join(
        f"{digest}  {name}\n".encode("ascii")
        for name, digest in (
            (_STAGE_PAYLOAD[expected_stage], payload_identity[0]),
            ("owned-child-receipt.json", hashlib.sha256(process_bytes).hexdigest()),
            ("stage-ledger.json", hashlib.sha256(ledger_bytes).hexdigest()),
            ("manifest.json", hashlib.sha256(manifest_bytes).hexdigest()),
        )
    )
    if checksum_bytes != expected_checksums:
        raise RouteAQualificationRuntimeError("qualification checksums changed")
    return RouteAQualificationStageArtifactInspection(
        stage=expected_stage,
        lineage=expected_lineage,
        payload_path=payload_path,
        payload_sha256=payload_identity[0],
        payload_byte_count=payload_identity[1],
        process_receipt_bytes=process_bytes,
        stage_ledger_bytes=ledger_bytes,
    )


def run_owned_route_a_qualification_stage(
    *,
    stage: RouteAQualificationSimulatorStage,
    repository_root: Path,
    lineage: RouteASyntheticSuiteLineage,
    scratch_parent: Path,
    output_directory: Path,
    producer_artifact_directory: Path | None = None,
    timeout_seconds: int = 2700,
) -> RouteAQualificationStageArtifactInspection:
    """Run q1 or q2 as one Linux-owned child and atomically install its tree."""

    if platform.system() != "Linux" or not hasattr(os, "wait4"):
        raise RouteAQualificationRuntimeError("qualification owned-child runtime is Linux-only")
    if stage not in _STAGE_PAYLOAD:
        raise RouteAQualificationRuntimeError("qualification stage is not implemented")
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 2700:
        raise RouteAQualificationRuntimeError("qualification timeout is outside its bound")
    for path, label in (
        (repository_root, "repository_root"),
        (scratch_parent, "scratch_parent"),
        (output_directory.parent, "output parent"),
    ):
        if not isinstance(path, Path) or not path.is_absolute():
            raise TypeError(f"{label} must be one absolute pathlib.Path")
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(status.st_mode):
            raise RouteAQualificationRuntimeError(f"{label} is not a direct directory")
    if output_directory.exists() or output_directory.is_symlink():
        raise RouteAQualificationRuntimeError("qualification output directory must be absent")
    scratch_root = scratch_parent / (
        f"route-a-{stage}-{lineage.provider_run_id}-{lineage.provider_run_attempt}"
    )
    if scratch_root.exists() or scratch_root.is_symlink():
        raise RouteAQualificationRuntimeError("qualification scratch identity already exists")
    scratch_root.mkdir(mode=0o700)
    scratch_identity = scratch_root.lstat()
    temporary_output = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    try:
        observation = _run_child(
            stage=stage,
            repository_root=repository_root,
            lineage=lineage,
            scratch_root=scratch_root,
            producer_artifact_directory=producer_artifact_directory,
            timeout_seconds=timeout_seconds,
        )
        trace = generate_route_a_qualification_trace(scale="M", qualification_seed=20260821)
        plan_bytes = (repository_root / "config/route-a-publication-plan.json").read_bytes()
        if stage == "q1":
            inspect_route_a_synthetic_suite_handoff(
                observation.payload_path,
                expected_trace=trace,
                expected_lineage=lineage,
                machine_plan_bytes=plan_bytes,
            )
        else:
            inspect_route_a_synthetic_suite_replay(
                observation.payload_path,
                expected_trace=trace,
                expected_lineage=lineage,
                machine_plan_bytes=plan_bytes,
            )
        payload_target = temporary_output / _STAGE_PAYLOAD[stage]
        os.replace(observation.payload_path, payload_target)
        current = scratch_root.lstat()
        if (current.st_dev, current.st_ino) != (
            scratch_identity.st_dev,
            scratch_identity.st_ino,
        ):
            raise RouteAQualificationRuntimeError(
                "qualification scratch identity changed before cleanup"
            )
        shutil.rmtree(scratch_root)
        if scratch_root.exists() or scratch_root.is_symlink():
            raise RouteAQualificationRuntimeError("qualification scratch cleanup failed")
        process_document = _canonical_object(
            observation.process_receipt_bytes, label="owned child receipt before cleanup"
        )
        if process_document.get("scratch_cleanup_verified") is not False:
            raise RouteAQualificationRuntimeError(
                "qualification child claimed cleanup before launcher cleanup"
            )
        process_document["scratch_cleanup_verified"] = True
        final_process_receipt = canonical_route_a_document(process_document)
        process_path = temporary_output / "owned-child-receipt.json"
        ledger_path = temporary_output / "stage-ledger.json"
        _write_new_file(process_path, final_process_receipt)
        _write_new_file(ledger_path, observation.stage_ledger_bytes)
        payload_identity = _sha256_file(payload_target, maximum=_MAX_PAYLOAD_BYTES)
        manifest_bytes = _manifest(
            stage=stage,
            lineage=lineage,
            members=(
                (_STAGE_PAYLOAD[stage], payload_identity),
                ("owned-child-receipt.json", final_process_receipt),
                ("stage-ledger.json", observation.stage_ledger_bytes),
            ),
        )
        manifest_path = temporary_output / "manifest.json"
        _write_new_file(manifest_path, manifest_bytes)
        checksum_bytes = b"".join(
            f"{digest}  {name}\n".encode("ascii")
            for name, digest in (
                (_STAGE_PAYLOAD[stage], payload_identity[0]),
                (
                    "owned-child-receipt.json",
                    hashlib.sha256(final_process_receipt).hexdigest(),
                ),
                (
                    "stage-ledger.json",
                    hashlib.sha256(observation.stage_ledger_bytes).hexdigest(),
                ),
                ("manifest.json", hashlib.sha256(manifest_bytes).hexdigest()),
            )
        )
        _write_new_file(temporary_output / "checksums.sha256", checksum_bytes)
        os.replace(temporary_output, output_directory)
        return inspect_route_a_qualification_stage_artifact(
            output_directory,
            expected_stage=stage,
            expected_lineage=lineage,
        )
    except BaseException:
        if scratch_root.exists() and not scratch_root.is_symlink():
            shutil.rmtree(scratch_root, ignore_errors=True)
        if temporary_output.exists() and not temporary_output.is_symlink():
            shutil.rmtree(temporary_output, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
