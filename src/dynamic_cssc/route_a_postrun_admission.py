"""Produce q6's non-authorizing postrun Route A resource record.

q6 runs only after q5 has reached terminal success.  It observes q1 through q5
as final provider facts and its own current identity/start time.  It cannot
observe or assert its own future completion or conclusion; the external live
controller performs that final check after q6 terminates.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dynamic_cssc.route_a_results import canonical_route_a_document

__all__ = (
    "RouteAPostrunAdmissionError",
    "RouteAPostrunAdmissionInspection",
    "inspect_route_a_postrun_admission",
    "produce_route_a_postrun_admission",
)

_SCHEMA = "dynamic-cssc-route-a-q6-postrun-resource-admission-v1"
_RECORD_NAME = "route-a-qualification-postrun.json"
_CHECKSUMS_NAME = "checksums.sha256"
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_PROVIDER_BYTES = 4 * 1024 * 1024
_MAX_RECORD_BYTES = 1024 * 1024
_COMPUTATIONAL_SECONDS = 45 * 60
_Q6_WALL_SECONDS = 10 * 60
_TOTAL_SECONDS = 55 * 60
_NATIVE_SCREEN_SECONDS = 9_000
_JOBS = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)
_PREFIX_ARTIFACTS = (
    "q1-simulator-pre-replay-handoff",
    "q2-simulator-guarded-receipt",
    "q3-native-pre-replay-build-plus-three-retained-packages",
    "q4-native-guarded-case-bundle",
    "q5-combined-guard-bundle",
)


class RouteAPostrunAdmissionError(RuntimeError):
    """q6 provider state or retained record failed closed."""


def _canonical_object(content: bytes, *, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAPostrunAdmissionError(f"{field} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAPostrunAdmissionError(f"{field} is not ASCII JSON") from error
    if type(value) is not dict or canonical_route_a_document(value) != content:
        raise RouteAPostrunAdmissionError(f"{field} is not canonical JSON")
    return value


def _provider_object(content: bytes, *, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAPostrunAdmissionError(f"{field} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAPostrunAdmissionError(f"{field} is not readable JSON") from error
    if type(value) is not dict:
        raise RouteAPostrunAdmissionError(f"{field} is not one JSON object")
    return value


def _stable_read(path: Path, *, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteAPostrunAdmissionError("q6 input is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RouteAPostrunAdmissionError("q6 input violates its byte bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns)
        ):
            raise RouteAPostrunAdmissionError("q6 input changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        os.fchmod(descriptor, 0o400)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write raises or advances
                raise RouteAPostrunAdmissionError("q6 record write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _timestamp(value: object, *, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise RouteAPostrunAdmissionError(f"{field} is not a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RouteAPostrunAdmissionError(
            f"{field} is not a canonical UTC timestamp"
        ) from error
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise RouteAPostrunAdmissionError(f"{field} is not a canonical UTC timestamp")
    return parsed


def _render_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _seconds(value: timedelta, *, field: str) -> int:
    seconds = value.total_seconds()
    if seconds < 0 or not seconds.is_integer():
        raise RouteAPostrunAdmissionError(f"{field} is not a whole-second duration")
    return int(seconds)


@dataclass(frozen=True, slots=True)
class _Job:
    database_id: int
    name: str
    started_at: datetime
    completed_at: datetime | None
    status: str
    conclusion: str | None

    @property
    def final_document(self) -> dict[str, object]:
        if self.completed_at is None or self.conclusion is None:
            raise RouteAPostrunAdmissionError("nonterminal q6 job cannot be a final record")
        return {
            "completedAt": _render_time(self.completed_at),
            "conclusion": self.conclusion,
            "databaseId": self.database_id,
            "name": self.name,
            "startedAt": _render_time(self.started_at),
            "status": self.status,
        }


def _jobs(document: dict[str, object]) -> tuple[_Job, ...]:
    rows = document.get("jobs")
    if (
        type(rows) is not list
        or document.get("total_count") != len(rows)
        or len(rows) != len(_JOBS)
        or any(type(row) is not dict for row in rows)
    ):
        raise RouteAPostrunAdmissionError("q6 provider job set is incomplete")
    by_name: dict[str, dict[str, object]] = {}
    for row in rows:
        name = row.get("name")
        if type(name) is not str or name in by_name:
            raise RouteAPostrunAdmissionError("q6 provider job identity is duplicated")
        by_name[name] = row
    if set(by_name) != set(_JOBS):
        raise RouteAPostrunAdmissionError("q6 provider job names are missing or extra")
    parsed: list[_Job] = []
    identifiers: set[int] = set()
    for name in _JOBS:
        row = by_name[name]
        identifier = row.get("id")
        started = _timestamp(row.get("started_at"), field=f"{name}.started_at")
        completed_raw = row.get("completed_at")
        completed = (
            None
            if completed_raw is None
            else _timestamp(completed_raw, field=f"{name}.completed_at")
        )
        conclusion = row.get("conclusion")
        if (
            type(identifier) is not int
            or identifier <= 0
            or identifier in identifiers
            or type(row.get("status")) is not str
            or (conclusion is not None and type(conclusion) is not str)
        ):
            raise RouteAPostrunAdmissionError("q6 provider job type is invalid")
        identifiers.add(identifier)
        parsed.append(
            _Job(
                database_id=identifier,
                name=name,
                started_at=started,
                completed_at=completed,
                status=row["status"],
                conclusion=conclusion,
            )
        )
    for previous, job in zip(parsed, parsed[1:], strict=False):
        if previous.completed_at is None or job.started_at < previous.completed_at:
            raise RouteAPostrunAdmissionError("qualification jobs are not strictly serial")
    for job in parsed[:5]:
        if (
            job.status != "completed"
            or job.conclusion != "success"
            or job.completed_at is None
            or job.completed_at < job.started_at
        ):
            raise RouteAPostrunAdmissionError("q1 through q5 are not terminal successes")
    q6 = parsed[5]
    if q6.status != "in_progress" or q6.conclusion is not None or q6.completed_at is not None:
        raise RouteAPostrunAdmissionError("q6 did not observe its own live in-progress state")
    return tuple(parsed)


def _validate_prefix_artifacts(
    document: dict[str, object],
    *,
    expected_head_sha: str,
    expected_run_id: int,
) -> None:
    if type(expected_run_id) is not int or expected_run_id <= 0:
        raise RouteAPostrunAdmissionError("q6 expected provider run ID is invalid")
    rows = document.get("artifacts")
    if (
        type(rows) is not list
        or document.get("total_count") != len(rows)
        or len(rows) != len(_PREFIX_ARTIFACTS)
        or any(type(row) is not dict for row in rows)
    ):
        raise RouteAPostrunAdmissionError("q6 prefix artifact set is incomplete")
    by_name: dict[str, dict[str, object]] = {}
    identifiers: set[int] = set()
    for row in rows:
        name = row.get("name")
        identifier = row.get("id")
        workflow_run = row.get("workflow_run")
        if (
            type(name) is not str
            or name in by_name
            or type(identifier) is not int
            or identifier <= 0
            or identifier in identifiers
            or type(row.get("digest")) is not str
            or _PROVIDER_DIGEST.fullmatch(row["digest"]) is None
            or type(row.get("size_in_bytes")) is not int
            or row["size_in_bytes"] <= 0
            or row.get("expired") is not False
            or type(workflow_run) is not dict
            or workflow_run.get("id") != expected_run_id
            or workflow_run.get("head_sha") != expected_head_sha
        ):
            raise RouteAPostrunAdmissionError("q6 prefix artifact identity is invalid")
        identifiers.add(identifier)
        by_name[name] = row
    if set(by_name) != set(_PREFIX_ARTIFACTS):
        raise RouteAPostrunAdmissionError("q6 prefix artifact names are missing or extra")


@dataclass(frozen=True, slots=True)
class RouteAPostrunAdmissionInspection:
    root: Path
    record_bytes: bytes
    record_sha256: str
    record: dict[str, object]


def inspect_route_a_postrun_admission(root: Path) -> RouteAPostrunAdmissionInspection:
    """Close q6's two-file local tree before the provider wraps it."""

    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RouteAPostrunAdmissionError("q6 output root is unsafe")
    if tuple(sorted(path.name for path in root.iterdir())) != (
        _CHECKSUMS_NAME,
        _RECORD_NAME,
    ):
        raise RouteAPostrunAdmissionError("q6 output members are missing or extra")
    record_bytes = _stable_read(root / _RECORD_NAME, maximum=_MAX_RECORD_BYTES)
    record = _canonical_object(record_bytes, field="q6 postrun record")
    checksum = _stable_read(root / _CHECKSUMS_NAME, maximum=_MAX_RECORD_BYTES)
    digest = hashlib.sha256(record_bytes).hexdigest()
    if checksum != f"{digest}  {_RECORD_NAME}\n".encode("ascii"):
        raise RouteAPostrunAdmissionError("q6 checksum differs from its record")
    if (
        set(record)
        != {
            "authority",
            "cancellation_ledger",
            "computational_45_minute_gate",
            "formal_execution_authorized",
            "frozen_q6_deadline_utc",
            "jobs_q1_through_q5",
            "native_c_q_seconds",
            "native_planning_screen",
            "native_six_c_q_seconds",
            "q6",
            "qualification_computational_seconds",
            "record_observed_utc",
            "run",
            "schema_version",
        }
        or record.get("schema_version") != _SCHEMA
        or record.get("authority") is not False
        or record.get("formal_execution_authorized") is not False
        or record.get("computational_45_minute_gate") != "pass"
        or record.get("native_planning_screen") != "pass"
        or record.get("cancellation_ledger") is not None
    ):
        raise RouteAPostrunAdmissionError("q6 record shape or authority changed")
    return RouteAPostrunAdmissionInspection(
        root=root,
        record_bytes=record_bytes,
        record_sha256=digest,
        record=record,
    )


def produce_route_a_postrun_admission(
    *,
    run_json_path: Path,
    jobs_json_path: Path,
    artifacts_json_path: Path,
    expected_run_id: int,
    expected_s2_git_sha: str,
    expected_head_branch: str,
    expected_run_attempt: int,
    output_directory: Path,
    observed_at: datetime | None = None,
) -> RouteAPostrunAdmissionInspection:
    """Validate live q1-q5/q6 provider state and write q6's authority-false record."""

    if (
        type(expected_run_id) is not int
        or expected_run_id <= 0
        or _LOWER_GIT_SHA.fullmatch(expected_s2_git_sha) is None
        or expected_head_branch != "main"
        or expected_run_attempt != 1
    ):
        raise RouteAPostrunAdmissionError("q6 expected run identity is invalid")
    if (
        not output_directory.is_absolute()
        or output_directory.exists()
        or output_directory.is_symlink()
    ):
        raise RouteAPostrunAdmissionError("q6 output target is unsafe")
    run = _provider_object(
        _stable_read(run_json_path, maximum=_MAX_PROVIDER_BYTES),
        field="q6 provider run",
    )
    if (
        run.get("id") != expected_run_id
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != expected_s2_git_sha
        or run.get("head_branch") != expected_head_branch
        or run.get("run_attempt") != expected_run_attempt
        or run.get("status") != "in_progress"
        or run.get("conclusion") is not None
    ):
        raise RouteAPostrunAdmissionError("q6 provider run is not the exact live run")
    jobs = _jobs(
        _provider_object(
            _stable_read(jobs_json_path, maximum=_MAX_PROVIDER_BYTES),
            field="q6 provider jobs",
        )
    )
    _validate_prefix_artifacts(
        _provider_object(
            _stable_read(artifacts_json_path, maximum=_MAX_PROVIDER_BYTES),
            field="q6 provider artifacts",
        ),
        expected_head_sha=expected_s2_git_sha,
        expected_run_id=expected_run_id,
    )
    q1, _q2, q3, q4, q5, q6 = jobs
    assert q5.completed_at is not None
    current = observed_at if observed_at is not None else datetime.now(UTC).replace(microsecond=0)
    if type(current) is not datetime or current.tzinfo is None:
        raise RouteAPostrunAdmissionError("q6 observation time is not timezone-aware")
    current = current.astimezone(UTC)
    computational = _seconds(q5.completed_at - q1.started_at, field="computational path")
    native = sum(
        _seconds(job.completed_at - job.started_at, field="native job")
        for job in (q3, q4, q5)
        if job.completed_at is not None
    )
    deadline = q5.completed_at + timedelta(seconds=_Q6_WALL_SECONDS)
    if (
        computational > _COMPUTATIONAL_SECONDS
        or 6 * native > _NATIVE_SCREEN_SECONDS
        or q6.started_at > deadline
        or current < q6.started_at
        or current > deadline
        or current - q1.started_at > timedelta(seconds=_TOTAL_SECONDS)
    ):
        raise RouteAPostrunAdmissionError("q6 resource admission screen did not pass")
    record = {
        "authority": False,
        "cancellation_ledger": None,
        "computational_45_minute_gate": "pass",
        "formal_execution_authorized": False,
        "frozen_q6_deadline_utc": _render_time(deadline),
        "jobs_q1_through_q5": [job.final_document for job in jobs[:5]],
        "native_c_q_seconds": native,
        "native_planning_screen": "pass",
        "native_six_c_q_seconds": 6 * native,
        "q6": {
            "databaseId": q6.database_id,
            "name": q6.name,
            "startedAt": _render_time(q6.started_at),
        },
        "qualification_computational_seconds": computational,
        "record_observed_utc": _render_time(current),
        "run": {
            "attempt": expected_run_attempt,
            "databaseId": expected_run_id,
            "event": "workflow_dispatch",
            "headBranch": expected_head_branch,
            "headSha": expected_s2_git_sha,
        },
        "schema_version": _SCHEMA,
    }
    output_directory.mkdir(mode=0o700)
    try:
        record_bytes = canonical_route_a_document(record)
        _write_new(output_directory / _RECORD_NAME, record_bytes)
        _write_new(
            output_directory / _CHECKSUMS_NAME,
            f"{hashlib.sha256(record_bytes).hexdigest()}  {_RECORD_NAME}\n".encode(
                "ascii"
            ),
        )
        return inspect_route_a_postrun_admission(output_directory)
    except BaseException:
        for path in output_directory.iterdir():
            path.unlink()
        output_directory.rmdir()
        raise
