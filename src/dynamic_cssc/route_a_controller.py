"""Fail-closed live admission for the bounded Route A publication workflow.

The controller consumes one fresh, normalized provider observation.  It does
not persist an authorization bit: the only positive result is an opaque,
single-use capability that must remain in the issuing process.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import threading
import weakref
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

__all__ = (
    "RouteAArtifactSnapshot",
    "RouteAControllerError",
    "RouteAJobSnapshot",
    "RouteAProviderObservation",
    "RouteAQualificationCapability",
    "RouteAQualificationRequest",
    "RouteARunSnapshot",
    "abandon_route_a_qualification_capability",
    "authorize_route_a_qualification",
    "claim_route_a_qualification_capability",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_QUALIFICATION_JOB_NAMES = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)
_Q6_ARTIFACT_NAME = "q6-postrun-resource-admission-record"
_Q6_RECORD_SCHEMA = "dynamic-cssc-route-a-q6-postrun-resource-admission-v1"
_PLAN_SCHEMA = "dynamic-cssc-route-a-publication-plan-v3"
_PLAN_SHA256 = "c391119d36ea882919cf787167baa9c80f346d2860fce9e3b8f98421a034fbfb"
_MAX_OBSERVATION_AGE = timedelta(seconds=30)
_COMPUTATIONAL_LIMIT = timedelta(minutes=45)
_Q6_JOB_LIMIT = timedelta(minutes=5)
_Q6_WALL_LIMIT = timedelta(minutes=10)
_TOTAL_PATH_LIMIT = timedelta(minutes=55)
_NATIVE_SCREEN_SECONDS = 9_000
_MAX_Q6_ARCHIVE_BYTES = 2 * 1024 * 1024
_MAX_Q6_RECORD_BYTES = 1024 * 1024
_MAX_PLAN_BYTES = 256 * 1024
_Q6_RECORD_NAME = "route-a-qualification-postrun.json"
_CHECKSUMS_NAME = "checksums.sha256"


class RouteAControllerError(RuntimeError):
    """The live provider observation cannot authorize Route A dispatch."""


@dataclass(frozen=True, slots=True)
class RouteARunSnapshot:
    database_id: int
    event: str
    head_sha: str
    head_branch: str
    attempt: int
    status: str
    conclusion: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class RouteAJobSnapshot:
    database_id: int
    name: str
    started_at: datetime
    completed_at: datetime
    status: str
    conclusion: str


@dataclass(frozen=True, slots=True)
class RouteAArtifactSnapshot:
    database_id: int
    name: str
    digest: str
    size_in_bytes: int
    expired: bool
    workflow_run_head_sha: str


@dataclass(frozen=True, slots=True)
class RouteAProviderObservation:
    observed_at: datetime
    plan_bytes: bytes
    run: RouteARunSnapshot
    jobs: tuple[RouteAJobSnapshot, ...]
    q6_artifact: RouteAArtifactSnapshot
    q6_archive_bytes: bytes


@dataclass(frozen=True, slots=True)
class RouteAQualificationRequest:
    run_id: int
    expected_s2_git_sha: str
    expected_head_branch: str
    expected_run_attempt: int


@dataclass(frozen=True, slots=True)
class _QualificationRequestIdentity:
    """Detached request values owned by the controller after validation."""

    run_id: int
    expected_s2_git_sha: str
    expected_head_branch: str
    expected_run_attempt: int


class _QualificationProvider(Protocol):
    def read_qualification(self, run_id: int) -> RouteAProviderObservation: ...


@dataclass(frozen=True, slots=True)
class _QualificationBinding:
    request_identity: _QualificationRequestIdentity
    plan_sha256: str
    provider_run_updated_at: datetime
    controller_observed_at: datetime
    expires_at: datetime
    q6_artifact_id: int
    q6_artifact_digest: str


class _QualificationToken:
    """Unforgeable-by-construction in-process link to a registry-owned binding."""

    __slots__ = ()


class RouteAQualificationCapability:
    """Opaque one-shot result of an exact live qualification inspection."""

    __slots__ = ("_binding_token", "_lock", "__weakref__")

    def __new__(cls) -> RouteAQualificationCapability:
        raise TypeError("Route A qualification capabilities are controller-minted")

    def __bool__(self) -> bool:
        raise TypeError("Route A qualification capability is not a Boolean")


@dataclass(frozen=True, slots=True)
class _IssuedCapability:
    capability_ref: weakref.ReferenceType[RouteAQualificationCapability]
    binding_token: _QualificationToken
    binding: _QualificationBinding


_ISSUED_CAPABILITIES: dict[int, _IssuedCapability] = {}
_ISSUED_CAPABILITIES_LOCK = threading.Lock()


def _utc_now() -> datetime:
    """Return the live controller clock; tests may replace this private seam."""

    return datetime.now(UTC)


def _discard_issued_capability(
    capability_id: int,
    capability_ref: weakref.ReferenceType[RouteAQualificationCapability],
) -> None:
    with _ISSUED_CAPABILITIES_LOCK:
        issued = _ISSUED_CAPABILITIES.get(capability_id)
        if issued is not None and issued.capability_ref is capability_ref:
            _ISSUED_CAPABILITIES.pop(capability_id, None)


def _require_utc(value: datetime, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise RouteAControllerError(f"{field} must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.utcoffset() != timedelta(0):  # pragma: no cover - astimezone owns this
        raise RouteAControllerError(f"{field} must normalize to UTC")
    return normalized


def _timestamp(value: object, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise RouteAControllerError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RouteAControllerError(f"{field} must be a canonical UTC timestamp") from error
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise RouteAControllerError(f"{field} must be a canonical UTC timestamp")
    return parsed


def _seconds(value: timedelta, field: str) -> int:
    seconds = value.total_seconds()
    if seconds < 0 or not seconds.is_integer():
        raise RouteAControllerError(f"{field} must be a nonnegative whole-second duration")
    return int(seconds)


def _freeze_request(
    request: RouteAQualificationRequest,
) -> _QualificationRequestIdentity:
    if type(request) is not RouteAQualificationRequest:
        raise TypeError("request must be an exact RouteAQualificationRequest")
    identity = _QualificationRequestIdentity(
        run_id=request.run_id,
        expected_s2_git_sha=request.expected_s2_git_sha,
        expected_head_branch=request.expected_head_branch,
        expected_run_attempt=request.expected_run_attempt,
    )
    if type(identity.run_id) is not int or identity.run_id <= 0:
        raise RouteAControllerError("qualification run ID must be a positive strict integer")
    if (
        type(identity.expected_s2_git_sha) is not str
        or _LOWER_GIT_SHA.fullmatch(identity.expected_s2_git_sha) is None
    ):
        raise RouteAControllerError("expected S2 Git SHA is invalid")
    if (
        type(identity.expected_head_branch) is not str
        or identity.expected_head_branch != "main"
    ):
        raise RouteAControllerError("qualification must be controlled from terminal S2 on main")
    if (
        type(identity.expected_run_attempt) is not int
        or identity.expected_run_attempt != 1
    ):
        raise RouteAControllerError("qualification is one-shot and requires run attempt one")
    return identity


def _validate_run(
    run: RouteARunSnapshot,
    request: _QualificationRequestIdentity,
    observed_at: datetime,
) -> None:
    if type(run) is not RouteARunSnapshot:
        raise RouteAControllerError("qualification run snapshot type is invalid")
    created_at = _require_utc(run.created_at, "run createdAt")
    updated_at = _require_utc(run.updated_at, "run updatedAt")
    if (
        type(run.database_id) is not int
        or run.database_id != request.run_id
        or type(run.event) is not str
        or run.event != "workflow_dispatch"
        or type(run.head_sha) is not str
        or run.head_sha != request.expected_s2_git_sha
        or type(run.head_branch) is not str
        or run.head_branch != request.expected_head_branch
        or type(run.attempt) is not int
        or run.attempt != request.expected_run_attempt
        or type(run.status) is not str
        or run.status != "completed"
        or type(run.conclusion) is not str
        or run.conclusion != "success"
        or created_at > updated_at
        or updated_at > observed_at
    ):
        raise RouteAControllerError(
            "qualification run identity is not the exact terminal success"
        )


def _validate_jobs(jobs: tuple[RouteAJobSnapshot, ...]) -> tuple[RouteAJobSnapshot, ...]:
    if type(jobs) is not tuple:
        raise RouteAControllerError("qualification job collection type is invalid")
    if any(type(job) is not RouteAJobSnapshot for job in jobs):
        raise RouteAControllerError("qualification job snapshot type is invalid")
    if tuple(job.name for job in jobs) != _QUALIFICATION_JOB_NAMES:
        raise RouteAControllerError(
            "qualification job identity set is missing, extra, or reordered"
        )
    identifiers: set[int] = set()
    previous_completed_at: datetime | None = None
    for job in jobs:
        started_at = _require_utc(job.started_at, f"{job.name} startedAt")
        completed_at = _require_utc(job.completed_at, f"{job.name} completedAt")
        if (
            type(job.database_id) is not int
            or job.database_id <= 0
            or job.database_id in identifiers
            or job.status != "completed"
            or job.conclusion != "success"
            or completed_at < started_at
            or (previous_completed_at is not None and started_at < previous_completed_at)
        ):
            raise RouteAControllerError("qualification jobs are not exact serial successes")
        identifiers.add(job.database_id)
        previous_completed_at = completed_at
    q1, _, q3, q4, q5, q6 = jobs
    if q5.completed_at - q1.started_at > _COMPUTATIONAL_LIMIT:
        raise RouteAControllerError("qualification exceeded the 45-minute computational gate")
    if q6.completed_at - q6.started_at > _Q6_JOB_LIMIT:
        raise RouteAControllerError("qualification q6 exceeded its five-minute job limit")
    if q6.completed_at - q5.completed_at > _Q6_WALL_LIMIT:
        raise RouteAControllerError("qualification q6 missed its frozen wall deadline")
    if q6.completed_at - q1.started_at > _TOTAL_PATH_LIMIT:
        raise RouteAControllerError("qualification exceeded the 55-minute total path gate")
    native_seconds = sum(
        _seconds(job.completed_at - job.started_at, "native job duration")
        for job in (q3, q4, q5)
    )
    if 6 * native_seconds > _NATIVE_SCREEN_SECONDS:
        raise RouteAControllerError("qualification failed the native 6*C_q planning screen")
    return jobs


def _job_record(job: RouteAJobSnapshot) -> dict[str, object]:
    return {
        "databaseId": job.database_id,
        "name": job.name,
        "startedAt": job.started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "completedAt": job.completed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "status": job.status,
        "conclusion": job.conclusion,
    }


def _validate_q6_record(
    record: Mapping[str, object],
    run: RouteARunSnapshot,
    jobs: tuple[RouteAJobSnapshot, ...],
) -> None:
    expected_keys = {
        "schema_version",
        "authority",
        "formal_execution_authorized",
        "run",
        "jobs_q1_through_q5",
        "q6",
        "record_observed_utc",
        "frozen_q6_deadline_utc",
        "qualification_computational_seconds",
        "native_c_q_seconds",
        "native_six_c_q_seconds",
        "computational_45_minute_gate",
        "native_planning_screen",
        "cancellation_ledger",
    }
    if type(record) is not dict or set(record) != expected_keys:
        raise RouteAControllerError("q6 record has a non-closed top-level shape")
    run_record = record.get("run")
    job_records = record.get("jobs_q1_through_q5")
    q6_record = record.get("q6")
    if (
        type(run_record) is not dict
        or set(run_record) != {"databaseId", "event", "headSha", "headBranch", "attempt"}
        or type(run_record.get("databaseId")) is not int
        or type(run_record.get("event")) is not str
        or type(run_record.get("headSha")) is not str
        or type(run_record.get("headBranch")) is not str
        or type(run_record.get("attempt")) is not int
        or type(job_records) is not list
        or len(job_records) != 5
        or any(
            type(item) is not dict
            or set(item)
            != {"databaseId", "name", "startedAt", "completedAt", "status", "conclusion"}
            or type(item.get("databaseId")) is not int
            or any(
                type(item.get(field)) is not str
                for field in ("name", "startedAt", "completedAt", "status", "conclusion")
            )
            for item in job_records
        )
        or type(q6_record) is not dict
        or set(q6_record) != {"databaseId", "name", "startedAt"}
        or type(q6_record.get("databaseId")) is not int
        or type(q6_record.get("name")) is not str
        or type(q6_record.get("startedAt")) is not str
        or type(record.get("authority")) is not bool
        or type(record.get("formal_execution_authorized")) is not bool
        or any(
            type(record.get(field)) is not int
            for field in (
                "qualification_computational_seconds",
                "native_c_q_seconds",
                "native_six_c_q_seconds",
            )
        )
        or type(record.get("computational_45_minute_gate")) is not str
        or type(record.get("native_planning_screen")) is not str
    ):
        raise RouteAControllerError("q6 record contains a non-exact typed identity")
    expected_run = {
        "databaseId": run.database_id,
        "event": run.event,
        "headSha": run.head_sha,
        "headBranch": run.head_branch,
        "attempt": run.attempt,
    }
    expected_q6 = {
        "databaseId": jobs[5].database_id,
        "name": jobs[5].name,
        "startedAt": jobs[5].started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }
    q1, _, q3, q4, q5, q6 = jobs
    computational_seconds = _seconds(q5.completed_at - q1.started_at, "critical path")
    native_seconds = sum(
        _seconds(job.completed_at - job.started_at, "native job duration")
        for job in (q3, q4, q5)
    )
    record_observed_at = _timestamp(record.get("record_observed_utc"), "record observation")
    frozen_q6_deadline = _timestamp(record.get("frozen_q6_deadline_utc"), "q6 deadline")
    if (
        record.get("schema_version") != _Q6_RECORD_SCHEMA
        or record.get("authority") is not False
        or record.get("formal_execution_authorized") is not False
        or record.get("run") != expected_run
        or record.get("jobs_q1_through_q5") != [_job_record(job) for job in jobs[:5]]
        or record.get("q6") != expected_q6
        or record_observed_at < q6.started_at
        or record_observed_at > q6.completed_at
        or frozen_q6_deadline != q5.completed_at + _Q6_WALL_LIMIT
        or record.get("qualification_computational_seconds") != computational_seconds
        or record.get("native_c_q_seconds") != native_seconds
        or record.get("native_six_c_q_seconds") != 6 * native_seconds
        or record.get("computational_45_minute_gate") != "pass"
        or record.get("native_planning_screen") != "pass"
        or record.get("cancellation_ledger") is not None
    ):
        raise RouteAControllerError("q6 record does not match the final provider state")


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
        raise RouteAControllerError("q6 record is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _validate_frozen_plan(plan_bytes: bytes) -> str:
    if type(plan_bytes) is not bytes or not plan_bytes or len(plan_bytes) > _MAX_PLAN_BYTES:
        raise RouteAControllerError("Route A plan violates its retained-byte bound")
    digest = hashlib.sha256(plan_bytes).hexdigest()
    if digest != _PLAN_SHA256:
        raise RouteAControllerError("Route A plan does not match the preregistered digest")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAControllerError("Route A plan contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(plan_bytes, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAControllerError("Route A plan is not readable JSON") from error
    if (
        type(document) is not dict
        or document.get("schema_version") != _PLAN_SCHEMA
        or type(document.get("authority")) is not dict
        or document["authority"].get("formal_execution_authorized") is not False
    ):
        raise RouteAControllerError("Route A plan identity or authority boundary is invalid")
    return digest


def _decode_q6_archive(archive_bytes: bytes) -> dict[str, object]:
    if (
        type(archive_bytes) is not bytes
        or not archive_bytes
        or len(archive_bytes) > _MAX_Q6_ARCHIVE_BYTES
    ):
        raise RouteAControllerError("q6 artifact archive violates its byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            members = archive.infolist()
            if [member.filename for member in members] != [_Q6_RECORD_NAME, _CHECKSUMS_NAME]:
                raise RouteAControllerError("q6 artifact archive has missing or extra members")
            if any(
                member.is_dir()
                or member.flag_bits & 0x1
                or member.file_size <= 0
                or member.file_size > _MAX_Q6_RECORD_BYTES
                for member in members
            ):
                raise RouteAControllerError("q6 artifact archive member is inadmissible")
            record_bytes = archive.read(_Q6_RECORD_NAME)
            checksums_bytes = archive.read(_CHECKSUMS_NAME)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise RouteAControllerError("q6 artifact is not a readable ZIP archive") from error
    expected_checksums = (
        f"{hashlib.sha256(record_bytes).hexdigest()}  {_Q6_RECORD_NAME}\n".encode("ascii")
    )
    if checksums_bytes != expected_checksums:
        raise RouteAControllerError("q6 artifact checksum does not bind its record")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAControllerError("q6 record contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        record = json.loads(record_bytes, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAControllerError("q6 record is not readable JSON") from error
    if type(record) is not dict or _canonical_json_bytes(record) != record_bytes:
        raise RouteAControllerError("q6 record is not canonical JSON")
    return record


def _validate_artifact(
    artifact: RouteAArtifactSnapshot,
    archive_bytes: bytes,
    source_sha: str,
) -> dict[str, object]:
    if (
        type(artifact) is not RouteAArtifactSnapshot
        or type(artifact.database_id) is not int
        or artifact.database_id <= 0
        or artifact.name != _Q6_ARTIFACT_NAME
        or type(artifact.digest) is not str
        or _PROVIDER_DIGEST.fullmatch(artifact.digest) is None
        or type(artifact.size_in_bytes) is not int
        or artifact.size_in_bytes <= 0
        or artifact.expired is not False
        or artifact.workflow_run_head_sha != source_sha
    ):
        raise RouteAControllerError("q6 artifact is not the exact live provider object")
    if artifact.size_in_bytes != len(archive_bytes):
        raise RouteAControllerError("q6 artifact size differs from the downloaded wrapper")
    observed_digest = "sha256:" + hashlib.sha256(archive_bytes).hexdigest()
    if artifact.digest != observed_digest:
        raise RouteAControllerError("q6 artifact digest differs from the downloaded wrapper")
    return _decode_q6_archive(archive_bytes)


def authorize_route_a_qualification(
    provider: _QualificationProvider,
    request: RouteAQualificationRequest,
) -> RouteAQualificationCapability:
    """Inspect one fresh provider snapshot and mint one ephemeral capability."""

    request_identity = _freeze_request(request)
    try:
        observation = provider.read_qualification(request_identity.run_id)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise RouteAControllerError("qualification provider observation failed") from error
    if type(observation) is not RouteAProviderObservation:
        raise RouteAControllerError("qualification provider returned the wrong snapshot type")
    controller_observed_at = _require_utc(_utc_now(), "controller observation")
    provider_observed_at = _require_utc(observation.observed_at, "provider observation")
    age = controller_observed_at - provider_observed_at
    if age < timedelta(0) or age > _MAX_OBSERVATION_AGE:
        raise RouteAControllerError("qualification provider observation is stale")
    plan_sha256 = _validate_frozen_plan(observation.plan_bytes)
    _validate_run(observation.run, request_identity, provider_observed_at)
    jobs = _validate_jobs(observation.jobs)
    if observation.run.created_at > jobs[0].started_at:
        raise RouteAControllerError("qualification first job predates its run")
    if observation.run.updated_at < jobs[-1].completed_at:
        raise RouteAControllerError("qualification run state predates q6 completion")
    q6_record = _validate_artifact(
        observation.q6_artifact,
        observation.q6_archive_bytes,
        observation.run.head_sha,
    )
    _validate_q6_record(q6_record, observation.run, jobs)

    binding = _QualificationBinding(
        request_identity=request_identity,
        plan_sha256=plan_sha256,
        provider_run_updated_at=observation.run.updated_at,
        controller_observed_at=controller_observed_at,
        expires_at=provider_observed_at + _MAX_OBSERVATION_AGE,
        q6_artifact_id=observation.q6_artifact.database_id,
        q6_artifact_digest=observation.q6_artifact.digest,
    )
    binding_token = _QualificationToken()
    capability = object.__new__(RouteAQualificationCapability)
    object.__setattr__(capability, "_binding_token", binding_token)
    object.__setattr__(capability, "_lock", threading.Lock())
    capability_id = id(capability)
    capability_ref = weakref.ref(
        capability,
        lambda dead_ref: _discard_issued_capability(capability_id, dead_ref),
    )
    with _ISSUED_CAPABILITIES_LOCK:
        _ISSUED_CAPABILITIES[capability_id] = _IssuedCapability(
            capability_ref=capability_ref,
            binding_token=binding_token,
            binding=binding,
        )
    return capability


def _consume_qualification_capability(
    capability: RouteAQualificationCapability,
) -> _QualificationBinding:
    if type(capability) is not RouteAQualificationCapability:
        raise TypeError("capability must be exact controller-minted Route A authority")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise RouteAControllerError("Route A qualification capability is not authoritative")
    with lock, _ISSUED_CAPABILITIES_LOCK:
        issued = _ISSUED_CAPABILITIES.pop(id(capability), None)
        if issued is None or issued.capability_ref() is not capability:
            raise RouteAControllerError(
                "Route A qualification capability is absent or consumed"
            )
        presented_token = getattr(capability, "_binding_token", None)
        object.__setattr__(capability, "_binding_token", None)
    if (
        type(issued) is not _IssuedCapability
        or type(issued.binding) is not _QualificationBinding
        or presented_token is not issued.binding_token
    ):
        raise RouteAControllerError("Route A qualification capability is not authoritative")
    return issued.binding


def claim_route_a_qualification_capability(
    capability: RouteAQualificationCapability,
    request: RouteAQualificationRequest,
) -> None:
    """Consume a controller-minted capability without exposing a replay token."""

    binding = _consume_qualification_capability(capability)
    request_identity = _freeze_request(request)
    if binding.request_identity != request_identity:
        raise RouteAControllerError("Route A qualification binding does not match")
    normalized_claimed_at = _require_utc(_utc_now(), "capability claim")
    if normalized_claimed_at < binding.controller_observed_at:
        raise RouteAControllerError("Route A qualification claim predates its observation")
    if normalized_claimed_at > binding.expires_at:
        raise RouteAControllerError("Route A qualification capability expired before claim")


def abandon_route_a_qualification_capability(
    capability: RouteAQualificationCapability,
) -> None:
    """Consume an unused qualification capability without authorizing dispatch."""

    _consume_qualification_capability(capability)
