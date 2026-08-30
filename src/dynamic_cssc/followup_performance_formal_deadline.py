"""Fail-closed provider-clock deadline checks for one formal unit run."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_formal_matrix import FollowupFormalUnitSpec

__all__ = (
    "FollowupFormalDeadlineCheckpoint",
    "FollowupFormalDeadlineError",
    "inspect_followup_formal_phase_deadline",
)

FollowupFormalPhase = Literal["private-handoff", "guarded-final"]

_SCHEMA = "dynamic-cssc-followup-performance-formal-provider-deadline-v1"
_WORKFLOW_PATH = ".github/workflows/followup-performance-formal-unit.yml"
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
_NOT_STARTED_STATUSES = frozenset({"pending", "queued", "requested", "waiting"})


class FollowupFormalDeadlineError(FollowupContractError):
    """The exact provider run cannot safely execute another formal stage."""


def _object(content: bytes, *, label: str) -> dict[str, object]:
    value = _parse_ascii_json(content, label=label)
    if type(value) is not dict:
        raise FollowupFormalDeadlineError(f"{label} is not one object")
    return value


def _positive_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise FollowupFormalDeadlineError(f"{field} is not a positive integer")
    return value


def _timestamp(value: object, *, field: str) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise FollowupFormalDeadlineError(f"{field} is not provider UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:  # pragma: no cover - syntax is already narrowed
        raise FollowupFormalDeadlineError(f"{field} is not a real timestamp") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise FollowupFormalDeadlineError(f"{field} is not canonical provider UTC")
    return parsed


def _render(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _jobs(content: bytes, *, expected_run_id: int) -> dict[str, dict[str, object]]:
    document = _object(content, label="formal jobs API response")
    rows = document.get("jobs")
    if (
        type(rows) is not list
        or document.get("total_count") != len(rows)
        or len(rows) > 2
        or any(type(row) is not dict for row in rows)
    ):
        raise FollowupFormalDeadlineError("formal jobs API response is incomplete")
    by_name: dict[str, dict[str, object]] = {}
    identifiers: set[int] = set()
    for raw in rows:
        assert type(raw) is dict
        name = raw.get("name")
        identifier = _positive_integer(raw.get("id"), field="formal job.id")
        if (
            type(name) is not str
            or name in by_name
            or identifier in identifiers
            or raw.get("run_id") != expected_run_id
            or raw.get("run_attempt") != 1
        ):
            raise FollowupFormalDeadlineError("formal provider job identity changed")
        by_name[name] = raw
        identifiers.add(identifier)
    return by_name


def _running_job(
    job: dict[str, object],
    *,
    expected_name: str,
) -> tuple[int, datetime]:
    if (
        job.get("name") != expected_name
        or job.get("status") != "in_progress"
        or job.get("conclusion") is not None
        or job.get("completed_at") is not None
    ):
        raise FollowupFormalDeadlineError(f"{expected_name} is not the running job")
    started = _timestamp(job.get("started_at"), field=f"{expected_name}.started_at")
    return _positive_integer(job.get("id"), field=f"{expected_name}.id"), started


def _successful_job(
    job: dict[str, object],
    *,
    expected_name: str,
) -> tuple[datetime, datetime]:
    if (
        job.get("name") != expected_name
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
    ):
        raise FollowupFormalDeadlineError(f"{expected_name} is not successful")
    started = _timestamp(job.get("started_at"), field=f"{expected_name}.started_at")
    completed = _timestamp(
        job.get("completed_at"),
        field=f"{expected_name}.completed_at",
    )
    if completed < started:
        raise FollowupFormalDeadlineError(f"{expected_name} has negative duration")
    return started, completed


def _not_started(job: dict[str, object], *, expected_name: str) -> None:
    if (
        job.get("name") != expected_name
        or job.get("status") not in _NOT_STARTED_STATUSES
        or job.get("conclusion") is not None
        or job.get("started_at") is not None
        or job.get("completed_at") is not None
    ):
        raise FollowupFormalDeadlineError(
            f"{expected_name} started before its producer closed"
        )


@dataclass(frozen=True, slots=True)
class FollowupFormalDeadlineCheckpoint:
    """One non-authorizing provider-clock observation of the shared deadline."""

    document: dict[str, object]
    document_bytes: bytes
    sha256: str
    remaining_seconds: int


def inspect_followup_formal_phase_deadline(
    run_json: bytes,
    jobs_json: bytes,
    *,
    provider_observed_at: datetime,
    expected_run_id: int,
    expected_s2: str,
    spec: FollowupFormalUnitSpec,
    phase: FollowupFormalPhase,
    checkpoint: str,
    require_positive_remaining: bool,
    expected_head_branch: str = "main",
) -> FollowupFormalDeadlineCheckpoint:
    """Rebind a live phase to the producer-start shared reservation.

    The provider ``Date`` observation, never the runner wall clock, determines
    whether another stage may start.  A final zero-second observation may be
    recorded, but no new stage may start with zero seconds remaining.
    """

    if type(spec) is not FollowupFormalUnitSpec:
        raise TypeError("spec must be an exact FollowupFormalUnitSpec")
    _positive_integer(expected_run_id, field="formal run ID")
    if _LOWER_GIT_SHA.fullmatch(expected_s2) is None:
        raise FollowupFormalDeadlineError("expected S2 is not a lowercase Git SHA")
    if phase not in {"private-handoff", "guarded-final"}:
        raise FollowupFormalDeadlineError("formal phase is not frozen")
    if type(checkpoint) is not str or not checkpoint or len(checkpoint) > 80:
        raise FollowupFormalDeadlineError("deadline checkpoint label is invalid")
    if type(require_positive_remaining) is not bool:
        raise TypeError("require_positive_remaining must be bool")
    if (
        type(provider_observed_at) is not datetime
        or provider_observed_at.tzinfo is None
        or provider_observed_at.utcoffset() != timedelta(0)
        or provider_observed_at.microsecond != 0
    ):
        raise FollowupFormalDeadlineError(
            "provider observation is not exact UTC seconds"
        )
    run = _object(run_json, label="formal run API response")
    if (
        run.get("id") != expected_run_id
        or run.get("run_attempt") != 1
        or run.get("path") != _WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != expected_s2
        or run.get("head_branch") != expected_head_branch
        or run.get("status") != "in_progress"
        or run.get("conclusion") is not None
    ):
        raise FollowupFormalDeadlineError("formal live run identity changed")
    by_name = _jobs(jobs_json, expected_run_id=expected_run_id)
    expected_names = {spec.producer_job_name, spec.guard_job_name}
    if not set(by_name) <= expected_names:
        raise FollowupFormalDeadlineError("formal run contains an extra job")
    producer = by_name.get(spec.producer_job_name)
    if producer is None:
        raise FollowupFormalDeadlineError("formal producer job is absent")

    if phase == "private-handoff":
        current_job_id, producer_started = _running_job(
            producer,
            expected_name=spec.producer_job_name,
        )
        guard = by_name.get(spec.guard_job_name)
        if guard is not None:
            _not_started(guard, expected_name=spec.guard_job_name)
    else:
        producer_started, producer_completed = _successful_job(
            producer,
            expected_name=spec.producer_job_name,
        )
        guard = by_name.get(spec.guard_job_name)
        if guard is None:
            raise FollowupFormalDeadlineError("formal guard job is absent")
        current_job_id, guard_started = _running_job(
            guard,
            expected_name=spec.guard_job_name,
        )
        if guard_started < producer_completed:
            raise FollowupFormalDeadlineError("formal guard overlapped its producer")

    if provider_observed_at < producer_started:
        raise FollowupFormalDeadlineError("provider Date predates producer startedAt")
    deadline = producer_started + timedelta(minutes=spec.reservation_minutes)
    if provider_observed_at > deadline:
        raise FollowupFormalDeadlineError("formal unit exceeded its shared reservation")
    remaining = int((deadline - provider_observed_at).total_seconds())
    if require_positive_remaining and remaining <= 0:
        raise FollowupFormalDeadlineError(
            "formal unit has no shared reservation left for another stage"
        )
    document: dict[str, object] = {
        "authority": False,
        "checkpoint": checkpoint,
        "current_job_id": current_job_id,
        "evidence_freeze_S2_sha": expected_s2,
        "formal_unit_deadline_utc": _render(deadline),
        "formal_unit_ordinal": spec.ordinal,
        "job_token": spec.job_token,
        "phase": phase,
        "producer_started_at_utc": _render(producer_started),
        "provider_observed_at_utc": _render(provider_observed_at),
        "provider_run_attempt": 1,
        "provider_run_id": expected_run_id,
        "publication_evidence_admitted": False,
        "remaining_seconds": remaining,
        "reservation_minutes": spec.reservation_minutes,
        "schema_version": _SCHEMA,
    }
    document_bytes = _canonical_json_bytes(document)
    return FollowupFormalDeadlineCheckpoint(
        document=document,
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
        remaining_seconds=remaining,
    )
