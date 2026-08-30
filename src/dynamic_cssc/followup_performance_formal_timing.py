"""Provider-API timing ledger for the frozen formal campaign prefix."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_formal_matrix import (
    followup_formal_unit_specs,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FollowupFormalTimingError",
    "FollowupFormalTimingLedger",
    "inspect_followup_formal_timing_prefix",
)

_SCHEMA = "dynamic-cssc-followup-performance-formal-timing-ledger-v1"
_WORKFLOW_PATH = ".github/workflows/followup-performance-formal.yml"
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_SEGMENT_LIMIT_SECONDS = {
    "acquisition-and-ordered": 3 * 60 * 60,
    "native": 150 * 60,
    "synthetic": 5 * 60 * 60,
}


class FollowupFormalTimingError(FollowupContractError):
    """Formal provider timing, ordering, or budget data failed closed."""


def _object(content: bytes, *, label: str) -> dict[str, object]:
    value = _parse_ascii_json(content, label=label)
    if type(value) is not dict:
        raise FollowupFormalTimingError(f"{label} is not an object")
    return value


def _timestamp(value: object, *, field: str) -> datetime:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise FollowupFormalTimingError(f"{field} is not provider UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:  # pragma: no cover - regex has already narrowed syntax
        raise FollowupFormalTimingError(f"{field} is not a real UTC timestamp") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise FollowupFormalTimingError(f"{field} is not canonical UTC")
    return parsed


def _positive_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise FollowupFormalTimingError(f"{field} is not a positive integer")
    return value


def _job_map(jobs_document: dict[str, object]) -> dict[str, dict[str, object]]:
    jobs = jobs_document.get("jobs")
    total = jobs_document.get("total_count")
    if (
        type(jobs) is not list
        or type(total) is not int
        or total != len(jobs)
        or total > 100
        or any(type(job) is not dict for job in jobs)
    ):
        raise FollowupFormalTimingError("formal jobs API response is incomplete")
    by_name: dict[str, dict[str, object]] = {}
    for raw_job in jobs:
        assert type(raw_job) is dict
        name = raw_job.get("name")
        if type(name) is not str or name in by_name:
            raise FollowupFormalTimingError("formal provider job names are not unique")
        by_name[name] = raw_job
    return by_name


def _closed_success_job(
    job: dict[str, object],
    *,
    expected_name: str,
    expected_run_id: int,
    expected_attempt: int,
) -> tuple[datetime, datetime, dict[str, object]]:
    if (
        job.get("name") != expected_name
        or _positive_integer(job.get("id"), field=f"{expected_name}.id") <= 0
        or job.get("run_id") != expected_run_id
        or job.get("run_attempt") != expected_attempt
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
    ):
        raise FollowupFormalTimingError(f"{expected_name} is not one exact successful job")
    started = _timestamp(job.get("started_at"), field=f"{expected_name}.started_at")
    completed = _timestamp(job.get("completed_at"), field=f"{expected_name}.completed_at")
    if completed < started:
        raise FollowupFormalTimingError(f"{expected_name} has negative duration")
    return started, completed, {
        "completed_at": job["completed_at"],
        "conclusion": "success",
        "job_id": job["id"],
        "job_name": expected_name,
        "started_at": job["started_at"],
    }


@dataclass(frozen=True, slots=True)
class FollowupFormalTimingLedger:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def inspect_followup_formal_timing_prefix(
    run_json: bytes,
    jobs_json: bytes,
    *,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    expected_head_branch: str = "main",
) -> FollowupFormalTimingLedger:
    """Close all 34 unit jobs before terminal admission begins."""

    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    run = _object(run_json, label="formal run API response")
    if (
        run.get("id") != lineage.provider_run_id
        or run.get("run_attempt") != lineage.provider_run_attempt
        or run.get("path") != _WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != lineage.workflow_head_sha
        or run.get("head_branch") != expected_head_branch
        or run.get("status") not in {"in_progress", "queued"}
        or run.get("conclusion") is not None
    ):
        raise FollowupFormalTimingError("formal run identity or live state changed")
    by_name = _job_map(_object(jobs_json, label="formal jobs API response"))
    specs = followup_formal_unit_specs(scientific_profile)
    expected_unit_job_names = {
        name
        for spec in specs
        for name in (spec.producer_job_name, spec.guard_job_name)
    }
    unexpected_unit_jobs = {
        name
        for name in by_name
        if name.startswith("formal-")
        and (name.endswith("-producer") or name.endswith("-independent-replay-and-guard"))
        and name not in expected_unit_job_names
    }
    if unexpected_unit_jobs:
        raise FollowupFormalTimingError("formal run contains an extra unit attempt job")

    rows: list[dict[str, object]] = []
    previous_guard_completed: datetime | None = None
    segment_seconds = {name: 0 for name in _SEGMENT_LIMIT_SECONDS}
    total_runner_seconds = 0
    for spec in specs:
        try:
            producer_job = by_name[spec.producer_job_name]
            guard_job = by_name[spec.guard_job_name]
        except KeyError as error:
            raise FollowupFormalTimingError("formal run lacks one expected unit job") from error
        producer_started, producer_completed, producer_row = _closed_success_job(
            producer_job,
            expected_name=spec.producer_job_name,
            expected_run_id=lineage.provider_run_id,
            expected_attempt=lineage.provider_run_attempt,
        )
        guard_started, guard_completed, guard_row = _closed_success_job(
            guard_job,
            expected_name=spec.guard_job_name,
            expected_run_id=lineage.provider_run_id,
            expected_attempt=lineage.provider_run_attempt,
        )
        if (
            guard_started < producer_completed
            or (
                previous_guard_completed is not None
                and producer_started < previous_guard_completed
            )
        ):
            raise FollowupFormalTimingError("formal jobs overlap or changed serial order")
        critical_seconds = int((guard_completed - producer_started).total_seconds())
        runner_seconds = int(
            (producer_completed - producer_started).total_seconds()
            + (guard_completed - guard_started).total_seconds()
        )
        reservation_seconds = spec.reservation_minutes * 60
        if (
            critical_seconds < 0
            or critical_seconds > reservation_seconds
            or critical_seconds > 60 * 60
            or runner_seconds < 0
            or runner_seconds > critical_seconds
        ):
            raise FollowupFormalTimingError("formal unit exceeded its frozen budget")
        segment_seconds[spec.segment] += runner_seconds
        total_runner_seconds += runner_seconds
        rows.append(
            {
                "critical_path_seconds": critical_seconds,
                "guard": guard_row,
                "producer": producer_row,
                "reservation_seconds": reservation_seconds,
                "runner_seconds": runner_seconds,
                "segment": spec.segment,
                "unit_kind": spec.unit_kind,
                "unit_ordinal": spec.ordinal,
            }
        )
        previous_guard_completed = guard_completed
    if (
        any(
            segment_seconds[name] > limit
            for name, limit in _SEGMENT_LIMIT_SECONDS.items()
        )
        or total_runner_seconds > 630 * 60
    ):
        raise FollowupFormalTimingError("formal segment or ordinary runner budget exceeded")
    document = {
        "authority": False,
        "formal_campaign_provider_run_attempt": lineage.provider_run_attempt,
        "formal_campaign_provider_run_id": lineage.provider_run_id,
        "formal_unit_count": 17,
        "provider_retry_used": False,
        "publication_evidence_admitted": False,
        "schema_version": _SCHEMA,
        "segment_runner_seconds": segment_seconds,
        "study_id": FOLLOWUP_STUDY_ID,
        "total_ordinary_runner_seconds": total_runner_seconds,
        "units": rows,
    }
    document_bytes = _canonical_json_bytes(document)
    return FollowupFormalTimingLedger(
        document=document,
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
    )
