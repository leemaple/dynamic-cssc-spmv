from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.followup_performance_formal_timing import (
    FollowupFormalTimingError,
    inspect_followup_formal_timing_prefix,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

PLAN = b'{"formal_timing_sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="formal-timing-sentinel",
    qualification_seed=92_001,
    formal_seeds=(92_002, 92_003, 92_004),
    query_vector_seed=9_200_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=404,
        provider_run_attempt=1,
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _provider_documents() -> tuple[bytes, dict[str, object]]:
    run = {
        "conclusion": None,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": "2" * 40,
        "id": 404,
        "path": ".github/workflows/followup-performance-formal.yml",
        "run_attempt": 1,
        "status": "in_progress",
    }
    jobs: list[dict[str, object]] = []
    cursor = datetime(2026, 8, 30, 0, 0, tzinfo=UTC)
    for index, spec in enumerate(followup_formal_unit_specs(PROFILE)):
        producer_start = cursor
        producer_end = producer_start + timedelta(seconds=5)
        guard_start = producer_end + timedelta(seconds=1)
        guard_end = guard_start + timedelta(seconds=4)
        for ordinal, (name, started, completed) in enumerate(
            (
                (spec.producer_job_name, producer_start, producer_end),
                (spec.guard_job_name, guard_start, guard_end),
            )
        ):
            jobs.append(
                {
                    "completed_at": _timestamp(completed),
                    "conclusion": "success",
                    "id": 1_000 + index * 2 + ordinal,
                    "name": name,
                    "run_attempt": 1,
                    "run_id": 404,
                    "started_at": _timestamp(started),
                    "status": "completed",
                }
            )
        cursor = guard_end + timedelta(seconds=1)
    return _canonical_json_bytes(run), {"jobs": jobs, "total_count": len(jobs)}


def test_formal_timing_closes_exact_serial_matrix_and_budgets() -> None:
    run, jobs = _provider_documents()
    ledger = inspect_followup_formal_timing_prefix(
        run,
        _canonical_json_bytes(jobs),
        lineage=_lineage(),
        scientific_profile=PROFILE,
    )

    assert len(ledger.document["units"]) == 17
    assert ledger.document["provider_retry_used"] is False
    assert ledger.document["total_ordinary_runner_seconds"] == 17 * 9
    assert sum(spec.reservation_minutes for spec in followup_formal_unit_specs(PROFILE)) == 630


def test_formal_timing_rejects_overlap_and_reservation_overrun() -> None:
    run, jobs = _provider_documents()
    second_producer = jobs["jobs"][2]  # type: ignore[index]
    first_guard = jobs["jobs"][1]  # type: ignore[index]
    second_producer["started_at"] = first_guard["started_at"]  # type: ignore[index]

    with pytest.raises(FollowupFormalTimingError, match="overlap"):
        inspect_followup_formal_timing_prefix(
            run,
            _canonical_json_bytes(jobs),
            lineage=_lineage(),
            scientific_profile=PROFILE,
        )

    _run, overrun_jobs = _provider_documents()
    first_guard = overrun_jobs["jobs"][1]  # type: ignore[index]
    first_guard["completed_at"] = "2026-08-30T00:20:01Z"  # type: ignore[index]
    with pytest.raises(FollowupFormalTimingError, match="budget"):
        inspect_followup_formal_timing_prefix(
            run,
            _canonical_json_bytes(overrun_jobs),
            lineage=_lineage(),
            scientific_profile=PROFILE,
        )
