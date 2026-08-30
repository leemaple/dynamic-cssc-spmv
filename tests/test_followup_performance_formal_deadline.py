from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from dynamic_cssc.followup_performance_formal_deadline import (
    FollowupFormalDeadlineError,
    inspect_followup_formal_phase_deadline,
)
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

PLAN = b'{"formal-deadline-sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="formal-deadline-sentinel",
    qualification_seed=98_001,
    formal_seeds=(98_002, 98_003, 98_004),
    query_vector_seed=9_800_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)
RUN_ID = 91_001
S2 = "2" * 40
START = datetime(2026, 8, 30, tzinfo=UTC)


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _run() -> bytes:
    return _bytes(
        {
            "conclusion": None,
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": S2,
            "id": RUN_ID,
            "path": ".github/workflows/followup-performance-formal-unit.yml",
            "run_attempt": 1,
            "status": "in_progress",
        }
    )


def _job(
    *,
    identifier: int,
    name: str,
    status: str,
    started: datetime | None,
    completed: datetime | None,
    conclusion: str | None,
) -> dict[str, object]:
    return {
        "completed_at": None if completed is None else _time(completed),
        "conclusion": conclusion,
        "id": identifier,
        "name": name,
        "run_attempt": 1,
        "run_id": RUN_ID,
        "started_at": None if started is None else _time(started),
        "status": status,
    }


def _producer_jobs(ordinal: int = 0) -> bytes:
    spec = followup_formal_unit_specs(PROFILE)[ordinal]
    rows = [
        _job(
            identifier=1,
            name=spec.producer_job_name,
            status="in_progress",
            started=START,
            completed=None,
            conclusion=None,
        ),
        _job(
            identifier=2,
            name=spec.guard_job_name,
            status="queued",
            started=None,
            completed=None,
            conclusion=None,
        ),
    ]
    return _bytes({"jobs": rows, "total_count": len(rows)})


def _guard_jobs(ordinal: int = 0) -> bytes:
    spec = followup_formal_unit_specs(PROFILE)[ordinal]
    rows = [
        _job(
            identifier=1,
            name=spec.producer_job_name,
            status="completed",
            started=START,
            completed=START + timedelta(minutes=5),
            conclusion="success",
        ),
        _job(
            identifier=2,
            name=spec.guard_job_name,
            status="in_progress",
            started=START + timedelta(minutes=6),
            completed=None,
            conclusion=None,
        ),
    ]
    return _bytes({"jobs": rows, "total_count": len(rows)})


def test_producer_checkpoint_derives_remaining_from_provider_date() -> None:
    spec = followup_formal_unit_specs(PROFILE)[0]
    result = inspect_followup_formal_phase_deadline(
        _run(),
        _producer_jobs(),
        provider_observed_at=START + timedelta(minutes=5),
        expected_run_id=RUN_ID,
        expected_s2=S2,
        spec=spec,
        phase="private-handoff",
        checkpoint="before-formal-phase",
        require_positive_remaining=True,
    )

    assert result.remaining_seconds == 15 * 60
    assert result.document["formal_unit_deadline_utc"] == "2026-08-30T00:20:00Z"
    assert result.document["authority"] is False
    assert hashlib.sha256(result.document_bytes).hexdigest() == result.sha256


def test_guard_inherits_producer_start_instead_of_resetting_its_budget() -> None:
    spec = followup_formal_unit_specs(PROFILE)[0]
    result = inspect_followup_formal_phase_deadline(
        _run(),
        _guard_jobs(),
        provider_observed_at=START + timedelta(minutes=8),
        expected_run_id=RUN_ID,
        expected_s2=S2,
        spec=spec,
        phase="guarded-final",
        checkpoint="before-formal-phase",
        require_positive_remaining=True,
    )

    assert result.remaining_seconds == 12 * 60
    assert result.document["producer_started_at_utc"] == "2026-08-30T00:00:00Z"
    assert result.document["current_job_id"] == 2


def test_no_new_stage_may_start_at_the_exact_deadline() -> None:
    spec = followup_formal_unit_specs(PROFILE)[0]
    with pytest.raises(FollowupFormalDeadlineError, match="no shared reservation"):
        inspect_followup_formal_phase_deadline(
            _run(),
            _producer_jobs(),
            provider_observed_at=START + timedelta(minutes=20),
            expected_run_id=RUN_ID,
            expected_s2=S2,
            spec=spec,
            phase="private-handoff",
            checkpoint="before-upload",
            require_positive_remaining=True,
        )

    final = inspect_followup_formal_phase_deadline(
        _run(),
        _producer_jobs(),
        provider_observed_at=START + timedelta(minutes=20),
        expected_run_id=RUN_ID,
        expected_s2=S2,
        spec=spec,
        phase="private-handoff",
        checkpoint="after-upload",
        require_positive_remaining=False,
    )
    assert final.remaining_seconds == 0


def test_overrun_overlap_and_extra_job_fail_closed() -> None:
    spec = followup_formal_unit_specs(PROFILE)[0]
    with pytest.raises(FollowupFormalDeadlineError, match="exceeded"):
        inspect_followup_formal_phase_deadline(
            _run(),
            _guard_jobs(),
            provider_observed_at=START + timedelta(minutes=20, seconds=1),
            expected_run_id=RUN_ID,
            expected_s2=S2,
            spec=spec,
            phase="guarded-final",
            checkpoint="after-upload",
            require_positive_remaining=False,
        )

    jobs = json.loads(_guard_jobs())
    jobs["jobs"][1]["started_at"] = _time(START + timedelta(minutes=4))
    with pytest.raises(FollowupFormalDeadlineError, match="overlapped"):
        inspect_followup_formal_phase_deadline(
            _run(),
            _bytes(jobs),
            provider_observed_at=START + timedelta(minutes=8),
            expected_run_id=RUN_ID,
            expected_s2=S2,
            spec=spec,
            phase="guarded-final",
            checkpoint="before-formal-phase",
            require_positive_remaining=True,
        )

    jobs = json.loads(_producer_jobs())
    jobs["jobs"].append(
        _job(
            identifier=3,
            name="unexpected-job",
            status="queued",
            started=None,
            completed=None,
            conclusion=None,
        )
    )
    jobs["total_count"] = 3
    with pytest.raises(FollowupFormalDeadlineError, match="incomplete"):
        inspect_followup_formal_phase_deadline(
            _run(),
            _bytes(jobs),
            provider_observed_at=START + timedelta(minutes=5),
            expected_run_id=RUN_ID,
            expected_s2=S2,
            spec=spec,
            phase="private-handoff",
            checkpoint="before-formal-phase",
            require_positive_remaining=True,
        )
