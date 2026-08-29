from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

import dynamic_cssc.route_a_controller as controller_module
from dynamic_cssc.route_a_controller import (
    RouteAControllerError,
    RouteALiveJobSnapshot,
    RouteALiveQualificationObservation,
    RouteALiveRunSnapshot,
    RouteAQualificationRequest,
    watch_route_a_qualification,
)

BASE = datetime(2026, 8, 29, 0, 0, tzinfo=UTC)
HEAD = "a" * 40
JOBS = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)


class _Clock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current

    def wait(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


class _Provider:
    def __init__(
        self,
        observations: list[RouteALiveQualificationObservation | Exception],
        *,
        clock: _Clock,
        fail_cancel: bool = False,
    ) -> None:
        self.observations = observations
        self.clock = clock
        self.fail_cancel = fail_cancel
        self.cancelled: list[int] = []

    def read_live_qualification(self, run_id: int) -> RouteALiveQualificationObservation:
        assert run_id == 999
        if not self.observations:
            raise AssertionError("unexpected live provider read")
        observation = self.observations.pop(0)
        if isinstance(observation, Exception):
            raise observation
        return observation

    def cancel_qualification(self, run_id: int) -> None:
        self.cancelled.append(run_id)
        if self.fail_cancel:
            raise OSError("cancel failed")
        self.clock.current += timedelta(seconds=1)


def _observation(
    observed_at: datetime,
    *,
    q5_completed_at: datetime | None = None,
    terminal_cancelled: bool = False,
) -> RouteALiveQualificationObservation:
    bounds: list[tuple[datetime | None, datetime | None, str, str | None]] = [
        (BASE, BASE + timedelta(minutes=5), "completed", "success"),
        (
            BASE + timedelta(minutes=5),
            BASE + timedelta(minutes=10),
            "completed",
            "success",
        ),
        (
            BASE + timedelta(minutes=10),
            BASE + timedelta(minutes=15),
            "completed",
            "success",
        ),
        (
            BASE + timedelta(minutes=15),
            BASE + timedelta(minutes=20),
            "completed",
            "success",
        ),
        (
            BASE + timedelta(minutes=20),
            q5_completed_at,
            "completed" if q5_completed_at is not None else "in_progress",
            (
                "cancelled"
                if terminal_cancelled
                else "success" if q5_completed_at is not None else None
            ),
        ),
        (
            q5_completed_at if terminal_cancelled else None,
            q5_completed_at if terminal_cancelled else None,
            "completed" if terminal_cancelled else "queued",
            "skipped" if terminal_cancelled else None,
        ),
    ]
    jobs = tuple(
        RouteALiveJobSnapshot(
            database_id=101 + ordinal,
            name=name,
            started_at=started,
            completed_at=completed,
            status=status,
            conclusion=conclusion,
        )
        for ordinal, (name, (started, completed, status, conclusion)) in enumerate(
            zip(JOBS, bounds, strict=True)
        )
    )
    return RouteALiveQualificationObservation(
        observed_at=observed_at,
        run=RouteALiveRunSnapshot(
            database_id=999,
            event="workflow_dispatch",
            head_sha=HEAD,
            head_branch="main",
            attempt=1,
            status="completed" if terminal_cancelled else "in_progress",
            conclusion="cancelled" if terminal_cancelled else None,
            created_at=BASE - timedelta(minutes=1),
            updated_at=observed_at,
        ),
        jobs=jobs,
    )


def _request() -> RouteAQualificationRequest:
    return RouteAQualificationRequest(
        run_id=999,
        expected_s2_git_sha=HEAD,
        expected_head_branch="main",
        expected_run_attempt=1,
    )


def test_live_stop_loss_does_not_cancel_q5_success_at_or_before_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=44, seconds=50))
    provider = _Provider(
        [
            _observation(clock.current),
            _observation(
                BASE + timedelta(minutes=44, seconds=55),
                q5_completed_at=BASE + timedelta(minutes=44, seconds=55),
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(
        provider,
        _request(),
        poll_interval_seconds=5,
        wait=clock.wait,
    )

    assert result.decision == "combined-guard-success-before-threshold"
    assert result.threshold_at == BASE + timedelta(minutes=45)
    assert provider.cancelled == []
    assert result.document["formal_execution_authorized"] is False


def test_live_stop_loss_accepts_jobs_as_the_serial_dag_is_instantiated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=44, seconds=50))
    first = _observation(clock.current)
    provider = _Provider(
        [
            replace(first, jobs=first.jobs[:1]),
            _observation(
                BASE + timedelta(minutes=44, seconds=55),
                q5_completed_at=BASE + timedelta(minutes=44, seconds=55),
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(
        provider,
        _request(),
        poll_interval_seconds=5,
        wait=clock.wait,
    )

    assert result.decision == "combined-guard-success-before-threshold"
    assert result.q1_started_at == BASE
    assert provider.cancelled == []


def test_live_stop_loss_accepts_q5_success_at_exact_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=44, seconds=55))
    provider = _Provider(
        [
            _observation(clock.current),
            _observation(
                BASE + timedelta(minutes=45),
                q5_completed_at=BASE + timedelta(minutes=45),
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(
        provider,
        _request(),
        poll_interval_seconds=5,
        wait=clock.wait,
    )

    assert result.decision == "combined-guard-success-before-threshold"
    assert result.q5_completed_at == result.threshold_at
    assert provider.cancelled == []


def test_live_stop_loss_cancels_exactly_once_at_threshold_and_records_terminal_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=45))
    provider = _Provider(
        [
            _observation(clock.current),
            _observation(
                clock.current + timedelta(seconds=1),
                q5_completed_at=clock.current + timedelta(seconds=1),
                terminal_cancelled=True,
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(provider, _request(), wait=clock.wait)

    assert result.decision == "route-c-cancelled"
    assert provider.cancelled == [999]
    assert result.cancellation_requested_at == BASE + timedelta(minutes=45)
    assert result.cancellation_acknowledged_at == BASE + timedelta(minutes=45, seconds=1)
    assert result.provider_terminal_updated_at == BASE + timedelta(minutes=45, seconds=1)


def test_live_stop_loss_wrong_head_fails_without_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=45))
    wrong = _observation(clock.current)
    wrong = replace(wrong, run=replace(wrong.run, head_sha="b" * 40))
    provider = _Provider([wrong], clock=clock)
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    with pytest.raises(RouteAControllerError, match="identity or state"):
        watch_route_a_qualification(provider, _request(), wait=clock.wait)

    assert provider.cancelled == []


def test_live_stop_loss_rejects_a_downstream_job_without_its_predecessor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=1))
    observation = _observation(clock.current)
    observation = replace(observation, jobs=(observation.jobs[1],))
    provider = _Provider([observation], clock=clock)
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    with pytest.raises(RouteAControllerError, match="job identity set"):
        watch_route_a_qualification(provider, _request(), wait=clock.wait)

    assert provider.cancelled == []


def test_live_stop_loss_records_cancel_api_failure_as_route_c(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=45))
    provider = _Provider([_observation(clock.current)], clock=clock, fail_cancel=True)
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(provider, _request(), wait=clock.wait)

    assert result.decision == "route-c-cancel-request-failed"
    assert result.cancellation_error == "provider-cancel-request-failed"
    assert provider.cancelled == [999]


def test_live_stop_loss_cancels_if_provider_fails_at_threshold_after_exact_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=44, seconds=55))
    terminal_at = BASE + timedelta(minutes=45, seconds=1)
    provider = _Provider(
        [
            _observation(clock.current),
            OSError("provider unavailable at threshold"),
            _observation(
                terminal_at,
                q5_completed_at=terminal_at,
                terminal_cancelled=True,
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(
        provider,
        _request(),
        poll_interval_seconds=5,
        wait=clock.wait,
    )

    assert result.decision == "route-c-cancelled"
    assert result.cancellation_requested_at == BASE + timedelta(minutes=45)
    assert provider.cancelled == [999]


def test_live_stop_loss_cancels_immediately_after_a_bound_job_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=25))
    failed = _observation(clock.current)
    failed_jobs = list(failed.jobs[:4])
    failed_jobs[3] = replace(failed_jobs[3], conclusion="failure")
    failed = replace(failed, jobs=tuple(failed_jobs))
    terminal_at = clock.current + timedelta(seconds=1)
    provider = _Provider(
        [
            failed,
            _observation(
                terminal_at,
                q5_completed_at=terminal_at,
                terminal_cancelled=True,
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(provider, _request(), wait=clock.wait)

    assert result.decision == "route-c-cancelled"
    assert result.cancellation_requested_at == BASE + timedelta(minutes=25)
    assert provider.cancelled == [999]


def test_live_stop_loss_uses_cumulative_q1_to_q5_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock(BASE + timedelta(minutes=45))
    provider = _Provider(
        [
            _observation(clock.current),
            _observation(
                clock.current + timedelta(seconds=1),
                q5_completed_at=clock.current + timedelta(seconds=1),
                terminal_cancelled=True,
            ),
        ],
        clock=clock,
    )
    monkeypatch.setattr(controller_module, "_utc_now", clock)

    result = watch_route_a_qualification(provider, _request(), wait=clock.wait)

    assert all(
        job.completed_at is None
        or job.started_at is None
        or job.completed_at - job.started_at <= timedelta(minutes=5)
        for job in _observation(BASE + timedelta(minutes=45)).jobs
    )
    assert result.decision == "route-c-cancelled"
    assert provider.cancelled == [999]
