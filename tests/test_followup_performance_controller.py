from __future__ import annotations

import io
import json
import pickle
import threading
import zipfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import dynamic_cssc.followup_performance_controller as controller
import dynamic_cssc.route_a_controller as route_a_controller
from dynamic_cssc.followup_performance_contract import (
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_controller import (
    FollowupArtifactSnapshot,
    FollowupControllerError,
    FollowupDispatchPrerequisites,
    FollowupFormalAdmissionRequest,
    FollowupFormalLiveJobSnapshot,
    FollowupFormalLiveObservation,
    FollowupFormalLiveRunSnapshot,
    FollowupJobSnapshot,
    FollowupOneShotInventoryObservation,
    FollowupPrerequisiteObservation,
    FollowupProviderAuthoritySnapshot,
    FollowupQualificationObservation,
    FollowupRunSnapshot,
    abandon_followup_qualification_capability,
    authorize_followup_formal_campaign,
    authorize_followup_qualification_dispatch,
    consume_followup_formal_campaign_capability,
    consume_followup_qualification_capability,
    watch_followup_formal_campaign,
    watch_followup_qualification,
)
from dynamic_cssc.route_a_controller import (
    RouteALiveJobSnapshot,
    RouteALiveQualificationObservation,
    RouteALiveRunSnapshot,
)


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


@pytest.fixture(autouse=True)
def isolated_capability_registry() -> None:
    with controller._ISSUED_CAPABILITIES_LOCK:  # noqa: SLF001
        controller._ISSUED_CAPABILITIES.clear()  # noqa: SLF001
    yield
    with controller._ISSUED_CAPABILITIES_LOCK:  # noqa: SLF001
        controller._ISSUED_CAPABILITIES.clear()  # noqa: SLF001


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    value = _Clock(datetime(2026, 8, 30, 6, 0, tzinfo=UTC))
    monkeypatch.setattr(controller, "_utc_now", value)
    monkeypatch.setattr(route_a_controller, "_utc_now", value)
    return value


def _request() -> FollowupDispatchPrerequisites:
    return FollowupDispatchPrerequisites(
        expected_s1_git_sha="a" * 40,
        expected_s2_git_sha="b" * 40,
        expected_compatibility_receipt_sha256="c" * 64,
        ci_run_id=11,
        pre_s1_run_id=12,
        registration_run_id=13,
        source_anchor_run_id=14,
        independent_review_run_id=15,
    )


class _PrerequisiteProvider:
    def __init__(
        self,
        observed_at: datetime,
        *,
        qualification_run_ids: tuple[int, ...] = (),
        final_qualification_run_ids: tuple[int, ...] | None = None,
        formal_run_ids: tuple[int, ...] = (),
    ) -> None:
        self.observation = FollowupPrerequisiteObservation(
            observed_at=observed_at,
            controls=(),
            qualification_run_ids=qualification_run_ids,
            formal_run_ids=formal_run_ids,
        )
        self.inventory = FollowupOneShotInventoryObservation(
            observed_at=observed_at,
            qualification_run_ids=(
                qualification_run_ids
                if final_qualification_run_ids is None
                else final_qualification_run_ids
            ),
            formal_run_ids=formal_run_ids,
        )
        self.calls: list[tuple[int, ...]] = []
        self.inventory_calls = 0

    def read_prerequisites(
        self,
        run_ids: tuple[int, ...],
    ) -> FollowupPrerequisiteObservation:
        self.calls.append(run_ids)
        return self.observation

    def read_one_shot_inventory(self) -> FollowupOneShotInventoryObservation:
        self.inventory_calls += 1
        return self.inventory


def _stub_local_and_prerequisite_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scientific = materialize_followup_scientific_plan(Path.cwd())
    monkeypatch.setattr(
        controller,
        "_inspect_local_authority",
        lambda _root, _request: controller._LocalAuthority(  # noqa: SLF001
            scientific=scientific,
            compatibility_receipt_sha256="c" * 64,
        ),
    )
    monkeypatch.setattr(
        controller,
        "_validate_prerequisite_observation",
        lambda *_args, **_kwargs: None,
    )


def _qualification_observation(observed_at: datetime) -> FollowupQualificationObservation:
    run = FollowupRunSnapshot(
        database_id=90,
        workflow_path=".github/workflows/followup-performance-qualification.yml",
        event="workflow_dispatch",
        head_sha="b" * 40,
        head_branch="main",
        attempt=1,
        status="completed",
        conclusion="success",
        created_at=observed_at - timedelta(minutes=40),
        updated_at=observed_at - timedelta(minutes=1),
    )
    return FollowupQualificationObservation(
        observed_at=observed_at,
        run=run,
        jobs=(),
        artifacts=(),
        q6_provider_archive_bytes=b"placeholder",
        authority_binding=_authority_binding("qualification", 90),
    )


def _authority_binding(
    kind: str,
    run_id: int,
) -> FollowupProviderAuthoritySnapshot:
    workflow = (
        "followup-performance-qualification.yml"
        if kind == "qualification"
        else "followup-performance-formal.yml"
    )
    document = {
        "authority": False,
        "authority_kind": kind,
        "claim_oid": "b" * 40,
        "compatibility_receipt_sha256": "c" * 64,
        "evidence_freeze_S2_sha": "b" * 40,
        "expected_qualification_run_id_or_null": 90 if kind == "formal" else None,
        "experiment_source_S1_sha": "a" * 40,
        "provider_run_attempt": 1,
        "provider_run_id": run_id,
        "schema_version": "dynamic-cssc-followup-performance-provider-run-binding-v1",
        "study_id": "dynamic-cssc-followup-performance-2026-08-30",
        "workflow_ref": (
            "leemaple/dynamic-cssc-spmv/.github/workflows/"
            f"{workflow}@refs/heads/main"
        ),
    }
    return FollowupProviderAuthoritySnapshot(
        ref_name=(
            "refs/tags/dynamic-cssc-followup-performance-"
            f"{kind}-authority-v1"
        ),
        target_oid="e" * 40,
        commit_message=json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ),
        tree_oid="d" * 40,
        claim_tree_oid="d" * 40,
        parent_oids=("b" * 40,),
    )


class _QualificationProvider:
    def __init__(self, observation: FollowupQualificationObservation) -> None:
        self.observation = observation

    def read_qualification(self, run_id: int) -> FollowupQualificationObservation:
        assert run_id == 90
        return self.observation


def test_qualification_capability_is_nonserializable_and_consumes_once(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = _request()
    provider = _PrerequisiteProvider(clock.value)
    capability = authorize_followup_qualification_dispatch(
        Path.cwd(),
        provider,
        request,
    )

    with pytest.raises(TypeError, match="not a Boolean"):
        bool(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)
    clock.value += timedelta(seconds=1)
    opening = consume_followup_qualification_capability(capability, request)
    assert opening.experiment_source_s1_sha == "a" * 40
    assert opening.evidence_freeze_s2_sha == "b" * 40
    assert opening.compatibility_receipt_sha256 == "c" * 64
    with pytest.raises(FollowupControllerError, match="absent or consumed"):
        consume_followup_qualification_capability(capability, request)


def test_expired_qualification_capability_is_consumed_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = _request()
    capability = authorize_followup_qualification_dispatch(
        Path.cwd(),
        _PrerequisiteProvider(clock.value),
        request,
    )
    clock.value += timedelta(seconds=31)
    with pytest.raises(FollowupControllerError, match="expired"):
        consume_followup_qualification_capability(capability, request)
    clock.value -= timedelta(seconds=30)
    with pytest.raises(FollowupControllerError, match="absent or consumed"):
        consume_followup_qualification_capability(capability, request)


def test_qualification_capability_lease_starts_after_heavy_validation(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = _request()
    provider = _PrerequisiteProvider(clock.value)

    def validate_then_refresh(*_args: object, **_kwargs: object) -> None:
        clock.value += timedelta(seconds=47)
        provider.inventory = replace(provider.inventory, observed_at=clock.value)

    monkeypatch.setattr(
        controller,
        "_validate_prerequisite_observation",
        validate_then_refresh,
    )

    capability = authorize_followup_qualification_dispatch(
        Path.cwd(),
        provider,
        request,
    )

    assert provider.inventory_calls == 1
    clock.value += timedelta(seconds=1)
    opening = consume_followup_qualification_capability(capability, request)
    assert opening.evidence_freeze_s2_sha == "b" * 40


@pytest.mark.parametrize(
    ("qualification_run_ids", "formal_run_ids"),
    (
        ((90,), ()),
        ((), (91,)),
    ),
)
def test_qualification_mint_rejects_a_post_validation_inventory_race(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
    qualification_run_ids: tuple[int, ...],
    formal_run_ids: tuple[int, ...],
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    provider = _PrerequisiteProvider(clock.value)
    provider.inventory = replace(
        provider.inventory,
        qualification_run_ids=qualification_run_ids,
        formal_run_ids=formal_run_ids,
    )

    with pytest.raises(FollowupControllerError, match="inventory changed"):
        authorize_followup_qualification_dispatch(Path.cwd(), provider, _request())

    with controller._ISSUED_CAPABILITIES_LOCK:  # noqa: SLF001
        assert controller._ISSUED_CAPABILITIES == {}  # noqa: SLF001


@pytest.mark.parametrize("offset_seconds", (-31, 1))
def test_one_shot_inventory_must_be_fresh_and_not_from_the_future(
    clock: _Clock,
    offset_seconds: int,
) -> None:
    observation = FollowupOneShotInventoryObservation(
        observed_at=clock.value + timedelta(seconds=offset_seconds),
        qualification_run_ids=(),
        formal_run_ids=(),
    )

    with pytest.raises(FollowupControllerError, match="observation is stale"):
        controller._validate_one_shot_inventory(  # noqa: SLF001
            observation,
            clock.value,
            expected_qualification_run_ids=(),
        )


@pytest.mark.parametrize(
    ("qualification_run_ids", "formal_run_ids"),
    (
        ((True,), ()),
        ((90, 90), ()),
        ((), [91]),
    ),
)
def test_one_shot_inventory_rejects_non_strict_or_duplicate_ids(
    clock: _Clock,
    qualification_run_ids: object,
    formal_run_ids: object,
) -> None:
    observation = FollowupOneShotInventoryObservation(
        observed_at=clock.value,
        qualification_run_ids=qualification_run_ids,  # type: ignore[arg-type]
        formal_run_ids=formal_run_ids,  # type: ignore[arg-type]
    )

    with pytest.raises(FollowupControllerError, match="identity changed"):
        controller._validate_one_shot_inventory(  # noqa: SLF001
            observation,
            clock.value,
            expected_qualification_run_ids=(),
        )


def test_capability_lease_includes_30_seconds_but_not_more(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = _request()
    first = authorize_followup_qualification_dispatch(
        Path.cwd(),
        _PrerequisiteProvider(clock.value),
        request,
    )
    clock.value += timedelta(seconds=30)
    consume_followup_qualification_capability(first, request)

    second = authorize_followup_qualification_dispatch(
        Path.cwd(),
        _PrerequisiteProvider(clock.value),
        request,
    )
    clock.value += timedelta(seconds=30, microseconds=1)
    with pytest.raises(FollowupControllerError, match="expired"):
        consume_followup_qualification_capability(second, request)


def test_formal_capability_is_distinct_and_consumes_one_cas_opening(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    prerequisites = _request()
    request = FollowupFormalAdmissionRequest(
        prerequisites=prerequisites,
        qualification_run_id=90,
    )
    q6 = FollowupArtifactSnapshot(
        database_id=106,
        name="q6",
        digest="sha256:" + "d" * 64,
        size_in_bytes=1,
        expired=False,
        workflow_run_id=90,
        workflow_run_head_sha="b" * 40,
    )
    monkeypatch.setattr(
        controller,
        "_validate_qualification_observation",
        lambda *_args, **_kwargs: q6,
    )
    capability = authorize_followup_formal_campaign(
        Path.cwd(),
        _PrerequisiteProvider(clock.value, qualification_run_ids=(90,)),
        _QualificationProvider(_qualification_observation(clock.value)),
        request,
    )
    with pytest.raises(TypeError, match="wrong follow-up authority type"):
        consume_followup_qualification_capability(capability, prerequisites)  # type: ignore[arg-type]
    clock.value += timedelta(seconds=1)
    opening = consume_followup_formal_campaign_capability(capability, request)
    assert opening.experiment_source_s1_sha == "a" * 40
    assert opening.evidence_freeze_s2_sha == "b" * 40
    assert opening.compatibility_receipt_sha256 == "c" * 64
    assert opening.qualification_run_id == 90
    assert opening.qualification_q6_artifact_id == 106
    assert opening.qualification_q6_artifact_digest == "sha256:" + "d" * 64
    with pytest.raises(FollowupControllerError, match="absent or consumed"):
        consume_followup_formal_campaign_capability(capability, request)


def test_formal_capability_lease_starts_after_both_heavy_validations(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    prerequisites = _request()
    request = FollowupFormalAdmissionRequest(
        prerequisites=prerequisites,
        qualification_run_id=90,
    )
    provider = _PrerequisiteProvider(clock.value, qualification_run_ids=(90,))
    q6 = FollowupArtifactSnapshot(
        database_id=106,
        name="q6",
        digest="sha256:" + "d" * 64,
        size_in_bytes=1,
        expired=False,
        workflow_run_id=90,
        workflow_run_head_sha="b" * 40,
    )

    def validate_prerequisites(*_args: object, **_kwargs: object) -> None:
        clock.value += timedelta(seconds=24)

    def validate_qualification(*_args: object, **_kwargs: object) -> FollowupArtifactSnapshot:
        clock.value += timedelta(seconds=24)
        provider.inventory = replace(provider.inventory, observed_at=clock.value)
        return q6

    monkeypatch.setattr(
        controller,
        "_validate_prerequisite_observation",
        validate_prerequisites,
    )
    monkeypatch.setattr(
        controller,
        "_validate_qualification_observation",
        validate_qualification,
    )

    capability = authorize_followup_formal_campaign(
        Path.cwd(),
        provider,
        _QualificationProvider(_qualification_observation(clock.value)),
        request,
    )

    assert provider.inventory_calls == 1
    clock.value += timedelta(seconds=1)
    opening = consume_followup_formal_campaign_capability(capability, request)
    assert opening.qualification_run_id == 90


@pytest.mark.parametrize(
    ("qualification_run_ids", "formal_run_ids"),
    (
        ((), ()),
        ((90, 91), ()),
        ((90,), (92,)),
    ),
)
def test_formal_mint_rejects_a_post_validation_inventory_race(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
    qualification_run_ids: tuple[int, ...],
    formal_run_ids: tuple[int, ...],
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = FollowupFormalAdmissionRequest(
        prerequisites=_request(),
        qualification_run_id=90,
    )
    provider = _PrerequisiteProvider(
        clock.value,
        qualification_run_ids=(90,),
        final_qualification_run_ids=qualification_run_ids,
        formal_run_ids=formal_run_ids,
    )
    q6 = FollowupArtifactSnapshot(
        database_id=106,
        name="q6",
        digest="sha256:" + "d" * 64,
        size_in_bytes=1,
        expired=False,
        workflow_run_id=90,
        workflow_run_head_sha="b" * 40,
    )
    monkeypatch.setattr(
        controller,
        "_validate_qualification_observation",
        lambda *_args, **_kwargs: q6,
    )

    with pytest.raises(FollowupControllerError, match="inventory changed"):
        authorize_followup_formal_campaign(
            Path.cwd(),
            provider,
            _QualificationProvider(_qualification_observation(clock.value)),
            request,
        )

    with controller._ISSUED_CAPABILITIES_LOCK:  # noqa: SLF001
        assert controller._ISSUED_CAPABILITIES == {}  # noqa: SLF001


def test_abandonment_consumes_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = _request()
    capability = authorize_followup_qualification_dispatch(
        Path.cwd(),
        _PrerequisiteProvider(clock.value),
        request,
    )

    abandon_followup_qualification_capability(capability)

    with pytest.raises(FollowupControllerError, match="absent or consumed"):
        consume_followup_qualification_capability(capability, request)


def _qualification_jobs(now: datetime) -> tuple[FollowupJobSnapshot, ...]:
    spans = (
        (50, 45),
        (44, 39),
        (38, 30),
        (29, 22),
        (21, 15),
        (14, 10),
    )
    return tuple(
        FollowupJobSnapshot(
            database_id=100 + index,
            name=name,
            started_at=now - timedelta(minutes=start),
            completed_at=now - timedelta(minutes=end),
            status="completed",
            conclusion="success",
        )
        for index, (name, (start, end)) in enumerate(
            zip(controller._QUALIFICATION_JOB_NAMES, spans, strict=True)  # noqa: SLF001
        )
    )


def test_qualification_timing_gate_is_not_relaxed() -> None:
    now = datetime(2026, 8, 30, 6, 0, tzinfo=UTC)
    jobs = _qualification_jobs(now)

    assert controller._validate_qualification_jobs(jobs) == jobs  # noqa: SLF001

    q5 = replace(jobs[4], completed_at=jobs[0].started_at + timedelta(minutes=46))
    q6 = replace(
        jobs[5],
        started_at=q5.completed_at + timedelta(seconds=1),
        completed_at=q5.completed_at + timedelta(minutes=2),
    )
    with pytest.raises(FollowupControllerError, match="45-minute"):
        controller._validate_qualification_jobs((*jobs[:4], q5, q6))  # noqa: SLF001


class _LiveQualificationProvider:
    def __init__(
        self,
        observations: list[RouteALiveQualificationObservation],
    ) -> None:
        self.observations = observations
        self.cancelled: list[int] = []

    def read_live_qualification(
        self,
        run_id: int,
    ) -> RouteALiveQualificationObservation:
        assert run_id == 90
        if len(self.observations) > 1:
            return self.observations.pop(0)
        return self.observations[0]

    def cancel_qualification(self, run_id: int) -> None:
        self.cancelled.append(run_id)


def _live_qualification_observation(
    clock: datetime,
    *,
    jobs: tuple[RouteALiveJobSnapshot, ...],
    provider_now: datetime,
    status: str,
    conclusion: str | None,
) -> RouteALiveQualificationObservation:
    return RouteALiveQualificationObservation(
        observed_at=clock,
        provider_observed_at=provider_now,
        run=RouteALiveRunSnapshot(
            database_id=90,
            event="workflow_dispatch",
            head_sha="b" * 40,
            head_branch="main",
            attempt=1,
            status=status,
            conclusion=conclusion,
            created_at=jobs[0].started_at - timedelta(seconds=5),  # type: ignore[operator]
            updated_at=provider_now - timedelta(seconds=1),
        ),
        jobs=jobs,
    )


def _live_qualification_jobs(
    start: datetime,
    *,
    include_q6: bool = False,
    q6_completed: datetime | None,
    q6_conclusion: str | None,
) -> tuple[RouteALiveJobSnapshot, ...]:
    jobs: list[RouteALiveJobSnapshot] = []
    cursor = start
    for index, name in enumerate(controller._QUALIFICATION_JOB_NAMES[:5]):  # noqa: SLF001
        completed = cursor + timedelta(minutes=4)
        jobs.append(
            RouteALiveJobSnapshot(
                database_id=500 + index,
                name=name,
                started_at=cursor,
                completed_at=completed,
                status="completed",
                conclusion="success",
            )
        )
        cursor = completed
    if include_q6 or q6_completed is not None or q6_conclusion is not None:
        jobs.append(
            RouteALiveJobSnapshot(
                database_id=505,
                name=controller._QUALIFICATION_JOB_NAMES[5],  # noqa: SLF001
                started_at=cursor,
                completed_at=q6_completed,
                status="completed" if q6_completed is not None else "in_progress",
                conclusion=q6_conclusion,
            )
        )
    return tuple(jobs)


def test_qualification_watch_stays_armed_through_q6_and_the_55_minute_gate(
    clock: _Clock,
) -> None:
    start = clock.value - timedelta(minutes=30)
    prefix = _live_qualification_jobs(
        start,
        q6_completed=None,
        q6_conclusion=None,
    )[:5]
    complete = _live_qualification_jobs(
        start,
        q6_completed=start + timedelta(minutes=22),
        q6_conclusion="success",
    )
    provider = _LiveQualificationProvider(
        [
            _live_qualification_observation(
                clock.value,
                jobs=prefix,
                provider_now=clock.value,
                status="in_progress",
                conclusion=None,
            ),
            _live_qualification_observation(
                clock.value,
                jobs=complete,
                provider_now=clock.value,
                status="completed",
                conclusion="success",
            ),
        ]
    )

    result = watch_followup_qualification(
        provider,
        FollowupFormalAdmissionRequest(
            prerequisites=_request(),
            qualification_run_id=90,
        ),
        poll_interval_seconds=1,
        wait=lambda _seconds: None,
    )

    assert result.qualification_decision == "qualification-go"
    assert result.q6_started_at == start + timedelta(minutes=20)
    assert result.q6_completed_at == start + timedelta(minutes=22)
    assert result.q6_wall_threshold_at == start + timedelta(minutes=30)
    assert result.q6_provider_terminal_conclusion == "success"
    assert result.q6_cancellation_requested_at is None
    assert result.document["schema_version"].endswith("-v2")
    assert provider.cancelled == []


def test_qualification_watch_cancels_when_q6_misses_the_total_gate(
    clock: _Clock,
) -> None:
    start = clock.value - timedelta(minutes=54)
    prefix = _live_qualification_jobs(
        start,
        q6_completed=None,
        q6_conclusion=None,
    )[:5]
    active = _live_qualification_jobs(
        start,
        include_q6=True,
        q6_completed=None,
        q6_conclusion=None,
    )
    terminal = list(active)
    terminal[-1] = replace(
        terminal[-1],
        completed_at=clock.value + timedelta(minutes=1),
        status="completed",
        conclusion="cancelled",
    )
    provider = _LiveQualificationProvider(
        [
            _live_qualification_observation(
                clock.value,
                jobs=prefix,
                provider_now=clock.value,
                status="in_progress",
                conclusion=None,
            ),
            _live_qualification_observation(
                clock.value,
                jobs=active,
                provider_now=clock.value + timedelta(minutes=2),
                status="in_progress",
                conclusion=None,
            ),
            _live_qualification_observation(
                clock.value,
                jobs=tuple(terminal),
                provider_now=clock.value + timedelta(minutes=3),
                status="completed",
                conclusion="cancelled",
            ),
        ]
    )

    result = watch_followup_qualification(
        provider,
        FollowupFormalAdmissionRequest(
            prerequisites=_request(),
            qualification_run_id=90,
        ),
        poll_interval_seconds=1,
        wait=lambda _seconds: None,
    )

    assert result.qualification_decision == "qualification-no-go"
    assert result.q6_started_at == start + timedelta(minutes=20)
    assert result.q6_cancellation_requested_at == clock.value
    assert result.q6_cancellation_acknowledged_at == clock.value
    assert result.q6_provider_terminal_conclusion == "cancelled"
    assert result.q6_watch_decided_at == clock.value
    assert result.q6_cancellation_error is None
    assert provider.cancelled == [90]


def test_provider_archive_path_traversal_fails_closed() -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("../escape", b"payload")

    with (
        pytest.raises(FollowupControllerError, match="unsafe"),
        controller._extracted_provider_archive(  # noqa: SLF001
            output.getvalue(),
            maximum_bytes=1024,
        ),
    ):
        raise AssertionError("unsafe archive unexpectedly yielded")


def test_concurrent_double_consume_has_one_live_opening(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    request = _request()
    capability = authorize_followup_qualification_dispatch(
        Path.cwd(),
        _PrerequisiteProvider(clock.value),
        request,
    )
    clock.value += timedelta(seconds=1)
    barrier = threading.Barrier(2)

    def consume() -> str:
        barrier.wait()
        try:
            consume_followup_qualification_capability(capability, request)
        except FollowupControllerError as error:
            assert "absent or consumed" in str(error)
            return "rejected"
        return "consumed"

    results: list[str] = []

    def record() -> None:
        results.append(consume())

    threads = [threading.Thread(target=record) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == ["consumed", "rejected"]


class _FormalLiveProvider:
    def __init__(self, observations: list[FollowupFormalLiveObservation]) -> None:
        self.observations = observations
        self.cancelled: list[int] = []

    def read_live_formal(self, run_id: int) -> FollowupFormalLiveObservation:
        assert run_id == 92
        if len(self.observations) > 1:
            return self.observations.pop(0)
        return self.observations[0]

    def cancel_formal(self, run_id: int) -> None:
        self.cancelled.append(run_id)


def _live_run(
    now: datetime,
    *,
    status: str,
    conclusion: str | None,
) -> FollowupFormalLiveRunSnapshot:
    return FollowupFormalLiveRunSnapshot(
        database_id=92,
        workflow_path=".github/workflows/followup-performance-formal.yml",
        event="workflow_dispatch",
        head_sha="b" * 40,
        head_branch="main",
        attempt=1,
        status=status,
        conclusion=conclusion,
        created_at=now - timedelta(minutes=30),
        updated_at=now,
    )


def _live_job(
    database_id: int,
    name: str,
    *,
    started_at: datetime | None,
    completed_at: datetime | None,
    status: str,
    conclusion: str | None,
) -> FollowupFormalLiveJobSnapshot:
    return FollowupFormalLiveJobSnapshot(
        database_id=database_id,
        name=name,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        conclusion=conclusion,
    )


def test_formal_watch_cancels_at_the_combined_unit_deadline(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    scientific = materialize_followup_scientific_plan(Path.cwd())
    first = controller.followup_formal_unit_specs(scientific.scientific_profile)[0]
    launch = _live_job(
        201,
        "formal-launch-admission",
        started_at=clock.value - timedelta(minutes=22),
        completed_at=clock.value - timedelta(minutes=21, seconds=30),
        status="completed",
        conclusion="success",
    )
    producer = _live_job(
        202,
        first.producer_job_name,
        started_at=clock.value - timedelta(minutes=21),
        completed_at=None,
        status="in_progress",
        conclusion=None,
    )
    active = FollowupFormalLiveObservation(
        observed_at=clock.value,
        provider_observed_at=clock.value,
        run=_live_run(clock.value, status="in_progress", conclusion=None),
        jobs=(launch, producer),
        authority_binding=_authority_binding("formal", 92),
    )
    cancelled_producer = replace(
        producer,
        completed_at=clock.value,
        status="completed",
        conclusion="cancelled",
    )
    terminal = FollowupFormalLiveObservation(
        observed_at=clock.value,
        provider_observed_at=clock.value,
        run=_live_run(clock.value, status="completed", conclusion="cancelled"),
        jobs=(launch, cancelled_producer),
        authority_binding=_authority_binding("formal", 92),
    )
    provider = _FormalLiveProvider([active, terminal])
    request = FollowupFormalAdmissionRequest(
        prerequisites=_request(),
        qualification_run_id=90,
    )

    result = watch_followup_formal_campaign(
        Path.cwd(),
        provider,
        request,
        92,
        poll_interval_seconds=1,
        wait=lambda _seconds: None,
    )

    assert provider.cancelled == [92]
    assert result.document["decision"] == "terminal-no-go"
    assert result.document["current_unit_ordinal_or_null"] == 0
    assert result.document["reason"] == "formal unit reached its combined reservation"
    assert result.document["cancellation"]["provider_request_submitted"] is True


def test_formal_watch_accepts_only_one_complete_serial_success(
    monkeypatch: pytest.MonkeyPatch,
    clock: _Clock,
) -> None:
    _stub_local_and_prerequisite_validation(monkeypatch)
    scientific = materialize_followup_scientific_plan(Path.cwd())
    specs = controller.followup_formal_unit_specs(scientific.scientific_profile)
    cursor = clock.value - timedelta(minutes=10)
    jobs = [
        _live_job(
            301,
            "formal-launch-admission",
            started_at=cursor,
            completed_at=cursor + timedelta(seconds=5),
            status="completed",
            conclusion="success",
        )
    ]
    cursor += timedelta(seconds=5)
    identifier = 302
    for spec in specs:
        producer_started = cursor
        producer_completed = producer_started + timedelta(seconds=5)
        guard_started = producer_completed
        guard_completed = guard_started + timedelta(seconds=5)
        jobs.extend(
            (
                _live_job(
                    identifier,
                    spec.producer_job_name,
                    started_at=producer_started,
                    completed_at=producer_completed,
                    status="completed",
                    conclusion="success",
                ),
                _live_job(
                    identifier + 1,
                    spec.guard_job_name,
                    started_at=guard_started,
                    completed_at=guard_completed,
                    status="completed",
                    conclusion="success",
                ),
            )
        )
        identifier += 2
        cursor = guard_completed
    jobs.extend(
        (
            _live_job(
                identifier,
                "formal-terminal-admission",
                started_at=cursor,
                completed_at=cursor + timedelta(seconds=5),
                status="completed",
                conclusion="success",
            ),
            _live_job(
                identifier + 1,
                "formal-aggregate",
                started_at=cursor + timedelta(seconds=5),
                completed_at=cursor + timedelta(seconds=10),
                status="completed",
                conclusion="success",
            ),
        )
    )
    observation = FollowupFormalLiveObservation(
        observed_at=clock.value,
        provider_observed_at=clock.value,
        run=_live_run(clock.value, status="completed", conclusion="success"),
        jobs=tuple(jobs),
        authority_binding=_authority_binding("formal", 92),
    )
    provider = _FormalLiveProvider([observation])
    request = FollowupFormalAdmissionRequest(
        prerequisites=_request(),
        qualification_run_id=90,
    )

    result = watch_followup_formal_campaign(
        Path.cwd(),
        provider,
        request,
        92,
        poll_interval_seconds=1,
        wait=lambda _seconds: None,
    )

    assert not provider.cancelled
    assert result.document["decision"] == "terminal-success-candidate"
    assert result.document["cancellation"] is None
    assert result.document["publication_evidence_admitted"] is False
