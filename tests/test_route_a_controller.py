from __future__ import annotations

import hashlib
import inspect
import io
import json
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import dynamic_cssc.route_a_controller as route_a_controller_module
from dynamic_cssc.route_a_controller import (
    RouteAArtifactSnapshot,
    RouteAControllerError,
    RouteAJobSnapshot,
    RouteAProviderObservation,
    RouteAQualificationRequest,
    RouteARunSnapshot,
    abandon_route_a_qualification_capability,
    authorize_route_a_qualification,
    claim_route_a_qualification_capability,
)


class _MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


class _EqualitySpoofingBranch(str):
    def __new__(cls) -> _EqualitySpoofingBranch:
        return super().__new__(cls, "not-main")

    def __eq__(self, other: object) -> bool:
        return other == "main" or super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    __hash__ = str.__hash__


@pytest.fixture(autouse=True)
def route_a_clock(monkeypatch: pytest.MonkeyPatch) -> _MutableClock:
    clock = _MutableClock(datetime(2026, 8, 28, 6, 0, tzinfo=UTC))
    monkeypatch.setattr(route_a_controller_module, "_utc_now", clock)
    return clock


class _MemoryProvider:
    def __init__(self, observation: object) -> None:
        self._observation = observation

    def read_qualification(self, run_id: int) -> object:
        assert type(run_id) is int and run_id > 0
        return self._observation


def _q6_archive(record: dict[str, object]) -> bytes:
    record_bytes = (
        json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    checksum = hashlib.sha256(record_bytes).hexdigest()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in (
            ("route-a-qualification-postrun.json", record_bytes),
            ("checksums.sha256", f"{checksum}  route-a-qualification-postrun.json\n".encode()),
        ):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_STORED
            member.external_attr = 0o100600 << 16
            archive.writestr(member, content)
    return output.getvalue()


def _successful_observation() -> RouteAProviderObservation:
    observed_at = datetime(2026, 8, 28, 6, 0, tzinfo=UTC)
    source_sha = "a" * 40
    jobs = (
        RouteAJobSnapshot(
            database_id=101,
            name="qualification-simulator-producer",
            started_at=observed_at - timedelta(minutes=50),
            completed_at=observed_at - timedelta(minutes=45),
            status="completed",
            conclusion="success",
        ),
        RouteAJobSnapshot(
            database_id=102,
            name="qualification-simulator-independent-replay-and-guard",
            started_at=observed_at - timedelta(minutes=44),
            completed_at=observed_at - timedelta(minutes=39),
            status="completed",
            conclusion="success",
        ),
        RouteAJobSnapshot(
            database_id=103,
            name="qualification-native-case-shaped-producer",
            started_at=observed_at - timedelta(minutes=38),
            completed_at=observed_at - timedelta(minutes=30),
            status="completed",
            conclusion="success",
        ),
        RouteAJobSnapshot(
            database_id=104,
            name="qualification-native-independent-replay-and-guard",
            started_at=observed_at - timedelta(minutes=29),
            completed_at=observed_at - timedelta(minutes=22),
            status="completed",
            conclusion="success",
        ),
        RouteAJobSnapshot(
            database_id=105,
            name="qualification-combined-guard",
            started_at=observed_at - timedelta(minutes=21),
            completed_at=observed_at - timedelta(minutes=15),
            status="completed",
            conclusion="success",
        ),
        RouteAJobSnapshot(
            database_id=106,
            name="qualification-postrun-resource-admission",
            started_at=observed_at - timedelta(minutes=14),
            completed_at=observed_at - timedelta(minutes=10),
            status="completed",
            conclusion="success",
        ),
    )
    q6_record = {
        "schema_version": "dynamic-cssc-route-a-q6-postrun-resource-admission-v1",
        "authority": False,
        "formal_execution_authorized": False,
        "run": {
            "databaseId": 100,
            "event": "workflow_dispatch",
            "headSha": source_sha,
            "headBranch": "main",
            "attempt": 1,
        },
        "jobs_q1_through_q5": [
            {
                "databaseId": job.database_id,
                "name": job.name,
                "startedAt": job.started_at.isoformat().replace("+00:00", "Z"),
                "completedAt": job.completed_at.isoformat().replace("+00:00", "Z"),
                "status": job.status,
                "conclusion": job.conclusion,
            }
            for job in jobs[:5]
        ],
        "q6": {
            "databaseId": jobs[5].database_id,
            "name": jobs[5].name,
            "startedAt": jobs[5].started_at.isoformat().replace("+00:00", "Z"),
        },
        "record_observed_utc": (observed_at - timedelta(minutes=13)).isoformat().replace(
            "+00:00", "Z"
        ),
        "frozen_q6_deadline_utc": (
            jobs[4].completed_at + timedelta(minutes=10)
        ).isoformat().replace("+00:00", "Z"),
        "qualification_computational_seconds": 2100,
        "native_c_q_seconds": 1260,
        "native_six_c_q_seconds": 7560,
        "computational_45_minute_gate": "pass",
        "native_planning_screen": "pass",
        "cancellation_ledger": None,
    }
    q6_archive = _q6_archive(q6_record)
    return RouteAProviderObservation(
        observed_at=observed_at,
        plan_bytes=Path("config/route-a-publication-plan.json").read_bytes(),
        run=RouteARunSnapshot(
            database_id=100,
            event="workflow_dispatch",
            head_sha=source_sha,
            head_branch="main",
            attempt=1,
            status="completed",
            conclusion="success",
            created_at=observed_at - timedelta(minutes=51),
            updated_at=observed_at - timedelta(minutes=9),
        ),
        jobs=jobs,
        q6_artifact=RouteAArtifactSnapshot(
            database_id=107,
            name="q6-postrun-resource-admission-record",
            digest="sha256:" + hashlib.sha256(q6_archive).hexdigest(),
            size_in_bytes=len(q6_archive),
            expired=False,
            workflow_run_head_sha=source_sha,
        ),
        q6_archive_bytes=q6_archive,
    )


def test_exact_fresh_qualification_mints_one_single_use_capability(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )

    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )

    with pytest.raises(TypeError, match="not a Boolean"):
        bool(capability)
    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    claim_route_a_qualification_capability(
        capability,
        request,
    )
    route_a_clock.current = observation.observed_at + timedelta(seconds=2)
    with pytest.raises(RuntimeError, match="absent or consumed"):
        claim_route_a_qualification_capability(
            capability,
            request,
        )


def test_expired_qualification_capability_is_atomically_consumed(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )

    route_a_clock.current = observation.observed_at + timedelta(seconds=31)
    with pytest.raises(RouteAControllerError, match="expired"):
        claim_route_a_qualification_capability(
            capability,
            request,
        )
    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(
            capability,
            request,
        )


def test_retargeted_claim_fails_closed_and_consumes_the_capability(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )
    retargeted = replace(request, expected_s2_git_sha="b" * 40)

    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    with pytest.raises(RouteAControllerError, match="binding does not match"):
        claim_route_a_qualification_capability(
            capability,
            retargeted,
        )
    route_a_clock.current = observation.observed_at + timedelta(seconds=2)
    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(
            capability,
            request,
        )


def test_mutating_the_issued_request_cannot_retarget_its_registry_binding(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )
    object.__setattr__(request, "expected_s2_git_sha", "b" * 40)

    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    with pytest.raises(RouteAControllerError, match="binding does not match"):
        claim_route_a_qualification_capability(capability, request)
    original_request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(capability, original_request)


def test_equality_spoofing_branch_retarget_rejects_and_consumes(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )
    object.__setattr__(request, "expected_head_branch", _EqualitySpoofingBranch())

    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    with pytest.raises(RouteAControllerError, match="controlled from terminal S2"):
        claim_route_a_qualification_capability(capability, request)
    original_request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(capability, original_request)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("expected_head_branch", "not-main", "controlled from terminal S2"),
        ("expected_run_attempt", 2, "requires run attempt one"),
    ],
)
def test_malformed_retarget_attempt_is_consumed_before_request_validation(
    route_a_clock: _MutableClock,
    field: str,
    value: object,
    message: str,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )
    malformed = replace(request, **{field: value})

    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    with pytest.raises(RouteAControllerError, match=message):
        claim_route_a_qualification_capability(capability, malformed)
    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(capability, request)


def test_abandonment_consumes_an_unused_qualification_capability() -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )

    abandon_route_a_qualification_capability(capability)

    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(
            capability,
            request,
        )


def test_concurrent_double_claim_has_exactly_one_winner(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(
        _MemoryProvider(observation),
        request,
    )
    route_a_clock.current = observation.observed_at + timedelta(seconds=1)
    barrier = threading.Barrier(2)

    def claim() -> str:
        barrier.wait()
        try:
            claim_route_a_qualification_capability(
                capability,
                request,
            )
        except RouteAControllerError as error:
            assert "absent or consumed" in str(error)
            return "rejected"
        return "claimed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _ordinal: claim(), range(2)))

    assert sorted(outcomes) == ["claimed", "rejected"]


def test_live_clock_is_not_a_public_authority_input() -> None:
    assert "observed_at" not in inspect.signature(
        authorize_route_a_qualification
    ).parameters
    assert "claimed_at" not in inspect.signature(
        claim_route_a_qualification_capability
    ).parameters


def test_claim_at_the_exact_provider_freshness_deadline_succeeds(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(_MemoryProvider(observation), request)

    route_a_clock.current = observation.observed_at + timedelta(seconds=30)
    claim_route_a_qualification_capability(capability, request)


def test_mutated_capability_token_fails_closed_and_is_consumed(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    capability = authorize_route_a_qualification(_MemoryProvider(observation), request)
    object.__setattr__(capability, "_binding_token", object())
    route_a_clock.current = observation.observed_at + timedelta(seconds=1)

    with pytest.raises(RouteAControllerError, match="not authoritative"):
        claim_route_a_qualification_capability(capability, request)
    with pytest.raises(RouteAControllerError, match="absent or consumed"):
        claim_route_a_qualification_capability(capability, request)


def test_provider_run_attempt_boolean_fails_closed() -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    observation = replace(
        observation,
        run=replace(observation.run, attempt=True),
    )

    with pytest.raises(RouteAControllerError, match="run identity"):
        authorize_route_a_qualification(_MemoryProvider(observation), request)


def test_q6_record_rejects_boolean_spliced_into_integer_identity() -> None:
    observation = _successful_observation()
    with zipfile.ZipFile(io.BytesIO(observation.q6_archive_bytes), "r") as archive:
        record = json.loads(archive.read("route-a-qualification-postrun.json"))
    record["run"]["attempt"] = True
    archive_bytes = _q6_archive(record)
    observation = replace(
        observation,
        q6_artifact=replace(
            observation.q6_artifact,
            digest="sha256:" + hashlib.sha256(archive_bytes).hexdigest(),
            size_in_bytes=len(archive_bytes),
        ),
        q6_archive_bytes=archive_bytes,
    )
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )

    with pytest.raises(RouteAControllerError, match="typed identity"):
        authorize_route_a_qualification(
            _MemoryProvider(observation),
            request,
        )


def test_provider_run_snapshot_wrong_type_fails_closed() -> None:
    original = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=original.run.database_id,
        expected_s2_git_sha=original.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    observation = replace(original, run=object())  # type: ignore[arg-type]

    with pytest.raises(RouteAControllerError, match="run snapshot type"):
        authorize_route_a_qualification(
            _MemoryProvider(observation),
            request,
        )


def test_provider_job_snapshot_wrong_type_fails_closed() -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    jobs = (object(), *observation.jobs[1:])
    observation = replace(observation, jobs=jobs)  # type: ignore[arg-type]

    with pytest.raises(RouteAControllerError, match="job snapshot type"):
        authorize_route_a_qualification(
            _MemoryProvider(observation),
            request,
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "reordered"])
def test_provider_job_identity_set_fails_closed(mutation: str) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    if mutation == "missing":
        jobs = observation.jobs[:-1]
    elif mutation == "extra":
        jobs = (*observation.jobs, observation.jobs[-1])
    else:
        jobs = (observation.jobs[1], observation.jobs[0], *observation.jobs[2:])
    observation = replace(observation, jobs=jobs)

    with pytest.raises(RouteAControllerError, match="missing, extra, or reordered"):
        authorize_route_a_qualification(
            _MemoryProvider(observation),
            request,
        )


def test_retargeted_run_fails_closed() -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    observation = replace(
        observation,
        run=replace(observation.run, head_sha="b" * 40),
    )

    with pytest.raises(RouteAControllerError, match="exact terminal success"):
        authorize_route_a_qualification(
            _MemoryProvider(observation),
            request,
        )


def test_stale_provider_observation_fails_closed(
    route_a_clock: _MutableClock,
) -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )

    route_a_clock.current = observation.observed_at + timedelta(seconds=31)
    with pytest.raises(RouteAControllerError, match="observation is stale"):
        authorize_route_a_qualification(_MemoryProvider(observation), request)


def test_q6_job_timeout_fails_closed() -> None:
    observation = _successful_observation()
    request = RouteAQualificationRequest(
        run_id=observation.run.database_id,
        expected_s2_git_sha=observation.run.head_sha,
        expected_head_branch="main",
        expected_run_attempt=1,
    )
    q6 = replace(
        observation.jobs[-1],
        completed_at=observation.observed_at - timedelta(minutes=8),
    )
    observation = replace(
        observation,
        run=replace(
            observation.run,
            updated_at=observation.observed_at - timedelta(minutes=7),
        ),
        jobs=(*observation.jobs[:-1], q6),
    )

    with pytest.raises(RouteAControllerError, match="five-minute job limit"):
        authorize_route_a_qualification(
            _MemoryProvider(observation),
            request,
        )
