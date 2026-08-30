from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from dynamic_cssc.followup_performance_campaign import (
    arm_followup_campaign_watch,
    bind_followup_campaign_run,
    build_followup_campaign_selection,
    commit_followup_campaign_unit,
    inspect_followup_campaign_state,
    open_followup_campaign_state,
    record_followup_provider_failure,
    reserve_followup_campaign_unit,
)
from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.followup_performance_formal_timing import (
    FollowupFormalRunEvidence,
    FollowupFormalTimingError,
    inspect_followup_formal_attempt_runner_seconds,
    inspect_followup_formal_timing_campaign,
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


def _campaign_documents(*, replacement_ordinal: int | None = None):  # type: ignore[no-untyped-def]
    previous = open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        qualification_run_id=7_001,
        qualification_q6_artifact_id=8_001,
        qualification_q6_artifact_digest=f"sha256:{'4' * 64}",
        scientific_profile=PROFILE,
    )
    admissions = []
    terminal_attempts = []
    run_id = 20_000
    for spec in followup_formal_unit_specs(PROFILE):
        reserved = reserve_followup_campaign_unit(
            previous,
            spec,
            unit_attempt_ordinal=1,
        )
        bound = bind_followup_campaign_run(reserved, provider_run_id=run_id)
        armed = arm_followup_campaign_watch(
            bound,
            watcher_session_sha256=f"{run_id + 1:064x}",
        )
        if spec.ordinal == replacement_ordinal:
            failed = record_followup_provider_failure(
                armed,
                provider_failure_class="hosted-runner-loss-or-shutdown",
                provider_failure_evidence_sha256=f"{run_id + 2:064x}",
                watcher_receipt_sha256=f"{run_id + 3:064x}",
            )
            terminal_attempts.append(failed)
            run_id += 10
            reserved = reserve_followup_campaign_unit(
                failed,
                spec,
                unit_attempt_ordinal=2,
            )
            bound = bind_followup_campaign_run(reserved, provider_run_id=run_id)
            armed = arm_followup_campaign_watch(
                bound,
                watcher_session_sha256=f"{run_id + 1:064x}",
            )
        success = commit_followup_campaign_unit(
            armed,
            watcher_receipt_sha256=f"{run_id + 2:064x}",
            artifact_id=30_000 + spec.ordinal,
            artifact_name=f"followup-performance-v1-{spec.job_token.lower()}",
            artifact_provider_digest=f"sha256:{40_000 + spec.ordinal:064x}",
            unit_output_envelope_sha256=f"{50_000 + spec.ordinal:064x}",
        )
        terminal_attempts.append(success)
        admissions.append(f"{60_000 + spec.ordinal:064x}")
        previous = success
        run_id += 10
    evidence = []
    committed = []
    cursor = datetime(2026, 8, 30, 0, 0, tzinfo=UTC)
    for state in terminal_attempts:
        ordinal = state.document["unit_ordinal_or_null"]
        attempt = state.document["unit_attempt_ordinal_or_null"]
        run_id = state.document["provider_run_id_or_null"]
        assert type(ordinal) is int
        assert type(attempt) is int
        assert type(run_id) is int
        spec = followup_formal_unit_specs(PROFILE)[ordinal]
        successful = state.state == "unit-committed"
        producer_start = cursor
        producer_end = producer_start + timedelta(seconds=5 if successful else 3)
        jobs = [
            {
                "completed_at": _timestamp(producer_end),
                "conclusion": "success" if successful else "cancelled",
                "id": run_id * 10,
                "name": spec.producer_job_name,
                "run_attempt": 1,
                "run_id": run_id,
                "started_at": _timestamp(producer_start),
                "status": "completed",
            }
        ]
        if successful:
            guard_start = producer_end + timedelta(seconds=1)
            guard_end = guard_start + timedelta(seconds=4)
            jobs.append(
                {
                    "completed_at": _timestamp(guard_end),
                    "conclusion": "success",
                    "id": run_id * 10 + 1,
                    "name": spec.guard_job_name,
                    "run_attempt": 1,
                    "run_id": run_id,
                    "started_at": _timestamp(guard_start),
                    "status": "completed",
                }
            )
            updated = guard_end + timedelta(seconds=1)
        else:
            jobs.append(
                {
                    "completed_at": None,
                    "conclusion": "skipped",
                    "id": run_id * 10 + 1,
                    "name": spec.guard_job_name,
                    "run_attempt": 1,
                    "run_id": run_id,
                    "started_at": None,
                    "status": "completed",
                }
            )
            updated = producer_end + timedelta(seconds=1)
        run = {
            "conclusion": "success" if successful else "cancelled",
            "created_at": _timestamp(cursor),
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": "2" * 40,
            "id": run_id,
            "path": ".github/workflows/followup-performance-formal-unit.yml",
            "run_attempt": 1,
            "status": "completed",
            "updated_at": _timestamp(updated),
        }
        run_bytes = _canonical_json_bytes(run)
        jobs_bytes = _canonical_json_bytes(
            {"jobs": jobs, "total_count": len(jobs)}
        )
        cancellation_ledger = None
        watcher_session = state.document["watcher_session_sha256_or_null"]
        assert type(watcher_session) is str
        common_receipt = {
            "artifacts_api_sha256": "0" * 64,
            "authority": False,
            "campaign_id": state.document["campaign_id"],
            "cancellation_ledger": cancellation_ledger,
            "decision": "success" if successful else "provider-failure",
            "formal_unit_ordinal": ordinal,
            "jobs_api_sha256": hashlib.sha256(jobs_bytes).hexdigest(),
            "provider_run_id": run_id,
            "publication_evidence_admitted": False,
            "run_api_sha256": hashlib.sha256(run_bytes).hexdigest(),
            "schema_version": (
                "dynamic-cssc-followup-performance-watcher-receipt-v3"
            ),
            "unit_attempt_ordinal": attempt,
            "watcher_session_sha256": watcher_session,
        }
        if successful:
            receipt_document = {
                **common_receipt,
                "artifact_id": state.document["artifact_id_or_null"],
                "artifact_name": state.document["artifact_name_or_null"],
                "artifact_provider_digest": state.document[
                    "artifact_provider_digest_or_null"
                ],
                "critical_path_seconds": 10,
                "guard_receipt_bytes_sha256": "7" * 64,
                "reservation_minutes": spec.reservation_minutes,
                "unit_output_envelope_sha256": state.document[
                    "unit_output_envelope_sha256_or_null"
                ],
            }
        else:
            receipt_document = {
                **common_receipt,
                "no_go_reason_or_null": None,
                "provider_failure_class_or_null": state.document[
                    "provider_failure_class_or_null"
                ],
                "provider_failure_evidence_sha256_or_null": state.document[
                    "provider_failure_evidence_sha256_or_null"
                ],
            }
        watcher_receipt = _canonical_json_bytes(receipt_document)
        state_document = dict(state.document)
        state_document["watcher_receipt_sha256_or_null"] = hashlib.sha256(
            watcher_receipt
        ).hexdigest()
        state = inspect_followup_campaign_state(
            _canonical_json_bytes(state_document)
        )
        if successful:
            committed.append(state)
        evidence.append(
            FollowupFormalRunEvidence(
                unit_ordinal=ordinal,
                unit_attempt_ordinal=attempt,
                run_json=run_bytes,
                jobs_json=jobs_bytes,
                watcher_receipt_json=watcher_receipt,
                terminal_campaign_state_bytes=state.document_bytes,
            )
        )
        cursor = updated + timedelta(seconds=1)
    selection = build_followup_campaign_selection(
        tuple(committed),
        tuple(admissions),
        scientific_profile=PROFILE,
    )
    return tuple(evidence), selection


def test_campaign_timing_closes_seventeen_separate_runs() -> None:
    evidence, selection = _campaign_documents()
    ledger = inspect_followup_formal_timing_campaign(
        evidence,
        campaign_selection=selection,
        scientific_profile=PROFILE,
    )

    assert len(ledger.document["units"]) == 17
    assert ledger.document["total_ordinary_runner_seconds"] == 17 * 9
    assert ledger.document["retry_runner_seconds"] == 0
    assert ledger.document["provider_retry_used"] is False


def test_campaign_timing_charges_failed_and_replacement_attempt_once() -> None:
    evidence, selection = _campaign_documents(replacement_ordinal=4)
    ledger = inspect_followup_formal_timing_campaign(
        evidence,
        campaign_selection=selection,
        scientific_profile=PROFILE,
    )

    assert len(evidence) == 18
    assert ledger.document["provider_retry_used"] is True
    assert ledger.document["total_ordinary_runner_seconds"] == 17 * 9 + 3
    assert ledger.document["retry_runner_seconds"] == 0
    assert len(ledger.document["units"][4]["attempts"]) == 2  # type: ignore[index]


def test_campaign_timing_rejects_rehashed_provider_failure_cancellation() -> None:
    evidence, selection = _campaign_documents(replacement_ordinal=4)
    failed = evidence[4]
    receipt = json.loads(failed.watcher_receipt_json)
    receipt["cancellation_ledger"] = {
        "ack_to_watch_decision_seconds": 1,
        "cancel_request_utc": "2026-08-30T00:00:02Z",
        "controller_detection_utc": "2026-08-30T00:00:01Z",
        "final_conclusion": "cancelled",
        "provider_api_ack_utc": "2026-08-30T00:00:03Z",
        "provider_terminal_updated_utc": "2026-08-30T00:00:04Z",
        "request_to_ack_seconds": 1,
        "threshold_utc": None,
        "watch_decided_utc": "2026-08-30T00:00:04Z",
    }
    receipt_bytes = _canonical_json_bytes(receipt)
    state = inspect_followup_campaign_state(failed.terminal_campaign_state_bytes)
    state_document = dict(state.document)
    state_document["watcher_receipt_sha256_or_null"] = hashlib.sha256(
        receipt_bytes
    ).hexdigest()
    tampered = replace(
        failed,
        watcher_receipt_json=receipt_bytes,
        terminal_campaign_state_bytes=_canonical_json_bytes(state_document),
    )
    evidence = (*evidence[:4], tampered, *evidence[5:])

    with pytest.raises(FollowupFormalTimingError, match="canonical inspection"):
        inspect_followup_formal_timing_campaign(
            evidence,
            campaign_selection=selection,
            scientific_profile=PROFILE,
        )


def test_attempt_runner_charge_is_available_before_replacement_dispatch() -> None:
    evidence, _selection = _campaign_documents(replacement_ordinal=4)
    failed = evidence[4]
    spec = followup_formal_unit_specs(PROFILE)[4]

    assert inspect_followup_formal_attempt_runner_seconds(
        failed.jobs_json,
        expected_run_id=20_040,
        spec=spec,
    ) == 3
