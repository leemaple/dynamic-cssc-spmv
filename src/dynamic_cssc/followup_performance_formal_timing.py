"""Provider-API timing ledger for the frozen formal campaign prefix."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from dynamic_cssc.followup_performance_campaign import (
    FollowupCampaignSelection,
    inspect_followup_campaign_state,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_formal_matrix import (
    FollowupFormalUnitSpec,
    followup_formal_unit_specs,
)
from dynamic_cssc.followup_performance_watcher_receipt import (
    FollowupFormalWatcherReceiptError,
    inspect_followup_formal_watcher_receipt,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FollowupFormalRunEvidence",
    "FollowupFormalTimingError",
    "FollowupFormalTimingLedger",
    "inspect_followup_formal_attempt_runner_seconds",
    "inspect_followup_formal_timing_campaign",
    "inspect_followup_formal_timing_prefix",
)

_SCHEMA = "dynamic-cssc-followup-performance-formal-timing-ledger-v1"
_WORKFLOW_PATH = ".github/workflows/followup-performance-formal.yml"
_UNIT_WORKFLOW_PATH = ".github/workflows/followup-performance-formal-unit.yml"
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


@dataclass(frozen=True, slots=True)
class FollowupFormalRunEvidence:
    """Provider API documents plus the terminal CAS state for one unit attempt."""

    unit_ordinal: int
    unit_attempt_ordinal: int
    run_json: bytes
    jobs_json: bytes
    watcher_receipt_json: bytes
    terminal_campaign_state_bytes: bytes


def _watcher_cancellation_ledger(
    content: bytes,
    *,
    expected_jobs_json: bytes,
    expected_run_id: int,
    expected_run_json: bytes,
    expected_unit_ordinal: int,
    expected_unit_attempt_ordinal: int,
    expected_decision: str,
    expected_run_updated_at: object,
    expected_run_conclusion: object,
) -> tuple[dict[str, object], dict[str, object] | None]:
    try:
        inspected = inspect_followup_formal_watcher_receipt(content)
    except FollowupFormalWatcherReceiptError as error:
        raise FollowupFormalTimingError(
            "formal watcher receipt failed canonical inspection"
        ) from error
    receipt = inspected.document
    if (
        receipt.get("provider_run_id") != expected_run_id
        or receipt.get("formal_unit_ordinal") != expected_unit_ordinal
        or receipt.get("unit_attempt_ordinal") != expected_unit_attempt_ordinal
        or receipt.get("decision") != expected_decision
        or receipt.get("run_api_sha256")
        != hashlib.sha256(expected_run_json).hexdigest()
        or receipt.get("jobs_api_sha256")
        != hashlib.sha256(expected_jobs_json).hexdigest()
    ):
        raise FollowupFormalTimingError("formal watcher receipt identity changed")
    cancellation = inspected.cancellation_ledger
    if cancellation is None:
        if (
            expected_decision == "no-go"
            and receipt.get("no_go_reason_or_null") == "budget-exhausted"
        ):
            raise FollowupFormalTimingError(
                "budget-exhausted watcher lacks its cancellation ledger"
            )
        return receipt, None
    if (
        cancellation["provider_terminal_updated_utc"]
        != expected_run_updated_at
        or cancellation["final_conclusion"] != expected_run_conclusion
        or expected_run_conclusion == "success"
    ):
        raise FollowupFormalTimingError(
            "formal cancellation ledger terminal binding changed"
        )
    return receipt, dict(cancellation)


def _campaign_run(
    content: bytes,
    *,
    expected_run_id: int,
    expected_s2: str,
    expected_head_branch: str,
    successful: bool,
) -> tuple[dict[str, object], datetime, datetime]:
    run = _object(content, label="formal unit run API response")
    conclusion = run.get("conclusion")
    if (
        run.get("id") != expected_run_id
        or run.get("run_attempt") != 1
        or run.get("path") != _UNIT_WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != expected_s2
        or run.get("head_branch") != expected_head_branch
        or run.get("status") != "completed"
        or (successful and conclusion != "success")
        or (not successful and conclusion not in {"failure", "cancelled"})
    ):
        raise FollowupFormalTimingError("formal unit run identity or conclusion changed")
    created = _timestamp(run.get("created_at"), field="formal run created_at")
    updated = _timestamp(run.get("updated_at"), field="formal run updated_at")
    if updated < created:
        raise FollowupFormalTimingError("formal unit run has negative lifetime")
    return run, created, updated


def _attempt_jobs(
    content: bytes,
    *,
    expected_run_id: int,
    producer_name: str,
    guard_name: str,
    successful: bool,
) -> tuple[list[dict[str, object]], int, datetime | None, datetime | None]:
    by_name = _job_map(_object(content, label="formal unit jobs API response"))
    expected_names = {producer_name, guard_name}
    if not set(by_name) <= expected_names:
        raise FollowupFormalTimingError("formal unit run contains an extra job")
    if successful and set(by_name) != expected_names:
        raise FollowupFormalTimingError("successful formal unit lacks one exact job")
    rows: list[dict[str, object]] = []
    runner_seconds = 0
    earliest: datetime | None = None
    latest: datetime | None = None
    for name in (producer_name, guard_name):
        job = by_name.get(name)
        if job is None:
            continue
        if (
            _positive_integer(job.get("id"), field=f"{name}.id") <= 0
            or job.get("run_id") != expected_run_id
            or job.get("run_attempt") != 1
            or job.get("status") != "completed"
            or type(job.get("conclusion")) is not str
        ):
            raise FollowupFormalTimingError("formal unit job identity changed")
        started_value = job.get("started_at")
        completed_value = job.get("completed_at")
        if started_value is None or completed_value is None:
            if started_value is not None or completed_value is not None:
                raise FollowupFormalTimingError("formal unit job has a partial clock")
            duration = 0
        else:
            started = _timestamp(started_value, field=f"{name}.started_at")
            completed = _timestamp(completed_value, field=f"{name}.completed_at")
            if completed < started:
                raise FollowupFormalTimingError("formal unit job has negative duration")
            duration = int((completed - started).total_seconds())
            earliest = started if earliest is None else min(earliest, started)
            latest = completed if latest is None else max(latest, completed)
        runner_seconds += duration
        rows.append(
            {
                "completed_at_or_null": completed_value,
                "conclusion": job["conclusion"],
                "job_id": job["id"],
                "job_name": name,
                "runner_seconds": duration,
                "started_at_or_null": started_value,
            }
        )
    if successful:
        producer = by_name[producer_name]
        guard = by_name[guard_name]
        producer_started = _timestamp(
            producer.get("started_at"),
            field=f"{producer_name}.started_at",
        )
        producer_completed = _timestamp(
            producer.get("completed_at"),
            field=f"{producer_name}.completed_at",
        )
        guard_started = _timestamp(
            guard.get("started_at"),
            field=f"{guard_name}.started_at",
        )
        guard_completed = _timestamp(
            guard.get("completed_at"),
            field=f"{guard_name}.completed_at",
        )
        if (
            producer.get("conclusion") != "success"
            or guard.get("conclusion") != "success"
            or guard_started < producer_completed
        ):
            raise FollowupFormalTimingError(
                "successful formal unit jobs overlap or are not successful"
            )
        return rows, runner_seconds, producer_started, guard_completed
    return rows, runner_seconds, earliest, latest


def inspect_followup_formal_attempt_runner_seconds(
    jobs_json: bytes,
    *,
    expected_run_id: int,
    spec: FollowupFormalUnitSpec,
) -> int:
    """Charge one terminal attempt before a later dispatch may be reserved."""

    if type(spec) is not FollowupFormalUnitSpec:
        raise TypeError("spec must be an exact FollowupFormalUnitSpec")
    _positive_integer(expected_run_id, field="formal attempt run ID")
    _rows, runner_seconds, _earliest, _latest = _attempt_jobs(
        jobs_json,
        expected_run_id=expected_run_id,
        producer_name=spec.producer_job_name,
        guard_name=spec.guard_job_name,
        successful=False,
    )
    return runner_seconds


def inspect_followup_formal_timing_campaign(
    evidence: tuple[FollowupFormalRunEvidence, ...],
    *,
    campaign_selection: FollowupCampaignSelection,
    scientific_profile: RouteAScientificProfile,
    expected_head_branch: str = "main",
) -> FollowupFormalTimingLedger:
    """Close 17 successful unit runs and the optional sole provider replacement."""

    if type(evidence) is not tuple or any(
        type(item) is not FollowupFormalRunEvidence for item in evidence
    ):
        raise FollowupFormalTimingError("formal run evidence is not one exact tuple")
    if type(campaign_selection) is not FollowupCampaignSelection:
        raise TypeError("campaign_selection must be exact")
    selection = campaign_selection.document
    expected_s2 = selection.get("evidence_freeze_S2_sha")
    campaign_id = selection.get("campaign_id")
    selected_units = campaign_selection.units
    specs = followup_formal_unit_specs(scientific_profile)
    if (
        type(expected_s2) is not str
        or type(campaign_id) is not str
        or len(selected_units) != 17
    ):
        raise FollowupFormalTimingError("campaign selection lineage changed")
    expected_shape = tuple(
        (spec.ordinal, attempt)
        for spec, selected in zip(specs, selected_units, strict=True)
        for attempt in (
            (1, 2) if selected.get("unit_attempt_ordinal") == 2 else (1,)
        )
    )
    if tuple(
        (item.unit_ordinal, item.unit_attempt_ordinal) for item in evidence
    ) != expected_shape:
        raise FollowupFormalTimingError("formal attempt order or retry shape changed")

    cursor = 0
    previous_run_updated: datetime | None = None
    segment_seconds = {name: 0 for name in _SEGMENT_LIMIT_SECONDS}
    units: list[dict[str, object]] = []
    all_run_ids: set[int] = set()
    cancellation_ledger: list[dict[str, object]] = []
    total_ordinary_seconds = 0
    total_retry_seconds = 0
    for spec, selected in zip(specs, selected_units, strict=True):
        selected_attempt = selected.get("unit_attempt_ordinal")
        attempts = 2 if selected_attempt == 2 else 1
        attempt_rows: list[dict[str, object]] = []
        unit_runner_seconds = 0
        failed_runner_seconds = 0
        successful_critical_seconds: int | None = None
        for local_index in range(attempts):
            item = evidence[cursor]
            cursor += 1
            attempt = local_index + 1
            successful = attempt == attempts
            state = inspect_followup_campaign_state(
                item.terminal_campaign_state_bytes
            )
            run_id = state.document["provider_run_id_or_null"]
            watcher_receipt_sha256 = hashlib.sha256(
                item.watcher_receipt_json
            ).hexdigest()
            if (
                state.document["campaign_id"] != campaign_id
                or state.document["unit_ordinal_or_null"] != spec.ordinal
                or state.document["unit_kind_or_null"] != spec.unit_kind
                or state.document["unit_attempt_ordinal_or_null"] != attempt
                or state.document["provider_run_attempt_or_null"] != 1
                or type(run_id) is not int
                or run_id in all_run_ids
                or state.document["watcher_receipt_sha256_or_null"]
                != watcher_receipt_sha256
                or (successful and state.state != "unit-committed")
                or (not successful and state.state != "unit-provider-failed")
            ):
                raise FollowupFormalTimingError(
                    "formal attempt terminal campaign state changed"
                )
            if successful and (
                run_id != selected.get("provider_run_id")
                or state.sha256 != selected.get("committed_state_sha256")
            ):
                raise FollowupFormalTimingError(
                    "successful run differs from the campaign selection"
                )
            all_run_ids.add(run_id)
            run, created, updated = _campaign_run(
                item.run_json,
                expected_run_id=run_id,
                expected_s2=expected_s2,
                expected_head_branch=expected_head_branch,
                successful=successful,
            )
            if previous_run_updated is not None and created < previous_run_updated:
                raise FollowupFormalTimingError("formal unit runs overlap")
            previous_run_updated = updated
            job_rows, runner_seconds, earliest, latest = _attempt_jobs(
                item.jobs_json,
                expected_run_id=run_id,
                producer_name=spec.producer_job_name,
                guard_name=spec.guard_job_name,
                successful=successful,
            )
            receipt_document, cancellation = _watcher_cancellation_ledger(
                item.watcher_receipt_json,
                expected_jobs_json=item.jobs_json,
                expected_run_id=run_id,
                expected_run_json=item.run_json,
                expected_unit_ordinal=spec.ordinal,
                expected_unit_attempt_ordinal=attempt,
                expected_decision=("success" if successful else "provider-failure"),
                expected_run_updated_at=run["updated_at"],
                expected_run_conclusion=run["conclusion"],
            )
            if (
                receipt_document["watcher_session_sha256"]
                != state.document["watcher_session_sha256_or_null"]
                or (
                    successful
                    and (
                        receipt_document["artifact_id"]
                        != state.document["artifact_id_or_null"]
                        or receipt_document["artifact_name"]
                        != state.document["artifact_name_or_null"]
                        or receipt_document["artifact_provider_digest"]
                        != state.document["artifact_provider_digest_or_null"]
                        or receipt_document["unit_output_envelope_sha256"]
                        != state.document["unit_output_envelope_sha256_or_null"]
                    )
                )
                or (
                    not successful
                    and (
                        receipt_document["provider_failure_class_or_null"]
                        != state.document["provider_failure_class_or_null"]
                        or receipt_document[
                            "provider_failure_evidence_sha256_or_null"
                        ]
                        != state.document[
                            "provider_failure_evidence_sha256_or_null"
                        ]
                    )
                )
            ):
                raise FollowupFormalTimingError(
                    "formal watcher receipt differs from its terminal campaign state"
                )
            if cancellation is not None:
                cancellation = {
                    **cancellation,
                    "charged_runner_seconds": runner_seconds,
                    "formal_unit_ordinal": spec.ordinal,
                    "provider_run_id": run_id,
                    "unit_attempt_ordinal": attempt,
                }
                cancellation_ledger.append(cancellation)
            if successful:
                assert earliest is not None
                assert latest is not None
                successful_critical_seconds = int((latest - earliest).total_seconds())
                if (
                    successful_critical_seconds > spec.reservation_minutes * 60
                    or successful_critical_seconds > 60 * 60
                ):
                    raise FollowupFormalTimingError(
                        "formal unit exceeded its critical-path budget"
                    )
            else:
                failed_runner_seconds += runner_seconds
            unit_runner_seconds += runner_seconds
            attempt_rows.append(
                {
                    "campaign_state_sha256": state.sha256,
                    "cancellation_ledger": cancellation,
                    "jobs": job_rows,
                    "provider_failure_class_or_null": state.document[
                        "provider_failure_class_or_null"
                    ],
                    "provider_run_conclusion": run["conclusion"],
                    "provider_run_created_at": run["created_at"],
                    "provider_run_id": run_id,
                    "provider_run_updated_at": run["updated_at"],
                    "runner_seconds": runner_seconds,
                    "terminal_state": state.state,
                    "unit_attempt_ordinal": attempt,
                }
            )
        assert successful_critical_seconds is not None
        reservation_seconds = spec.reservation_minutes * 60
        if attempts == 2:
            failed_ordinary = min(failed_runner_seconds, reservation_seconds)
            retry_spent_before_replacement = max(
                failed_runner_seconds - reservation_seconds,
                0,
            )
            if (
                reservation_seconds - failed_ordinary
                + 3600
                - retry_spent_before_replacement
                < reservation_seconds
            ):
                raise FollowupFormalTimingError(
                    "retry budget could not reserve the full replacement"
                )
        ordinary_seconds = min(unit_runner_seconds, reservation_seconds)
        retry_seconds = max(unit_runner_seconds - reservation_seconds, 0)
        if attempts == 1 and retry_seconds:
            raise FollowupFormalTimingError(
                "ordinary unit borrowed the provider retry reserve"
            )
        segment_seconds[spec.segment] += ordinary_seconds
        total_ordinary_seconds += ordinary_seconds
        total_retry_seconds += retry_seconds
        units.append(
            {
                "attempts": attempt_rows,
                "critical_path_seconds": successful_critical_seconds,
                "ordinary_runner_seconds": ordinary_seconds,
                "reservation_seconds": reservation_seconds,
                "retry_runner_seconds": retry_seconds,
                "segment": spec.segment,
                "unit_kind": spec.unit_kind,
                "unit_ordinal": spec.ordinal,
            }
        )
    if cursor != len(evidence):
        raise AssertionError("formal timing evidence cursor changed")
    if (
        any(
            segment_seconds[name] > limit
            for name, limit in _SEGMENT_LIMIT_SECONDS.items()
        )
        or total_ordinary_seconds > 630 * 60
        or total_retry_seconds > 60 * 60
        or total_ordinary_seconds + total_retry_seconds > 690 * 60
    ):
        raise FollowupFormalTimingError("formal campaign runner budget exceeded")
    replacement_used = selection.get("replacement_attempt_used")
    if replacement_used is not (len(evidence) == 18):
        raise FollowupFormalTimingError("timing retry does not match campaign selection")
    document = {
        "authority": False,
        "campaign_id": campaign_id,
        "campaign_selection_sha256": campaign_selection.sha256,
        "cancellation_ledger": cancellation_ledger,
        "formal_unit_count": 17,
        "provider_retry_used": replacement_used,
        "publication_evidence_admitted": False,
        "retry_runner_seconds": total_retry_seconds,
        "schema_version": (
            "dynamic-cssc-followup-performance-formal-timing-ledger-v3"
        ),
        "segment_ordinary_runner_seconds": segment_seconds,
        "study_id": FOLLOWUP_STUDY_ID,
        "total_ordinary_runner_seconds": total_ordinary_seconds,
        "total_preterminal_runner_seconds": (
            total_ordinary_seconds + total_retry_seconds
        ),
        "units": units,
    }
    document_bytes = _canonical_json_bytes(document)
    return FollowupFormalTimingLedger(
        document=document,
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
    )


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
