"""Atomic dispatch, exact-run binding, mandatory watch, and terminal CAS.

This module is deliberately smaller than the scientific runners.  It owns the
single dangerous transition from live controller authority to one provider run;
the workflows and artifact modules consume only authority-false receipts.
"""

from __future__ import annotations

import hashlib
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from dynamic_cssc.followup_performance_campaign import (
    FOLLOWUP_PROVIDER_FAILURE_CLASSES,
    FollowupCampaignRunAdmissionReceipt,
    FollowupCampaignState,
    arm_followup_campaign_watch,
    bind_followup_campaign_run,
    build_followup_campaign_run_admission_receipt,
    close_followup_campaign_no_go,
    commit_followup_campaign_unit,
    record_followup_provider_failure,
    reserve_followup_campaign_unit,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_formal_matrix import FollowupFormalUnitSpec
from dynamic_cssc.followup_performance_watcher_receipt import (
    FollowupFormalWatcherReceiptError,
    inspect_followup_formal_watcher_receipt,
)

__all__ = (
    "FollowupAcquisitionRunBinding",
    "FollowupBoundUnitResult",
    "FollowupCampaignControlError",
    "FollowupCampaignProvider",
    "FollowupFormalCancellationSubmission",
    "FollowupFormalUnitWatch",
    "FollowupFormalUnitWatchOutcome",
    "dispatch_bind_watch",
)


class FollowupCampaignControlError(FollowupContractError):
    """One provider mutation was failed, ambiguous, or could not be closed."""


@dataclass(frozen=True, slots=True)
class FollowupFormalCancellationSubmission:
    """Proof that the formal provider received one exact cancel POST."""

    provider_run_id: int
    response_status: Literal[202]
    provider_observed_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.provider_run_id) is not int
            or self.provider_run_id <= 0
            or self.response_status != 202
            or type(self.provider_observed_at) is not datetime
            or self.provider_observed_at.tzinfo is not UTC
        ):
            raise FollowupCampaignControlError(
                "formal cancellation submission changed"
            )


_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARTIFACT_NAME = re.compile(r"followup-performance-v1-[a-z0-9][a-z0-9._-]{0,254}\Z")


def _is_sha256(value: object) -> bool:
    return type(value) is str and _LOWER_SHA256.fullmatch(value) is not None


def _is_provider_digest(value: object) -> bool:
    return type(value) is str and _PROVIDER_DIGEST.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class FollowupAcquisitionRunBinding:
    artifact_name: str
    provider_run_id: int
    provider_artifact_id: int
    provider_artifact_digest: str
    campaign_run_admission_sha256: str
    unit_attempt_ordinal: int


@dataclass(frozen=True, slots=True)
class FollowupFormalUnitWatchOutcome:
    provider_run_id: int
    watcher_session_sha256: str
    watcher_receipt_sha256: str
    watcher_receipt_bytes: bytes
    provider_run_json: bytes
    provider_jobs_json: bytes
    provider_artifacts_json: bytes
    provider_guard_receipt_bytes_or_null: bytes | None
    decision: Literal["success", "provider-failure", "no-go"]
    artifact_id_or_null: int | None
    artifact_name_or_null: str | None
    artifact_provider_digest_or_null: str | None
    unit_output_envelope_sha256_or_null: str | None
    provider_failure_class_or_null: str | None
    provider_failure_evidence_sha256_or_null: str | None
    provider_failure_evidence_bytes_or_null: bytes | None
    no_go_reason_or_null: str | None


class FollowupFormalUnitWatch(Protocol):
    @property
    def session_sha256(self) -> str: ...

    def wait(self) -> FollowupFormalUnitWatchOutcome: ...


class FollowupCampaignProvider(Protocol):
    def install_campaign_state(
        self,
        *,
        expected_oid: str,
        expected_tree_oid: str,
        state: FollowupCampaignState,
    ) -> str: ...

    def dispatch_formal_unit(self, *, inputs: dict[str, str]) -> int: ...

    def start_formal_unit_watch(
        self,
        *,
        provider_run_id: int,
        spec: FollowupFormalUnitSpec,
        reservation_minutes: int,
    ) -> FollowupFormalUnitWatch: ...

    def cancel_formal_unit(
        self,
        provider_run_id: int,
    ) -> FollowupFormalCancellationSubmission: ...


@dataclass(frozen=True, slots=True)
class FollowupBoundUnitResult:
    provider_run_id: int
    reservation_oid: str
    binding_oid: str
    watch_armed_oid: str
    terminal_oid: str
    run_admission: FollowupCampaignRunAdmissionReceipt
    reservation_state: FollowupCampaignState
    binding_state: FollowupCampaignState
    watch_armed_state: FollowupCampaignState
    terminal_state: FollowupCampaignState
    outcome: FollowupFormalUnitWatchOutcome


def _acquisition_inputs(
    spec: FollowupFormalUnitSpec,
    acquisition: FollowupAcquisitionRunBinding | None,
) -> dict[str, str]:
    if spec.unit_kind != "formal-ordered-event":
        if acquisition is not None:
            raise FollowupCampaignControlError(
                "a non-ordered formal unit received acquisition inputs"
            )
        return {}
    if type(acquisition) is not FollowupAcquisitionRunBinding:
        raise FollowupCampaignControlError(
            "an ordered formal unit lacks its admitted acquisition"
        )
    if (
        type(acquisition.artifact_name) is not str
        or _ARTIFACT_NAME.fullmatch(acquisition.artifact_name) is None
        or type(acquisition.provider_run_id) is not int
        or acquisition.provider_run_id <= 0
        or type(acquisition.provider_artifact_id) is not int
        or acquisition.provider_artifact_id <= 0
        or not _is_provider_digest(acquisition.provider_artifact_digest)
        or not _is_sha256(acquisition.campaign_run_admission_sha256)
        or acquisition.unit_attempt_ordinal not in {1, 2}
    ):
        raise FollowupCampaignControlError("acquisition provider binding changed")
    return {
        "acquisition_artifact_name": acquisition.artifact_name,
        "acquisition_campaign_run_admission_sha256": (
            acquisition.campaign_run_admission_sha256
        ),
        "acquisition_provider_artifact_digest": (
            acquisition.provider_artifact_digest
        ),
        "acquisition_provider_artifact_id": str(acquisition.provider_artifact_id),
        "acquisition_provider_run_id": str(acquisition.provider_run_id),
        "acquisition_unit_attempt_ordinal": str(
            acquisition.unit_attempt_ordinal
        ),
    }


def _dispatch_inputs(
    reserved: FollowupCampaignState,
    reservation_oid: str,
    spec: FollowupFormalUnitSpec,
    *,
    acquisition: FollowupAcquisitionRunBinding | None,
) -> dict[str, str]:
    document = reserved.document
    inputs = {
        "expected_campaign_id": document["campaign_id"],
        "expected_compatibility_receipt_sha256": document[
            "compatibility_receipt_sha256"
        ],
        "expected_job_token": spec.job_token,
        "expected_reservation_oid": reservation_oid,
        "expected_reservation_minutes": str(spec.reservation_minutes),
        "expected_s1_git_sha": document["experiment_source_S1_sha"],
        "expected_s2_git_sha": document["evidence_freeze_S2_sha"],
        "formal_unit_ordinal": str(spec.ordinal),
        "unit_attempt_ordinal": str(document["unit_attempt_ordinal_or_null"]),
    }
    if any(type(value) is not str for value in inputs.values()):
        raise FollowupCampaignControlError("campaign dispatch input type changed")
    inputs.update(_acquisition_inputs(spec, acquisition))
    return {key: str(value) for key, value in inputs.items()}


def _validated_watch_outcome(
    outcome: object,
    *,
    campaign_id: str,
    formal_unit_ordinal: int,
    provider_run_id: int,
    reservation_minutes: int,
    unit_attempt_ordinal: int,
    watcher_session_sha256: str,
) -> FollowupFormalUnitWatchOutcome:
    if (
        type(outcome) is not FollowupFormalUnitWatchOutcome
        or outcome.provider_run_id != provider_run_id
        or outcome.watcher_session_sha256 != watcher_session_sha256
        or not _is_sha256(outcome.watcher_session_sha256)
        or not _is_sha256(outcome.watcher_receipt_sha256)
        or type(outcome.watcher_receipt_bytes) is not bytes
        or hashlib.sha256(outcome.watcher_receipt_bytes).hexdigest()
        != outcome.watcher_receipt_sha256
        or any(
            type(content) is not bytes or not 0 < len(content) <= 8 * 1024 * 1024
            for content in (
                outcome.provider_run_json,
                outcome.provider_jobs_json,
                outcome.provider_artifacts_json,
            )
        )
    ):
        raise FollowupCampaignControlError("watcher outcome identity changed")
    try:
        receipt = inspect_followup_formal_watcher_receipt(
            outcome.watcher_receipt_bytes
        )
    except FollowupFormalWatcherReceiptError as error:
        raise FollowupCampaignControlError(
            "watcher receipt failed canonical inspection"
        ) from error
    receipt_document = receipt.document
    if (
        receipt.sha256 != outcome.watcher_receipt_sha256
        or receipt_document["campaign_id"] != campaign_id
        or receipt_document["formal_unit_ordinal"] != formal_unit_ordinal
        or receipt_document["provider_run_id"] != provider_run_id
        or receipt_document["unit_attempt_ordinal"] != unit_attempt_ordinal
        or receipt_document["watcher_session_sha256"]
        != watcher_session_sha256
        or receipt_document["decision"] != outcome.decision
        or receipt_document["run_api_sha256"]
        != hashlib.sha256(outcome.provider_run_json).hexdigest()
        or receipt_document["jobs_api_sha256"]
        != hashlib.sha256(outcome.provider_jobs_json).hexdigest()
        or receipt_document["artifacts_api_sha256"]
        != hashlib.sha256(outcome.provider_artifacts_json).hexdigest()
    ):
        raise FollowupCampaignControlError(
            "watcher receipt is not bound to the exact provider outcome"
        )
    cancellation = receipt.cancellation_ledger
    if cancellation is not None:
        try:
            run = _parse_ascii_json(
                outcome.provider_run_json,
                label="formal watcher run API response",
            )
        except FollowupContractError as error:
            raise FollowupCampaignControlError(
                "watcher terminal provider run is unreadable"
            ) from error
        if (
            type(run) is not dict
            or cancellation["provider_terminal_updated_utc"]
            != run.get("updated_at")
            or cancellation["final_conclusion"] != run.get("conclusion")
        ):
            raise FollowupCampaignControlError(
                "watcher cancellation is not bound to the terminal provider run"
            )
    artifact_fields = (
        outcome.artifact_id_or_null,
        outcome.artifact_name_or_null,
        outcome.artifact_provider_digest_or_null,
        outcome.unit_output_envelope_sha256_or_null,
    )
    provider_failure_fields = (
        outcome.provider_failure_class_or_null,
        outcome.provider_failure_evidence_sha256_or_null,
    )
    if outcome.decision == "success":
        if (
            type(outcome.artifact_id_or_null) is not int
            or outcome.artifact_id_or_null <= 0
            or type(outcome.artifact_name_or_null) is not str
            or _ARTIFACT_NAME.fullmatch(outcome.artifact_name_or_null) is None
            or not _is_provider_digest(outcome.artifact_provider_digest_or_null)
            or not _is_sha256(outcome.unit_output_envelope_sha256_or_null)
            or type(outcome.provider_guard_receipt_bytes_or_null) is not bytes
            or not outcome.provider_guard_receipt_bytes_or_null
            or any(value is not None for value in provider_failure_fields)
            or outcome.provider_failure_evidence_bytes_or_null is not None
            or outcome.no_go_reason_or_null is not None
            or receipt_document["artifact_id"] != outcome.artifact_id_or_null
            or receipt_document["artifact_name"] != outcome.artifact_name_or_null
            or receipt_document["artifact_provider_digest"]
            != outcome.artifact_provider_digest_or_null
            or receipt_document["unit_output_envelope_sha256"]
            != outcome.unit_output_envelope_sha256_or_null
            or receipt_document["guard_receipt_bytes_sha256"]
            != hashlib.sha256(
                outcome.provider_guard_receipt_bytes_or_null
            ).hexdigest()
            or receipt_document["reservation_minutes"] != reservation_minutes
        ):
            raise FollowupCampaignControlError(
                "successful watcher outcome lacks one exact guarded artifact"
            )
    elif outcome.decision == "provider-failure":
        if (
            any(value is not None for value in artifact_fields)
            or cancellation is not None
            or outcome.provider_failure_class_or_null
            not in FOLLOWUP_PROVIDER_FAILURE_CLASSES
            or not _is_sha256(outcome.provider_failure_evidence_sha256_or_null)
            or type(outcome.provider_failure_evidence_bytes_or_null) is not bytes
            or hashlib.sha256(
                outcome.provider_failure_evidence_bytes_or_null
            ).hexdigest()
            != outcome.provider_failure_evidence_sha256_or_null
            or outcome.provider_guard_receipt_bytes_or_null is not None
            or outcome.no_go_reason_or_null is not None
            or receipt_document["provider_failure_class_or_null"]
            != outcome.provider_failure_class_or_null
            or receipt_document["provider_failure_evidence_sha256_or_null"]
            != outcome.provider_failure_evidence_sha256_or_null
        ):
            raise FollowupCampaignControlError(
                "provider-failure watcher outcome is not replacement-eligible"
            )
    elif outcome.decision == "no-go":
        if (
            any(value is not None for value in artifact_fields)
            or any(value is not None for value in provider_failure_fields)
            or outcome.provider_failure_evidence_bytes_or_null is not None
            or outcome.provider_guard_receipt_bytes_or_null is not None
            or type(outcome.no_go_reason_or_null) is not str
            or (
                (outcome.no_go_reason_or_null == "budget-exhausted")
                != (cancellation is not None)
            )
            or receipt_document["no_go_reason_or_null"]
            != outcome.no_go_reason_or_null
        ):
            raise FollowupCampaignControlError("NO-GO watcher outcome is malformed")
    else:
        raise FollowupCampaignControlError("watcher decision changed")
    return outcome


def _best_effort_cancel(
    provider: FollowupCampaignProvider,
    provider_run_id: int | None,
) -> None:
    if provider_run_id is None:
        return
    with suppress(AttributeError, OSError, RuntimeError, TypeError, ValueError):
        provider.cancel_formal_unit(provider_run_id)


def _best_effort_no_go(
    provider: FollowupCampaignProvider,
    *,
    expected_oid: str,
    expected_tree_oid: str,
    previous: FollowupCampaignState,
    reason: str,
) -> None:
    with suppress(AttributeError, OSError, RuntimeError, TypeError, ValueError):
        provider.install_campaign_state(
            expected_oid=expected_oid,
            expected_tree_oid=expected_tree_oid,
            state=close_followup_campaign_no_go(
                previous,
                terminal_reason_code=reason,
            ),
        )


def dispatch_bind_watch(
    previous: FollowupCampaignState,
    *,
    progress_oid: str,
    evidence_tree_oid: str,
    spec: FollowupFormalUnitSpec,
    unit_attempt_ordinal: int,
    provider: FollowupCampaignProvider,
    acquisition: FollowupAcquisitionRunBinding | None = None,
) -> FollowupBoundUnitResult:
    """Perform the only allowed reserve→dispatch→bind→watch→terminal sequence."""

    reserved = reserve_followup_campaign_unit(
        previous,
        spec,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    try:
        reservation_oid = provider.install_campaign_state(
            expected_oid=progress_oid,
            expected_tree_oid=evidence_tree_oid,
            state=reserved,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupCampaignControlError(
            "campaign reservation CAS failed or was ambiguous"
        ) from error

    provider_run_id: int | None = None
    try:
        dispatch_inputs = _dispatch_inputs(
            reserved,
            reservation_oid,
            spec,
            acquisition=acquisition,
        )
    except FollowupCampaignControlError:
        _best_effort_no_go(
            provider,
            expected_oid=reservation_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=reserved,
            reason="identity-invalid",
        )
        raise
    try:
        provider_run_id = provider.dispatch_formal_unit(inputs=dispatch_inputs)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_no_go(
            provider,
            expected_oid=reservation_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=reserved,
            reason="dispatch-failed-or-ambiguous",
        )
        raise FollowupCampaignControlError(
            "formal unit dispatch failed or was ambiguous"
        ) from error
    if type(provider_run_id) is not int or provider_run_id <= 0:
        _best_effort_no_go(
            provider,
            expected_oid=reservation_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=reserved,
            reason="dispatch-failed-or-ambiguous",
        )
        raise FollowupCampaignControlError(
            "formal unit dispatch did not return one exact run ID"
        )

    bound = bind_followup_campaign_run(reserved, provider_run_id=provider_run_id)
    try:
        binding_oid = provider.install_campaign_state(
            expected_oid=reservation_oid,
            expected_tree_oid=evidence_tree_oid,
            state=bound,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, provider_run_id)
        _best_effort_no_go(
            provider,
            expected_oid=reservation_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=reserved,
            reason="cas-failed-or-ambiguous",
        )
        raise FollowupCampaignControlError(
            "exact-run binding CAS failed after dispatch"
        ) from error

    try:
        watcher = provider.start_formal_unit_watch(
            provider_run_id=provider_run_id,
            spec=spec,
            reservation_minutes=spec.reservation_minutes,
        )
        watcher_session = watcher.session_sha256
        armed = arm_followup_campaign_watch(
            bound,
            watcher_session_sha256=watcher_session,
        )
        watch_oid = provider.install_campaign_state(
            expected_oid=binding_oid,
            expected_tree_oid=evidence_tree_oid,
            state=armed,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, provider_run_id)
        _best_effort_no_go(
            provider,
            expected_oid=binding_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=bound,
            reason="watcher-failed-or-incomplete",
        )
        raise FollowupCampaignControlError(
            "mandatory watcher could not be armed"
        ) from error
    admission = build_followup_campaign_run_admission_receipt(
        armed,
        reservation_oid=reservation_oid,
        watch_armed_oid=watch_oid,
    )
    try:
        outcome = watcher.wait()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, provider_run_id)
        _best_effort_no_go(
            provider,
            expected_oid=watch_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=armed,
            reason="provider-observation-failed",
        )
        raise FollowupCampaignControlError(
            "mandatory watcher failed after run arm"
        ) from error
    try:
        outcome = _validated_watch_outcome(
            outcome,
            campaign_id=armed.document["campaign_id"],  # type: ignore[arg-type]
            formal_unit_ordinal=spec.ordinal,
            provider_run_id=provider_run_id,
            reservation_minutes=spec.reservation_minutes,
            unit_attempt_ordinal=unit_attempt_ordinal,
            watcher_session_sha256=watcher_session,
        )
    except FollowupCampaignControlError:
        _best_effort_cancel(provider, provider_run_id)
        _best_effort_no_go(
            provider,
            expected_oid=watch_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=armed,
            reason="watcher-failed-or-incomplete",
        )
        raise
    if outcome.decision == "success":
        artifact_id = outcome.artifact_id_or_null
        artifact_name = outcome.artifact_name_or_null
        artifact_digest = outcome.artifact_provider_digest_or_null
        envelope_sha256 = outcome.unit_output_envelope_sha256_or_null
        assert type(artifact_id) is int
        assert type(artifact_name) is str
        assert type(artifact_digest) is str
        assert type(envelope_sha256) is str
        terminal = commit_followup_campaign_unit(
            armed,
            watcher_receipt_sha256=outcome.watcher_receipt_sha256,
            artifact_id=artifact_id,
            artifact_name=artifact_name,
            artifact_provider_digest=artifact_digest,
            unit_output_envelope_sha256=envelope_sha256,
        )
    elif outcome.decision == "provider-failure":
        failure_class = outcome.provider_failure_class_or_null
        failure_evidence = outcome.provider_failure_evidence_sha256_or_null
        assert type(failure_class) is str
        assert type(failure_evidence) is str
        if armed.document["retry_used"] is True:
            terminal = close_followup_campaign_no_go(
                armed,
                terminal_reason_code="nonretryable-provider-failure",
            )
        else:
            terminal = record_followup_provider_failure(
                armed,
                provider_failure_class=failure_class,
                provider_failure_evidence_sha256=failure_evidence,
                watcher_receipt_sha256=outcome.watcher_receipt_sha256,
            )
    else:
        if outcome.no_go_reason_or_null is None:
            raise FollowupCampaignControlError("NO-GO watcher outcome lacks its reason")
        terminal = close_followup_campaign_no_go(
            armed,
            terminal_reason_code=outcome.no_go_reason_or_null,
        )
    try:
        terminal_oid = provider.install_campaign_state(
            expected_oid=watch_oid,
            expected_tree_oid=evidence_tree_oid,
            state=terminal,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_no_go(
            provider,
            expected_oid=watch_oid,
            expected_tree_oid=evidence_tree_oid,
            previous=armed,
            reason="cas-failed-or-ambiguous",
        )
        raise FollowupCampaignControlError(
            "terminal campaign-state CAS failed or was ambiguous"
        ) from error
    return FollowupBoundUnitResult(
        provider_run_id=provider_run_id,
        reservation_oid=reservation_oid,
        binding_oid=binding_oid,
        watch_armed_oid=watch_oid,
        terminal_oid=terminal_oid,
        run_admission=admission,
        reservation_state=reserved,
        binding_state=bound,
        watch_armed_state=armed,
        terminal_state=terminal,
        outcome=outcome,
    )
