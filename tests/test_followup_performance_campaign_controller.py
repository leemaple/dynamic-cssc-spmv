from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from dynamic_cssc.followup_performance_campaign import (
    FollowupCampaignState,
    arm_followup_campaign_watch,
    bind_followup_campaign_run,
    commit_followup_campaign_unit,
    open_followup_campaign_state,
    reserve_followup_campaign_unit,
)
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupAcquisitionRunBinding,
    FollowupCampaignControlError,
    FollowupFormalUnitWatchOutcome,
    dispatch_bind_watch,
)
from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_formal_matrix import (
    followup_formal_unit_specs,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

PLAN = b'{"campaign-controller-sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="campaign-controller-sentinel",
    qualification_seed=96_001,
    formal_seeds=(96_002, 96_003, 96_004),
    query_vector_seed=9_600_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _opened() -> FollowupCampaignState:
    return open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        qualification_run_id=7001,
        qualification_q6_artifact_id=8001,
        qualification_q6_artifact_digest=f"sha256:{'4' * 64}",
        scientific_profile=PROFILE,
    )


def _success_outcome(
    *,
    artifact_name: str | None = None,
    attempt: int = 1,
    ordinal: int = 0,
    run_id: int = 9001,
    watcher_session: str = "5" * 64,
) -> FollowupFormalUnitWatchOutcome:
    spec = followup_formal_unit_specs(PROFILE)[ordinal]
    artifact_name = artifact_name or f"followup-performance-v1-{spec.job_token}"
    run_json = b'{"conclusion":"success","updated_at":"2026-08-30T00:10:00Z"}\n'
    jobs_json = b'{"jobs":[],"total_count":0}\n'
    artifacts_json = b'{"artifacts":[],"total_count":0}\n'
    guard_receipt = b'{"guard":true}\n'
    watcher_receipt = _canonical_json_bytes(
        {
            "artifact_id": 9101,
            "artifact_name": artifact_name,
            "artifact_provider_digest": f"sha256:{'7' * 64}",
            "artifacts_api_sha256": hashlib.sha256(artifacts_json).hexdigest(),
            "authority": False,
            "campaign_id": _opened().document["campaign_id"],
            "cancellation_ledger": None,
            "critical_path_seconds": 600,
            "decision": "success",
            "formal_unit_ordinal": ordinal,
            "guard_receipt_bytes_sha256": hashlib.sha256(
                guard_receipt
            ).hexdigest(),
            "jobs_api_sha256": hashlib.sha256(jobs_json).hexdigest(),
            "provider_run_id": run_id,
            "publication_evidence_admitted": False,
            "reservation_minutes": spec.reservation_minutes,
            "run_api_sha256": hashlib.sha256(run_json).hexdigest(),
            "schema_version": (
                "dynamic-cssc-followup-performance-watcher-receipt-v3"
            ),
            "unit_attempt_ordinal": attempt,
            "unit_output_envelope_sha256": "8" * 64,
            "watcher_session_sha256": watcher_session,
        }
    )
    return FollowupFormalUnitWatchOutcome(
        provider_run_id=run_id,
        watcher_session_sha256=watcher_session,
        watcher_receipt_sha256=hashlib.sha256(watcher_receipt).hexdigest(),
        watcher_receipt_bytes=watcher_receipt,
        provider_run_json=run_json,
        provider_jobs_json=jobs_json,
        provider_artifacts_json=artifacts_json,
        provider_guard_receipt_bytes_or_null=guard_receipt,
        decision="success",
        artifact_id_or_null=9101,
        artifact_name_or_null=artifact_name,
        artifact_provider_digest_or_null=f"sha256:{'7' * 64}",
        unit_output_envelope_sha256_or_null="8" * 64,
        provider_failure_class_or_null=None,
        provider_failure_evidence_sha256_or_null=None,
        provider_failure_evidence_bytes_or_null=None,
        no_go_reason_or_null=None,
    )


def _provider_failure_outcome(
    *,
    attempt: int = 1,
    ordinal: int = 0,
    run_id: int = 9001,
    watcher_session: str = "5" * 64,
) -> FollowupFormalUnitWatchOutcome:
    failure_evidence = b'{"provider-failure-sentinel":true}\n'
    run_json = (
        b'{"conclusion":"cancelled",'
        b'"updated_at":"2026-08-30T00:10:00Z"}\n'
    )
    jobs_json = b'{"jobs":[],"total_count":0}\n'
    artifacts_json = b'{"artifacts":[],"total_count":0}\n'
    failure_sha = hashlib.sha256(failure_evidence).hexdigest()
    watcher_receipt = _canonical_json_bytes(
        {
            "artifacts_api_sha256": hashlib.sha256(artifacts_json).hexdigest(),
            "authority": False,
            "campaign_id": _opened().document["campaign_id"],
            "cancellation_ledger": None,
            "decision": "provider-failure",
            "formal_unit_ordinal": ordinal,
            "jobs_api_sha256": hashlib.sha256(jobs_json).hexdigest(),
            "no_go_reason_or_null": None,
            "provider_failure_class_or_null": "hosted-runner-loss-or-shutdown",
            "provider_failure_evidence_sha256_or_null": failure_sha,
            "provider_run_id": run_id,
            "publication_evidence_admitted": False,
            "run_api_sha256": hashlib.sha256(run_json).hexdigest(),
            "schema_version": (
                "dynamic-cssc-followup-performance-watcher-receipt-v3"
            ),
            "unit_attempt_ordinal": attempt,
            "watcher_session_sha256": watcher_session,
        }
    )
    return FollowupFormalUnitWatchOutcome(
        provider_run_id=run_id,
        watcher_session_sha256=watcher_session,
        watcher_receipt_sha256=hashlib.sha256(watcher_receipt).hexdigest(),
        watcher_receipt_bytes=watcher_receipt,
        provider_run_json=run_json,
        provider_jobs_json=jobs_json,
        provider_artifacts_json=artifacts_json,
        provider_guard_receipt_bytes_or_null=None,
        decision="provider-failure",
        artifact_id_or_null=None,
        artifact_name_or_null=None,
        artifact_provider_digest_or_null=None,
        unit_output_envelope_sha256_or_null=None,
        provider_failure_class_or_null="hosted-runner-loss-or-shutdown",
        provider_failure_evidence_sha256_or_null=failure_sha,
        provider_failure_evidence_bytes_or_null=failure_evidence,
        no_go_reason_or_null=None,
    )


class _Watch:
    def __init__(
        self,
        outcome: FollowupFormalUnitWatchOutcome,
        *,
        fail_wait: bool = False,
    ) -> None:
        self._outcome = outcome
        self._fail_wait = fail_wait

    @property
    def session_sha256(self) -> str:
        return self._outcome.watcher_session_sha256

    def wait(self) -> FollowupFormalUnitWatchOutcome:
        if self._fail_wait:
            raise OSError("provider observation disappeared")
        return self._outcome


class _Provider:
    def __init__(
        self,
        outcome: FollowupFormalUnitWatchOutcome | None = None,
        *,
        fail_install_calls: frozenset[int] = frozenset(),
        fail_dispatch: bool = False,
        fail_watch_start: bool = False,
        fail_watch_wait: bool = False,
    ) -> None:
        self.outcome = outcome or _success_outcome()
        self.fail_install_calls = fail_install_calls
        self.fail_dispatch = fail_dispatch
        self.fail_watch_start = fail_watch_start
        self.fail_watch_wait = fail_watch_wait
        self.install_calls: list[tuple[str, str, FollowupCampaignState]] = []
        self.dispatch_inputs: list[dict[str, str]] = []
        self.cancelled: list[int] = []

    def install_campaign_state(
        self,
        *,
        expected_oid: str,
        expected_tree_oid: str,
        state: FollowupCampaignState,
    ) -> str:
        self.install_calls.append((expected_oid, expected_tree_oid, state))
        call = len(self.install_calls)
        if call in self.fail_install_calls:
            raise OSError(f"CAS {call} ambiguous")
        return f"{call:040x}"

    def dispatch_formal_unit(self, *, inputs: dict[str, str]) -> int:
        self.dispatch_inputs.append(inputs)
        if self.fail_dispatch:
            raise OSError("dispatch response missing")
        return self.outcome.provider_run_id

    def start_formal_unit_watch(self, **_kwargs: object) -> _Watch:
        if self.fail_watch_start:
            raise OSError("watcher not established")
        return _Watch(self.outcome, fail_wait=self.fail_watch_wait)

    def cancel_formal_unit(self, provider_run_id: int) -> None:
        self.cancelled.append(provider_run_id)


def _dispatch(
    provider: _Provider,
    *,
    previous: FollowupCampaignState | None = None,
    ordinal: int = 0,
    attempt: int = 1,
    acquisition: FollowupAcquisitionRunBinding | None = None,
):  # type: ignore[no-untyped-def]
    return dispatch_bind_watch(
        previous or _opened(),
        progress_oid="a" * 40,
        evidence_tree_oid="b" * 40,
        spec=followup_formal_unit_specs(PROFILE)[ordinal],
        unit_attempt_ordinal=attempt,
        provider=provider,
        acquisition=acquisition,
    )


def _committed_prefix(count: int) -> FollowupCampaignState:
    state = _opened()
    for index, spec in enumerate(followup_formal_unit_specs(PROFILE)[:count]):
        reserved = reserve_followup_campaign_unit(
            state,
            spec,
            unit_attempt_ordinal=1,
        )
        bound = bind_followup_campaign_run(reserved, provider_run_id=10_000 + index)
        armed = arm_followup_campaign_watch(
            bound,
            watcher_session_sha256=f"{20_000 + index:064x}",
        )
        state = commit_followup_campaign_unit(
            armed,
            watcher_receipt_sha256=f"{30_000 + index:064x}",
            artifact_id=40_000 + index,
            artifact_name=f"followup-performance-v1-prefix-{index:02d}",
            artifact_provider_digest=f"sha256:{50_000 + index:064x}",
            unit_output_envelope_sha256=f"{60_000 + index:064x}",
        )
    return state


def test_dispatch_bind_watch_commits_only_after_watch_is_armed() -> None:
    provider = _Provider()

    result = _dispatch(provider)

    assert [call[2].state for call in provider.install_calls] == [
        "unit-reserved",
        "run-bound",
        "watch-armed",
        "unit-committed",
    ]
    assert result.terminal_state.state == "unit-committed"
    assert result.run_admission.document["provider_run_id"] == 9001
    assert result.run_admission.document["watch_armed_oid"] == result.watch_armed_oid
    assert provider.dispatch_inputs == [
        {
            "expected_campaign_id": _opened().document["campaign_id"],
            "expected_compatibility_receipt_sha256": "3" * 64,
                "expected_job_token": "formal-00-acquisition",
                "expected_reservation_oid": "0" * 39 + "1",
                "expected_reservation_minutes": "20",
                "expected_s1_git_sha": "1" * 40,
            "expected_s2_git_sha": "2" * 40,
            "formal_unit_ordinal": "0",
            "unit_attempt_ordinal": "1",
        }
    ]


@pytest.mark.parametrize(
    ("provider", "cancelled", "terminal_state"),
    [
        (_Provider(fail_dispatch=True), [], "campaign-no-go"),
        (_Provider(fail_install_calls=frozenset({2})), [9001], "campaign-no-go"),
        (_Provider(fail_watch_start=True), [9001], "campaign-no-go"),
        (_Provider(fail_watch_wait=True), [9001], "campaign-no-go"),
    ],
)
def test_provider_ambiguity_cancels_exact_run_and_closes_no_go_when_possible(
    provider: _Provider,
    cancelled: list[int],
    terminal_state: str,
) -> None:
    with pytest.raises(FollowupCampaignControlError):
        _dispatch(provider)

    assert provider.cancelled == cancelled
    assert provider.install_calls[-1][2].state == terminal_state


def test_malformed_success_is_cancelled_and_closed_instead_of_committed() -> None:
    malformed = replace(_success_outcome(), artifact_id_or_null=None)
    provider = _Provider(malformed)

    with pytest.raises(FollowupCampaignControlError, match="guarded artifact"):
        _dispatch(provider)

    assert provider.cancelled == [9001]
    assert provider.install_calls[-1][2].state == "campaign-no-go"
    assert (
        provider.install_calls[-1][2].document["terminal_reason_code_or_null"]
        == "watcher-failed-or-incomplete"
    )


def test_watcher_receipt_must_bind_exact_provider_bytes() -> None:
    outcome = _success_outcome()
    provider = _Provider(
        replace(
            outcome,
            provider_jobs_json=b'{"jobs":[{"tampered":true}],"total_count":1}\n',
        )
    )

    with pytest.raises(FollowupCampaignControlError, match="exact provider outcome"):
        _dispatch(provider)

    assert provider.cancelled == [9001]
    assert provider.install_calls[-1][2].state == "campaign-no-go"


def test_rehashed_watcher_authority_tamper_is_rejected() -> None:
    outcome = _success_outcome()
    receipt = json.loads(outcome.watcher_receipt_bytes)
    receipt["authority"] = True
    receipt_bytes = _canonical_json_bytes(receipt)
    provider = _Provider(
        replace(
            outcome,
            watcher_receipt_bytes=receipt_bytes,
            watcher_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        )
    )

    with pytest.raises(FollowupCampaignControlError, match="canonical inspection"):
        _dispatch(provider)

    assert provider.cancelled == [9001]
    assert provider.install_calls[-1][2].state == "campaign-no-go"


def test_only_first_closed_provider_failure_can_be_replaced() -> None:
    failed_outcome = _provider_failure_outcome()
    first = _dispatch(_Provider(failed_outcome))
    assert first.terminal_state.state == "unit-provider-failed"

    second_outcome = _provider_failure_outcome(run_id=9002, attempt=2)
    second = _dispatch(
        _Provider(second_outcome),
        previous=first.terminal_state,
        attempt=2,
    )
    assert second.terminal_state.state == "campaign-no-go"
    assert (
        second.terminal_state.document["terminal_reason_code_or_null"]
        == "nonretryable-provider-failure"
    )


def test_ordered_unit_requires_exact_acquisition_provider_binding() -> None:
    previous = _committed_prefix(13)
    missing = _Provider(replace(_success_outcome(), provider_run_id=9013))

    with pytest.raises(FollowupCampaignControlError, match="lacks its admitted acquisition"):
        _dispatch(missing, previous=previous, ordinal=13)
    assert missing.install_calls[-1][2].state == "campaign-no-go"

    binding = FollowupAcquisitionRunBinding(
        artifact_name="followup-performance-v1-formal-acquisition-00",
        provider_run_id=9001,
        provider_artifact_id=9101,
        provider_artifact_digest=f"sha256:{'7' * 64}",
        campaign_run_admission_sha256="8" * 64,
        unit_attempt_ordinal=1,
    )
    success = _Provider(
        _success_outcome(
            run_id=9013,
            ordinal=13,
            artifact_name="followup-performance-v1-formal-ordered-event-13",
        )
    )
    result = _dispatch(
        success,
        previous=previous,
        ordinal=13,
        acquisition=binding,
    )
    assert result.terminal_state.state == "unit-committed"
    assert success.dispatch_inputs[0]["acquisition_provider_run_id"] == "9001"


def test_terminal_cas_ambiguity_never_returns_a_committed_result() -> None:
    provider = _Provider(fail_install_calls=frozenset({4}))

    with pytest.raises(FollowupCampaignControlError, match="terminal"):
        _dispatch(provider)

    assert provider.install_calls[-1][2].state == "campaign-no-go"
