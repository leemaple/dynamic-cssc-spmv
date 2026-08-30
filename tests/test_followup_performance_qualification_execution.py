from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import dynamic_cssc.followup_performance_qualification_execution as execution_module
from dynamic_cssc.followup_performance_controller import (
    FollowupControllerError,
    FollowupDispatchPrerequisites,
    FollowupQualificationOpening,
    FollowupQualificationWatchResult,
)
from dynamic_cssc.followup_performance_qualification_evidence import (
    FollowupQualificationProviderEvidence,
    inspect_followup_qualification_evidence_bundle,
)
from dynamic_cssc.route_a_controller import RouteAQualificationWatchResult


def _request() -> FollowupDispatchPrerequisites:
    return FollowupDispatchPrerequisites(
        expected_s1_git_sha="1" * 40,
        expected_s2_git_sha="2" * 40,
        expected_compatibility_receipt_sha256="3" * 64,
        ci_run_id=1,
        pre_s1_run_id=2,
        registration_run_id=3,
        source_anchor_run_id=4,
        independent_review_run_id=5,
    )


def _opening() -> FollowupQualificationOpening:
    return FollowupQualificationOpening(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
    )


def _result() -> FollowupQualificationWatchResult:
    now = datetime(2026, 8, 30, tzinfo=UTC)
    return FollowupQualificationWatchResult(
        inherited=RouteAQualificationWatchResult(
            decision="combined-guard-success-before-threshold",
            run_id=7001,
            head_sha="2" * 40,
            run_attempt=1,
            q1_started_at=now,
            threshold_at=now,
            controller_observed_at=now,
            q5_completed_at=now,
            cancellation_requested_at=None,
            cancellation_acknowledged_at=None,
            provider_terminal_updated_at=now,
            provider_terminal_conclusion="success",
            watch_decided_at=now,
            cancellation_error=None,
        ),
        qualification_decision="qualification-go",
        q6_started_at=now,
        q6_completed_at=now,
        total_threshold_at=now,
        q6_wall_threshold_at=now,
        q6_controller_observed_at=now,
        q6_provider_terminal_updated_at=now,
        q6_provider_terminal_conclusion="success",
        q6_watch_decided_at=now,
        final_reason="test qualification GO",
    )


def _json(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class _Watch:
    @property
    def session_sha256(self) -> str:
        return "4" * 64

    def wait(self) -> FollowupQualificationWatchResult:
        return _result()


class _Provider:
    def __init__(self, *, fail_binding: bool = False) -> None:
        self.events: list[str] = []
        self.cancelled: list[int] = []
        self.fail_binding = fail_binding

    @property
    def qualification_workflow_ref(self) -> str:
        return (
            "owner/repository/.github/workflows/"
            "followup-performance-qualification.yml@refs/heads/main"
        )

    def open_qualification(self, _opening: object) -> tuple[str, str]:
        self.events.append("claim")
        return "2" * 40, "a" * 40

    def dispatch_qualification_run(self, *, inputs: dict[str, str]) -> int:
        assert inputs["expected_authority_claim_oid"] == "2" * 40
        self.events.append("dispatch")
        return 7001

    def start_qualification_watch(self, **_kwargs: object) -> _Watch:
        self.events.append("watch-started")
        return _Watch()

    def install_qualification_watch_binding(self, **_kwargs: object) -> str:
        self.events.append("binding-installed")
        if self.fail_binding:
            raise RuntimeError("CAS")
        return "b" * 40

    def cancel_qualification(self, provider_run_id: int) -> None:
        self.events.append("cancel")
        self.cancelled.append(provider_run_id)

    def read_qualification_terminal_evidence(
        self,
        provider_run_id: int,
    ) -> FollowupQualificationProviderEvidence:
        assert provider_run_id == 7001
        jobs = [
            {
                "conclusion": "success",
                "id": 8001 + ordinal,
                "name": name,
                "status": "completed",
            }
            for ordinal, name in enumerate(controller_name for controller_name in (
                "qualification-simulator-producer",
                "qualification-simulator-independent-replay-and-guard",
                "qualification-native-case-shaped-producer",
                "qualification-native-independent-replay-and-guard",
                "qualification-combined-guard",
                "qualification-postrun-resource-admission",
            ))
        ]
        artifacts = [{"id": 9001 + ordinal} for ordinal in range(6)]
        return FollowupQualificationProviderEvidence(
            observed_at=datetime(2026, 8, 30, tzinfo=UTC),
            run_json=_json(
                {
                    "conclusion": "success",
                    "event": "workflow_dispatch",
                    "head_branch": "main",
                    "head_sha": "2" * 40,
                    "id": 7001,
                    "path": (
                        ".github/workflows/"
                        "followup-performance-qualification.yml"
                    ),
                    "run_attempt": 1,
                    "status": "completed",
                }
            ),
            jobs_json=_json({"jobs": jobs, "total_count": 6}),
            artifacts_json=_json(
                {"artifacts": artifacts, "total_count": 6}
            ),
        )


def test_qualification_starts_mandatory_watcher_before_seed_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider = _Provider()
    monkeypatch.setattr(
        execution_module,
        "consume_followup_qualification_capability",
        lambda _capability, _request: _opening(),
    )

    result = execution_module.execute_followup_qualification(
        object(),  # type: ignore[arg-type]
        _request(),
        provider,
        evidence_root=tmp_path / "qualification-evidence",
    )

    assert provider.events == [
        "claim",
        "dispatch",
        "watch-started",
        "binding-installed",
    ]
    assert result.provider_run_id == 7001
    assert result.run_admission.document["watcher_session_sha256"] == "4" * 64
    bundle = inspect_followup_qualification_evidence_bundle(result.evidence_root)
    assert bundle.controller["qualification_decision"] == "qualification-go"


def test_qualification_binding_failure_cancels_only_the_exact_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider = _Provider(fail_binding=True)
    monkeypatch.setattr(
        execution_module,
        "consume_followup_qualification_capability",
        lambda _capability, _request: _opening(),
    )

    with pytest.raises(FollowupControllerError, match="could not be armed"):
        execution_module.execute_followup_qualification(
            object(),  # type: ignore[arg-type]
            _request(),
            provider,
            evidence_root=tmp_path / "qualification-evidence",
        )

    assert provider.cancelled == [7001]
    assert provider.events[-1] == "cancel"
