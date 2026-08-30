from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_analysis_execution as analysis_module
from dynamic_cssc.followup_performance_analysis_evidence import (
    inspect_followup_analysis_evidence_bundle,
)
from dynamic_cssc.followup_performance_analysis_execution import (
    FollowupAnalysisArtifactBinding,
    FollowupAnalysisWatchOutcome,
    build_followup_analysis_watch_outcome,
    execute_followup_analysis,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
)
from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_controller import FollowupControllerError

S1 = "1" * 40
S2 = "2" * 40
S3 = "3" * 40
COMPATIBILITY = "4" * 64


def _render(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _AnalysisWatch:
    def __init__(self, outcome: FollowupAnalysisWatchOutcome) -> None:
        self._outcome = outcome

    @property
    def session_sha256(self) -> str:
        return self._outcome.watcher_session_sha256

    def wait(self) -> FollowupAnalysisWatchOutcome:
        return self._outcome


class _AnalysisProvider:
    analysis_workflow_ref = (
        "example/project/.github/workflows/"
        "followup-performance-analysis.yml@refs/heads/main"
    )

    def __init__(self) -> None:
        self.run_id = 81_001
        self.watcher_started = False
        self.binding_installed_after_watch = False
        self.cancelled: list[int] = []

    def open_analysis(self, claim):  # type: ignore[no-untyped-def]
        assert claim.document["analysis_source_S3_sha"] == S3
        return "a" * 40, "b" * 40

    def dispatch_analysis_run(self, *, inputs: dict[str, str]) -> int:
        assert inputs == {
            "expected_analysis_claim_oid": "a" * 40,
            "expected_analysis_compatibility_receipt_sha256": COMPATIBILITY,
            "expected_campaign_id": "5" * 64,
            "expected_registration_compatibility_receipt_sha256": "6" * 64,
            "expected_s1_git_sha": S1,
            "expected_s2_git_sha": S2,
            "expected_s3_git_sha": S3,
        }
        return self.run_id

    def start_analysis_watch(
        self,
        *,
        provider_run_id,  # type: ignore[no-untyped-def]
        claim,  # type: ignore[no-untyped-def]
    ) -> _AnalysisWatch:
        assert provider_run_id == self.run_id
        self.watcher_started = True
        artifact = FollowupAnalysisArtifactBinding(
            provider_artifact_id=83_001,
            artifact_name="followup-performance-v1-analysis-sentinel",
            provider_digest=f"sha256:{'7' * 64}",
            size_in_bytes=700,
        )
        phase = _canonical_json_bytes(
            {
                "analysis_compatibility_receipt_sha256": COMPATIBILITY,
                "analysis_sha256": "8" * 64,
                "artifact_name": artifact.artifact_name,
                "schema_version": (
                    "dynamic-cssc-followup-performance-analysis-phase-receipt-v1"
                ),
                "unit_identity_sha256": "9" * 64,
            }
        )
        started = datetime(2026, 8, 30, 10, 0, tzinfo=UTC)
        completed = started + timedelta(minutes=5)
        run = _canonical_json_bytes(
            {
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": S3,
                "id": self.run_id,
                "path": ".github/workflows/followup-performance-analysis.yml",
                "run_attempt": 1,
                "status": "completed",
            }
        )
        jobs = _canonical_json_bytes(
            {
                "jobs": [
                    {
                        "completed_at": _render(completed),
                        "conclusion": "success",
                        "id": 82_001,
                        "name": "isolated-descriptive-analysis",
                        "run_attempt": 1,
                        "run_id": self.run_id,
                        "started_at": _render(started),
                        "status": "completed",
                    }
                ],
                "total_count": 1,
            }
        )
        artifacts = _canonical_json_bytes(
            {
                "artifacts": [
                    {
                        "digest": artifact.provider_digest,
                        "expired": False,
                        "id": artifact.provider_artifact_id,
                        "name": artifact.artifact_name,
                        "size_in_bytes": artifact.size_in_bytes,
                        "workflow_run": {"head_sha": S3, "id": self.run_id},
                    }
                ],
                "total_count": 1,
            }
        )
        return _AnalysisWatch(
            build_followup_analysis_watch_outcome(
                claim=claim,
                provider_run_id=self.run_id,
                watcher_session_sha256="c" * 64,
                provider_run_json=run,
                provider_jobs_json=jobs,
                provider_artifacts_json=artifacts,
                provider_phase_receipt_bytes_or_null=phase,
                provider_observed_at=completed + timedelta(seconds=2),
                decision="success",
                job_started_at_or_null=started,
                job_completed_at_or_null=completed,
                analysis_artifact_or_null=artifact,
                cancellation_requested_at_or_null=None,
                cancellation_acknowledged_at_or_null=None,
                no_go_reason_or_null=None,
            )
        )

    def install_analysis_watch_binding(self, **kwargs: object) -> str:
        assert self.watcher_started
        assert kwargs["expected_claim_oid"] == "a" * 40
        self.binding_installed_after_watch = True
        return "d" * 40

    def install_analysis_outcome(self, **kwargs: object) -> str:
        assert self.binding_installed_after_watch
        assert kwargs["expected_binding_oid"] == "d" * 40
        return "e" * 40

    def cancel_analysis_run(self, provider_run_id: int) -> None:
        self.cancelled.append(provider_run_id)


def test_analysis_execution_arms_watch_and_rebinds_exact_s3_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"analysis-transport-sentinel"
    transport = FollowupCampaignTransport(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        member_count=190,
        expanded_bytes=2_000_000,
    )
    terminal_artifact = {
        "artifact_name": (
            "followup-performance-v1-formal-terminal-admission-sentinel"
        ),
        "provider_artifact_id": 73_001,
        "provider_digest": f"sha256:{'a' * 64}",
        "size_in_bytes": 500,
    }
    aggregate_artifact = {
        "artifact_name": "followup-performance-v1-formal-aggregate-sentinel",
        "provider_artifact_id": 73_002,
        "provider_digest": f"sha256:{'b' * 64}",
        "size_in_bytes": 600,
    }
    terminal_watcher = {
        "aggregate_artifact_or_null": aggregate_artifact,
        "decision": "success",
        "runner_seconds_or_null": 10 * 60,
        "terminal_artifact_or_null": terminal_artifact,
    }
    terminal = SimpleNamespace(
        admission=SimpleNamespace(sha256="7" * 64),
        binding=SimpleNamespace(document={"provider_run_id": 71_001}),
        claim=SimpleNamespace(
            document={
                "campaign_id": "5" * 64,
                "campaign_transport_expanded_bytes": transport.expanded_bytes,
                "campaign_transport_member_count": transport.member_count,
                "campaign_transport_sha256": transport.sha256,
                "compatibility_receipt_sha256": "6" * 64,
                "evidence_freeze_S2_sha": S2,
                "experiment_source_S1_sha": S1,
            }
        ),
        controller={"outcome_oid": "f" * 40},
        phase_receipt={"terminal": "success"},
        watcher_receipt=terminal_watcher,
    )
    monkeypatch.setattr(
        analysis_module,
        "materialize_followup_scientific_plan",
        lambda _root: SimpleNamespace(scientific_profile=object()),
    )
    monkeypatch.setattr(
        analysis_module,
        "inspect_followup_terminal_evidence_bundle",
        lambda _root: terminal,
    )
    monkeypatch.setattr(
        analysis_module,
        "build_followup_campaign_transport",
        lambda *_args, **_kwargs: transport,
    )
    monkeypatch.setattr(
        analysis_module,
        "verify_followup_s1_s2_s3_analysis_compatibility",
        lambda *_args, **_kwargs: SimpleNamespace(sha256=COMPATIBILITY),
    )
    provider = _AnalysisProvider()

    result = execute_followup_analysis(
        repository_root=tmp_path,
        campaign_evidence_root=tmp_path / "campaign",
        terminal_evidence_root=tmp_path / "terminal",
        analysis_source_s3_sha=S3,
        expected_analysis_compatibility_receipt_sha256=COMPATIBILITY,
        provider=provider,
        evidence_root=(tmp_path / "analysis-evidence").resolve(),
    )
    inspected = inspect_followup_analysis_evidence_bundle(result.evidence_root)

    assert result.decision == "publication-results-ready"
    assert result.watch_outcome.runner_seconds_or_null == 5 * 60
    assert provider.binding_installed_after_watch
    assert inspected.controller["outcome_oid"] == "e" * 40
    assert inspected.watcher_receipt["terminal_segment_seconds_or_null"] == 15 * 60
    watcher = result.evidence_root / "watcher-receipt.json"
    watcher.chmod(0o600)
    watcher.write_bytes(watcher.read_bytes() + b" ")
    with pytest.raises(FollowupControllerError, match="watcher"):
        inspect_followup_analysis_evidence_bundle(result.evidence_root)


def test_analysis_watcher_rejects_shared_terminal_budget_overrun() -> None:
    claim = analysis_module.build_followup_analysis_claim(
        campaign_id="5" * 64,
        experiment_source_s1_sha=S1,
        evidence_freeze_s2_sha=S2,
        analysis_source_s3_sha=S3,
        registration_compatibility_receipt_sha256="6" * 64,
        analysis_compatibility_receipt_sha256=COMPATIBILITY,
        terminal_outcome_oid="f" * 40,
        terminal_provider_run_id=71_001,
        terminal_run_admission_sha256="7" * 64,
        terminal_watcher_receipt_sha256="8" * 64,
        terminal_runner_seconds=20 * 60,
        campaign_transport_sha256="9" * 64,
        campaign_transport_member_count=190,
        campaign_transport_expanded_bytes=2_000_000,
        terminal_artifact=analysis_module.FollowupTerminalArtifactBinding(
            provider_artifact_id=73_001,
            artifact_name=(
                "followup-performance-v1-formal-terminal-admission-sentinel"
            ),
            provider_digest=f"sha256:{'a' * 64}",
            size_in_bytes=500,
        ),
        aggregate_artifact=analysis_module.FollowupTerminalArtifactBinding(
            provider_artifact_id=73_002,
            artifact_name="followup-performance-v1-formal-aggregate-sentinel",
            provider_digest=f"sha256:{'b' * 64}",
            size_in_bytes=600,
        ),
    )
    started = datetime(2026, 8, 30, 11, 0, tzinfo=UTC)
    with pytest.raises(FollowupControllerError, match="shared terminal budget"):
        build_followup_analysis_watch_outcome(
            claim=claim,
            provider_run_id=81_001,
            watcher_session_sha256="c" * 64,
            provider_run_json=b"{}\n",
            provider_jobs_json=b"{}\n",
            provider_artifacts_json=b"{}\n",
            provider_phase_receipt_bytes_or_null=b"{}\n",
            provider_observed_at=started + timedelta(minutes=11),
            decision="success",
            job_started_at_or_null=started,
            job_completed_at_or_null=started + timedelta(minutes=11),
            analysis_artifact_or_null=FollowupAnalysisArtifactBinding(
                provider_artifact_id=83_001,
                artifact_name="followup-performance-v1-analysis-sentinel",
                provider_digest=f"sha256:{'7' * 64}",
                size_in_bytes=700,
            ),
            cancellation_requested_at_or_null=None,
            cancellation_acknowledged_at_or_null=None,
            no_go_reason_or_null=None,
        )
