from __future__ import annotations

import json

import pytest

from dynamic_cssc.followup_performance_analysis_binding import (
    FollowupAnalysisBindingError,
    build_followup_analysis_claim,
    build_followup_analysis_run_admission,
    build_followup_analysis_watch_binding,
    inspect_followup_analysis_claim,
    inspect_followup_analysis_watch_binding,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
)


def _claim():  # type: ignore[no-untyped-def]
    return build_followup_analysis_claim(
        campaign_id="1" * 64,
        experiment_source_s1_sha="2" * 40,
        evidence_freeze_s2_sha="3" * 40,
        analysis_source_s3_sha="4" * 40,
        registration_compatibility_receipt_sha256="5" * 64,
        analysis_compatibility_receipt_sha256="6" * 64,
        terminal_outcome_oid="7" * 40,
        terminal_provider_run_id=8_001,
        terminal_run_admission_sha256="8" * 64,
        terminal_watcher_receipt_sha256="9" * 64,
        terminal_runner_seconds=600,
        campaign_transport_sha256="a" * 64,
        campaign_transport_member_count=190,
        campaign_transport_expanded_bytes=2_000_000,
        terminal_artifact=FollowupTerminalArtifactBinding(
            provider_artifact_id=9_001,
            artifact_name=(
                "followup-performance-v1-formal-terminal-admission-sentinel"
            ),
            provider_digest=f"sha256:{'b' * 64}",
            size_in_bytes=101,
        ),
        aggregate_artifact=FollowupTerminalArtifactBinding(
            provider_artifact_id=9_002,
            artifact_name="followup-performance-v1-formal-aggregate-sentinel",
            provider_digest=f"sha256:{'c' * 64}",
            size_in_bytes=202,
        ),
    )


def test_analysis_claim_binding_and_admission_share_remaining_terminal_budget() -> None:
    claim = _claim()
    binding = build_followup_analysis_watch_binding(
        claim,
        claim_oid="d" * 40,
        provider_run_id=10_001,
        watcher_session_sha256="e" * 64,
        workflow_ref=(
            "owner/repository/.github/workflows/"
            "followup-performance-analysis.yml@refs/heads/main"
        ),
    )
    admission = build_followup_analysis_run_admission(
        claim,
        binding,
        binding_oid="f" * 40,
    )

    assert inspect_followup_analysis_claim(claim.document_bytes) == claim
    assert inspect_followup_analysis_watch_binding(binding.document_bytes) == binding
    assert claim.document["analysis_runner_seconds_limit"] == 20 * 60
    assert admission.document["analysis_runner_seconds_limit"] == 20 * 60
    assert admission.document["provider_run_id"] == 10_001


def test_analysis_binding_rejects_duplicate_or_exhausted_segment() -> None:
    claim = _claim()
    duplicate = claim.document_bytes.replace(
        b'{"aggregate_artifact":',
        b'{"aggregate_artifact":null,"aggregate_artifact":',
    )
    with pytest.raises(FollowupAnalysisBindingError, match="duplicate"):
        inspect_followup_analysis_claim(duplicate)

    value = json.loads(claim.document_bytes)
    value["terminal_runner_seconds"] = 1800
    value["analysis_runner_seconds_limit"] = 0
    with pytest.raises(FollowupAnalysisBindingError, match="projection"):
        inspect_followup_analysis_claim(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
