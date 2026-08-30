from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

from dynamic_cssc.followup_performance_analysis_binding import (
    FollowupAnalysisBindingError,
    build_followup_analysis_claim,
    build_followup_analysis_watch_binding,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
)
from scripts.verify_followup_analysis_run_admission import _main


def _write(path: Path, value: dict[str, object]) -> Path:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    return path


def _arguments(tmp_path: Path, *, parent: str = "d" * 40) -> argparse.Namespace:
    transport = b"campaign-evidence-transport"
    claim = build_followup_analysis_claim(
        campaign_id="1" * 64,
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        analysis_source_s3_sha="3" * 40,
        registration_compatibility_receipt_sha256="4" * 64,
        analysis_compatibility_receipt_sha256="5" * 64,
        terminal_outcome_oid="d" * 40,
        terminal_provider_run_id=70_001,
        terminal_run_admission_sha256="6" * 64,
        terminal_watcher_receipt_sha256="7" * 64,
        terminal_runner_seconds=600,
        campaign_transport_sha256=hashlib.sha256(transport).hexdigest(),
        campaign_transport_member_count=190,
        campaign_transport_expanded_bytes=2_000_000,
        terminal_artifact=FollowupTerminalArtifactBinding(
            provider_artifact_id=71_001,
            artifact_name=(
                "followup-performance-v1-formal-terminal-admission-sentinel"
            ),
            provider_digest=f"sha256:{'8' * 64}",
            size_in_bytes=101,
        ),
        aggregate_artifact=FollowupTerminalArtifactBinding(
            provider_artifact_id=71_002,
            artifact_name="followup-performance-v1-formal-aggregate-sentinel",
            provider_digest=f"sha256:{'9' * 64}",
            size_in_bytes=202,
        ),
    )
    binding = build_followup_analysis_watch_binding(
        claim,
        claim_oid="a" * 40,
        provider_run_id=80_001,
        watcher_session_sha256="b" * 64,
        workflow_ref=(
            "example/project/.github/workflows/"
            "followup-performance-analysis.yml@refs/heads/main"
        ),
    )
    transport_path = tmp_path / "campaign-evidence.zip"
    transport_path.write_bytes(transport)
    return argparse.Namespace(
        ref_json=_write(
            tmp_path / "ref.json",
            {
                "object": {"sha": "b" * 40, "type": "commit"},
                "ref": "refs/tags/dynamic-cssc-followup-performance-analysis-v1",
            },
        ),
        claim_commit_json=_write(
            tmp_path / "claim.json",
            {
                "message": claim.document_bytes.decode("ascii"),
                "parents": [{"sha": parent}],
                "sha": "a" * 40,
                "tree": {"sha": "c" * 40},
            },
        ),
        binding_commit_json=_write(
            tmp_path / "binding.json",
            {
                "message": binding.document_bytes.decode("ascii"),
                "parents": [{"sha": "a" * 40}],
                "sha": "b" * 40,
                "tree": {"sha": "c" * 40},
            },
        ),
        campaign_transport=transport_path,
        expected_claim_oid="a" * 40,
        expected_campaign_id="1" * 64,
        expected_s1="1" * 40,
        expected_s2="2" * 40,
        expected_s3="3" * 40,
        expected_registration_compatibility="4" * 64,
        expected_analysis_compatibility="5" * 64,
        expected_provider_run_id=80_001,
    )


def test_analysis_run_admission_rebuilds_exact_claim_and_binding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _main(_arguments(tmp_path)) == 0
    receipt = json.loads(capsys.readouterr().out)

    assert receipt["analysis_runner_seconds_limit"] == 1200
    assert receipt["terminal_runner_seconds"] == 600
    assert receipt["terminal_provider_run_id"] == 70_001
    assert receipt["terminal_artifact_size_in_bytes"] == 101
    assert receipt["aggregate_artifact_size_in_bytes"] == 202


def test_analysis_run_admission_rejects_wrong_terminal_parent(tmp_path: Path) -> None:
    with pytest.raises(FollowupAnalysisBindingError, match="identity"):
        _main(_arguments(tmp_path, parent="e" * 40))
