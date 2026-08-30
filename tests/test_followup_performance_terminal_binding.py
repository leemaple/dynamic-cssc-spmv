from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

import scripts.verify_followup_terminal_run_admission as admission_script
from dynamic_cssc.followup_performance_terminal_binding import (
    FollowupTerminalBindingError,
    build_followup_terminal_claim,
    build_followup_terminal_run_admission,
    build_followup_terminal_watch_binding,
    inspect_followup_terminal_claim,
    inspect_followup_terminal_watch_binding,
)


def _claim():  # type: ignore[no-untyped-def]
    return build_followup_terminal_claim(
        campaign_id="1" * 64,
        experiment_source_s1_sha="2" * 40,
        evidence_freeze_s2_sha="3" * 40,
        compatibility_receipt_sha256="4" * 64,
        final_progress_oid="5" * 40,
        campaign_selection_sha256="6" * 64,
        formal_timing_ledger_sha256="7" * 64,
        campaign_transport_sha256="8" * 64,
        campaign_transport_member_count=190,
        campaign_transport_expanded_bytes=2_000_000,
    )


def test_terminal_claim_binding_and_run_admission_close_one_exact_run() -> None:
    claim = _claim()
    binding = build_followup_terminal_watch_binding(
        claim,
        claim_oid="9" * 40,
        provider_run_id=10_001,
        watcher_session_sha256="a" * 64,
        workflow_ref=(
            "owner/repository/.github/workflows/"
            "followup-performance-terminal.yml@refs/heads/main"
        ),
    )
    admission = build_followup_terminal_run_admission(
        claim,
        binding,
        binding_oid="b" * 40,
    )

    assert inspect_followup_terminal_claim(claim.document_bytes) == claim
    assert inspect_followup_terminal_watch_binding(binding.document_bytes) == binding
    assert admission.document["provider_run_id"] == 10_001
    assert admission.document["campaign_transport_sha256"] == "8" * 64
    assert admission.document["authority"] is False


def test_terminal_binding_rejects_duplicate_or_cross_claim_bytes() -> None:
    claim = _claim()
    duplicate = claim.document_bytes.replace(
        b'{"authority":false,',
        b'{"authority":false,"authority":false,',
    )
    with pytest.raises(FollowupTerminalBindingError, match="duplicate"):
        inspect_followup_terminal_claim(duplicate)

    value = json.loads(claim.document_bytes)
    value["campaign_transport_sha256"] = "c" * 64
    changed = build_followup_terminal_claim(
        campaign_id=value["campaign_id"],
        experiment_source_s1_sha=value["experiment_source_S1_sha"],
        evidence_freeze_s2_sha=value["evidence_freeze_S2_sha"],
        compatibility_receipt_sha256=value["compatibility_receipt_sha256"],
        final_progress_oid=value["final_progress_oid"],
        campaign_selection_sha256=value["campaign_selection_sha256"],
        formal_timing_ledger_sha256=value["formal_timing_ledger_sha256"],
        campaign_transport_sha256=value["campaign_transport_sha256"],
        campaign_transport_member_count=value["campaign_transport_member_count"],
        campaign_transport_expanded_bytes=value["campaign_transport_expanded_bytes"],
    )
    binding = build_followup_terminal_watch_binding(
        changed,
        claim_oid="9" * 40,
        provider_run_id=10_001,
        watcher_session_sha256="a" * 64,
        workflow_ref=(
            "owner/repository/.github/workflows/"
            "followup-performance-terminal.yml@refs/heads/main"
        ),
    )
    with pytest.raises(FollowupTerminalBindingError, match="lineage"):
        build_followup_terminal_run_admission(
            claim,
            binding,
            binding_oid="b" * 40,
        )


def test_terminal_admission_script_rebuilds_claim_binding_and_transport(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transport = b"terminal-campaign-transport"
    claim = build_followup_terminal_claim(
        campaign_id="1" * 64,
        experiment_source_s1_sha="2" * 40,
        evidence_freeze_s2_sha="3" * 40,
        compatibility_receipt_sha256="4" * 64,
        final_progress_oid="5" * 40,
        campaign_selection_sha256="6" * 64,
        formal_timing_ledger_sha256="7" * 64,
        campaign_transport_sha256=hashlib.sha256(transport).hexdigest(),
        campaign_transport_member_count=190,
        campaign_transport_expanded_bytes=2_000_000,
    )
    claim_oid = "9" * 40
    binding_oid = "b" * 40
    tree_oid = "c" * 40
    binding = build_followup_terminal_watch_binding(
        claim,
        claim_oid=claim_oid,
        provider_run_id=10_001,
        watcher_session_sha256="a" * 64,
        workflow_ref=(
            "owner/repository/.github/workflows/"
            "followup-performance-terminal.yml@refs/heads/main"
        ),
    )

    def write(name: str, value: dict[str, object]) -> Path:
        path = tmp_path / name
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        return path

    transport_path = tmp_path / "campaign-evidence.zip"
    transport_path.write_bytes(transport)
    arguments = argparse.Namespace(
        ref_json=write(
            "ref.json",
            {
                "object": {"sha": binding_oid, "type": "commit"},
                "ref": "refs/tags/dynamic-cssc-followup-performance-formal-terminal-v1",
            },
        ),
        claim_commit_json=write(
            "claim.json",
            {
                "message": claim.document_bytes.decode("ascii"),
                "parents": [{"sha": "5" * 40}],
                "sha": claim_oid,
                "tree": {"sha": tree_oid},
            },
        ),
        binding_commit_json=write(
            "binding.json",
            {
                "message": binding.document_bytes.decode("ascii"),
                "parents": [{"sha": claim_oid}],
                "sha": binding_oid,
                "tree": {"sha": tree_oid},
            },
        ),
        campaign_transport=transport_path,
        expected_claim_oid=claim_oid,
        expected_campaign_id="1" * 64,
        expected_s1="2" * 40,
        expected_s2="3" * 40,
        expected_compatibility="4" * 64,
        expected_provider_run_id=10_001,
    )

    assert admission_script._main(arguments) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["binding_oid"] == binding_oid
    assert output["campaign_transport_sha256"] == hashlib.sha256(
        transport
    ).hexdigest()

    transport_path.write_bytes(transport + b"-changed")
    with pytest.raises(FollowupTerminalBindingError, match="transport changed"):
        admission_script._main(arguments)
