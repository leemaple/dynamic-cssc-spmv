from __future__ import annotations

import json

import pytest

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
