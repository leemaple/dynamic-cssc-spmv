from __future__ import annotations

import hashlib

import pytest

from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_watcher_receipt import (
    FollowupFormalWatcherReceiptError,
    inspect_followup_formal_watcher_receipt,
)


def _cancellation_ledger(
    *,
    threshold_utc: str = "2026-08-30T00:20:00Z",
    provider_terminal_updated_utc: str = "2026-08-30T00:20:01Z",
) -> dict[str, object]:
    return {
        "ack_to_watch_decision_seconds": 1,
        "cancel_request_utc": "2026-08-30T00:20:03Z",
        "controller_detection_utc": "2026-08-30T00:20:02Z",
        "final_conclusion": "cancelled",
        "provider_api_ack_utc": "2026-08-30T00:20:04Z",
        "provider_terminal_updated_utc": provider_terminal_updated_utc,
        "request_to_ack_seconds": 1,
        "threshold_utc": threshold_utc,
        "watch_decided_utc": "2026-08-30T00:20:05Z",
    }


def _terminal_receipt(
    *,
    decision: str,
    cancellation_ledger: dict[str, object],
    no_go_reason: str = "budget-exhausted",
) -> bytes:
    document: dict[str, object] = {
        "artifacts_api_sha256": hashlib.sha256(b"artifacts").hexdigest(),
        "authority": False,
        "campaign_id": "1" * 64,
        "cancellation_ledger": cancellation_ledger,
        "decision": decision,
        "formal_unit_ordinal": 0,
        "jobs_api_sha256": hashlib.sha256(b"jobs").hexdigest(),
        "no_go_reason_or_null": (
            no_go_reason if decision == "no-go" else None
        ),
        "provider_failure_class_or_null": (
            "hosted-runner-loss-or-shutdown"
            if decision == "provider-failure"
            else None
        ),
        "provider_failure_evidence_sha256_or_null": (
            hashlib.sha256(b"provider-failure").hexdigest()
            if decision == "provider-failure"
            else None
        ),
        "provider_run_id": 90_001,
        "publication_evidence_admitted": False,
        "run_api_sha256": hashlib.sha256(b"run").hexdigest(),
        "schema_version": "dynamic-cssc-followup-performance-watcher-receipt-v3",
        "unit_attempt_ordinal": 1,
        "watcher_session_sha256": "2" * 64,
    }
    return _canonical_json_bytes(document)


def test_provider_failure_cannot_carry_a_cancellation_ledger() -> None:
    content = _terminal_receipt(
        decision="provider-failure",
        cancellation_ledger=_cancellation_ledger(),
    )

    with pytest.raises(FollowupFormalWatcherReceiptError, match="provider-failure"):
        inspect_followup_formal_watcher_receipt(content)


def test_cancellation_threshold_cannot_follow_provider_terminal_update() -> None:
    content = _terminal_receipt(
        decision="no-go",
        cancellation_ledger=_cancellation_ledger(
            threshold_utc="2026-08-30T00:20:02Z",
            provider_terminal_updated_utc="2026-08-30T00:20:01Z",
        ),
    )

    with pytest.raises(FollowupFormalWatcherReceiptError, match="threshold"):
        inspect_followup_formal_watcher_receipt(content)


def test_scientific_no_go_cannot_carry_a_cancellation_ledger() -> None:
    content = _terminal_receipt(
        decision="no-go",
        cancellation_ledger=_cancellation_ledger(),
        no_go_reason="scientific-or-guard-failure",
    )

    with pytest.raises(FollowupFormalWatcherReceiptError, match="NO-GO"):
        inspect_followup_formal_watcher_receipt(content)
