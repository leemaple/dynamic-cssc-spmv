from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_controller as controller
import scripts.control_followup_performance as control
from dynamic_cssc.followup_performance_controller import FollowupControllerError
from scripts.control_followup_performance import GitHubFollowupAdapter


def _included(date: str, body: bytes = b'{"ok":true}\n') -> bytes:
    return (
        b"HTTP/2.0 200 OK\r\n"
        + f"Date: {date}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\n\r\n"
        + body
    )


def test_github_adapter_uses_monotonic_provider_date_not_local_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = GitHubFollowupAdapter(repository="owner/repository")
    responses = iter(
        (
            _included("Sun, 30 Aug 2026 12:00:00 GMT"),
            _included("Sun, 30 Aug 2026 12:00:01 GMT"),
        )
    )
    monkeypatch.setattr(adapter, "_gh", lambda *_args, **_kwargs: next(responses))

    assert adapter._api_json("/first") == {"ok": True}
    assert adapter._api_json("/second") == {"ok": True}
    assert adapter._provider_observed_at() == datetime(
        2026,
        8,
        30,
        12,
        0,
        1,
        tzinfo=UTC,
    )


def test_github_adapter_rejects_missing_backward_or_redirected_provider_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = GitHubFollowupAdapter(repository="owner/repository")
    monkeypatch.setattr(
        adapter,
        "_gh",
        lambda *_args, **_kwargs: _included("Sun, 30 Aug 2026 12:00:01 GMT"),
    )
    adapter._api_json("/first")
    monkeypatch.setattr(
        adapter,
        "_gh",
        lambda *_args, **_kwargs: _included("Sun, 30 Aug 2026 12:00:00 GMT"),
    )
    with pytest.raises(FollowupControllerError, match="moved backwards"):
        adapter._api_json("/backward")

    monkeypatch.setattr(
        adapter,
        "_gh",
        lambda *_args, **_kwargs: b"HTTP/2.0 200 OK\r\n\r\n{}\n",
    )
    with pytest.raises(FollowupControllerError, match="provider Date"):
        adapter._api_json("/missing")

    monkeypatch.setattr(
        adapter,
        "_gh",
        lambda *_args, **_kwargs: (
            _included("Sun, 30 Aug 2026 12:00:02 GMT", b"HTTP/2.0 200 OK\n{}\n")
        ),
    )
    with pytest.raises(FollowupControllerError, match="redirected"):
        adapter._api_json("/redirect")


def test_github_adapter_exposes_no_legacy_positive_dispatch() -> None:
    """Only the provider-global execution adapters may claim and dispatch."""

    assert not hasattr(GitHubFollowupAdapter, "_claim_authority")
    assert not hasattr(GitHubFollowupAdapter, "dispatch_qualification")
    assert not hasattr(GitHubFollowupAdapter, "open_formal_campaign")


def test_controller_exposes_no_legacy_positive_authority_consumers() -> None:
    """Positive authority has one provider-global CAS execution surface."""

    forbidden = {
        "FollowupFormalCampaignDispatcher",
        "FollowupQualificationDispatcher",
        "dispatch_followup_qualification",
        "open_followup_formal_campaign",
    }
    assert forbidden.isdisjoint(controller.__all__)
    assert all(not hasattr(controller, name) for name in forbidden)


def test_analysis_command_needs_no_preanalysis_control_run_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    campaign = tmp_path / "campaign"
    terminal = tmp_path / "terminal"
    campaign.mkdir()
    terminal.mkdir()
    analysis_evidence = tmp_path / "analysis-evidence"
    arguments = control._parser().parse_args(
        [
            "execute-analysis",
            "--repository-root",
            str(tmp_path),
            "--repository",
            "owner/repository",
            "--expected-s1-git-sha",
            "1" * 40,
            "--expected-s2-git-sha",
            "2" * 40,
            "--expected-s3-git-sha",
            "3" * 40,
            "--expected-compatibility-receipt-sha256",
            "4" * 64,
            "--expected-analysis-compatibility-receipt-sha256",
            "5" * 64,
            "--campaign-evidence-root",
            str(campaign),
            "--terminal-evidence-root",
            str(terminal),
            "--analysis-evidence-root",
            str(analysis_evidence),
        ]
    )
    provider = object()
    monkeypatch.setattr(
        control,
        "GitHubFollowupCampaignProvider",
        lambda **_kwargs: provider,
    )
    observed: dict[str, object] = {}

    def execute(**kwargs):  # type: ignore[no-untyped-def]
        observed.update(kwargs)
        return SimpleNamespace(
            decision="publication-results-ready",
            evidence_root=analysis_evidence,
            provider_run_id=90_001,
            run_admission=SimpleNamespace(sha256="6" * 64),
            watch_outcome=SimpleNamespace(
                runner_seconds_or_null=300,
                watcher_receipt_bytes=(
                    b'{"terminal_segment_seconds_or_null":900}\n'
                ),
            ),
        )

    monkeypatch.setattr(control, "execute_followup_analysis", execute)

    assert control._main(arguments) == 0
    output = json.loads(capsys.readouterr().out)
    assert observed["provider"] is provider
    assert observed["analysis_source_s3_sha"] == "3" * 40
    assert output["decision"] == "publication-results-ready"
    assert output["analysis_runner_seconds_or_null"] == 300
    assert output["terminal_segment_seconds_or_null"] == 900
