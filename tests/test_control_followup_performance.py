from __future__ import annotations

from datetime import UTC, datetime

import pytest

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
