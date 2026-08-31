from __future__ import annotations

import pytest

from dynamic_cssc.followup_performance_github_message import (
    FollowupGitHubCommitMessageError,
    canonical_json_from_github_commit_message,
    github_commit_message_from_canonical_json,
)


def test_github_commit_message_round_trip_restores_only_the_final_lf() -> None:
    canonical = b'{"authority":false,"schema_version":"sentinel-v1"}\n'
    provider_message = github_commit_message_from_canonical_json(canonical)

    assert provider_message == canonical[:-1].decode("ascii")
    assert canonical_json_from_github_commit_message(provider_message) == canonical


@pytest.mark.parametrize(
    "content",
    (
        b'{"authority":false}',
        b'{"authority":false}\n\n',
        b'{"authority": false}\n',
        b'{"authority":false,"authority":false}\n',
        b'{"authority":NaN}\n',
        '{"authority":"é"}\n'.encode(),
    ),
)
def test_github_commit_message_rejects_noncanonical_documents(content: bytes) -> None:
    with pytest.raises(FollowupGitHubCommitMessageError):
        github_commit_message_from_canonical_json(content)


@pytest.mark.parametrize(
    "message",
    (
        "",
        '{"authority":false}\n',
        '{"authority":false}\r',
        '{"authority": false}',
        '{"authority":false,"authority":false}',
        '{"authority":"é"}',
    ),
)
def test_github_commit_message_rejects_changed_provider_projection(
    message: str,
) -> None:
    with pytest.raises(FollowupGitHubCommitMessageError):
        canonical_json_from_github_commit_message(message)
