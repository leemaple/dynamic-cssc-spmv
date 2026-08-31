"""Exact boundary between canonical JSON bytes and GitHub commit messages.

GitHub's Git commit REST API removes one final line feed from the message it
returns.  Publication receipts remain canonical JSON ending in exactly one
line feed; only this boundary translates between the two representations.
"""

from __future__ import annotations

import json

from dynamic_cssc.followup_performance_contract import _canonical_json_bytes

__all__ = (
    "FollowupGitHubCommitMessageError",
    "canonical_json_from_github_commit_message",
    "github_commit_message_from_canonical_json",
)

_MAX_COMMIT_MESSAGE_BYTES = 64 * 1024


class FollowupGitHubCommitMessageError(ValueError):
    """One provider commit message is not the exact canonical JSON projection."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FollowupGitHubCommitMessageError(
                "GitHub commit message contains a duplicate JSON key"
            )
        value[key] = item
    return value


def github_commit_message_from_canonical_json(content: bytes) -> str:
    """Remove only the canonical final LF before sending JSON to GitHub."""

    if (
        type(content) is not bytes
        or not 1 < len(content) <= _MAX_COMMIT_MESSAGE_BYTES
        or not content.endswith(b"\n")
        or content.endswith(b"\n\n")
    ):
        raise FollowupGitHubCommitMessageError(
            "canonical GitHub commit document framing changed"
        )
    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupGitHubCommitMessageError(
                    f"GitHub commit message contains non-finite {token}"
                )
            ),
        )
        canonical = _canonical_json_bytes(value)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise FollowupGitHubCommitMessageError(
            "canonical GitHub commit document is invalid"
        ) from error
    if type(value) is not dict or canonical != content:
        raise FollowupGitHubCommitMessageError(
            "canonical GitHub commit document changed"
        )
    return content[:-1].decode("ascii")


def canonical_json_from_github_commit_message(message: str) -> bytes:
    """Restore the one final LF omitted by GitHub's commit API response."""

    if (
        type(message) is not str
        or not message
        or message.endswith(("\n", "\r"))
        or len(message.encode("utf-8")) >= _MAX_COMMIT_MESSAGE_BYTES
    ):
        raise FollowupGitHubCommitMessageError(
            "GitHub commit message framing changed"
        )
    try:
        content = (message + "\n").encode("ascii")
    except UnicodeEncodeError as error:
        raise FollowupGitHubCommitMessageError(
            "GitHub commit message is not ASCII"
        ) from error
    if github_commit_message_from_canonical_json(content) != message:
        raise FollowupGitHubCommitMessageError(
            "GitHub commit message round trip changed"
        )
    return content
