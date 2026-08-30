"""Bounded GitHub CLI transport with monotone provider-clock observations."""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Protocol

__all__ = (
    "FollowupGitHubTransport",
    "FollowupGitHubTransportError",
    "GitHubCliTransport",
    "GitHubHttpResponse",
)

_API_VERSION = "2026-03-10"
_MAX_HEADERS_BYTES = 64 * 1024


class FollowupGitHubTransportError(RuntimeError):
    """One bounded GitHub request or provider-clock observation failed."""


@dataclass(frozen=True, slots=True)
class GitHubHttpResponse:
    status: int
    provider_observed_at: datetime
    body: bytes


class FollowupGitHubTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        path: str,
        payload: bytes | None,
        expected_statuses: frozenset[int],
        maximum_bytes: int,
    ) -> GitHubHttpResponse: ...

    def request_bytes(self, *, path: str, maximum_bytes: int) -> bytes: ...


class GitHubCliTransport:
    """Run bounded ``gh api`` requests and require monotone response ``Date``."""

    def __init__(self, *, command_timeout_seconds: int = 180) -> None:
        if type(command_timeout_seconds) is not int or command_timeout_seconds <= 0:
            raise FollowupGitHubTransportError("GitHub command timeout is invalid")
        self._timeout = command_timeout_seconds
        self._last_provider_date: datetime | None = None
        self._date_lock = threading.Lock()

    def _run(
        self,
        arguments: tuple[str, ...],
        *,
        input_bytes: bytes | None,
        maximum_bytes: int,
    ) -> bytes:
        environment = os.environ.copy()
        environment["GH_PAGER"] = "cat"
        environment["NO_COLOR"] = "1"
        try:
            completed = subprocess.run(
                ("gh", *arguments),
                input=input_bytes,
                check=True,
                capture_output=True,
                env=environment,
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise FollowupGitHubTransportError("GitHub CLI request failed") from error
        if len(completed.stdout) > maximum_bytes:
            raise FollowupGitHubTransportError(
                "GitHub CLI response exceeded its byte bound"
            )
        return completed.stdout

    @staticmethod
    def _included_response(content: bytes) -> tuple[int, list[str], bytes]:
        separators = tuple(
            (content.find(marker), marker)
            for marker in (b"\r\n\r\n", b"\n\n")
            if content.find(marker) >= 0
        )
        if not separators:
            raise FollowupGitHubTransportError(
                "GitHub API response lacks one header block"
            )
        offset, marker = min(separators, key=lambda item: item[0])
        if offset <= 0 or offset > _MAX_HEADERS_BYTES:
            raise FollowupGitHubTransportError(
                "GitHub API header block exceeded its bound"
            )
        raw_headers = content[:offset].replace(b"\r\n", b"\n")
        body = content[offset + len(marker) :]
        try:
            lines = raw_headers.decode("ascii").splitlines()
        except UnicodeDecodeError as error:
            raise FollowupGitHubTransportError(
                "GitHub API headers are not ASCII"
            ) from error
        fields = lines[0].split()
        if len(fields) < 2 or not fields[0].startswith("HTTP/"):
            raise FollowupGitHubTransportError("GitHub API status line changed")
        try:
            status = int(fields[1])
        except ValueError as error:
            raise FollowupGitHubTransportError("GitHub API status changed") from error
        if body.startswith((b"HTTP/", b"HTTP\\")):
            raise FollowupGitHubTransportError(
                "GitHub API response contains an unclosed redirect"
            )
        return status, lines[1:], body

    def request(
        self,
        *,
        method: str,
        path: str,
        payload: bytes | None,
        expected_statuses: frozenset[int],
        maximum_bytes: int,
    ) -> GitHubHttpResponse:
        if method not in {"GET", "POST"} or not path.startswith("/"):
            raise FollowupGitHubTransportError("GitHub request shape changed")
        arguments = [
            "api",
            "--include",
            "--method",
            method,
            "-H",
            f"X-GitHub-Api-Version: {_API_VERSION}",
        ]
        if payload is not None:
            arguments.extend(("--input", "-"))
        arguments.append(path)
        included = self._run(
            tuple(arguments),
            input_bytes=payload,
            maximum_bytes=maximum_bytes + _MAX_HEADERS_BYTES,
        )
        status, headers, body = self._included_response(included)
        if status not in expected_statuses or len(body) > maximum_bytes:
            raise FollowupGitHubTransportError(
                "GitHub API status or body bound changed"
            )
        dates = [
            value.strip()
            for line in headers
            if ":" in line
            for name, value in (line.split(":", 1),)
            if name.strip().lower() == "date"
        ]
        if len(dates) != 1:
            raise FollowupGitHubTransportError(
                "GitHub API response lacks one provider Date"
            )
        try:
            provider_date = parsedate_to_datetime(dates[0]).astimezone(UTC)
        except (TypeError, ValueError) as error:
            raise FollowupGitHubTransportError(
                "GitHub provider Date is invalid"
            ) from error
        with self._date_lock:
            if (
                self._last_provider_date is not None
                and provider_date < self._last_provider_date
            ):
                raise FollowupGitHubTransportError(
                    "GitHub provider Date moved backwards"
                )
            self._last_provider_date = provider_date
        return GitHubHttpResponse(
            status=status,
            provider_observed_at=provider_date,
            body=body,
        )

    def request_bytes(self, *, path: str, maximum_bytes: int) -> bytes:
        if not path.startswith("/"):
            raise FollowupGitHubTransportError("GitHub byte request path changed")
        return self._run(
            (
                "api",
                "-H",
                f"X-GitHub-Api-Version: {_API_VERSION}",
                path,
            ),
            input_bytes=None,
            maximum_bytes=maximum_bytes,
        )
