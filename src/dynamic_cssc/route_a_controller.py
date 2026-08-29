"""Fail-closed live admission for the bounded Route A publication workflow.

The stop-loss path polls fresh normalized observations until q5 succeeds or an
exact cancellation boundary is reached.  Terminal admission then consumes one
fresh complete observation.  Neither path persists an authorization bit: the
only positive terminal result is an opaque, single-use capability that remains
in the issuing process.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import stat
import threading
import time
import weakref
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

__all__ = (
    "RouteAArtifactSnapshot",
    "RouteAControllerError",
    "GitHubActionsQualificationProvider",
    "RouteAJobSnapshot",
    "RouteALiveJobSnapshot",
    "RouteALiveQualificationObservation",
    "RouteALiveRunSnapshot",
    "RouteAProviderObservation",
    "RouteAQualificationCapability",
    "RouteAQualificationRequest",
    "RouteAQualificationWatchResult",
    "RouteARunSnapshot",
    "abandon_route_a_qualification_capability",
    "authorize_route_a_qualification",
    "claim_route_a_qualification_capability",
    "watch_route_a_qualification",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_QUALIFICATION_JOB_NAMES = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)
_QUALIFICATION_ARTIFACT_NAMES = (
    "q1-simulator-pre-replay-handoff",
    "q2-simulator-guarded-receipt",
    "q3-native-pre-replay-build-plus-three-retained-packages",
    "q4-native-guarded-case-bundle",
    "q5-combined-guard-bundle",
    "q6-postrun-resource-admission-record",
)
_Q6_ARTIFACT_NAME = "q6-postrun-resource-admission-record"
_Q6_RECORD_SCHEMA = "dynamic-cssc-route-a-q6-postrun-resource-admission-v1"
_PLAN_SCHEMA = "dynamic-cssc-route-a-publication-plan-v3"
_PLAN_SHA256 = "b5d561bb5579976e4a9b5cc976ecaf2a6b7bbc9318ef43689f870522e68c8f0a"
_MAX_OBSERVATION_AGE = timedelta(seconds=30)
_COMPUTATIONAL_LIMIT = timedelta(minutes=45)
_Q6_JOB_LIMIT = timedelta(minutes=5)
_Q6_WALL_LIMIT = timedelta(minutes=10)
_TOTAL_PATH_LIMIT = timedelta(minutes=55)
_NATIVE_SCREEN_SECONDS = 9_000
_MAX_Q6_ARCHIVE_BYTES = 2 * 1024 * 1024
_MAX_Q6_RECORD_BYTES = 1024 * 1024
_MAX_PLAN_BYTES = 256 * 1024
_Q6_RECORD_NAME = "route-a-qualification-postrun.json"
_CHECKSUMS_NAME = "checksums.sha256"
_REPOSITORY_SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_MAX_PROVIDER_RUN_BYTES = 2 * 1024 * 1024
_MAX_PROVIDER_LIST_BYTES = 4 * 1024 * 1024
_MAX_FROZEN_PLAN_BYTES = 2 * 1024 * 1024
_MAX_PROVIDER_CANCEL_BYTES = 64 * 1024
_CANCELLATION_OBSERVATION_LIMIT = timedelta(minutes=10)
_MAX_PROVIDER_REDIRECT_URL_BYTES = 8 * 1024
_MAX_ARTIFACT_REDIRECTS = 3

_RedirectPolicy = Literal["reject", "artifact-download"]


class RouteAControllerError(RuntimeError):
    """The live provider observation cannot authorize Route A dispatch."""


@dataclass(frozen=True, slots=True)
class RouteARunSnapshot:
    database_id: int
    event: str
    head_sha: str
    head_branch: str
    attempt: int
    status: str
    conclusion: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class RouteAJobSnapshot:
    database_id: int
    name: str
    started_at: datetime
    completed_at: datetime
    status: str
    conclusion: str


@dataclass(frozen=True, slots=True)
class RouteAArtifactSnapshot:
    database_id: int
    name: str
    digest: str
    size_in_bytes: int
    expired: bool
    workflow_run_head_sha: str


@dataclass(frozen=True, slots=True)
class RouteALiveRunSnapshot:
    database_id: int
    event: str
    head_sha: str
    head_branch: str
    attempt: int
    status: str
    conclusion: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class RouteALiveJobSnapshot:
    database_id: int
    name: str
    started_at: datetime | None
    completed_at: datetime | None
    status: str
    conclusion: str | None


@dataclass(frozen=True, slots=True)
class RouteALiveQualificationObservation:
    observed_at: datetime
    run: RouteALiveRunSnapshot
    jobs: tuple[RouteALiveJobSnapshot, ...]


RouteAWatchDecision = Literal[
    "combined-guard-success-before-threshold",
    "route-c-terminal-before-combined-guard",
    "route-c-threshold-missed-terminal",
    "route-c-cancel-request-failed",
    "route-c-cancelled",
    "route-c-cancel-completion-unobserved",
]


@dataclass(frozen=True, slots=True)
class RouteAQualificationWatchResult:
    decision: RouteAWatchDecision
    run_id: int
    head_sha: str
    run_attempt: int
    q1_started_at: datetime | None
    threshold_at: datetime | None
    controller_observed_at: datetime
    q5_completed_at: datetime | None
    cancellation_requested_at: datetime | None
    cancellation_acknowledged_at: datetime | None
    provider_terminal_updated_at: datetime | None
    provider_terminal_conclusion: str | None
    watch_decided_at: datetime
    cancellation_error: str | None

    @property
    def document(self) -> dict[str, object]:
        def stamp(value: datetime | None) -> str | None:
            return (
                None
                if value is None
                else value.astimezone(UTC).isoformat().replace("+00:00", "Z")
            )

        def elapsed_seconds(
            start: datetime | None,
            end: datetime | None,
        ) -> int | None:
            if start is None or end is None:
                return None
            seconds = (end - start).total_seconds()
            if seconds < 0:
                raise RouteAControllerError("live stop-loss timestamps are not monotonic")
            return math.ceil(seconds)

        detection_lag = (
            None
            if self.threshold_at is None
            or self.cancellation_requested_at is None
            or self.controller_observed_at < self.threshold_at
            else elapsed_seconds(self.threshold_at, self.controller_observed_at)
        )
        return {
            "ack_to_watch_decision_seconds": elapsed_seconds(
                self.cancellation_acknowledged_at,
                self.watch_decided_at,
            ),
            "authority": False,
            "cancellation_error_or_null": self.cancellation_error,
            "cancel_request_utc": stamp(self.cancellation_requested_at),
            "controller_detection_utc": stamp(self.controller_observed_at),
            "decision": self.decision,
            "detection_lag_seconds": detection_lag,
            "final_conclusion": self.provider_terminal_conclusion,
            "formal_execution_authorized": False,
            "head_sha": self.head_sha,
            "provider_api_ack_utc": stamp(self.cancellation_acknowledged_at),
            "provider_terminal_updated_utc": stamp(self.provider_terminal_updated_at),
            "q1_started_utc": stamp(self.q1_started_at),
            "q5_completed_utc": stamp(self.q5_completed_at),
            "request_to_ack_seconds": elapsed_seconds(
                self.cancellation_requested_at,
                self.cancellation_acknowledged_at,
            ),
            "run_attempt": self.run_attempt,
            "run_id": self.run_id,
            "schema_version": "dynamic-cssc-route-a-live-stop-loss-v2",
            "threshold_utc": stamp(self.threshold_at),
            "watch_decided_utc": stamp(self.watch_decided_at),
        }


@dataclass(frozen=True, slots=True)
class RouteAProviderObservation:
    observed_at: datetime
    plan_bytes: bytes
    run: RouteARunSnapshot
    jobs: tuple[RouteAJobSnapshot, ...]
    q6_artifact: RouteAArtifactSnapshot
    q6_archive_bytes: bytes


@dataclass(frozen=True, slots=True)
class RouteAQualificationRequest:
    run_id: int
    expected_s2_git_sha: str
    expected_head_branch: str
    expected_run_attempt: int


@dataclass(frozen=True, slots=True)
class _QualificationRequestIdentity:
    """Detached request values owned by the controller after validation."""

    run_id: int
    expected_s2_git_sha: str
    expected_head_branch: str
    expected_run_attempt: int


class _QualificationProvider(Protocol):
    def read_qualification(self, run_id: int) -> RouteAProviderObservation: ...


class _LiveQualificationProvider(Protocol):
    def read_live_qualification(
        self,
        run_id: int,
    ) -> RouteALiveQualificationObservation: ...

    def cancel_qualification(self, run_id: int) -> None: ...


class _HttpReader(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum_bytes: int,
        redirect_policy: _RedirectPolicy,
    ) -> bytes: ...

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum_bytes: int,
    ) -> bytes: ...


class _HttpsTokenStrippingRedirectHandler(HTTPRedirectHandler):
    """Reject API redirects or follow a bounded tokenless artifact redirect."""

    def __init__(self, policy: _RedirectPolicy) -> None:
        super().__init__()
        if policy not in ("reject", "artifact-download"):
            raise ValueError("redirect policy is not closed")
        self.policy = policy
        self.max_redirections = _MAX_ARTIFACT_REDIRECTS
        self.max_repeats = _MAX_ARTIFACT_REDIRECTS

    def redirect_request(  # type: ignore[no-untyped-def]
        self,
        request,
        file_pointer,
        code,
        message,
        headers,
        new_url,
    ):
        if self.policy == "reject":
            raise RouteAControllerError("GitHub API redirects are forbidden")
        if request.get_method() != "GET":
            raise RouteAControllerError("only artifact GET may follow a redirect")
        if type(new_url) is not str or len(new_url.encode("utf-8")) > (
            _MAX_PROVIDER_REDIRECT_URL_BYTES
        ):
            raise RouteAControllerError("GitHub artifact redirect URL is invalid")
        try:
            destination = urlsplit(new_url)
        except (TypeError, ValueError) as error:
            raise RouteAControllerError("GitHub artifact redirect URL is invalid") from error
        if (
            destination.scheme != "https"
            or not destination.netloc
            or destination.fragment
            or destination.username is not None
            or destination.password is not None
        ):
            raise RouteAControllerError("GitHub artifact redirect is not one safe HTTPS URL")
        redirected = super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            new_url,
        )
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


class _UrllibHttpReader:
    """Small bounded HTTPS adapter kept behind the controller's provider seam."""

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum_bytes: int,
        redirect_policy: _RedirectPolicy,
    ) -> bytes:
        request = Request(url, headers=headers, method="GET")
        try:
            opener = build_opener(_HttpsTokenStrippingRedirectHandler(redirect_policy))
            with opener.open(request, timeout=30) as response:  # noqa: S310 - HTTPS gated
                if response.status != 200:
                    raise OSError(f"GitHub API returned HTTP {response.status}")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except ValueError as error:
                        raise OSError("GitHub API returned an invalid Content-Length") from error
                    if declared_size < 0 or declared_size > maximum_bytes:
                        raise OSError("GitHub API response exceeds its closed byte bound")
                content = response.read(maximum_bytes + 1)
        except (HTTPError, URLError) as error:
            raise OSError(f"GitHub API request failed: {error}") from error
        if len(content) > maximum_bytes:
            raise OSError("GitHub API response exceeds its closed byte bound")
        return content

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        maximum_bytes: int,
    ) -> bytes:
        request = Request(url, data=b"", headers=headers, method="POST")
        try:
            opener = build_opener(_HttpsTokenStrippingRedirectHandler("reject"))
            with opener.open(request, timeout=30) as response:  # noqa: S310 - HTTPS gated
                if response.status != 202:
                    raise OSError(f"GitHub API returned HTTP {response.status}")
                content = response.read(maximum_bytes + 1)
        except (HTTPError, URLError) as error:
            raise OSError(f"GitHub API request failed: {error}") from error
        if len(content) > maximum_bytes:
            raise OSError("GitHub API response exceeds its closed byte bound")
        return content


@dataclass(frozen=True, slots=True)
class _QualificationBinding:
    request_identity: _QualificationRequestIdentity
    plan_sha256: str
    provider_run_updated_at: datetime
    controller_observed_at: datetime
    expires_at: datetime
    q6_artifact_id: int
    q6_artifact_digest: str


class _QualificationToken:
    """Unforgeable-by-construction in-process link to a registry-owned binding."""

    __slots__ = ()


class RouteAQualificationCapability:
    """Opaque one-shot result of an exact live qualification inspection."""

    __slots__ = ("_binding_token", "_lock", "__weakref__")

    def __new__(cls) -> RouteAQualificationCapability:
        raise TypeError("Route A qualification capabilities are controller-minted")

    def __bool__(self) -> bool:
        raise TypeError("Route A qualification capability is not a Boolean")


@dataclass(frozen=True, slots=True)
class _IssuedCapability:
    capability_ref: weakref.ReferenceType[RouteAQualificationCapability]
    binding_token: _QualificationToken
    binding: _QualificationBinding


_ISSUED_CAPABILITIES: dict[int, _IssuedCapability] = {}
_ISSUED_CAPABILITIES_LOCK = threading.Lock()


def _utc_now() -> datetime:
    """Return the live controller clock; tests may replace this private seam."""

    return datetime.now(UTC)


def _discard_issued_capability(
    capability_id: int,
    capability_ref: weakref.ReferenceType[RouteAQualificationCapability],
) -> None:
    with _ISSUED_CAPABILITIES_LOCK:
        issued = _ISSUED_CAPABILITIES.get(capability_id)
        if issued is not None and issued.capability_ref is capability_ref:
            _ISSUED_CAPABILITIES.pop(capability_id, None)


def _require_utc(value: datetime, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise RouteAControllerError(f"{field} must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.utcoffset() != timedelta(0):  # pragma: no cover - astimezone owns this
        raise RouteAControllerError(f"{field} must normalize to UTC")
    return normalized


def _timestamp(value: object, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise RouteAControllerError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RouteAControllerError(f"{field} must be a canonical UTC timestamp") from error
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise RouteAControllerError(f"{field} must be a canonical UTC timestamp")
    return parsed


def _optional_timestamp(value: object, field: str) -> datetime | None:
    return None if value is None else _timestamp(value, field)


def _optional_provider_string(value: object, field: str) -> str | None:
    return None if value is None else _provider_string(value, field)


def _provider_json(content: bytes, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise RouteAControllerError(f"{field} contains a duplicate JSON key")
            document[key] = value
        return document

    try:
        decoded = json.loads(content.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAControllerError(f"{field} is not readable JSON") from error
    if type(decoded) is not dict:
        raise RouteAControllerError(f"{field} must be one JSON object")
    return decoded


def _provider_integer(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise RouteAControllerError(f"{field} must be a positive strict integer")
    return value


def _provider_string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise RouteAControllerError(f"{field} must be a nonempty string")
    return value


def _read_frozen_plan(repository_root: Path) -> bytes:
    path = repository_root / "config/route-a-publication-plan.json"
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FROZEN_PLAN_BYTES:
            raise RouteAControllerError("frozen Route A machine plan is not a bounded regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            content = source.read(_MAX_FROZEN_PLAN_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise RouteAControllerError("frozen Route A machine plan cannot be read safely") from error
    if len(content) > _MAX_FROZEN_PLAN_BYTES or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RouteAControllerError("frozen Route A machine plan changed while being read")
    return content


class GitHubActionsQualificationProvider:
    """Normalize one live GitHub Actions run into the closed controller type."""

    __slots__ = (
        "_api_url",
        "_headers",
        "_http_reader",
        "_repository_root",
        "_repository_slug",
    )

    def __init__(
        self,
        *,
        repository_root: Path,
        repository_slug: str,
        token: str,
        api_url: str = "https://api.github.com",
        http_reader: _HttpReader | None = None,
    ) -> None:
        if not isinstance(repository_root, Path):
            raise TypeError("repository_root must be a pathlib.Path")
        try:
            resolved_root = repository_root.resolve(strict=True)
        except OSError as error:
            raise RouteAControllerError("controller repository root does not exist") from error
        if type(repository_slug) is not str or _REPOSITORY_SLUG.fullmatch(repository_slug) is None:
            raise RouteAControllerError("controller repository identity is invalid")
        if (
            type(token) is not str
            or not token
            or token.strip() != token
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
        ):
            raise RouteAControllerError("GitHub controller token is invalid")
        try:
            parsed_api_url = urlsplit(api_url) if type(api_url) is str else None
        except ValueError:
            parsed_api_url = None
        if (
            parsed_api_url is None
            or parsed_api_url.scheme != "https"
            or not parsed_api_url.netloc
            or parsed_api_url.path
            or parsed_api_url.query
            or parsed_api_url.fragment
            or parsed_api_url.username is not None
            or parsed_api_url.password is not None
        ):
            raise RouteAControllerError("GitHub API URL must be one exact HTTPS origin")
        if http_reader is not None and not hasattr(http_reader, "get"):
            raise TypeError("http_reader must implement the closed GET seam")
        self._repository_root = resolved_root
        self._repository_slug = repository_slug
        self._api_url = api_url
        self._headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "dynamic-cssc-route-a-live-controller-v1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._http_reader = http_reader if http_reader is not None else _UrllibHttpReader()

    def _get(
        self,
        path_or_url: str,
        maximum_bytes: int,
        *,
        allow_artifact_redirect: bool = False,
    ) -> bytes:
        if path_or_url.startswith("https://"):
            try:
                target = urlsplit(path_or_url)
                origin = urlsplit(self._api_url)
            except ValueError as error:
                raise RouteAControllerError(
                    "GitHub provider attempted an invalid HTTPS URL"
                ) from error
            if (
                (target.scheme, target.netloc) != (origin.scheme, origin.netloc)
                or target.username is not None
                or target.password is not None
            ):
                raise RouteAControllerError(
                    "GitHub provider attempted a foreign HTTPS origin"
                )
            url = path_or_url
        else:
            if not path_or_url.startswith("/"):
                raise RouteAControllerError("GitHub provider API path is not absolute")
            url = f"{self._api_url}{path_or_url}"
        try:
            return self._http_reader.get(
                url,
                headers=dict(self._headers),
                maximum_bytes=maximum_bytes,
                redirect_policy=(
                    "artifact-download" if allow_artifact_redirect else "reject"
                ),
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
            raise RouteAControllerError("GitHub provider request failed") from error

    def _post(self, path: str, maximum_bytes: int) -> bytes:
        url = f"{self._api_url}{path}"
        if not url.startswith("https://"):
            raise RouteAControllerError("GitHub provider attempted a non-HTTPS request")
        post = getattr(self._http_reader, "post", None)
        if not callable(post):
            raise RouteAControllerError("GitHub provider lacks the closed POST seam")
        try:
            return post(
                url,
                headers=dict(self._headers),
                maximum_bytes=maximum_bytes,
            )
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
            raise RouteAControllerError("GitHub provider cancellation request failed") from error

    def read_live_qualification(self, run_id: int) -> RouteALiveQualificationObservation:
        if type(run_id) is not int or run_id <= 0:
            raise RouteAControllerError("qualification run ID must be a positive strict integer")
        base = f"/repos/{self._repository_slug}/actions/runs/{run_id}"
        run_document = _provider_json(
            self._get(base, _MAX_PROVIDER_RUN_BYTES), "GitHub live qualification run"
        )
        jobs_document = _provider_json(
            self._get(f"{base}/jobs?per_page=100", _MAX_PROVIDER_LIST_BYTES),
            "GitHub live qualification jobs",
        )
        raw_jobs = jobs_document.get("jobs")
        if (
            type(raw_jobs) is not list
            or jobs_document.get("total_count") != len(raw_jobs)
            or len(raw_jobs) > len(_QUALIFICATION_JOB_NAMES)
            or any(type(job) is not dict for job in raw_jobs)
        ):
            raise RouteAControllerError("GitHub live qualification job list is incomplete")
        parsed_jobs = tuple(
            RouteALiveJobSnapshot(
                database_id=_provider_integer(job.get("id"), "job.id"),
                name=_provider_string(job.get("name"), "job.name"),
                started_at=_optional_timestamp(job.get("started_at"), "job.started_at"),
                completed_at=_optional_timestamp(job.get("completed_at"), "job.completed_at"),
                status=_provider_string(job.get("status"), "job.status"),
                conclusion=_optional_provider_string(job.get("conclusion"), "job.conclusion"),
            )
            for job in raw_jobs
        )
        jobs_by_name = {job.name: job for job in parsed_jobs}
        if (
            len(jobs_by_name) != len(parsed_jobs)
            or not set(jobs_by_name).issubset(_QUALIFICATION_JOB_NAMES)
        ):
            raise RouteAControllerError(
                "GitHub live qualification job identity set is missing, extra, or duplicated"
            )
        return RouteALiveQualificationObservation(
            observed_at=_utc_now(),
            run=RouteALiveRunSnapshot(
                database_id=_provider_integer(run_document.get("id"), "run.id"),
                event=_provider_string(run_document.get("event"), "run.event"),
                head_sha=_provider_string(run_document.get("head_sha"), "run.head_sha"),
                head_branch=_provider_string(run_document.get("head_branch"), "run.head_branch"),
                attempt=_provider_integer(run_document.get("run_attempt"), "run.run_attempt"),
                status=_provider_string(run_document.get("status"), "run.status"),
                conclusion=_optional_provider_string(
                    run_document.get("conclusion"), "run.conclusion"
                ),
                created_at=_timestamp(run_document.get("created_at"), "run.created_at"),
                updated_at=_timestamp(run_document.get("updated_at"), "run.updated_at"),
            ),
            jobs=tuple(
                jobs_by_name[name]
                for name in _QUALIFICATION_JOB_NAMES
                if name in jobs_by_name
            ),
        )

    def cancel_qualification(self, run_id: int) -> None:
        if type(run_id) is not int or run_id <= 0:
            raise RouteAControllerError("qualification run ID must be a positive strict integer")
        self._post(
            f"/repos/{self._repository_slug}/actions/runs/{run_id}/cancel",
            _MAX_PROVIDER_CANCEL_BYTES,
        )

    def read_qualification(self, run_id: int) -> RouteAProviderObservation:
        if type(run_id) is not int or run_id <= 0:
            raise RouteAControllerError("qualification run ID must be a positive strict integer")
        base = f"/repos/{self._repository_slug}/actions/runs/{run_id}"
        run_document = _provider_json(
            self._get(base, _MAX_PROVIDER_RUN_BYTES), "GitHub qualification run"
        )
        jobs_document = _provider_json(
            self._get(f"{base}/jobs?per_page=100", _MAX_PROVIDER_LIST_BYTES),
            "GitHub qualification jobs",
        )
        artifacts_document = _provider_json(
            self._get(f"{base}/artifacts?per_page=100", _MAX_PROVIDER_LIST_BYTES),
            "GitHub qualification artifacts",
        )
        run_database_id = _provider_integer(run_document.get("id"), "run.id")
        run_head_sha = _provider_string(run_document.get("head_sha"), "run.head_sha")

        raw_jobs = jobs_document.get("jobs")
        if (
            type(raw_jobs) is not list
            or jobs_document.get("total_count") != len(raw_jobs)
            or len(raw_jobs) > 100
            or any(type(job) is not dict for job in raw_jobs)
        ):
            raise RouteAControllerError("GitHub qualification job list is incomplete")
        parsed_jobs = tuple(
            RouteAJobSnapshot(
                database_id=_provider_integer(job.get("id"), "job.id"),
                name=_provider_string(job.get("name"), "job.name"),
                started_at=_timestamp(job.get("started_at"), "job.started_at"),
                completed_at=_timestamp(job.get("completed_at"), "job.completed_at"),
                status=_provider_string(job.get("status"), "job.status"),
                conclusion=_provider_string(job.get("conclusion"), "job.conclusion"),
            )
            for job in raw_jobs
        )
        jobs_by_name = {job.name: job for job in parsed_jobs}
        if (
            len(jobs_by_name) != len(parsed_jobs)
            or set(jobs_by_name) != set(_QUALIFICATION_JOB_NAMES)
        ):
            raise RouteAControllerError(
                "GitHub qualification job identity set is missing, extra, or duplicated"
            )
        jobs = tuple(jobs_by_name[name] for name in _QUALIFICATION_JOB_NAMES)

        raw_artifacts = artifacts_document.get("artifacts")
        if (
            type(raw_artifacts) is not list
            or artifacts_document.get("total_count") != len(raw_artifacts)
            or len(raw_artifacts) != len(_QUALIFICATION_ARTIFACT_NAMES)
            or any(type(artifact) is not dict for artifact in raw_artifacts)
        ):
            raise RouteAControllerError(
                "GitHub qualification artifact list is not the exact six-object set"
            )
        artifacts_by_name: dict[str, dict[str, object]] = {}
        artifact_ids: set[int] = set()
        for artifact in raw_artifacts:
            name = _provider_string(artifact.get("name"), "artifact.name")
            artifact_id = _provider_integer(artifact.get("id"), "artifact.id")
            digest = _provider_string(artifact.get("digest"), "artifact.digest")
            size = _provider_integer(artifact.get("size_in_bytes"), "artifact.size_in_bytes")
            expired = artifact.get("expired")
            workflow_run = artifact.get("workflow_run")
            if (
                name in artifacts_by_name
                or artifact_id in artifact_ids
                or _PROVIDER_DIGEST.fullmatch(digest) is None
                or size <= 0
                or expired is not False
                or type(workflow_run) is not dict
                or workflow_run.get("id") != run_database_id
                or workflow_run.get("head_sha") != run_head_sha
            ):
                raise RouteAControllerError(
                    "GitHub qualification artifact identity or provider binding is invalid"
                )
            artifacts_by_name[name] = artifact
            artifact_ids.add(artifact_id)
        if set(artifacts_by_name) != set(_QUALIFICATION_ARTIFACT_NAMES):
            raise RouteAControllerError(
                "GitHub qualification artifact identity set is missing, extra, or duplicated"
            )
        q6 = artifacts_by_name[_Q6_ARTIFACT_NAME]
        q6_workflow_run = q6["workflow_run"]
        assert type(q6_workflow_run) is dict  # established by the closed loop above
        q6_expired = q6["expired"]
        assert type(q6_expired) is bool  # established by the closed loop above
        download_url = _provider_string(
            q6.get("archive_download_url"), "artifact.archive_download_url"
        )
        archive_bytes = self._get(
            download_url,
            _MAX_Q6_ARCHIVE_BYTES,
            allow_artifact_redirect=True,
        )

        return RouteAProviderObservation(
            observed_at=_utc_now(),
            plan_bytes=_read_frozen_plan(self._repository_root),
            run=RouteARunSnapshot(
                database_id=run_database_id,
                event=_provider_string(run_document.get("event"), "run.event"),
                head_sha=run_head_sha,
                head_branch=_provider_string(run_document.get("head_branch"), "run.head_branch"),
                attempt=_provider_integer(run_document.get("run_attempt"), "run.run_attempt"),
                status=_provider_string(run_document.get("status"), "run.status"),
                conclusion=_provider_string(run_document.get("conclusion"), "run.conclusion"),
                created_at=_timestamp(run_document.get("created_at"), "run.created_at"),
                updated_at=_timestamp(run_document.get("updated_at"), "run.updated_at"),
            ),
            jobs=jobs,
            q6_artifact=RouteAArtifactSnapshot(
                database_id=_provider_integer(q6.get("id"), "artifact.id"),
                name=_provider_string(q6.get("name"), "artifact.name"),
                digest=_provider_string(q6.get("digest"), "artifact.digest"),
                size_in_bytes=_provider_integer(q6.get("size_in_bytes"), "artifact.size_in_bytes"),
                expired=q6_expired,
                workflow_run_head_sha=_provider_string(
                    q6_workflow_run.get("head_sha"), "artifact.workflow_run.head_sha"
                ),
            ),
            q6_archive_bytes=archive_bytes,
        )


def _seconds(value: timedelta, field: str) -> int:
    seconds = value.total_seconds()
    if seconds < 0 or not seconds.is_integer():
        raise RouteAControllerError(f"{field} must be a nonnegative whole-second duration")
    return int(seconds)


def _freeze_request(
    request: RouteAQualificationRequest,
) -> _QualificationRequestIdentity:
    if type(request) is not RouteAQualificationRequest:
        raise TypeError("request must be an exact RouteAQualificationRequest")
    identity = _QualificationRequestIdentity(
        run_id=request.run_id,
        expected_s2_git_sha=request.expected_s2_git_sha,
        expected_head_branch=request.expected_head_branch,
        expected_run_attempt=request.expected_run_attempt,
    )
    if type(identity.run_id) is not int or identity.run_id <= 0:
        raise RouteAControllerError("qualification run ID must be a positive strict integer")
    if (
        type(identity.expected_s2_git_sha) is not str
        or _LOWER_GIT_SHA.fullmatch(identity.expected_s2_git_sha) is None
    ):
        raise RouteAControllerError("expected S2 Git SHA is invalid")
    if type(identity.expected_head_branch) is not str or identity.expected_head_branch != "main":
        raise RouteAControllerError("qualification must be controlled from terminal S2 on main")
    if type(identity.expected_run_attempt) is not int or identity.expected_run_attempt != 1:
        raise RouteAControllerError("qualification is one-shot and requires run attempt one")
    return identity


def _validate_live_observation(
    observation: RouteALiveQualificationObservation,
    request: _QualificationRequestIdentity,
    controller_observed_at: datetime,
) -> tuple[RouteALiveRunSnapshot, tuple[RouteALiveJobSnapshot, ...]]:
    if type(observation) is not RouteALiveQualificationObservation:
        raise RouteAControllerError("live qualification provider returned the wrong type")
    provider_observed_at = _require_utc(observation.observed_at, "live provider observation")
    age = controller_observed_at - provider_observed_at
    if age < timedelta(0) or age > _MAX_OBSERVATION_AGE:
        raise RouteAControllerError("live qualification provider observation is stale")
    run = observation.run
    if type(run) is not RouteALiveRunSnapshot:
        raise RouteAControllerError("live qualification run snapshot type is invalid")
    created_at = _require_utc(run.created_at, "live run createdAt")
    updated_at = _require_utc(run.updated_at, "live run updatedAt")
    if (
        type(run.database_id) is not int
        or run.database_id != request.run_id
        or type(run.event) is not str
        or run.event != "workflow_dispatch"
        or type(run.head_sha) is not str
        or run.head_sha != request.expected_s2_git_sha
        or type(run.head_branch) is not str
        or run.head_branch != request.expected_head_branch
        or type(run.attempt) is not int
        or run.attempt != request.expected_run_attempt
        or type(run.status) is not str
        or not run.status
        or (run.conclusion is not None and type(run.conclusion) is not str)
        or (run.status == "completed") is not (type(run.conclusion) is str)
        or created_at > updated_at
        or updated_at > provider_observed_at
    ):
        raise RouteAControllerError("live qualification run identity or state is invalid")
    jobs = observation.jobs
    if type(jobs) is not tuple or any(
        type(job) is not RouteALiveJobSnapshot for job in jobs
    ):
        raise RouteAControllerError("live qualification job identity set changed")
    observed_names = tuple(job.name for job in jobs)
    observed_name_set = set(observed_names)
    expected_observed_order = _QUALIFICATION_JOB_NAMES[: len(observed_names)]
    if (
        len(observed_names) != len(observed_name_set)
        or not observed_name_set.issubset(_QUALIFICATION_JOB_NAMES)
        or observed_names != expected_observed_order
    ):
        raise RouteAControllerError("live qualification job identity set changed")
    identifiers: set[int] = set()
    previous: RouteALiveJobSnapshot | None = None
    for job in jobs:
        started_at = (
            None
            if job.started_at is None
            else _require_utc(job.started_at, f"{job.name} live startedAt")
        )
        completed_at = (
            None
            if job.completed_at is None
            else _require_utc(job.completed_at, f"{job.name} live completedAt")
        )
        if (
            type(job.database_id) is not int
            or job.database_id <= 0
            or job.database_id in identifiers
            or type(job.status) is not str
            or not job.status
            or (job.conclusion is not None and type(job.conclusion) is not str)
            or (completed_at is not None and started_at is None)
            or (completed_at is not None and completed_at < started_at)
            or (job.status == "completed")
            is not (completed_at is not None and type(job.conclusion) is str)
            or (started_at is not None and started_at < created_at)
            or (completed_at is not None and completed_at > provider_observed_at)
            or (
                previous is not None
                and started_at is not None
                and (
                    previous.completed_at is None
                    or started_at < previous.completed_at
                )
            )
        ):
            raise RouteAControllerError("live qualification job state is invalid")
        identifiers.add(job.database_id)
        previous = job
    return run, jobs


def _watch_result(
    *,
    decision: RouteAWatchDecision,
    request: _QualificationRequestIdentity,
    q1_started_at: datetime | None,
    threshold_at: datetime | None,
    controller_observed_at: datetime,
    q5_completed_at: datetime | None,
    cancellation_requested_at: datetime | None = None,
    cancellation_acknowledged_at: datetime | None = None,
    provider_terminal_updated_at: datetime | None = None,
    provider_terminal_conclusion: str | None = None,
    watch_decided_at: datetime | None = None,
    cancellation_error: str | None = None,
) -> RouteAQualificationWatchResult:
    decided_at = controller_observed_at if watch_decided_at is None else watch_decided_at
    return RouteAQualificationWatchResult(
        decision=decision,
        run_id=request.run_id,
        head_sha=request.expected_s2_git_sha,
        run_attempt=request.expected_run_attempt,
        q1_started_at=q1_started_at,
        threshold_at=threshold_at,
        controller_observed_at=controller_observed_at,
        q5_completed_at=q5_completed_at,
        cancellation_requested_at=cancellation_requested_at,
        cancellation_acknowledged_at=cancellation_acknowledged_at,
        provider_terminal_updated_at=provider_terminal_updated_at,
        provider_terminal_conclusion=provider_terminal_conclusion,
        watch_decided_at=decided_at,
        cancellation_error=cancellation_error,
    )


def watch_route_a_qualification(
    provider: _LiveQualificationProvider,
    request: RouteAQualificationRequest,
    *,
    poll_interval_seconds: int = 15,
    wait: Callable[[float], None] = time.sleep,
) -> RouteAQualificationWatchResult:
    """Poll one exact run and enforce the frozen q1-to-q5 45-minute stop-loss."""

    request_identity = _freeze_request(request)
    if (
        type(poll_interval_seconds) is not int
        or not 1 <= poll_interval_seconds <= 60
        or not callable(wait)
    ):
        raise RouteAControllerError("live stop-loss polling configuration is invalid")
    frozen_q1_started_at: datetime | None = None
    threshold_at: datetime | None = None
    last_q5_completed_at: datetime | None = None

    while True:
        try:
            observation = provider.read_live_qualification(request_identity.run_id)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
            controller_now = _require_utc(_utc_now(), "live controller observation")
            if threshold_at is None:
                raise RouteAControllerError(
                    "live qualification provider observation failed before exact binding"
                ) from error
            if controller_now < threshold_at:
                wait(
                    min(
                        float(poll_interval_seconds),
                        max(0.0, (threshold_at - controller_now).total_seconds()),
                    )
                )
                continue
        else:
            controller_now = _require_utc(_utc_now(), "live controller observation")
            run, jobs = _validate_live_observation(
                observation,
                request_identity,
                controller_now,
            )
            jobs_by_name = {job.name: job for job in jobs}
            q1 = jobs_by_name.get(_QUALIFICATION_JOB_NAMES[0])
            q5 = jobs_by_name.get(_QUALIFICATION_JOB_NAMES[4])
            last_q5_completed_at = None if q5 is None else q5.completed_at
            if q1 is not None and q1.started_at is not None:
                q1_started_at = _require_utc(q1.started_at, "q1 live startedAt")
                if frozen_q1_started_at is None:
                    frozen_q1_started_at = q1_started_at
                    threshold_at = q1_started_at + _COMPUTATIONAL_LIMIT
                elif q1_started_at != frozen_q1_started_at:
                    raise RouteAControllerError("q1 live startedAt changed after it was frozen")
            elif frozen_q1_started_at is not None:
                raise RouteAControllerError("q1 live startedAt disappeared after it was frozen")

            q5_success = (
                q5 is not None
                and q5.status == "completed"
                and q5.conclusion == "success"
                and q5.completed_at is not None
            )
            prefix_success = all(
                job is not None
                and job.status == "completed"
                and job.conclusion == "success"
                for job in (
                    jobs_by_name.get(name) for name in _QUALIFICATION_JOB_NAMES[:5]
                )
            )
            failed_job_observed = any(
                job.status == "completed" and job.conclusion != "success" for job in jobs
            )
            if (
                q5_success
                and prefix_success
                and threshold_at is not None
                and q5.completed_at <= threshold_at
            ):
                return _watch_result(
                    decision="combined-guard-success-before-threshold",
                    request=request_identity,
                    q1_started_at=frozen_q1_started_at,
                    threshold_at=threshold_at,
                    controller_observed_at=controller_now,
                    q5_completed_at=q5.completed_at,
                    provider_terminal_updated_at=(
                        run.updated_at if run.status == "completed" else None
                    ),
                    provider_terminal_conclusion=(
                        run.conclusion if run.status == "completed" else None
                    ),
                )
            if run.status == "completed":
                return _watch_result(
                    decision=(
                        "route-c-threshold-missed-terminal"
                        if q5_success
                        else "route-c-terminal-before-combined-guard"
                    ),
                    request=request_identity,
                    q1_started_at=frozen_q1_started_at,
                    threshold_at=threshold_at,
                    controller_observed_at=controller_now,
                    q5_completed_at=last_q5_completed_at,
                    provider_terminal_updated_at=run.updated_at,
                    provider_terminal_conclusion=run.conclusion,
                )
            if not failed_job_observed and (
                threshold_at is None or controller_now < threshold_at
            ):
                remaining = (
                    float(poll_interval_seconds)
                    if threshold_at is None
                    else min(
                        float(poll_interval_seconds),
                        max(0.0, (threshold_at - controller_now).total_seconds()),
                    )
                )
                wait(remaining)
                continue

        cancellation_requested_at = controller_now
        try:
            provider.cancel_qualification(request_identity.run_id)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            return _watch_result(
                decision="route-c-cancel-request-failed",
                request=request_identity,
                q1_started_at=frozen_q1_started_at,
                threshold_at=threshold_at,
                controller_observed_at=controller_now,
                q5_completed_at=last_q5_completed_at,
                cancellation_requested_at=cancellation_requested_at,
                cancellation_error="provider-cancel-request-failed",
            )
        cancellation_acknowledged_at = _require_utc(
            _utc_now(),
            "cancellation acknowledgement",
        )
        terminal_observation_deadline = (
            cancellation_acknowledged_at + _CANCELLATION_OBSERVATION_LIMIT
        )
        while True:
            terminal_now = _require_utc(_utc_now(), "cancellation terminal observation")
            if terminal_now > terminal_observation_deadline:
                return _watch_result(
                    decision="route-c-cancel-completion-unobserved",
                    request=request_identity,
                    q1_started_at=frozen_q1_started_at,
                    threshold_at=threshold_at,
                    controller_observed_at=cancellation_requested_at,
                    q5_completed_at=last_q5_completed_at,
                    cancellation_requested_at=cancellation_requested_at,
                    cancellation_acknowledged_at=cancellation_acknowledged_at,
                    watch_decided_at=terminal_now,
                    cancellation_error="provider-terminal-state-not-observed-within-ten-minutes",
                )
            try:
                terminal_observation = provider.read_live_qualification(
                    request_identity.run_id
                )
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                return _watch_result(
                    decision="route-c-cancel-completion-unobserved",
                    request=request_identity,
                    q1_started_at=frozen_q1_started_at,
                    threshold_at=threshold_at,
                    controller_observed_at=cancellation_requested_at,
                    q5_completed_at=last_q5_completed_at,
                    cancellation_requested_at=cancellation_requested_at,
                    cancellation_acknowledged_at=cancellation_acknowledged_at,
                    watch_decided_at=terminal_now,
                    cancellation_error="provider-terminal-read-failed",
                )
            terminal_run, terminal_jobs = _validate_live_observation(
                terminal_observation,
                request_identity,
                terminal_now,
            )
            terminal_jobs_by_name = {job.name: job for job in terminal_jobs}
            terminal_q1 = terminal_jobs_by_name.get(_QUALIFICATION_JOB_NAMES[0])
            terminal_q5 = terminal_jobs_by_name.get(_QUALIFICATION_JOB_NAMES[4])
            if terminal_q1 is None or terminal_q1.started_at != frozen_q1_started_at:
                raise RouteAControllerError("q1 live startedAt changed after cancellation")
            if terminal_run.status == "completed":
                return _watch_result(
                    decision="route-c-cancelled",
                    request=request_identity,
                    q1_started_at=frozen_q1_started_at,
                    threshold_at=threshold_at,
                    controller_observed_at=cancellation_requested_at,
                    q5_completed_at=(
                        None if terminal_q5 is None else terminal_q5.completed_at
                    ),
                    cancellation_requested_at=cancellation_requested_at,
                    cancellation_acknowledged_at=cancellation_acknowledged_at,
                    provider_terminal_updated_at=terminal_run.updated_at,
                    provider_terminal_conclusion=terminal_run.conclusion,
                    watch_decided_at=terminal_now,
                )
            remaining = max(
                0.0,
                (terminal_observation_deadline - terminal_now).total_seconds(),
            )
            if remaining == 0.0:
                return _watch_result(
                    decision="route-c-cancel-completion-unobserved",
                    request=request_identity,
                    q1_started_at=frozen_q1_started_at,
                    threshold_at=threshold_at,
                    controller_observed_at=cancellation_requested_at,
                    q5_completed_at=last_q5_completed_at,
                    cancellation_requested_at=cancellation_requested_at,
                    cancellation_acknowledged_at=cancellation_acknowledged_at,
                    watch_decided_at=terminal_now,
                    cancellation_error=(
                        "provider-terminal-state-not-observed-within-ten-minutes"
                    ),
                )
            wait(min(float(poll_interval_seconds), remaining))


def _validate_run(
    run: RouteARunSnapshot,
    request: _QualificationRequestIdentity,
    observed_at: datetime,
) -> None:
    if type(run) is not RouteARunSnapshot:
        raise RouteAControllerError("qualification run snapshot type is invalid")
    created_at = _require_utc(run.created_at, "run createdAt")
    updated_at = _require_utc(run.updated_at, "run updatedAt")
    if (
        type(run.database_id) is not int
        or run.database_id != request.run_id
        or type(run.event) is not str
        or run.event != "workflow_dispatch"
        or type(run.head_sha) is not str
        or run.head_sha != request.expected_s2_git_sha
        or type(run.head_branch) is not str
        or run.head_branch != request.expected_head_branch
        or type(run.attempt) is not int
        or run.attempt != request.expected_run_attempt
        or type(run.status) is not str
        or run.status != "completed"
        or type(run.conclusion) is not str
        or run.conclusion != "success"
        or created_at > updated_at
        or updated_at > observed_at
    ):
        raise RouteAControllerError("qualification run identity is not the exact terminal success")


def _validate_jobs(jobs: tuple[RouteAJobSnapshot, ...]) -> tuple[RouteAJobSnapshot, ...]:
    if type(jobs) is not tuple:
        raise RouteAControllerError("qualification job collection type is invalid")
    if any(type(job) is not RouteAJobSnapshot for job in jobs):
        raise RouteAControllerError("qualification job snapshot type is invalid")
    if tuple(job.name for job in jobs) != _QUALIFICATION_JOB_NAMES:
        raise RouteAControllerError(
            "qualification job identity set is missing, extra, or reordered"
        )
    identifiers: set[int] = set()
    previous_completed_at: datetime | None = None
    for job in jobs:
        started_at = _require_utc(job.started_at, f"{job.name} startedAt")
        completed_at = _require_utc(job.completed_at, f"{job.name} completedAt")
        if (
            type(job.database_id) is not int
            or job.database_id <= 0
            or job.database_id in identifiers
            or job.status != "completed"
            or job.conclusion != "success"
            or completed_at < started_at
            or (previous_completed_at is not None and started_at < previous_completed_at)
        ):
            raise RouteAControllerError("qualification jobs are not exact serial successes")
        identifiers.add(job.database_id)
        previous_completed_at = completed_at
    q1, _, q3, q4, q5, q6 = jobs
    if q5.completed_at - q1.started_at > _COMPUTATIONAL_LIMIT:
        raise RouteAControllerError("qualification exceeded the 45-minute computational gate")
    if q6.completed_at - q6.started_at > _Q6_JOB_LIMIT:
        raise RouteAControllerError("qualification q6 exceeded its five-minute job limit")
    if q6.completed_at - q5.completed_at > _Q6_WALL_LIMIT:
        raise RouteAControllerError("qualification q6 missed its frozen wall deadline")
    if q6.completed_at - q1.started_at > _TOTAL_PATH_LIMIT:
        raise RouteAControllerError("qualification exceeded the 55-minute total path gate")
    native_seconds = sum(
        _seconds(job.completed_at - job.started_at, "native job duration") for job in (q3, q4, q5)
    )
    if 6 * native_seconds > _NATIVE_SCREEN_SECONDS:
        raise RouteAControllerError("qualification failed the native 6*C_q planning screen")
    return jobs


def _job_record(job: RouteAJobSnapshot) -> dict[str, object]:
    return {
        "databaseId": job.database_id,
        "name": job.name,
        "startedAt": job.started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "completedAt": job.completed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "status": job.status,
        "conclusion": job.conclusion,
    }


def _validate_q6_record(
    record: Mapping[str, object],
    run: RouteARunSnapshot,
    jobs: tuple[RouteAJobSnapshot, ...],
) -> None:
    expected_keys = {
        "schema_version",
        "authority",
        "formal_execution_authorized",
        "run",
        "jobs_q1_through_q5",
        "q6",
        "record_observed_utc",
        "frozen_q6_deadline_utc",
        "qualification_computational_seconds",
        "native_c_q_seconds",
        "native_six_c_q_seconds",
        "computational_45_minute_gate",
        "native_planning_screen",
        "cancellation_ledger",
    }
    if type(record) is not dict or set(record) != expected_keys:
        raise RouteAControllerError("q6 record has a non-closed top-level shape")
    run_record = record.get("run")
    job_records = record.get("jobs_q1_through_q5")
    q6_record = record.get("q6")
    if (
        type(run_record) is not dict
        or set(run_record) != {"databaseId", "event", "headSha", "headBranch", "attempt"}
        or type(run_record.get("databaseId")) is not int
        or type(run_record.get("event")) is not str
        or type(run_record.get("headSha")) is not str
        or type(run_record.get("headBranch")) is not str
        or type(run_record.get("attempt")) is not int
        or type(job_records) is not list
        or len(job_records) != 5
        or any(
            type(item) is not dict
            or set(item)
            != {"databaseId", "name", "startedAt", "completedAt", "status", "conclusion"}
            or type(item.get("databaseId")) is not int
            or any(
                type(item.get(field)) is not str
                for field in ("name", "startedAt", "completedAt", "status", "conclusion")
            )
            for item in job_records
        )
        or type(q6_record) is not dict
        or set(q6_record) != {"databaseId", "name", "startedAt"}
        or type(q6_record.get("databaseId")) is not int
        or type(q6_record.get("name")) is not str
        or type(q6_record.get("startedAt")) is not str
        or type(record.get("authority")) is not bool
        or type(record.get("formal_execution_authorized")) is not bool
        or any(
            type(record.get(field)) is not int
            for field in (
                "qualification_computational_seconds",
                "native_c_q_seconds",
                "native_six_c_q_seconds",
            )
        )
        or type(record.get("computational_45_minute_gate")) is not str
        or type(record.get("native_planning_screen")) is not str
    ):
        raise RouteAControllerError("q6 record contains a non-exact typed identity")
    expected_run = {
        "databaseId": run.database_id,
        "event": run.event,
        "headSha": run.head_sha,
        "headBranch": run.head_branch,
        "attempt": run.attempt,
    }
    expected_q6 = {
        "databaseId": jobs[5].database_id,
        "name": jobs[5].name,
        "startedAt": jobs[5].started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }
    q1, _, q3, q4, q5, q6 = jobs
    computational_seconds = _seconds(q5.completed_at - q1.started_at, "critical path")
    native_seconds = sum(
        _seconds(job.completed_at - job.started_at, "native job duration") for job in (q3, q4, q5)
    )
    record_observed_at = _timestamp(record.get("record_observed_utc"), "record observation")
    frozen_q6_deadline = _timestamp(record.get("frozen_q6_deadline_utc"), "q6 deadline")
    if (
        record.get("schema_version") != _Q6_RECORD_SCHEMA
        or record.get("authority") is not False
        or record.get("formal_execution_authorized") is not False
        or record.get("run") != expected_run
        or record.get("jobs_q1_through_q5") != [_job_record(job) for job in jobs[:5]]
        or record.get("q6") != expected_q6
        or record_observed_at < q6.started_at
        or record_observed_at > q6.completed_at
        or frozen_q6_deadline != q5.completed_at + _Q6_WALL_LIMIT
        or record.get("qualification_computational_seconds") != computational_seconds
        or record.get("native_c_q_seconds") != native_seconds
        or record.get("native_six_c_q_seconds") != 6 * native_seconds
        or record.get("computational_45_minute_gate") != "pass"
        or record.get("native_planning_screen") != "pass"
        or record.get("cancellation_ledger") is not None
    ):
        raise RouteAControllerError("q6 record does not match the final provider state")


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise RouteAControllerError("q6 record is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _validate_frozen_plan(plan_bytes: bytes) -> str:
    if type(plan_bytes) is not bytes or not plan_bytes or len(plan_bytes) > _MAX_PLAN_BYTES:
        raise RouteAControllerError("Route A plan violates its retained-byte bound")
    digest = hashlib.sha256(plan_bytes).hexdigest()
    if digest != _PLAN_SHA256:
        raise RouteAControllerError("Route A plan does not match the preregistered digest")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAControllerError("Route A plan contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        document = json.loads(plan_bytes, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAControllerError("Route A plan is not readable JSON") from error
    if (
        type(document) is not dict
        or document.get("schema_version") != _PLAN_SCHEMA
        or type(document.get("authority")) is not dict
        or document["authority"].get("formal_execution_authorized") is not False
    ):
        raise RouteAControllerError("Route A plan identity or authority boundary is invalid")
    return digest


def _decode_q6_archive(archive_bytes: bytes) -> dict[str, object]:
    if (
        type(archive_bytes) is not bytes
        or not archive_bytes
        or len(archive_bytes) > _MAX_Q6_ARCHIVE_BYTES
    ):
        raise RouteAControllerError("q6 artifact archive violates its byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                archive.comment
                or len(names) != 2
                or len(names) != len(set(names))
                or set(names) != {_Q6_RECORD_NAME, _CHECKSUMS_NAME}
            ):
                raise RouteAControllerError("q6 artifact archive has missing or extra members")
            if any(
                member.is_dir()
                or member.flag_bits & 0x1
                or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFREG}
                or member.file_size <= 0
                or member.file_size > _MAX_Q6_RECORD_BYTES
                for member in members
            ):
                raise RouteAControllerError("q6 artifact archive member is inadmissible")
            record_bytes = archive.read(_Q6_RECORD_NAME)
            checksums_bytes = archive.read(_CHECKSUMS_NAME)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise RouteAControllerError("q6 artifact is not a readable ZIP archive") from error
    expected_checksums = f"{hashlib.sha256(record_bytes).hexdigest()}  {_Q6_RECORD_NAME}\n".encode(
        "ascii"
    )
    if checksums_bytes != expected_checksums:
        raise RouteAControllerError("q6 artifact checksum does not bind its record")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteAControllerError("q6 record contains a duplicate JSON key")
            result[key] = value
        return result

    try:
        record = json.loads(record_bytes, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAControllerError("q6 record is not readable JSON") from error
    if type(record) is not dict or _canonical_json_bytes(record) != record_bytes:
        raise RouteAControllerError("q6 record is not canonical JSON")
    return record


def _validate_artifact(
    artifact: RouteAArtifactSnapshot,
    archive_bytes: bytes,
    source_sha: str,
) -> dict[str, object]:
    if (
        type(artifact) is not RouteAArtifactSnapshot
        or type(artifact.database_id) is not int
        or artifact.database_id <= 0
        or artifact.name != _Q6_ARTIFACT_NAME
        or type(artifact.digest) is not str
        or _PROVIDER_DIGEST.fullmatch(artifact.digest) is None
        or type(artifact.size_in_bytes) is not int
        or artifact.size_in_bytes <= 0
        or artifact.expired is not False
        or artifact.workflow_run_head_sha != source_sha
    ):
        raise RouteAControllerError("q6 artifact is not the exact live provider object")
    if artifact.size_in_bytes != len(archive_bytes):
        raise RouteAControllerError("q6 artifact size differs from the downloaded wrapper")
    observed_digest = "sha256:" + hashlib.sha256(archive_bytes).hexdigest()
    if artifact.digest != observed_digest:
        raise RouteAControllerError("q6 artifact digest differs from the downloaded wrapper")
    return _decode_q6_archive(archive_bytes)


def authorize_route_a_qualification(
    provider: _QualificationProvider,
    request: RouteAQualificationRequest,
) -> RouteAQualificationCapability:
    """Inspect one fresh provider snapshot and mint one ephemeral capability."""

    request_identity = _freeze_request(request)
    try:
        observation = provider.read_qualification(request_identity.run_id)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise RouteAControllerError("qualification provider observation failed") from error
    if type(observation) is not RouteAProviderObservation:
        raise RouteAControllerError("qualification provider returned the wrong snapshot type")
    controller_observed_at = _require_utc(_utc_now(), "controller observation")
    provider_observed_at = _require_utc(observation.observed_at, "provider observation")
    age = controller_observed_at - provider_observed_at
    if age < timedelta(0) or age > _MAX_OBSERVATION_AGE:
        raise RouteAControllerError("qualification provider observation is stale")
    plan_sha256 = _validate_frozen_plan(observation.plan_bytes)
    _validate_run(observation.run, request_identity, provider_observed_at)
    jobs = _validate_jobs(observation.jobs)
    if observation.run.created_at > jobs[0].started_at:
        raise RouteAControllerError("qualification first job predates its run")
    if observation.run.updated_at < jobs[-1].completed_at:
        raise RouteAControllerError("qualification run state predates q6 completion")
    q6_record = _validate_artifact(
        observation.q6_artifact,
        observation.q6_archive_bytes,
        observation.run.head_sha,
    )
    _validate_q6_record(q6_record, observation.run, jobs)

    binding = _QualificationBinding(
        request_identity=request_identity,
        plan_sha256=plan_sha256,
        provider_run_updated_at=observation.run.updated_at,
        controller_observed_at=controller_observed_at,
        expires_at=provider_observed_at + _MAX_OBSERVATION_AGE,
        q6_artifact_id=observation.q6_artifact.database_id,
        q6_artifact_digest=observation.q6_artifact.digest,
    )
    binding_token = _QualificationToken()
    capability = object.__new__(RouteAQualificationCapability)
    object.__setattr__(capability, "_binding_token", binding_token)
    object.__setattr__(capability, "_lock", threading.Lock())
    capability_id = id(capability)
    capability_ref = weakref.ref(
        capability,
        lambda dead_ref: _discard_issued_capability(capability_id, dead_ref),
    )
    with _ISSUED_CAPABILITIES_LOCK:
        _ISSUED_CAPABILITIES[capability_id] = _IssuedCapability(
            capability_ref=capability_ref,
            binding_token=binding_token,
            binding=binding,
        )
    return capability


def _consume_qualification_capability(
    capability: RouteAQualificationCapability,
) -> _QualificationBinding:
    if type(capability) is not RouteAQualificationCapability:
        raise TypeError("capability must be exact controller-minted Route A authority")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise RouteAControllerError("Route A qualification capability is not authoritative")
    with lock, _ISSUED_CAPABILITIES_LOCK:
        issued = _ISSUED_CAPABILITIES.pop(id(capability), None)
        if issued is None or issued.capability_ref() is not capability:
            raise RouteAControllerError("Route A qualification capability is absent or consumed")
        presented_token = getattr(capability, "_binding_token", None)
        object.__setattr__(capability, "_binding_token", None)
    if (
        type(issued) is not _IssuedCapability
        or type(issued.binding) is not _QualificationBinding
        or presented_token is not issued.binding_token
    ):
        raise RouteAControllerError("Route A qualification capability is not authoritative")
    return issued.binding


def claim_route_a_qualification_capability(
    capability: RouteAQualificationCapability,
    request: RouteAQualificationRequest,
) -> None:
    """Consume a controller-minted capability without exposing a replay token."""

    binding = _consume_qualification_capability(capability)
    request_identity = _freeze_request(request)
    if binding.request_identity != request_identity:
        raise RouteAControllerError("Route A qualification binding does not match")
    normalized_claimed_at = _require_utc(_utc_now(), "capability claim")
    if normalized_claimed_at < binding.controller_observed_at:
        raise RouteAControllerError("Route A qualification claim predates its observation")
    if normalized_claimed_at > binding.expires_at:
        raise RouteAControllerError("Route A qualification capability expired before claim")


def abandon_route_a_qualification_capability(
    capability: RouteAQualificationCapability,
) -> None:
    """Consume an unused qualification capability without authorizing dispatch."""

    _consume_qualification_capability(capability)
