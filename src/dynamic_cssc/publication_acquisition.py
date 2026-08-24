"""Repository-owned, fail-closed acquisition of publication source objects.

The production interface intentionally accepts only a frozen dataset identity and
an all-new output directory.  URL selection, HTTP policy, attribution, evidence
flags, and repository provenance all remain behind that interface.  A private
transport/time/snapshot seam exists solely so the network transaction can be
tested without downloading the publication corpus.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import ssl
import stat
import sys
import sysconfig
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

from dynamic_cssc.evidence_compatibility import (
    BEHAVIOR_INVENTORY_SCHEMA,
    EvidenceCompatibilityError,
    EvidenceRole,
    capture_behavior_inventory,
    repository_behavior_paths,
    verify_current_role_source,
)
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactInstallError,
    install_verified_directory,
    quarantine_owned_directory,
    verify_existing_directory,
)
from dynamic_cssc.publication_traces import (
    _LICENSE_TERMS_MEDIA_TYPES,
    _LICENSE_TERMS_SECTION_ANCHORS,
    _LICENSE_TERMS_URLS,
    _NYC_TRIP_URLS,
    _NYC_ZONE_URL,
    _SIMPLEWIKI_URL,
    _SOURCE_MEDIA_TYPES,
    _STACK_OVERFLOW_URLS,
    frozen_dataset_release,
)

__all__ = ["AcquisitionBundle", "acquire_publication_sources"]

LOCAL_SOURCE_SET_SCHEMA = "dynamic-cssc-local-source-set-v5"
ACQUISITION_TRANSACTION_SCHEMA = "dynamic-cssc-acquisition-transaction-v3"
ACQUISITION_TRANSPORT_RUNTIME_SCHEMA = "dynamic-cssc-acquisition-transport-runtime-v1"

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_ROLE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_READ_CHUNK_BYTES = 1024 * 1024
_TRANSACTION_FILENAME = "ACQUISITION-TRANSACTION.json"
_SOURCE_SET_FILENAME = "source-set.json"
_CHECKSUMS_FILENAME = "SHA256SUMS"
_REDISTRIBUTION_POLICY = "derived-trace-and-download-by-source-only"
_TERMS_MAX_BYTE_COUNT = 2 * 1024 * 1024
_URLLIB_USER_AGENT = "dynamic-cssc-publication-acquisition/1"
_ACQUISITION_LOCK_SHA256 = "981196702bd46e00c408e39c441c0fdb4c4f98f1c343f7993c8a50a92a901cd5"
_CURL_TERMS_CA_BUNDLE_SHA256 = "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f"
_CURL_PROXY_OPTION = 10004
_STACK_TERMS_CURL_URLS = frozenset(
    {
        "https://stackoverflow.com/help/licensing",
        "https://stackoverflow.com/legal/terms-of-service/public",
    }
)
if frozenset(_LICENSE_TERMS_URLS["stack-overflow"]) != _STACK_TERMS_CURL_URLS:
    raise RuntimeError("the frozen Stack Overflow terms transport route drifted")
_CURL_TERMS_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)
_HTTP_REQUEST_POLICY = MappingProxyType(
    {
        "method": "GET",
        "accept_encoding": "identity",
        "redirect_policy": "reject-any-final-url-drift",
        "data_http_content_length_policy": "required-positive-exact-byte-count",
        "terms_http_content_length_policy": "absent-or-positive-exact-byte-count",
        "terms_max_byte_count": _TERMS_MAX_BYTE_COUNT,
        "content_encoding": "identity-or-absent",
        "content_range": "forbidden",
        "transport_adapters": {
            "default": {
                "adapter_id": "cpython-urllib-identity-v1",
                "ca_policy": "certifi-2026.7.22-sha256",
                "proxy_policy": "ProxyHandler-empty",
                "tls_minimum_version": "TLSv1.2",
                "user_agent": _URLLIB_USER_AGENT,
            },
            "exact_url_override": {
                "acquisition_lock_sha256": _ACQUISITION_LOCK_SHA256,
                "adapter_id": "curl-cffi-chrome150-stack-terms-v1",
                "ca_bundle_sha256": _CURL_TERMS_CA_BUNDLE_SHA256,
                "certifi_version": "2026.7.22",
                "curl_cffi_version": "0.16.1",
                "default_headers": False,
                "discard_cookies": True,
                "http_version": "v2",
                "impersonation_target": "chrome150",
                "impersonation_target_browser": "Chrome 150",
                "impersonation_target_os": "macOS Tahoe",
                "retry_count": 0,
                "trust_env": False,
                "proxy_policy": "CURLOPT_PROXY-empty",
                "urls": sorted(_STACK_TERMS_CURL_URLS),
                "user_agent": _CURL_TERMS_USER_AGENT,
            },
        },
    }
)
_STACK_TERMS_REQUIRED_MARKERS = MappingProxyType(
    {
        "https://stackoverflow.com/help/licensing": (
            b"What is the license for the content I post?"
        ),
        "https://stackoverflow.com/legal/terms-of-service/public": (
            b"Public Network Terms of Service"
        ),
    }
)

_ATTRIBUTION_TEXT = MappingProxyType(
    {
        "stack-overflow": (
            "Stanford SNAP Stack Overflow temporal network; Stack Exchange Data Dump provenance"
        ),
        "simplewiki-2026-07": "Wikimedia Analytics MediaWiki History (CC0)",
        "nyc-tlc-yellow-2022": "NYC Taxi and Limousine Commission Trip Record Data",
    }
)


class AcquisitionError(ValueError):
    """A frozen acquisition contract or downloaded bundle failed closed."""


@dataclass(frozen=True, slots=True)
class AcquisitionBundle:
    """Paths and digests for one atomically installed acquisition bundle."""

    dataset_id: str
    output_dir: Path
    source_set_path: Path
    transaction_path: Path
    checksums_path: Path
    source_set_sha256: str
    transaction_sha256: str


@dataclass(frozen=True, slots=True)
class _AcquisitionVerification:
    """Path-free semantic identity returned by descriptor-bound verification."""

    dataset_id: str
    source_set_sha256: str
    transaction_sha256: str


class _AcquisitionArtifactDirectory(Protocol):
    def entries(self) -> tuple[str, ...]: ...

    def read_regular(self, relative_path: str) -> bytes: ...

    def sha256_regular(self, relative_path: str) -> str: ...

    def regular_size(self, relative_path: str) -> int: ...


@dataclass(frozen=True, slots=True)
class _TransportResponse:
    """One response yielded by the private external-network adapter seam."""

    final_url: str
    http_status: int
    media_type: str
    content_encoding: str | None
    content_range: str | None
    content_length: int | None
    http_etag: str | None
    http_last_modified: str | None
    chunks: Iterable[bytes]
    http_version: str
    configured_request_headers: tuple[tuple[str, str], ...]
    normalized_response_headers: tuple[tuple[str, tuple[str, ...]], ...]
    normalized_response_headers_sha256: str


class _Transport(Protocol):
    def open(self, url: str) -> AbstractContextManager[_TransportResponse]: ...


class _RepositoryTransport:
    """Route only the frozen Stack Overflow terms URLs to the compatibility adapter."""

    def __init__(
        self,
        *,
        default_transport: _Transport,
        stack_terms_transport: _Transport,
    ) -> None:
        self._default_transport = default_transport
        self._stack_terms_transport = stack_terms_transport

    def open(self, url: str) -> AbstractContextManager[_TransportResponse]:
        transport = (
            self._stack_terms_transport
            if url in _STACK_TERMS_CURL_URLS
            else self._default_transport
        )
        return transport.open(url)


def _single_curl_response_header(headers: object, name: str) -> str | None:
    getter = getattr(headers, "get_list", None)
    if not callable(getter):
        raise AcquisitionError("curl response headers do not support duplicate detection")
    values = getter(name)
    if type(values) is not list:
        raise AcquisitionError(f"curl HTTP {name} header list is malformed")
    if not values:
        return None
    if len(values) != 1:
        raise AcquisitionError(f"HTTP response contains duplicate {name} headers")
    value = values[0]
    if type(value) is not str:
        raise AcquisitionError(f"HTTP {name} header must be text")
    return value


def _response_content_length(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    if not raw_value.isascii() or not raw_value.isdigit():
        raise AcquisitionError("HTTP Content-Length must be absent or decimal digits")
    value = int(raw_value)
    if value <= 0:
        raise AcquisitionError("HTTP Content-Length must be a positive integer")
    return value


class _CurlCffiTermsTransport:
    """One-shot frozen browser-fingerprint adapter for the two Stack terms pages."""

    def __init__(self, *, session_factory: Callable[..., object], ca_bundle_path: str) -> None:
        if not callable(session_factory):
            raise TypeError("session_factory must be callable")
        if type(ca_bundle_path) is not str or not ca_bundle_path:
            raise TypeError("ca_bundle_path must be a nonempty string")
        self._session_factory = session_factory
        self._ca_bundle_path = ca_bundle_path

    @contextmanager
    def open(self, url: str) -> Iterator[_TransportResponse]:
        if url not in _STACK_TERMS_CURL_URLS:
            raise AcquisitionError("curl terms adapter URL is not in the frozen exact route set")
        body = bytearray()

        def receive(chunk: bytes) -> None:
            if type(chunk) is not bytes or not chunk:
                raise AcquisitionError("curl response chunks must be nonempty bytes")
            if len(body) + len(chunk) > _TERMS_MAX_BYTE_COUNT:
                raise AcquisitionError("curl terms body exceeds the frozen byte limit")
            body.extend(chunk)

        session = self._session_factory(
            curl_options={_CURL_PROXY_OPTION: b""},
            default_headers=False,
            discard_cookies=True,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": _CURL_TERMS_USER_AGENT,
            },
            impersonate="chrome150",
            retry=0,
            trust_env=False,
        )
        try:
            getter = getattr(session, "get", None)
            if not callable(getter):
                raise AcquisitionError("curl session does not expose the frozen GET interface")
            response = getter(
                url,
                accept_encoding="identity",
                allow_redirects=False,
                http_version="v2",
                timeout=120,
                verify=self._ca_bundle_path,
                content_callback=receive,
            )
            if getattr(response, "http_version", None) != 3:
                raise AcquisitionError("curl terms response did not negotiate frozen HTTP/2")
            headers = getattr(response, "headers", None)
            request = getattr(response, "request", None)
            request_headers = getattr(getattr(request, "headers", None), "raw", None)
            configured_request_headers = _header_pairs(
                request_headers,
                field="curl configured request headers",
            )
            expected_request_headers = (
                ("accept-encoding", "identity"),
                ("user-agent", _CURL_TERMS_USER_AGENT),
            )
            if configured_request_headers != expected_request_headers:
                raise AcquisitionError("curl configured request headers drifted")
            media_type = _single_curl_response_header(headers, "Content-Type") or ""
            content_length = _response_content_length(
                _single_curl_response_header(headers, "Content-Length")
            )
            content_encoding = _single_curl_response_header(headers, "Content-Encoding")
            content_range = _single_curl_response_header(headers, "Content-Range")
            http_etag = _single_curl_response_header(headers, "ETag")
            http_last_modified = _single_curl_response_header(headers, "Last-Modified")
            response_header_observation = _normalized_response_header_observation(
                media_type=media_type,
                content_length=content_length,
                content_encoding=content_encoding,
                content_range=content_range,
                http_etag=http_etag,
                http_last_modified=http_last_modified,
            )
            marker = _STACK_TERMS_REQUIRED_MARKERS[url]
            if marker not in body:
                raise AcquisitionError("curl terms response is missing the frozen page marker")
            yield _TransportResponse(
                final_url=str(getattr(response, "url", "")),
                http_status=getattr(response, "status_code", None),
                media_type=media_type,
                content_encoding=content_encoding,
                content_range=content_range,
                content_length=content_length,
                http_etag=http_etag,
                http_last_modified=http_last_modified,
                chunks=(bytes(body),),
                http_version="HTTP/2",
                configured_request_headers=configured_request_headers,
                normalized_response_headers=response_header_observation,
                normalized_response_headers_sha256=_normalized_response_headers_sha256(
                    response_header_observation
                ),
            )
        except AcquisitionError:
            raise
        except Exception as error:
            raise AcquisitionError("frozen curl terms request failed") from error
        finally:
            closer = getattr(session, "close", None)
            if callable(closer):
                closer()


@dataclass(frozen=True, slots=True)
class _RepositorySnapshot:
    source_git_sha: str
    behavior_inventory: Mapping[str, object]
    verification_mode: str


@dataclass(frozen=True, slots=True)
class _ProductionTransportPlan:
    transport: _Transport
    runtime: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _ObjectSpec:
    object_kind: str
    role: str
    request_url: str
    allowed_media_types: frozenset[str]
    local_path: str
    section_anchor: str | None


@dataclass(frozen=True, slots=True)
class _DownloadedObject:
    spec: _ObjectSpec
    transport_adapter_id: str
    final_url: str
    http_status: int
    media_type: str
    content_encoding: str | None
    content_range: None
    retrieval_utc: str
    http_etag: str | None
    http_last_modified: str | None
    http_version: str
    configured_request_headers: tuple[tuple[str, str], ...]
    normalized_response_headers: tuple[tuple[str, tuple[str, ...]], ...]
    normalized_response_headers_sha256: str
    response_content_length_bytes: int | None
    body_length_mode: str
    body_limit_bytes: int | None
    byte_count: int
    sha256: str


def _canonical_json_bytes(payload: object) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise AcquisitionError("acquisition evidence is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _header_pairs(
    raw_pairs: object,
    *,
    field: str,
) -> tuple[tuple[str, str], ...]:
    if type(raw_pairs) is not list:
        raise AcquisitionError(f"{field} must expose an exact raw header list")
    normalized: list[tuple[str, str]] = []
    for ordinal, raw_pair in enumerate(raw_pairs):
        if type(raw_pair) is not tuple or len(raw_pair) != 2:
            raise AcquisitionError(f"{field}[{ordinal}] must be an exact header pair")
        raw_name, raw_value = raw_pair
        if type(raw_name) is bytes and type(raw_value) is bytes:
            try:
                name = raw_name.decode("ascii").lower()
                value = raw_value.decode("latin-1")
            except UnicodeDecodeError as error:
                raise AcquisitionError(f"{field}[{ordinal}] is not an HTTP header") from error
        elif type(raw_name) is str and type(raw_value) is str:
            name = raw_name.lower()
            value = raw_value
        else:
            raise AcquisitionError(f"{field}[{ordinal}] must contain text or bytes")
        if (
            not name
            or not value
            or any(character in name for character in "\r\n:")
            or "\r" in value
            or "\n" in value
        ):
            raise AcquisitionError(f"{field}[{ordinal}] is malformed")
        normalized.append((name, value))
    return tuple(normalized)


def _normalized_response_header_observation(
    *,
    media_type: object,
    content_length: object,
    content_encoding: object,
    content_range: object,
    http_etag: object,
    http_last_modified: object,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Return the complete normalized observation for contract-relevant headers.

    Transport implementations reject duplicate values before calling this helper.
    Empty tuples therefore record true absence rather than an invented value.  The
    observation deliberately excludes cookies and unrelated response headers.
    """

    normalized_media_type = _normalize_media_type(media_type)
    if content_length is not None and (type(content_length) is not int or content_length <= 0):
        raise AcquisitionError("HTTP Content-Length observation is malformed")
    normalized_content_encoding = _content_encoding(content_encoding)
    _content_range(content_range)
    normalized_etag = _header_value(http_etag, "ETag")
    normalized_last_modified = _header_value(http_last_modified, "Last-Modified")
    return (
        ("content-type", (normalized_media_type,)),
        (
            "content-length",
            () if content_length is None else (str(content_length),),
        ),
        (
            "content-encoding",
            () if normalized_content_encoding is None else (normalized_content_encoding,),
        ),
        ("content-range", ()),
        ("etag", () if normalized_etag is None else (normalized_etag,)),
        (
            "last-modified",
            () if normalized_last_modified is None else (normalized_last_modified,),
        ),
    )


def _normalized_response_headers_sha256(
    observation: tuple[tuple[str, tuple[str, ...]], ...],
) -> str:
    payload = [{"name": name, "values": list(values)} for name, values in observation]
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _transport_adapter_id(request_url: str) -> str:
    if request_url in _STACK_TERMS_CURL_URLS:
        return "curl-cffi-chrome150-stack-terms-v1"
    return "cpython-urllib-identity-v1"


def _dataset_data_urls(dataset_id: str) -> tuple[tuple[str, str], ...]:
    if dataset_id == "stack-overflow":
        return tuple((role, _STACK_OVERFLOW_URLS[role]) for role in ("a2q", "c2q", "c2a"))
    if dataset_id == "simplewiki-2026-07":
        return (("history", _SIMPLEWIKI_URL),)
    if dataset_id == "nyc-tlc-yellow-2022":
        return (
            *((role, _NYC_TRIP_URLS[role]) for role in sorted(_NYC_TRIP_URLS)),
            ("zone-lookup", _NYC_ZONE_URL),
        )
    raise AcquisitionError(f"unsupported primary dataset: {dataset_id!r}")


def _require_frozen_https_url(url: object, field: str) -> str:
    if type(url) is not str or not url:
        raise AcquisitionError(f"{field} must be a nonempty string")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise AcquisitionError(f"{field} must be an exact no-fragment HTTPS URL")
    return url


def _basename_for_url(url: str) -> str:
    basename = Path(urlsplit(url).path).name
    if not basename or basename in {".", ".."} or "/" in basename or "\\" in basename:
        raise AcquisitionError("frozen source URL does not have a safe object basename")
    return basename


def _dataset_specs(dataset_id: str) -> tuple[_ObjectSpec, ...]:
    data_specs: list[_ObjectSpec] = []
    for role, request_url in _dataset_data_urls(dataset_id):
        if _SAFE_ROLE.fullmatch(role) is None:
            raise AcquisitionError("repository-owned acquisition role is not canonical")
        request_url = _require_frozen_https_url(request_url, "data request_url")
        data_specs.append(
            _ObjectSpec(
                object_kind="data",
                role=role,
                request_url=request_url,
                allowed_media_types=frozenset(
                    _normalize_media_type(item) for item in _SOURCE_MEDIA_TYPES[request_url]
                ),
                local_path=(f"objects/data/{role}--{_basename_for_url(request_url)}"),
                section_anchor=None,
            )
        )
    try:
        terms_urls = tuple(sorted(_LICENSE_TERMS_URLS[dataset_id]))
    except KeyError as error:  # pragma: no cover - guarded by the data registry
        raise AcquisitionError("dataset has no frozen license terms set") from error
    terms_specs: list[_ObjectSpec] = []
    for ordinal, request_url in enumerate(terms_urls, start=1):
        request_url = _require_frozen_https_url(request_url, "terms request_url")
        terms_specs.append(
            _ObjectSpec(
                object_kind="terms",
                role=f"license-terms-{ordinal:02d}",
                request_url=request_url,
                allowed_media_types=frozenset(
                    _normalize_media_type(item) for item in _LICENSE_TERMS_MEDIA_TYPES[request_url]
                ),
                local_path=f"objects/terms/license-terms-{ordinal:02d}.html",
                section_anchor=_LICENSE_TERMS_SECTION_ANCHORS[request_url],
            )
        )
    specs = (*data_specs, *terms_specs)
    roles = tuple(spec.role for spec in specs)
    targets = tuple(spec.local_path for spec in specs)
    urls = tuple(spec.request_url for spec in specs)
    if len(set(roles)) != len(roles):
        raise AcquisitionError("repository-owned acquisition roles are not unique")
    if len(set(targets)) != len(targets):
        raise AcquisitionError("repository-owned acquisition targets are not unique")
    if len(set(urls)) != len(urls):
        raise AcquisitionError("repository-owned acquisition URLs are not unique")
    return specs


def _normalize_media_type(value: object) -> str:
    if type(value) is not str or not value:
        raise AcquisitionError("HTTP media type must be a nonempty string")
    parts = [part.strip().lower() for part in value.split(";")]
    if any(not part for part in parts):
        raise AcquisitionError("HTTP media type is malformed")
    return "; ".join(parts)


def _header_value(value: object, field: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value or "\r" in value or "\n" in value:
        raise AcquisitionError(f"{field} must be null or one nonempty HTTP header value")
    return value


def _content_encoding(value: object) -> str | None:
    raw = _header_value(value, "Content-Encoding")
    if raw is None:
        return None
    if raw.strip().lower() != "identity":
        raise AcquisitionError("HTTP Content-Encoding must be identity or absent")
    return "identity"


def _content_range(value: object) -> None:
    raw = _header_value(value, "Content-Range")
    if raw is not None:
        raise AcquisitionError("HTTP Content-Range must be absent")


def _retrieval_timestamp(clock: Callable[[], datetime]) -> str:
    observed = clock()
    if type(observed) is not datetime or observed.tzinfo is None:
        raise AcquisitionError("acquisition clock must return an aware datetime")
    try:
        utc = observed.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise AcquisitionError("acquisition clock returned an invalid datetime") from error
    return utc.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _behavior_inventory_payload(snapshot: _RepositorySnapshot) -> dict[str, object]:
    if type(snapshot) is not _RepositorySnapshot:
        raise TypeError("repository_snapshot must be an exact _RepositorySnapshot")
    if _LOWER_GIT_SHA.fullmatch(snapshot.source_git_sha) is None:
        raise AcquisitionError("source Git SHA must be an exact lowercase 40-digit object ID")
    if snapshot.verification_mode not in {
        "hardened-acquisition-role-git-object-worktree-v1",
        "test-only-fixed-repository-snapshot-v1",
    }:
        raise AcquisitionError("repository snapshot verification mode is not recognized")
    if not isinstance(snapshot.behavior_inventory, Mapping):
        raise AcquisitionError("repository behavior inventory must be a mapping")
    payload = dict(snapshot.behavior_inventory)
    expected_keys = {
        "behavior_set_schema_version",
        "behavior_set_sha256",
        "entries",
        "role",
        "schema_version",
        "source_git_sha",
    }
    if set(payload) != expected_keys:
        raise AcquisitionError("repository behavior inventory does not match the closed schema")
    if (
        payload["schema_version"] != BEHAVIOR_INVENTORY_SCHEMA
        or payload["role"] != EvidenceRole.ACQUISITION.value
        or payload["source_git_sha"] != snapshot.source_git_sha
    ):
        raise AcquisitionError("repository behavior inventory identity is not acquisition S1")
    if (
        type(payload["behavior_set_schema_version"]) is not str
        or not payload["behavior_set_schema_version"]
        or type(payload["behavior_set_sha256"]) is not str
        or _LOWER_SHA256.fullmatch(payload["behavior_set_sha256"]) is None
    ):
        raise AcquisitionError("repository behavior inventory digest identity is malformed")
    entries = payload["entries"]
    expected_paths = repository_behavior_paths(EvidenceRole.ACQUISITION)
    if (
        type(entries) is not list
        or any(type(entry) is not dict for entry in entries)
        or [entry.get("path") for entry in entries] != list(expected_paths)
    ):
        raise AcquisitionError("repository behavior inventory must bind the exact acquisition set")
    for entry in entries:
        if (
            type(entry) is not dict
            or set(entry) != {"mode", "object_id", "object_type", "path"}
            or entry["mode"] not in {"100644", "100755"}
            or entry["object_type"] != "blob"
            or type(entry["object_id"]) is not str
            or _LOWER_GIT_SHA.fullmatch(entry["object_id"]) is None
        ):
            raise AcquisitionError("repository behavior inventory contains a malformed entry")
    return payload


def _require_pytest_fixture_seam() -> None:
    marker = os.environ.get("PYTEST_CURRENT_TEST")
    if not marker or "tests/test_" not in marker:
        raise RuntimeError("the acquisition fixture seam is available only under pytest")


def _test_only_repository_snapshot() -> _RepositorySnapshot:
    """Create deterministic non-authoritative Git identities for the private test seam."""

    _require_pytest_fixture_seam()
    source_git_sha = "f" * 40
    entries = [
        {
            "mode": "100644",
            "object_id": f"{ordinal:040x}",
            "object_type": "blob",
            "path": path,
        }
        for ordinal, path in enumerate(
            repository_behavior_paths(EvidenceRole.ACQUISITION),
            start=1,
        )
    ]
    return _RepositorySnapshot(
        source_git_sha=source_git_sha,
        behavior_inventory=MappingProxyType(
            {
                "behavior_set_schema_version": "dynamic-cssc-acquisition-behavior-set-v2",
                "behavior_set_sha256": "e" * 64,
                "entries": entries,
                "role": EvidenceRole.ACQUISITION.value,
                "schema_version": BEHAVIOR_INVENTORY_SCHEMA,
                "source_git_sha": source_git_sha,
            }
        ),
        verification_mode="test-only-fixed-repository-snapshot-v1",
    )


def _verify_clean_repository_snapshot(repository_root: Path) -> _RepositorySnapshot:
    try:
        attestation = verify_current_role_source(EvidenceRole.ACQUISITION, repository_root)
        inventory = capture_behavior_inventory(
            EvidenceRole.ACQUISITION,
            source_git_sha=attestation.git_sha,
            repository_root=repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise AcquisitionError(
            "publication acquisition source failed hardened verification"
        ) from error
    snapshot = _RepositorySnapshot(
        source_git_sha=attestation.git_sha,
        behavior_inventory=MappingProxyType(inventory),
        verification_mode="hardened-acquisition-role-git-object-worktree-v1",
    )
    _behavior_inventory_payload(snapshot)
    return snapshot


def _revalidate_repository_snapshot(
    snapshot: _RepositorySnapshot,
    repository_root: Path,
) -> None:
    if snapshot.verification_mode == "test-only-fixed-repository-snapshot-v1":
        return
    observed = _verify_clean_repository_snapshot(repository_root)
    if (
        observed.source_git_sha != snapshot.source_git_sha
        or observed.verification_mode != snapshot.verification_mode
        or dict(observed.behavior_inventory) != dict(snapshot.behavior_inventory)
    ):
        raise AcquisitionError("acquisition source snapshot changed during the transaction")


def _test_only_transport_runtime() -> dict[str, object]:
    return {
        "schema_version": ACQUISITION_TRANSPORT_RUNTIME_SCHEMA,
        "mode": "test-only-fixed-transport-runtime-v1",
        "python_implementation": "test-only",
        "python_version": "test-only",
        "platform_system": "test-only",
        "platform_release": "test-only",
        "platform_machine": "test-only",
        "platform_tag": "test-only",
        "requirements_acquisition_sha256": _ACQUISITION_LOCK_SHA256,
        "curl_adapter_runtime": None,
        "urllib_adapter_runtime": None,
        "runtime_execution_isolation_verified": False,
        "formal_authority_granted": False,
    }


def _runtime_file_identity(path: Path, environment_root: Path, field: str) -> dict[str, str]:
    resolved = path.resolve()
    if not resolved.is_relative_to(environment_root):
        raise AcquisitionError(f"{field} is outside the active acquisition runtime")
    return {
        "path_relative_to_runtime": resolved.relative_to(environment_root).as_posix(),
        "sha256": _sha256_file(resolved),
    }


def _module_runtime_identity(module: object, environment_root: Path, field: str) -> dict[str, str]:
    raw_path = getattr(module, "__file__", None)
    if type(raw_path) is not str or not raw_path:
        raise AcquisitionError(f"{field} does not expose a frozen import origin")
    return _runtime_file_identity(Path(raw_path), environment_root, field)


def _production_runtime_base(repository_root: Path) -> dict[str, object]:
    if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
        raise AcquisitionError("publication acquisition requires exact CPython 3.12.13")
    lock_path = repository_root / "requirements-acquisition.txt"
    if _sha256_file(lock_path) != _ACQUISITION_LOCK_SHA256:
        raise AcquisitionError("requirements-acquisition.txt does not match the frozen lock")
    system = platform.system()
    machine = platform.machine()
    if system not in {"Darwin", "Linux"} or machine not in {
        "arm64",
        "aarch64",
        "x86_64",
    }:
        raise AcquisitionError("acquisition runtime platform is outside the frozen wheel set")
    platform_tag = sysconfig.get_platform()
    if type(platform_tag) is not str or not platform_tag:
        raise AcquisitionError("acquisition runtime platform tag is unavailable")
    try:
        certifi_version = importlib.metadata.version("certifi")
        import certifi  # type: ignore[import-not-found]
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise AcquisitionError(
            "publication acquisition requires the frozen requirements-acquisition.txt environment"
        ) from error
    if certifi_version != "2026.7.22":
        raise AcquisitionError("urllib acquisition certifi version is not frozen")
    environment_root = Path(sys.prefix).resolve()
    ca_bundle_path = Path(certifi.where()).resolve()
    if _sha256_file(ca_bundle_path) != _CURL_TERMS_CA_BUNDLE_SHA256:
        raise AcquisitionError("urllib certifi CA bundle does not match the frozen digest")
    return {
        "schema_version": ACQUISITION_TRANSPORT_RUNTIME_SCHEMA,
        "mode": "repository-checked-descriptive-current-process-runtime-v1",
        "python_implementation": "CPython",
        "python_version": "3.12.13",
        "platform_system": system,
        "platform_release": platform.release(),
        "platform_machine": machine,
        "platform_tag": platform_tag,
        "requirements_acquisition_sha256": _ACQUISITION_LOCK_SHA256,
        "curl_adapter_runtime": None,
        "urllib_adapter_runtime": {
            "schema_version": "dynamic-cssc-urllib-transport-runtime-v1",
            "certifi_version": certifi_version,
            "openssl_version": ssl.OPENSSL_VERSION,
            "proxy_policy": "ProxyHandler-empty",
            "tls_minimum_version": "TLSv1.2",
            "runtime_files": {
                "certifi_module": _module_runtime_identity(
                    certifi, environment_root, "urllib certifi module"
                ),
                "ca_bundle": _runtime_file_identity(
                    ca_bundle_path, environment_root, "urllib certifi CA bundle"
                ),
            },
        },
        "runtime_execution_isolation_verified": False,
        "formal_authority_granted": False,
    }


def _verified_transport_runtime(
    value: object,
    *,
    dataset_id: str,
    test_only: bool,
) -> dict[str, object]:
    if type(value) is not dict:
        raise AcquisitionError("transport_runtime must be a JSON object")
    expected_keys = {
        "schema_version",
        "mode",
        "python_implementation",
        "python_version",
        "platform_system",
        "platform_release",
        "platform_machine",
        "platform_tag",
        "requirements_acquisition_sha256",
        "curl_adapter_runtime",
        "urllib_adapter_runtime",
        "runtime_execution_isolation_verified",
        "formal_authority_granted",
    }
    if set(value) != expected_keys:
        raise AcquisitionError("transport_runtime does not match the closed schema")
    if test_only:
        expected = _test_only_transport_runtime()
        if value != expected:
            raise AcquisitionError("test-only transport_runtime is not the frozen fixture")
        return expected
    if (
        value["schema_version"] != ACQUISITION_TRANSPORT_RUNTIME_SCHEMA
        or value["mode"] != "repository-checked-descriptive-current-process-runtime-v1"
        or value["python_implementation"] != "CPython"
        or value["python_version"] != "3.12.13"
        or value["requirements_acquisition_sha256"] != _ACQUISITION_LOCK_SHA256
        or value["runtime_execution_isolation_verified"] is not False
        or value["formal_authority_granted"] is not False
    ):
        raise AcquisitionError("transport_runtime fixed identity is not frozen")
    for field in ("platform_release", "platform_tag"):
        if type(value[field]) is not str or not value[field]:
            raise AcquisitionError(f"transport_runtime {field} is malformed")
    if value["platform_system"] not in {"Darwin", "Linux"} or value["platform_machine"] not in {
        "arm64",
        "aarch64",
        "x86_64",
    }:
        raise AcquisitionError("transport_runtime platform is outside the frozen wheel set")
    _verified_urllib_runtime(value["urllib_adapter_runtime"])
    curl_runtime = value["curl_adapter_runtime"]
    if dataset_id == "stack-overflow":
        _verified_curl_runtime(curl_runtime)
    elif curl_runtime is not None:
        raise AcquisitionError("non-Stack acquisition must not claim a curl adapter runtime")
    return dict(value)


def _verified_urllib_runtime(value: object) -> None:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "certifi_version",
        "openssl_version",
        "proxy_policy",
        "tls_minimum_version",
        "runtime_files",
    }:
        raise AcquisitionError("urllib adapter runtime does not match the closed schema")
    if (
        value["schema_version"] != "dynamic-cssc-urllib-transport-runtime-v1"
        or value["certifi_version"] != "2026.7.22"
        or value["proxy_policy"] != "ProxyHandler-empty"
        or value["tls_minimum_version"] != "TLSv1.2"
        or type(value["openssl_version"]) is not str
        or not value["openssl_version"]
    ):
        raise AcquisitionError("urllib adapter runtime identity drifted")
    runtime_files = value["runtime_files"]
    if type(runtime_files) is not dict or set(runtime_files) != {
        "certifi_module",
        "ca_bundle",
    }:
        raise AcquisitionError("urllib adapter runtime file set is not exact")
    for field in ("ca_bundle", "certifi_module"):
        _verified_runtime_file_identity(runtime_files[field], f"urllib runtime {field}")
    if runtime_files["ca_bundle"]["sha256"] != _CURL_TERMS_CA_BUNDLE_SHA256:
        raise AcquisitionError("urllib adapter CA bundle digest drifted")


def _verified_runtime_file_identity(value: object, field: str) -> None:
    if type(value) is not dict or set(value) != {"path_relative_to_runtime", "sha256"}:
        raise AcquisitionError(f"{field} does not match the closed runtime-file schema")
    relative_path = value["path_relative_to_runtime"]
    digest = value["sha256"]
    if (
        type(relative_path) is not str
        or not relative_path
        or relative_path.startswith("/")
        or ".." in Path(relative_path).parts
        or type(digest) is not str
        or _LOWER_SHA256.fullmatch(digest) is None
    ):
        raise AcquisitionError(f"{field} identity is malformed")


def _verified_curl_runtime(value: object) -> None:
    if type(value) is not dict:
        raise AcquisitionError("Stack acquisition requires a curl adapter runtime")
    expected_keys = {
        "schema_version",
        "distribution_versions",
        "curl_version",
        "http_version_numeric",
        "native_impersonation_target",
        "proxy_option_numeric",
        "proxy_value",
        "runtime_files",
    }
    if set(value) != expected_keys or value["schema_version"] != (
        "dynamic-cssc-curl-cffi-transport-runtime-v1"
    ):
        raise AcquisitionError("curl adapter runtime does not match the closed schema")
    if value["distribution_versions"] != {
        "certifi": "2026.7.22",
        "cffi": "2.1.1",
        "curl-cffi": "0.16.1",
        "pycparser": "3.0",
    }:
        raise AcquisitionError("curl adapter distribution versions drifted")
    curl_version = value["curl_version"]
    if type(curl_version) is not str or not curl_version.startswith(
        "libcurl/8.21.0-IMPERSONATE BoringSSL "
    ):
        raise AcquisitionError("curl adapter native runtime version drifted")
    if (
        value["http_version_numeric"] != 3
        or value["proxy_option_numeric"] != _CURL_PROXY_OPTION
        or value["proxy_value"] != "empty"
        or value["native_impersonation_target"]
        != {
            "browser": "Chrome",
            "version": "150",
            "os": "macOS",
            "os_version": "Tahoe",
            "target_name": "chrome150",
            "h3_fingerprints": True,
        }
    ):
        raise AcquisitionError("curl adapter native profile identity drifted")
    runtime_files = value["runtime_files"]
    expected_files = {
        "certifi_module",
        "ca_bundle",
        "cffi_backend",
        "cffi_module",
        "curl_cffi_module",
        "curl_cffi_native_wrapper",
        "pycparser_module",
    }
    if type(runtime_files) is not dict or set(runtime_files) != expected_files:
        raise AcquisitionError("curl adapter runtime file set is not exact")
    for field in sorted(expected_files):
        _verified_runtime_file_identity(runtime_files[field], f"curl runtime {field}")
    if runtime_files["ca_bundle"]["sha256"] != _CURL_TERMS_CA_BUNDLE_SHA256:
        raise AcquisitionError("curl adapter CA bundle digest drifted")


def _ca_bundle_path_from_runtime(runtime: Mapping[str, object]) -> Path:
    urllib_runtime = runtime.get("urllib_adapter_runtime")
    if type(urllib_runtime) is not dict:
        raise AcquisitionError("verified urllib runtime is unavailable")
    runtime_files = urllib_runtime.get("runtime_files")
    if type(runtime_files) is not dict:
        raise AcquisitionError("verified urllib runtime file set is unavailable")
    ca_bundle = runtime_files.get("ca_bundle")
    if type(ca_bundle) is not dict:
        raise AcquisitionError("verified urllib CA bundle identity is unavailable")
    relative_path = ca_bundle.get("path_relative_to_runtime")
    if type(relative_path) is not str:
        raise AcquisitionError("verified urllib CA bundle path is malformed")
    path = (Path(sys.prefix).resolve() / relative_path).resolve()
    if _sha256_file(path) != _CURL_TERMS_CA_BUNDLE_SHA256:
        raise AcquisitionError("verified urllib CA bundle changed before transport creation")
    return path


def _require_outside_repository(path: Path, repository_root: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    if not isinstance(repository_root, Path) or not repository_root.is_dir():
        raise AcquisitionError("repository_root must be an existing pathlib.Path directory")
    normalized = path.resolve(strict=False)
    root = repository_root.resolve()
    if normalized == root or root in normalized.parents:
        raise AcquisitionError("acquisition output directory must live outside the checkout")
    return normalized


def _require_new_output_directory(output_dir: Path) -> None:
    try:
        output_dir.lstat()
    except FileNotFoundError:
        pass
    else:
        raise AcquisitionError("acquisition output directory must not already exist")
    parent = output_dir.parent
    try:
        parent_mode = parent.lstat().st_mode
    except FileNotFoundError as error:
        raise AcquisitionError("acquisition output parent must already exist") from error
    if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
        raise AcquisitionError("acquisition output parent must be a non-symlink directory")


def _retain_transport_response(
    spec: _ObjectSpec,
    target: Path,
    response: _TransportResponse,
    *,
    clock: Callable[[], datetime],
) -> _DownloadedObject:
    if type(response) is not _TransportResponse:
        raise AcquisitionError("transport must yield an exact _TransportResponse")
    if response.final_url != spec.request_url:
        raise AcquisitionError(f"unexpected HTTP redirect for acquisition role {spec.role}")
    if type(response.http_status) is not int or response.http_status != 200:
        raise AcquisitionError(f"HTTP status for acquisition role {spec.role} must be 200")
    media_type = _normalize_media_type(response.media_type)
    if media_type not in spec.allowed_media_types:
        raise AcquisitionError(
            f"HTTP media type for acquisition role {spec.role} is outside the frozen set"
        )
    if response.content_length is None:
        if spec.object_kind != "terms":
            raise AcquisitionError(
                f"Content-Length for acquisition role {spec.role} must be a positive integer"
            )
        body_length_mode = "terms-bounded-clean-transfer-v1"
    elif type(response.content_length) is not int or response.content_length <= 0:
        raise AcquisitionError(
            f"Content-Length for acquisition role {spec.role} must be a positive integer"
        )
    else:
        body_length_mode = "content-length-exact-v1"
    body_limit_bytes = _TERMS_MAX_BYTE_COUNT if spec.object_kind == "terms" else None
    if (
        body_limit_bytes is not None
        and response.content_length is not None
        and response.content_length > body_limit_bytes
    ):
        raise AcquisitionError(f"terms body exceeds the frozen byte limit for role {spec.role}")
    content_encoding = _content_encoding(response.content_encoding)
    _content_range(response.content_range)
    http_etag = _header_value(response.http_etag, "ETag")
    http_last_modified = _header_value(response.http_last_modified, "Last-Modified")
    adapter_id = _transport_adapter_id(spec.request_url)
    expected_http_version = (
        "HTTP/2" if adapter_id == "curl-cffi-chrome150-stack-terms-v1" else "HTTP/1.1"
    )
    if response.http_version != expected_http_version:
        raise AcquisitionError(
            f"HTTP version for acquisition role {spec.role} is outside the frozen route"
        )
    expected_user_agent = (
        _CURL_TERMS_USER_AGENT
        if adapter_id == "curl-cffi-chrome150-stack-terms-v1"
        else _URLLIB_USER_AGENT
    )
    expected_request_headers = (
        ("accept-encoding", "identity"),
        ("user-agent", expected_user_agent),
    )
    if response.configured_request_headers != expected_request_headers:
        raise AcquisitionError(
            f"configured request headers for acquisition role {spec.role} drifted"
        )
    expected_response_headers = _normalized_response_header_observation(
        media_type=media_type,
        content_length=response.content_length,
        content_encoding=content_encoding,
        content_range=None,
        http_etag=http_etag,
        http_last_modified=http_last_modified,
    )
    if response.normalized_response_headers != expected_response_headers:
        raise AcquisitionError(
            f"normalized response headers for acquisition role {spec.role} drifted"
        )
    if (
        type(response.normalized_response_headers_sha256) is not str
        or _LOWER_SHA256.fullmatch(response.normalized_response_headers_sha256) is None
        or response.normalized_response_headers_sha256
        != _normalized_response_headers_sha256(expected_response_headers)
    ):
        raise AcquisitionError(
            f"response-header SHA-256 for acquisition role {spec.role} is invalid"
        )
    retrieval_utc = _retrieval_timestamp(clock)
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with target.open("xb") as output:
            for chunk in response.chunks:
                if type(chunk) is not bytes or not chunk:
                    raise AcquisitionError("HTTP response chunks must be nonempty bytes")
                byte_count += len(chunk)
                if body_limit_bytes is not None and byte_count > body_limit_bytes:
                    raise AcquisitionError(
                        f"terms body exceeds the frozen byte limit for role {spec.role}"
                    )
                if response.content_length is not None and byte_count > response.content_length:
                    raise AcquisitionError(
                        f"downloaded bytes exceed Content-Length for role {spec.role}"
                    )
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise AcquisitionError(f"duplicate acquisition target for role {spec.role}") from error
    if byte_count <= 0:
        raise AcquisitionError(f"downloaded body for role {spec.role} must be nonempty")
    if response.content_length is not None and byte_count != response.content_length:
        raise AcquisitionError(
            f"downloaded byte count does not match Content-Length for role {spec.role}"
        )
    target.chmod(0o444)
    return _DownloadedObject(
        spec=spec,
        transport_adapter_id=adapter_id,
        final_url=response.final_url,
        http_status=response.http_status,
        media_type=media_type,
        content_encoding=content_encoding,
        content_range=None,
        retrieval_utc=retrieval_utc,
        http_etag=http_etag,
        http_last_modified=http_last_modified,
        http_version=response.http_version,
        configured_request_headers=response.configured_request_headers,
        normalized_response_headers=expected_response_headers,
        normalized_response_headers_sha256=response.normalized_response_headers_sha256,
        response_content_length_bytes=response.content_length,
        body_length_mode=body_length_mode,
        body_limit_bytes=body_limit_bytes,
        byte_count=byte_count,
        sha256=digest.hexdigest(),
    )


def _download_object(
    spec: _ObjectSpec,
    target_root: Path,
    *,
    transport: _Transport,
    clock: Callable[[], datetime],
) -> _DownloadedObject:
    target = target_root / Path(spec.local_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with transport.open(spec.request_url) as response:
            return _retain_transport_response(spec, target, response, clock=clock)
    except AcquisitionError:
        raise
    except Exception as error:
        raise AcquisitionError(f"transport failed for frozen role {spec.role}") from error


def _source_set_payload(
    dataset_id: str,
    downloaded: tuple[_DownloadedObject, ...],
) -> dict[str, object]:
    attribution = _ATTRIBUTION_TEXT[dataset_id]
    terms = [item for item in downloaded if item.spec.object_kind == "terms"]
    data = [item for item in downloaded if item.spec.object_kind == "data"]
    return {
        "schema_version": LOCAL_SOURCE_SET_SCHEMA,
        "dataset_id": dataset_id,
        "dataset_release": frozen_dataset_release(dataset_id),
        "terms_objects": [
            {
                "source_url": item.spec.request_url,
                "final_url": item.final_url,
                "http_status": item.http_status,
                "media_type": item.media_type,
                "retrieval_utc": item.retrieval_utc,
                "http_etag": item.http_etag,
                "http_last_modified": item.http_last_modified,
                "section_anchor": item.spec.section_anchor,
                "local_path": item.spec.local_path,
                "byte_count": item.byte_count,
                "sha256": item.sha256,
            }
            for item in terms
        ],
        "objects": [
            {
                "role": item.spec.role,
                "local_path": item.spec.local_path,
                "source_url": item.spec.request_url,
                "final_url": item.final_url,
                "http_status": item.http_status,
                "media_type": item.media_type,
                "retrieval_utc": item.retrieval_utc,
                "byte_count": item.byte_count,
                "http_etag": item.http_etag,
                "http_last_modified": item.http_last_modified,
                "local_sha256": item.sha256,
                "publisher_sha256": None,
                "attribution_text": attribution,
            }
            for item in data
        ],
    }


def _transaction_payload(
    dataset_id: str,
    downloaded: tuple[_DownloadedObject, ...],
    *,
    source_set_sha256: str,
    repository_snapshot: _RepositorySnapshot,
    transport_runtime: Mapping[str, object],
) -> dict[str, object]:
    test_only = repository_snapshot.verification_mode == "test-only-fixed-repository-snapshot-v1"
    return {
        "schema_version": ACQUISITION_TRANSACTION_SCHEMA,
        "dataset_id": dataset_id,
        "dataset_release": frozen_dataset_release(dataset_id),
        "repository_provenance": {
            "source_git_sha": repository_snapshot.source_git_sha,
            "verification_mode": repository_snapshot.verification_mode,
            "behavior_inventory": _behavior_inventory_payload(repository_snapshot),
        },
        "network_fetch_performed": not test_only,
        "formal_authority_granted": False,
        "acquisition_network_authority_verified": False,
        "post_run_anchor_verified": False,
        "evidence_compatibility_verified": False,
        "authority_hold_reason": (
            "test-only-fixture-no-network-acquisition"
            if test_only
            else "post-run-anchor-and-adr-0010-evidence-compatibility-not-admitted"
        ),
        "http_request_policy": dict(_HTTP_REQUEST_POLICY),
        "transport_runtime": dict(transport_runtime),
        "redistribution_policy": _REDISTRIBUTION_POLICY,
        "source_set": {
            "filename": _SOURCE_SET_FILENAME,
            "schema_version": LOCAL_SOURCE_SET_SCHEMA,
            "sha256": source_set_sha256,
        },
        "object_count": len(downloaded),
        "objects": [
            {
                "object_kind": item.spec.object_kind,
                "role": item.spec.role,
                "transport_adapter_id": item.transport_adapter_id,
                "request_url": item.spec.request_url,
                "final_url": item.final_url,
                "http_status": item.http_status,
                "media_type": item.media_type,
                "content_encoding": item.content_encoding,
                "content_range": item.content_range,
                "retrieval_utc": item.retrieval_utc,
                "http_etag": item.http_etag,
                "http_last_modified": item.http_last_modified,
                "http_version": item.http_version,
                "configured_request_headers": [
                    {"name": name, "value": value}
                    for name, value in item.configured_request_headers
                ],
                "normalized_response_headers": [
                    {"name": name, "values": list(values)}
                    for name, values in item.normalized_response_headers
                ],
                "normalized_response_headers_sha256": (item.normalized_response_headers_sha256),
                "response_content_length_bytes": item.response_content_length_bytes,
                "body_length_mode": item.body_length_mode,
                "body_limit_bytes": item.body_limit_bytes,
                "body_completion": "clean-eof-v1",
                "byte_count": item.byte_count,
                "sha256": item.sha256,
                "local_path": item.spec.local_path,
                "section_anchor": item.spec.section_anchor,
            }
            for item in downloaded
        ],
    }


def _write_bytes_new(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o444)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    if not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionError("acquisition verification requires OS O_NOFOLLOW support")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
        )
    except OSError as error:
        raise AcquisitionError(f"acquisition artifact cannot be securely opened: {path}") from error
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AcquisitionError(f"acquisition artifact is not a regular file: {path}")
        for chunk in iter(lambda: handle.read(_READ_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksum_manifest(root: Path, relative_paths: tuple[str, ...]) -> bytes:
    lines = [
        f"{_sha256_file(root / relative_path)}  {relative_path}\n"
        for relative_path in sorted(relative_paths)
    ]
    payload = "".join(lines).encode("ascii")
    _write_bytes_new(root / _CHECKSUMS_FILENAME, payload)
    return payload


def _read_artifact_bytes(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionError("acquisition verification requires OS O_NOFOLLOW support")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
        )
    except OSError as error:
        raise AcquisitionError(f"acquisition artifact cannot be securely opened: {path}") from error
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AcquisitionError(f"acquisition artifact is not a regular file: {path}")
        return handle.read()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise AcquisitionError(f"duplicate JSON key is forbidden: {key}")
        payload[key] = value
    return payload


def _decode_canonical_json_object(
    raw: bytes,
    field: str,
) -> tuple[dict[str, object], bytes]:
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                AcquisitionError(f"non-finite JSON value is forbidden: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcquisitionError(f"{field} must be canonical UTF-8 JSON") from error
    if type(payload) is not dict:
        raise AcquisitionError(f"{field} must be a JSON object")
    if _canonical_json_bytes(payload) != raw:
        raise AcquisitionError(f"{field} must use the canonical JSON encoding")
    return payload, raw


def _read_canonical_json_object(path: Path, field: str) -> tuple[dict[str, object], bytes]:
    return _decode_canonical_json_object(_read_artifact_bytes(path), field)


def _require_retrieval_utc(value: object, field: str) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise AcquisitionError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise AcquisitionError(f"{field} must be a valid RFC 3339 timestamp") from error
    if parsed.tzinfo != UTC:
        raise AcquisitionError(f"{field} must be UTC")
    return value


def _verified_downloaded_objects(
    transaction: Mapping[str, object],
    specs: tuple[_ObjectSpec, ...],
    artifact_directory: _AcquisitionArtifactDirectory,
) -> tuple[_DownloadedObject, ...]:
    raw_objects = transaction.get("objects")
    if type(raw_objects) is not list or len(raw_objects) != len(specs):
        raise AcquisitionError("transaction objects must equal the exact frozen role set")
    downloaded: list[_DownloadedObject] = []
    expected_keys = {
        "object_kind",
        "role",
        "transport_adapter_id",
        "request_url",
        "final_url",
        "http_status",
        "media_type",
        "content_encoding",
        "content_range",
        "retrieval_utc",
        "http_etag",
        "http_last_modified",
        "http_version",
        "configured_request_headers",
        "normalized_response_headers",
        "normalized_response_headers_sha256",
        "response_content_length_bytes",
        "body_length_mode",
        "body_limit_bytes",
        "body_completion",
        "byte_count",
        "sha256",
        "local_path",
        "section_anchor",
    }
    for ordinal, (raw_object, spec) in enumerate(zip(raw_objects, specs, strict=True)):
        if type(raw_object) is not dict or set(raw_object) != expected_keys:
            raise AcquisitionError(
                f"transaction object {ordinal} does not match the closed object schema"
            )
        if raw_object["object_kind"] != spec.object_kind:
            raise AcquisitionError(
                "transaction contains an extra, missing, or reordered object kind"
            )
        if raw_object["role"] != spec.role:
            raise AcquisitionError(
                "transaction contains a duplicate, extra, missing, or reordered role"
            )
        transport_adapter_id = _transport_adapter_id(spec.request_url)
        if raw_object["transport_adapter_id"] != transport_adapter_id:
            raise AcquisitionError("transaction transport adapter route is not frozen")
        if raw_object["request_url"] != spec.request_url:
            raise AcquisitionError("transaction request URL does not match the frozen URL")
        if raw_object["final_url"] != spec.request_url:
            raise AcquisitionError("transaction records an unexpected HTTP redirect")
        if type(raw_object["http_status"]) is not int or raw_object["http_status"] != 200:
            raise AcquisitionError("transaction HTTP status must be the strict integer 200")
        media_type = _normalize_media_type(raw_object["media_type"])
        if media_type not in spec.allowed_media_types or media_type != raw_object["media_type"]:
            raise AcquisitionError(
                "transaction media type does not match the frozen normalized set"
            )
        content_encoding = _content_encoding(raw_object["content_encoding"])
        _content_range(raw_object["content_range"])
        retrieval_utc = _require_retrieval_utc(
            raw_object["retrieval_utc"], f"transaction object {ordinal} retrieval_utc"
        )
        http_etag = _header_value(raw_object["http_etag"], "transaction ETag")
        http_last_modified = _header_value(
            raw_object["http_last_modified"], "transaction Last-Modified"
        )
        expected_http_version = (
            "HTTP/2" if transport_adapter_id == "curl-cffi-chrome150-stack-terms-v1" else "HTTP/1.1"
        )
        if raw_object["http_version"] != expected_http_version:
            raise AcquisitionError("transaction HTTP version does not match its frozen route")
        raw_request_headers = raw_object["configured_request_headers"]
        if type(raw_request_headers) is not list:
            raise AcquisitionError("transaction configured request headers must be an array")
        request_headers: list[tuple[str, str]] = []
        for header_ordinal, raw_header in enumerate(raw_request_headers):
            if type(raw_header) is not dict or set(raw_header) != {"name", "value"}:
                raise AcquisitionError(
                    f"transaction request header {header_ordinal} does not match the closed schema"
                )
            name = raw_header["name"]
            value = raw_header["value"]
            if type(name) is not str or type(value) is not str:
                raise AcquisitionError("transaction configured request header is malformed")
            request_headers.append((name, value))
        expected_user_agent = (
            _CURL_TERMS_USER_AGENT
            if transport_adapter_id == "curl-cffi-chrome150-stack-terms-v1"
            else _URLLIB_USER_AGENT
        )
        if tuple(request_headers) != (
            ("accept-encoding", "identity"),
            ("user-agent", expected_user_agent),
        ):
            raise AcquisitionError("transaction configured request headers are not frozen")
        raw_response_headers = raw_object["normalized_response_headers"]
        if type(raw_response_headers) is not list:
            raise AcquisitionError("transaction normalized response headers must be an array")
        response_headers: list[tuple[str, tuple[str, ...]]] = []
        for header_ordinal, raw_header in enumerate(raw_response_headers):
            if type(raw_header) is not dict or set(raw_header) != {"name", "values"}:
                raise AcquisitionError(
                    "transaction normalized response header "
                    f"{header_ordinal} does not match the closed schema"
                )
            name = raw_header["name"]
            values = raw_header["values"]
            if (
                type(name) is not str
                or type(values) is not list
                or any(type(value) is not str for value in values)
            ):
                raise AcquisitionError("transaction normalized response headers are malformed")
            response_headers.append((name, tuple(values)))
        response_headers_sha256 = raw_object["normalized_response_headers_sha256"]
        if (
            type(response_headers_sha256) is not str
            or _LOWER_SHA256.fullmatch(response_headers_sha256) is None
        ):
            raise AcquisitionError("transaction response-header SHA-256 is malformed")
        response_content_length = raw_object["response_content_length_bytes"]
        body_length_mode = raw_object["body_length_mode"]
        body_limit_bytes = raw_object["body_limit_bytes"]
        byte_count = raw_object["byte_count"]
        if type(byte_count) is not int or byte_count <= 0:
            raise AcquisitionError("transaction byte count must be a positive integer")
        expected_response_headers = _normalized_response_header_observation(
            media_type=media_type,
            content_length=response_content_length,
            content_encoding=content_encoding,
            content_range=None,
            http_etag=http_etag,
            http_last_modified=http_last_modified,
        )
        if tuple(response_headers) != expected_response_headers:
            raise AcquisitionError("transaction normalized response headers are not exact")
        if response_headers_sha256 != _normalized_response_headers_sha256(
            expected_response_headers
        ):
            raise AcquisitionError("transaction response-header SHA-256 is not reproducible")
        if spec.object_kind == "data":
            if (
                type(response_content_length) is not int
                or response_content_length <= 0
                or response_content_length != byte_count
                or body_length_mode != "content-length-exact-v1"
                or body_limit_bytes is not None
            ):
                raise AcquisitionError(
                    "transaction data byte count must equal positive Content-Length"
                )
        elif (
            (
                response_content_length is not None
                and (
                    type(response_content_length) is not int
                    or response_content_length <= 0
                    or response_content_length != byte_count
                )
            )
            or body_length_mode
            != (
                "terms-bounded-clean-transfer-v1"
                if response_content_length is None
                else "content-length-exact-v1"
            )
            or body_limit_bytes != _TERMS_MAX_BYTE_COUNT
            or byte_count > _TERMS_MAX_BYTE_COUNT
        ):
            raise AcquisitionError("transaction terms body length contract is invalid")
        if raw_object["body_completion"] != "clean-eof-v1":
            raise AcquisitionError("transaction body completion is not clean EOF")
        sha256 = raw_object["sha256"]
        if type(sha256) is not str or _LOWER_SHA256.fullmatch(sha256) is None:
            raise AcquisitionError("transaction object SHA-256 must be lowercase hexadecimal")
        if raw_object["local_path"] != spec.local_path:
            raise AcquisitionError("transaction contains a duplicate or non-frozen target path")
        if raw_object["section_anchor"] != spec.section_anchor:
            raise AcquisitionError(
                "transaction terms section anchor does not match the frozen value"
            )
        if artifact_directory.regular_size(spec.local_path) != byte_count:
            raise AcquisitionError("transaction byte count does not match the retained object")
        if artifact_directory.sha256_regular(spec.local_path) != sha256:
            raise AcquisitionError("transaction SHA-256 does not match the retained object")
        downloaded.append(
            _DownloadedObject(
                spec=spec,
                transport_adapter_id=transport_adapter_id,
                final_url=spec.request_url,
                http_status=200,
                media_type=media_type,
                content_encoding=content_encoding,
                content_range=None,
                retrieval_utc=retrieval_utc,
                http_etag=http_etag,
                http_last_modified=http_last_modified,
                http_version=expected_http_version,
                configured_request_headers=tuple(request_headers),
                normalized_response_headers=expected_response_headers,
                normalized_response_headers_sha256=response_headers_sha256,
                response_content_length_bytes=response_content_length,
                body_length_mode=body_length_mode,
                body_limit_bytes=body_limit_bytes,
                byte_count=byte_count,
                sha256=sha256,
            )
        )
    return tuple(downloaded)


def _verify_acquisition_directory(
    artifact_directory: _AcquisitionArtifactDirectory,
    *,
    repository_snapshot: _RepositorySnapshot,
    repository_root: Path,
) -> _AcquisitionVerification:
    """Rehash one descriptor-bound directory without consulting its pathname."""

    _revalidate_repository_snapshot(repository_snapshot, repository_root)
    behavior_inventory = _behavior_inventory_payload(repository_snapshot)

    transaction, transaction_bytes = _decode_canonical_json_object(
        artifact_directory.read_regular(_TRANSACTION_FILENAME),
        "acquisition transaction",
    )
    dataset_id = transaction.get("dataset_id")
    if type(dataset_id) is not str:
        raise AcquisitionError("acquisition transaction dataset_id must be an exact string")
    specs = _dataset_specs(dataset_id)
    transport_runtime = _verified_transport_runtime(
        transaction.get("transport_runtime"),
        dataset_id=dataset_id,
        test_only=(
            repository_snapshot.verification_mode == "test-only-fixed-repository-snapshot-v1"
        ),
    )
    expected_files = {
        *(spec.local_path for spec in specs),
        _SOURCE_SET_FILENAME,
        _TRANSACTION_FILENAME,
        _CHECKSUMS_FILENAME,
    }
    expected_directories = {
        "objects",
        "objects/data",
        "objects/terms",
    }
    expected_entries = tuple(sorted(expected_files | expected_directories))
    if artifact_directory.entries() != expected_entries:
        raise AcquisitionError("acquisition bundle entries do not match the exact frozen set")

    checksummed_paths = tuple(sorted(expected_files - {_CHECKSUMS_FILENAME}))
    expected_checksums = "".join(
        f"{artifact_directory.sha256_regular(relative_path)}  {relative_path}\n"
        for relative_path in checksummed_paths
    ).encode("ascii")
    if artifact_directory.read_regular(_CHECKSUMS_FILENAME) != expected_checksums:
        raise AcquisitionError("SHA256SUMS does not exactly bind every acquisition artifact")

    source_set, source_set_bytes = _decode_canonical_json_object(
        artifact_directory.read_regular(_SOURCE_SET_FILENAME),
        "source-set",
    )
    downloaded = _verified_downloaded_objects(transaction, specs, artifact_directory)
    expected_source_set_bytes = _canonical_json_bytes(_source_set_payload(dataset_id, downloaded))
    if source_set_bytes != expected_source_set_bytes or source_set != _source_set_payload(
        dataset_id, downloaded
    ):
        raise AcquisitionError("source-set does not match the repository-owned acquisition facts")
    source_set_sha256 = hashlib.sha256(source_set_bytes).hexdigest()

    expected_transaction = _transaction_payload(
        dataset_id,
        downloaded,
        source_set_sha256=source_set_sha256,
        repository_snapshot=repository_snapshot,
        transport_runtime=transport_runtime,
    )
    if expected_transaction["repository_provenance"] != {
        "source_git_sha": repository_snapshot.source_git_sha,
        "verification_mode": repository_snapshot.verification_mode,
        "behavior_inventory": behavior_inventory,
    }:
        raise AssertionError("repository provenance construction drifted")
    expected_transaction_bytes = _canonical_json_bytes(expected_transaction)
    if transaction_bytes != expected_transaction_bytes:
        raise AcquisitionError(
            "acquisition transaction does not match the closed repository-owned contract"
        )
    transaction_sha256 = hashlib.sha256(transaction_bytes).hexdigest()
    _revalidate_repository_snapshot(repository_snapshot, repository_root)
    return _AcquisitionVerification(
        dataset_id=dataset_id,
        source_set_sha256=source_set_sha256,
        transaction_sha256=transaction_sha256,
    )


def _verify_acquisition_bundle(
    output_dir: Path,
    *,
    repository_snapshot: _RepositorySnapshot,
    repository_root: Path,
) -> AcquisitionBundle:
    """Rehash and semantically verify an existing acquisition bundle."""

    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    try:
        root_mode = output_dir.lstat().st_mode
    except FileNotFoundError as error:
        raise AcquisitionError("acquisition bundle directory does not exist") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise AcquisitionError("acquisition bundle must be a non-symlink directory")
    root = _require_outside_repository(output_dir, repository_root)
    try:
        verified = verify_existing_directory(
            root,
            verifier=lambda artifact_directory: _verify_acquisition_directory(
                artifact_directory,
                repository_snapshot=repository_snapshot,
                repository_root=repository_root,
            ),
        )
    except PublicationArtifactInstallError as error:
        raise AcquisitionError("acquisition bundle failed descriptor-bound verification") from error
    return AcquisitionBundle(
        dataset_id=verified.dataset_id,
        output_dir=root,
        source_set_path=root / _SOURCE_SET_FILENAME,
        transaction_path=root / _TRANSACTION_FILENAME,
        checksums_path=root / _CHECKSUMS_FILENAME,
        source_set_sha256=verified.source_set_sha256,
        transaction_sha256=verified.transaction_sha256,
    )


def _acquisition_verification_fingerprint(
    verification: _AcquisitionVerification,
) -> tuple[str, str, str]:
    return (
        verification.dataset_id,
        verification.source_set_sha256,
        verification.transaction_sha256,
    )


def _quarantine_acquisition_staging(
    temporary: Path,
    staging_identity: tuple[int, int],
) -> None:
    try:
        quarantine_owned_directory(temporary, staging_identity=staging_identity)
    except (OSError, PublicationArtifactInstallError):
        # Preserve any changed directory as diagnostic evidence; never delete it by path.
        return


def _acquire_publication_sources(
    dataset_id: str,
    output_dir: Path,
    *,
    transport: _Transport,
    clock: Callable[[], datetime],
    repository_snapshot: _RepositorySnapshot,
    repository_root: Path,
    transport_runtime: Mapping[str, object] | None = None,
) -> AcquisitionBundle:
    """Private deterministic seam for transport, time, and repository test adapters."""

    _require_pytest_fixture_seam()
    if type(dataset_id) is not str:
        raise TypeError("dataset_id must be an exact string")
    specs = _dataset_specs(dataset_id)
    if repository_snapshot.verification_mode != "test-only-fixed-repository-snapshot-v1":
        raise AcquisitionError("injectable acquisition only accepts the test-only snapshot")
    _behavior_inventory_payload(repository_snapshot)
    if transport_runtime is None:
        transport_runtime = _test_only_transport_runtime()
    transport_runtime = _verified_transport_runtime(
        dict(transport_runtime),
        dataset_id=dataset_id,
        test_only=True,
    )
    normalized_output = _require_outside_repository(output_dir, repository_root)
    _require_new_output_directory(normalized_output)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{normalized_output.name}.tmp-", dir=normalized_output.parent)
    )
    temporary_stat = temporary.lstat()
    staging_identity = temporary_stat.st_dev, temporary_stat.st_ino
    installed = False
    try:
        downloaded = tuple(
            _download_object(spec, temporary, transport=transport, clock=clock) for spec in specs
        )
        source_set_bytes = _canonical_json_bytes(_source_set_payload(dataset_id, downloaded))
        source_set_sha256 = hashlib.sha256(source_set_bytes).hexdigest()
        transaction_bytes = _canonical_json_bytes(
            _transaction_payload(
                dataset_id,
                downloaded,
                source_set_sha256=source_set_sha256,
                repository_snapshot=repository_snapshot,
                transport_runtime=transport_runtime,
            )
        )
        _write_bytes_new(temporary / _SOURCE_SET_FILENAME, source_set_bytes)
        _write_bytes_new(temporary / _TRANSACTION_FILENAME, transaction_bytes)
        artifact_paths = tuple(
            [spec.local_path for spec in specs] + [_SOURCE_SET_FILENAME, _TRANSACTION_FILENAME]
        )
        _write_checksum_manifest(temporary, artifact_paths)
        verified = install_verified_directory(
            temporary,
            normalized_output,
            staging_identity=staging_identity,
            verifier=lambda artifact_directory: _verify_acquisition_directory(
                artifact_directory,
                repository_snapshot=repository_snapshot,
                repository_root=repository_root,
            ),
            fingerprint=_acquisition_verification_fingerprint,
        )
        installed = True
    except PublicationArtifactInstallError as error:
        # The installer preserves rejected or identity-changed evidence.  Do not
        # recurse through a directory whose member ownership is no longer known.
        raise AcquisitionError("acquisition staging installation failed") from error
    except BaseException:
        if not installed:
            _quarantine_acquisition_staging(temporary, staging_identity)
        raise
    return AcquisitionBundle(
        dataset_id=verified.dataset_id,
        output_dir=normalized_output,
        source_set_path=normalized_output / _SOURCE_SET_FILENAME,
        transaction_path=normalized_output / _TRANSACTION_FILENAME,
        checksums_path=normalized_output / _CHECKSUMS_FILENAME,
        source_set_sha256=verified.source_set_sha256,
        transaction_sha256=verified.transaction_sha256,
    )


def _acquire_publication_sources_production(
    dataset_id: str,
    output_dir: Path,
) -> AcquisitionBundle:
    """Run the repository-owned network path without caller-supplied HTTP facts."""

    repository_root = Path(__file__).resolve().parents[2]
    specs = _dataset_specs(dataset_id)
    repository_snapshot = _verify_clean_repository_snapshot(repository_root)
    transport_plan = _production_transport(dataset_id, repository_root)
    transport_runtime = _verified_transport_runtime(
        dict(transport_plan.runtime),
        dataset_id=dataset_id,
        test_only=False,
    )
    normalized_output = _require_outside_repository(output_dir, repository_root)
    _require_new_output_directory(normalized_output)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{normalized_output.name}.tmp-", dir=normalized_output.parent)
    )
    temporary_stat = temporary.lstat()
    staging_identity = temporary_stat.st_dev, temporary_stat.st_ino
    installed = False
    try:
        downloaded = tuple(
            _download_object(
                spec,
                temporary,
                transport=transport_plan.transport,
                clock=lambda: datetime.now(UTC),
            )
            for spec in specs
        )
        source_set_bytes = _canonical_json_bytes(_source_set_payload(dataset_id, downloaded))
        source_set_sha256 = hashlib.sha256(source_set_bytes).hexdigest()
        transaction_bytes = _canonical_json_bytes(
            _transaction_payload(
                dataset_id,
                downloaded,
                source_set_sha256=source_set_sha256,
                repository_snapshot=repository_snapshot,
                transport_runtime=transport_runtime,
            )
        )
        _write_bytes_new(temporary / _SOURCE_SET_FILENAME, source_set_bytes)
        _write_bytes_new(temporary / _TRANSACTION_FILENAME, transaction_bytes)
        artifact_paths = tuple(
            [spec.local_path for spec in specs] + [_SOURCE_SET_FILENAME, _TRANSACTION_FILENAME]
        )
        _write_checksum_manifest(temporary, artifact_paths)
        verified = install_verified_directory(
            temporary,
            normalized_output,
            staging_identity=staging_identity,
            verifier=lambda artifact_directory: _verify_acquisition_directory(
                artifact_directory,
                repository_snapshot=repository_snapshot,
                repository_root=repository_root,
            ),
            fingerprint=_acquisition_verification_fingerprint,
        )
        installed = True
    except PublicationArtifactInstallError as error:
        # The installer preserves rejected or identity-changed evidence.  Do not
        # recurse through a directory whose member ownership is no longer known.
        raise AcquisitionError("acquisition staging installation failed") from error
    except BaseException:
        if not installed:
            _quarantine_acquisition_staging(temporary, staging_identity)
        raise
    return AcquisitionBundle(
        dataset_id=verified.dataset_id,
        output_dir=normalized_output,
        source_set_path=normalized_output / _SOURCE_SET_FILENAME,
        transaction_path=normalized_output / _TRANSACTION_FILENAME,
        checksums_path=normalized_output / _CHECKSUMS_FILENAME,
        source_set_sha256=verified.source_set_sha256,
        transaction_sha256=verified.transaction_sha256,
    )


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: Mapping[str, str],
        new_url: str,
    ) -> None:
        return None


def _single_response_header(headers: object, name: str) -> str | None:
    getter = getattr(headers, "get_all", None)
    if getter is None:
        raise AcquisitionError("HTTP response headers do not support duplicate detection")
    values = getter(name)
    if not values:
        return None
    if len(values) != 1:
        raise AcquisitionError(f"HTTP response contains duplicate {name} headers")
    value = values[0]
    if type(value) is not str:
        raise AcquisitionError(f"HTTP {name} header must be text")
    return value


class _UrllibTransport:
    def __init__(self, *, ca_bundle_path: str) -> None:
        if type(ca_bundle_path) is not str or not ca_bundle_path:
            raise TypeError("ca_bundle_path must be a nonempty string")
        try:
            context = ssl.create_default_context(cafile=ca_bundle_path)
        except (OSError, ssl.SSLError) as error:
            raise AcquisitionError("urllib frozen CA bundle cannot be loaded") from error
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectRedirects(),
            urllib.request.HTTPSHandler(context=context),
        )

    @contextmanager
    def open(self, url: str) -> Iterator[_TransportResponse]:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": _URLLIB_USER_AGENT,
            },
        )
        configured_request_headers = _header_pairs(
            list(request.header_items()),
            field="urllib configured request headers",
        )
        try:
            handle = self._opener.open(request, timeout=120)
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                raise AcquisitionError(f"unexpected HTTP redirect for frozen URL: {url}") from error
            raise AcquisitionError(
                f"HTTP status for frozen URL must be 200; observed {error.code}"
            ) from error
        except urllib.error.URLError as error:
            raise AcquisitionError(f"network acquisition failed for frozen URL: {url}") from error
        with handle:
            raw_content_length = _single_response_header(handle.headers, "Content-Length")
            content_length = _response_content_length(raw_content_length)
            media_type = _single_response_header(handle.headers, "Content-Type")
            if media_type is None:
                media_type = ""
            content_encoding = _single_response_header(handle.headers, "Content-Encoding")
            content_range = _single_response_header(handle.headers, "Content-Range")
            http_etag = _single_response_header(handle.headers, "ETag")
            http_last_modified = _single_response_header(handle.headers, "Last-Modified")
            response_header_observation = _normalized_response_header_observation(
                media_type=media_type,
                content_length=content_length,
                content_encoding=content_encoding,
                content_range=content_range,
                http_etag=http_etag,
                http_last_modified=http_last_modified,
            )

            def chunks() -> Iterator[bytes]:
                while True:
                    chunk = handle.read(_READ_CHUNK_BYTES)
                    if not chunk:
                        return
                    yield chunk

            yield _TransportResponse(
                final_url=handle.geturl(),
                http_status=getattr(handle, "status", None),
                media_type=media_type,
                content_encoding=content_encoding,
                content_range=content_range,
                content_length=content_length,
                http_etag=http_etag,
                http_last_modified=http_last_modified,
                chunks=chunks(),
                http_version=(
                    "HTTP/1.1" if getattr(handle, "version", None) == 11 else "unsupported"
                ),
                configured_request_headers=configured_request_headers,
                normalized_response_headers=response_header_observation,
                normalized_response_headers_sha256=_normalized_response_headers_sha256(
                    response_header_observation
                ),
            )


def _production_curl_terms_transport(
    repository_root: Path,
) -> tuple[_CurlCffiTermsTransport, dict[str, object]]:
    runtime = _production_runtime_base(repository_root)
    expected_distributions = {
        "certifi": "2026.7.22",
        "cffi": "2.1.1",
        "curl-cffi": "0.16.1",
        "pycparser": "3.0",
    }
    try:
        observed_distributions = {
            name: importlib.metadata.version(name) for name in expected_distributions
        }
        import _cffi_backend  # type: ignore[import-not-found]
        import certifi  # type: ignore[import-not-found]
        import cffi  # type: ignore[import-not-found]
        import curl_cffi  # type: ignore[import-not-found]
        import pycparser  # type: ignore[import-not-found]
        from curl_cffi import Curl  # type: ignore[import-not-found]
        from curl_cffi import requests as curl_requests  # type: ignore[import-not-found]
        from curl_cffi.const import CurlHttpVersion, CurlOpt  # type: ignore[import-not-found]
        from curl_cffi.fingerprints import (  # type: ignore[import-not-found]
            NATIVE_IMPERSONATE_TARGETS,
        )
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise AcquisitionError(
            "curl terms acquisition requires the frozen requirements-acquisition.txt environment"
        ) from error
    if observed_distributions != expected_distributions or curl_cffi.__version__ != "0.16.1":
        raise AcquisitionError("curl terms acquisition distribution versions are not frozen")
    environment_root = Path(sys.prefix).resolve()
    native_targets = [
        target for target in NATIVE_IMPERSONATE_TARGETS if target.get("target_name") == "chrome150"
    ]
    if native_targets != [
        {
            "browser": "Chrome",
            "version": "150",
            "os": "macOS",
            "os_version": "Tahoe",
            "target_name": "chrome150",
            "h3_fingerprints": True,
        }
    ]:
        raise AcquisitionError("curl chrome150 native impersonation identity drifted")
    if int(CurlHttpVersion.V2_0) != 3:
        raise AcquisitionError("curl HTTP/2 response identity drifted")
    if int(CurlOpt.PROXY) != _CURL_PROXY_OPTION:
        raise AcquisitionError("curl proxy option identity drifted")
    curl_handle = Curl()
    try:
        curl_version = curl_handle.version().decode("ascii", errors="strict")
    finally:
        curl_handle.close()
    if not curl_version.startswith("libcurl/8.21.0-IMPERSONATE BoringSSL "):
        raise AcquisitionError("curl impersonation runtime version drifted")
    ca_bundle_path = Path(certifi.where()).resolve()
    if _sha256_file(ca_bundle_path) != _CURL_TERMS_CA_BUNDLE_SHA256:
        raise AcquisitionError("curl certifi CA bundle does not match the frozen digest")
    curl_module_path = getattr(curl_cffi, "__file__", None)
    if type(curl_module_path) is not str or not curl_module_path:
        raise AcquisitionError("curl_cffi does not expose a frozen import origin")
    runtime["curl_adapter_runtime"] = {
        "schema_version": "dynamic-cssc-curl-cffi-transport-runtime-v1",
        "distribution_versions": observed_distributions,
        "curl_version": curl_version,
        "http_version_numeric": int(CurlHttpVersion.V2_0),
        "native_impersonation_target": native_targets[0],
        "proxy_option_numeric": int(CurlOpt.PROXY),
        "proxy_value": "empty",
        "runtime_files": {
            "certifi_module": _module_runtime_identity(certifi, environment_root, "certifi module"),
            "ca_bundle": _runtime_file_identity(
                ca_bundle_path, environment_root, "certifi CA bundle"
            ),
            "cffi_backend": _module_runtime_identity(
                _cffi_backend, environment_root, "cffi backend"
            ),
            "cffi_module": _module_runtime_identity(cffi, environment_root, "cffi module"),
            "curl_cffi_module": _module_runtime_identity(
                curl_cffi, environment_root, "curl_cffi module"
            ),
            "curl_cffi_native_wrapper": _runtime_file_identity(
                Path(curl_module_path).with_name("_wrapper.abi3.so"),
                environment_root,
                "curl_cffi native wrapper",
            ),
            "pycparser_module": _module_runtime_identity(
                pycparser, environment_root, "pycparser module"
            ),
        },
    }
    verified_runtime = _verified_transport_runtime(
        runtime,
        dataset_id="stack-overflow",
        test_only=False,
    )
    return (
        _CurlCffiTermsTransport(
            session_factory=curl_requests.Session,
            ca_bundle_path=str(ca_bundle_path),
        ),
        verified_runtime,
    )


def _production_transport(dataset_id: str, repository_root: Path) -> _ProductionTransportPlan:
    if dataset_id != "stack-overflow":
        runtime = _verified_transport_runtime(
            _production_runtime_base(repository_root),
            dataset_id=dataset_id,
            test_only=False,
        )
        default_transport = _UrllibTransport(
            ca_bundle_path=str(_ca_bundle_path_from_runtime(runtime))
        )
        return _ProductionTransportPlan(transport=default_transport, runtime=runtime)
    stack_terms_transport, runtime = _production_curl_terms_transport(repository_root)
    default_transport = _UrllibTransport(ca_bundle_path=str(_ca_bundle_path_from_runtime(runtime)))
    return _ProductionTransportPlan(
        transport=_RepositoryTransport(
            default_transport=default_transport,
            stack_terms_transport=stack_terms_transport,
        ),
        runtime=runtime,
    )


def acquire_publication_sources(dataset_id: str, output_dir: Path) -> AcquisitionBundle:
    """Acquire one repository-frozen primary corpus into an all-new external bundle.

    The resulting transaction records a real exact-URL network fetch but remains
    non-authoritative until a later post-run anchor and ADR 0010 compatibility
    receipt admit the experiment source snapshot.
    """

    if type(dataset_id) is not str:
        raise TypeError("dataset_id must be an exact string")
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    repository_root = Path(__file__).resolve().parents[2]
    normalized_output = _require_outside_repository(output_dir, repository_root)
    return _acquire_publication_sources_production(
        dataset_id,
        normalized_output,
    )
