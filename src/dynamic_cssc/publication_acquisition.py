"""Repository-owned, fail-closed acquisition of publication source objects.

The production interface intentionally accepts only a frozen dataset identity and
an all-new output directory.  URL selection, HTTP policy, attribution, evidence
flags, and repository provenance all remain behind that interface.  A private
transport/time/snapshot seam exists solely so the network transaction can be
tested without downloading the publication corpus.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
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
ACQUISITION_TRANSACTION_SCHEMA = "dynamic-cssc-acquisition-transaction-v2"

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_ROLE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_READ_CHUNK_BYTES = 1024 * 1024
_TRANSACTION_FILENAME = "ACQUISITION-TRANSACTION.json"
_SOURCE_SET_FILENAME = "source-set.json"
_CHECKSUMS_FILENAME = "SHA256SUMS"
_REDISTRIBUTION_POLICY = "derived-trace-and-download-by-source-only"
_HTTP_USER_AGENT = "dynamic-cssc-publication-acquisition/1"
_HTTP_REQUEST_POLICY = MappingProxyType(
    {
        "method": "GET",
        "accept_encoding": "identity",
        "user_agent": _HTTP_USER_AGENT,
        "redirect_policy": "reject-any-final-url-drift",
        "content_length_required": True,
        "content_encoding": "identity-or-absent",
        "content_range": "forbidden",
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


class _Transport(Protocol):
    def open(self, url: str) -> AbstractContextManager[_TransportResponse]: ...


@dataclass(frozen=True, slots=True)
class _RepositorySnapshot:
    source_git_sha: str
    behavior_inventory: Mapping[str, object]
    verification_mode: str


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
    final_url: str
    http_status: int
    media_type: str
    content_encoding: str | None
    content_range: None
    retrieval_utc: str
    http_etag: str | None
    http_last_modified: str | None
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


def _test_only_repository_snapshot() -> _RepositorySnapshot:
    """Create deterministic non-authoritative Git identities for the private test seam."""

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
                "behavior_set_schema_version": "dynamic-cssc-acquisition-behavior-set-v1",
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
    if type(response.content_length) is not int or response.content_length <= 0:
        raise AcquisitionError(
            f"Content-Length for acquisition role {spec.role} must be a positive integer"
        )
    content_encoding = _content_encoding(response.content_encoding)
    _content_range(response.content_range)
    http_etag = _header_value(response.http_etag, "ETag")
    http_last_modified = _header_value(response.http_last_modified, "Last-Modified")
    retrieval_utc = _retrieval_timestamp(clock)
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with target.open("xb") as output:
            for chunk in response.chunks:
                if type(chunk) is not bytes or not chunk:
                    raise AcquisitionError("HTTP response chunks must be nonempty bytes")
                byte_count += len(chunk)
                if byte_count > response.content_length:
                    raise AcquisitionError(
                        f"downloaded bytes exceed Content-Length for role {spec.role}"
                    )
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as error:
        raise AcquisitionError(f"duplicate acquisition target for role {spec.role}") from error
    if byte_count != response.content_length:
        raise AcquisitionError(
            f"downloaded byte count does not match Content-Length for role {spec.role}"
        )
    target.chmod(0o444)
    return _DownloadedObject(
        spec=spec,
        final_url=response.final_url,
        http_status=response.http_status,
        media_type=media_type,
        content_encoding=content_encoding,
        content_range=None,
        retrieval_utc=retrieval_utc,
        http_etag=http_etag,
        http_last_modified=http_last_modified,
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
) -> dict[str, object]:
    return {
        "schema_version": ACQUISITION_TRANSACTION_SCHEMA,
        "dataset_id": dataset_id,
        "dataset_release": frozen_dataset_release(dataset_id),
        "repository_provenance": {
            "source_git_sha": repository_snapshot.source_git_sha,
            "verification_mode": repository_snapshot.verification_mode,
            "behavior_inventory": _behavior_inventory_payload(repository_snapshot),
        },
        "network_fetch_performed": True,
        "formal_authority_granted": False,
        "acquisition_network_authority_verified": False,
        "post_run_anchor_verified": False,
        "evidence_compatibility_verified": False,
        "authority_hold_reason": (
            "post-run-anchor-and-adr-0010-evidence-compatibility-not-admitted"
        ),
        "http_request_policy": dict(_HTTP_REQUEST_POLICY),
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
                "request_url": item.spec.request_url,
                "final_url": item.final_url,
                "http_status": item.http_status,
                "media_type": item.media_type,
                "content_encoding": item.content_encoding,
                "content_range": item.content_range,
                "retrieval_utc": item.retrieval_utc,
                "http_etag": item.http_etag,
                "http_last_modified": item.http_last_modified,
                "content_length": item.byte_count,
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


def _read_canonical_json_object(path: Path, field: str) -> tuple[dict[str, object], bytes]:
    raw = _read_artifact_bytes(path)
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
    root: Path,
) -> tuple[_DownloadedObject, ...]:
    raw_objects = transaction.get("objects")
    if type(raw_objects) is not list or len(raw_objects) != len(specs):
        raise AcquisitionError("transaction objects must equal the exact frozen role set")
    downloaded: list[_DownloadedObject] = []
    expected_keys = {
        "object_kind",
        "role",
        "request_url",
        "final_url",
        "http_status",
        "media_type",
        "content_encoding",
        "content_range",
        "retrieval_utc",
        "http_etag",
        "http_last_modified",
        "content_length",
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
        content_length = raw_object["content_length"]
        byte_count = raw_object["byte_count"]
        if (
            type(content_length) is not int
            or content_length <= 0
            or type(byte_count) is not int
            or byte_count != content_length
        ):
            raise AcquisitionError("transaction byte count must equal positive Content-Length")
        sha256 = raw_object["sha256"]
        if type(sha256) is not str or _LOWER_SHA256.fullmatch(sha256) is None:
            raise AcquisitionError("transaction object SHA-256 must be lowercase hexadecimal")
        if raw_object["local_path"] != spec.local_path:
            raise AcquisitionError("transaction contains a duplicate or non-frozen target path")
        if raw_object["section_anchor"] != spec.section_anchor:
            raise AcquisitionError(
                "transaction terms section anchor does not match the frozen value"
            )
        object_path = root / spec.local_path
        if object_path.stat().st_size != byte_count:
            raise AcquisitionError("transaction byte count does not match the retained object")
        if _sha256_file(object_path) != sha256:
            raise AcquisitionError("transaction SHA-256 does not match the retained object")
        downloaded.append(
            _DownloadedObject(
                spec=spec,
                final_url=spec.request_url,
                http_status=200,
                media_type=media_type,
                content_encoding=content_encoding,
                content_range=None,
                retrieval_utc=retrieval_utc,
                http_etag=http_etag,
                http_last_modified=http_last_modified,
                byte_count=byte_count,
                sha256=sha256,
            )
        )
    return tuple(downloaded)


def _verify_acquisition_bundle(
    output_dir: Path,
    *,
    repository_snapshot: _RepositorySnapshot,
    repository_root: Path,
) -> AcquisitionBundle:
    """Rehash and semantically verify a bundle through the private evidence seam."""

    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    try:
        root_mode = output_dir.lstat().st_mode
    except FileNotFoundError as error:
        raise AcquisitionError("acquisition bundle directory does not exist") from error
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise AcquisitionError("acquisition bundle must be a non-symlink directory")
    root = _require_outside_repository(output_dir, repository_root)
    _revalidate_repository_snapshot(repository_snapshot, repository_root)
    behavior_inventory = _behavior_inventory_payload(repository_snapshot)

    transaction, transaction_bytes = _read_canonical_json_object(
        root / _TRANSACTION_FILENAME,
        "acquisition transaction",
    )
    dataset_id = transaction.get("dataset_id")
    if type(dataset_id) is not str:
        raise AcquisitionError("acquisition transaction dataset_id must be an exact string")
    specs = _dataset_specs(dataset_id)
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
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for path in root.rglob("*"):
        relative_path = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise AcquisitionError("acquisition bundle must not contain symbolic links")
        if stat.S_ISDIR(mode):
            observed_directories.add(relative_path)
        elif stat.S_ISREG(mode):
            observed_files.add(relative_path)
        else:
            raise AcquisitionError("acquisition bundle must contain only regular files")
    if observed_files != expected_files:
        raise AcquisitionError("acquisition bundle files do not match the exact frozen set")
    if observed_directories != expected_directories:
        raise AcquisitionError("acquisition bundle directories do not match the exact frozen set")

    checksummed_paths = tuple(sorted(expected_files - {_CHECKSUMS_FILENAME}))
    expected_checksums = "".join(
        f"{_sha256_file(root / relative_path)}  {relative_path}\n"
        for relative_path in checksummed_paths
    ).encode("ascii")
    if _read_artifact_bytes(root / _CHECKSUMS_FILENAME) != expected_checksums:
        raise AcquisitionError("SHA256SUMS does not exactly bind every acquisition artifact")

    source_set, source_set_bytes = _read_canonical_json_object(
        root / _SOURCE_SET_FILENAME,
        "source-set",
    )
    downloaded = _verified_downloaded_objects(transaction, specs, root)
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
    return AcquisitionBundle(
        dataset_id=dataset_id,
        output_dir=root,
        source_set_path=root / _SOURCE_SET_FILENAME,
        transaction_path=root / _TRANSACTION_FILENAME,
        checksums_path=root / _CHECKSUMS_FILENAME,
        source_set_sha256=source_set_sha256,
        transaction_sha256=transaction_sha256,
    )


def _acquire_publication_sources(
    dataset_id: str,
    output_dir: Path,
    *,
    transport: _Transport,
    clock: Callable[[], datetime],
    repository_snapshot: _RepositorySnapshot,
    repository_root: Path,
) -> AcquisitionBundle:
    """Private deterministic seam for transport, time, and repository test adapters."""

    if type(dataset_id) is not str:
        raise TypeError("dataset_id must be an exact string")
    specs = _dataset_specs(dataset_id)
    _behavior_inventory_payload(repository_snapshot)
    normalized_output = _require_outside_repository(output_dir, repository_root)
    _require_new_output_directory(normalized_output)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{normalized_output.name}.tmp-", dir=normalized_output.parent)
    )
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
            )
        )
        _write_bytes_new(temporary / _SOURCE_SET_FILENAME, source_set_bytes)
        _write_bytes_new(temporary / _TRANSACTION_FILENAME, transaction_bytes)
        artifact_paths = tuple(
            [spec.local_path for spec in specs] + [_SOURCE_SET_FILENAME, _TRANSACTION_FILENAME]
        )
        _write_checksum_manifest(temporary, artifact_paths)
        verified = _verify_acquisition_bundle(
            temporary,
            repository_snapshot=repository_snapshot,
            repository_root=repository_root,
        )
        _require_new_output_directory(normalized_output)
        temporary.rename(normalized_output)
        installed = True
    except BaseException:
        if not installed:
            shutil.rmtree(temporary, ignore_errors=True)
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
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_RejectRedirects())

    @contextmanager
    def open(self, url: str) -> Iterator[_TransportResponse]:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": _HTTP_USER_AGENT,
            },
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
            if (
                raw_content_length is None
                or not raw_content_length.isascii()
                or not raw_content_length.isdigit()
            ):
                content_length: int | None = None
            else:
                content_length = int(raw_content_length)
            media_type = _single_response_header(handle.headers, "Content-Type")
            if media_type is None:
                media_type = ""

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
                content_encoding=_single_response_header(handle.headers, "Content-Encoding"),
                content_range=_single_response_header(handle.headers, "Content-Range"),
                content_length=content_length,
                http_etag=_single_response_header(handle.headers, "ETag"),
                http_last_modified=_single_response_header(handle.headers, "Last-Modified"),
                chunks=chunks(),
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
    snapshot = _verify_clean_repository_snapshot(repository_root)
    return _acquire_publication_sources(
        dataset_id,
        normalized_output,
        transport=_UrllibTransport(),
        clock=lambda: datetime.now(UTC),
        repository_snapshot=snapshot,
        repository_root=repository_root,
    )
